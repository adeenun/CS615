"""
LINE Cloud Resource Request Bot  (CS615 Cloud Project)
Runtime : Python 3.12  |  Handler : lambda_function.lambda_handler
Role    : LabRole       |  Timeout : 5 min  |  Memory : 256 MB

Scenarios
  1) ขอ EC2   : ส่ง template #ec2 -> กดยืนยัน -> สร้างเครื่อง -> push IP + ลิงก์ key
  2) ฝากไฟล์   : ส่งรูป/ไฟล์ในแชท -> เก็บใน S3 -> ได้ลิงก์ presigned, คำสั่ง files
  3) รายงาน    : คำสั่ง report -> ใครใช้อะไร, ใช้ไป/เพดาน, อัตราค่าใช้จ่าย
"""
import base64
import hashlib
import hmac
import json
import os
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone

import boto3

# ---------------------------------------------------------------- config
CHANNEL_SECRET = os.environ["LINE_CHANNEL_SECRET"]
ACCESS_TOKEN = os.environ["LINE_CHANNEL_ACCESS_TOKEN"]
ALLOWED_USERS = {u.strip() for u in os.environ.get("ALLOWED_USER_IDS", "").split(",") if u.strip()}
BUCKET = os.environ["BUCKET_NAME"]
KEY_OBJECT = os.environ.get("KEY_OBJECT", "keys/aws-line-bot-key.pem")
KEY_FILE = KEY_OBJECT.split("/")[-1]  # ชื่อไฟล์ที่ผู้ใช้ดาวน์โหลด
KEY_NAME = os.environ["KEY_NAME"]
AMI_ID = os.environ["AMI_ID"]
SG_ID = os.environ["SECURITY_GROUP_ID"]
MAX_INSTANCES = int(os.environ.get("MAX_INSTANCES", "5"))
MAX_VCPU = int(os.environ.get("MAX_VCPU", "10"))
S3_QUOTA_GB = float(os.environ.get("S3_QUOTA_GB", "5"))
MAX_FILE_MB = 10
LINK_TTL = 3600  # presigned URL อายุ 1 ชั่วโมง

PROJECT_TAG = "line-resource-bot"
TH_TZ = timezone(timedelta(hours=7))

# vCPU และราคาโดยประมาณ (USD, us-east-1, Linux On-Demand) — ตรวจราคาล่าสุดก่อนใช้งานจริง
INSTANCE_TYPES = {
    "t2.micro": {"vcpu": 1, "usd_hr": 0.0116},
    "t3.micro": {"vcpu": 2, "usd_hr": 0.0104},
    "t3.small": {"vcpu": 2, "usd_hr": 0.0208},
}
EBS_GB = 8
EBS_USD_GB_MONTH = 0.08     # gp3
IPV4_USD_HR = 0.005         # public IPv4
S3_USD_GB_MONTH = 0.023     # S3 Standard
HOURS_PER_MONTH = 730

ec2 = boto3.client("ec2")
s3 = boto3.client("s3")
lam = boto3.client("lambda")

USER_DATA = """#!/bin/bash
dnf install -y nginx
echo "<h1>Provisioned by LINE Resource Bot</h1><p>Owner: {owner}</p>" > /usr/share/nginx/html/index.html
systemctl enable --now nginx
"""

HELP_TEXT = (
    "คำสั่งที่ใช้ได้\n"
    "• ขอเครื่อง: ส่งข้อความตาม template ด้านล่าง\n"
    "#ec2\nuser: ชื่อผู้ขอ\ntype: t3.micro\npurpose: web\n\n"
    "• status — ดูเครื่องของฉัน\n"
    "• stop <id> / start <id> / terminate <id>\n"
    "• key — ขอลิงก์ดาวน์โหลด SSH key ใหม่\n"
    "• ส่งรูปหรือไฟล์ — ฝากเข้า S3\n"
    "• files — ดูไฟล์ของฉัน\n"
    "• report — รายงานการใช้งานและค่าใช้จ่าย\n"
    f"ชนิดเครื่องที่ขอได้: {', '.join(INSTANCE_TYPES)}"
)


# ================================================================ entry point
def lambda_handler(event, context):
    # งานเบื้องหลังที่ Lambda เรียกตัวเองแบบ async
    if event.get("task") == "create_ec2":
        create_ec2_worker(event)
        return {"ok": True}

    # webhook จาก LINE ผ่าน API Gateway
    body = event.get("body") or ""
    if event.get("isBase64Encoded"):
        body = base64.b64decode(body).decode("utf-8")
    headers = {k.lower(): v for k, v in (event.get("headers") or {}).items()}

    if not verify_signature(body, headers.get("x-line-signature", "")):
        print("invalid signature")
        return {"statusCode": 401, "body": "invalid signature"}

    for ev in json.loads(body).get("events", []):
        try:
            handle_event(ev, context)
        except Exception as e:  # ไม่ให้ event เดียวทำให้ทั้ง batch ล้ม
            print("error:", repr(e))
            token = ev.get("replyToken")
            if token:
                reply(token, [text(f"เกิดข้อผิดพลาด: {e}")])
    return {"statusCode": 200, "body": "OK"}


def verify_signature(body: str, signature: str) -> bool:
    digest = hmac.new(CHANNEL_SECRET.encode(), body.encode(), hashlib.sha256).digest()
    return hmac.compare_digest(base64.b64encode(digest).decode(), signature)


def handle_event(ev, context):
    user_id = ev.get("source", {}).get("userId", "")
    token = ev.get("replyToken")
    if not token:
        return
    if ALLOWED_USERS and user_id not in ALLOWED_USERS:
        reply(token, [text("ขออภัย บัญชีนี้ยังไม่ได้รับสิทธิ์ใช้งาน\nuserId: " + user_id)])
        return

    if ev["type"] == "postback":
        handle_postback(ev["postback"]["data"], user_id, token, context)
    elif ev["type"] == "message":
        msg = ev["message"]
        if msg["type"] == "text":
            handle_text(msg["text"].strip(), user_id, token)
        elif msg["type"] in ("image", "file"):
            handle_upload(msg, user_id, token)
        else:
            reply(token, [text("รองรับเฉพาะข้อความ รูป และไฟล์")])


# ================================================================ text commands
def handle_text(msg, user_id, token):
    lower = msg.lower()
    parts = lower.split()
    cmd = parts[0] if parts else ""

    if lower.startswith("#ec2"):
        return handle_ec2_request(msg, token)
    if cmd in ("help", "เมนู", "menu"):
        return reply(token, [text(HELP_TEXT)])
    if cmd == "status":
        return reply(token, [text(status_text(user_id))])
    if cmd in ("stop", "start") and len(parts) == 2:
        return reply(token, [text(change_state(cmd, parts[1], user_id))])
    if cmd == "terminate" and len(parts) == 2:
        inst = get_owned_instance(parts[1], user_id)
        if not inst:
            return reply(token, [text("ไม่พบเครื่องนี้ หรือไม่ใช่เครื่องของคุณ")])
        return reply(token, [confirm_message(
            f"ยืนยันลบเครื่อง {parts[1]} ถาวร?\nข้อมูลในเครื่องจะหายทั้งหมด",
            "a=term&id=" + parts[1])])
    if cmd == "key":
        return reply(token, [text("ลิงก์ SSH key (อายุ 1 ชม.)\n" + presign(KEY_OBJECT))])
    if cmd == "files":
        return reply(token, [text(files_text(user_id))])
    if cmd == "report":
        return reply(token, [text(report_text())])
    reply(token, [text("ไม่รู้จักคำสั่งนี้ พิมพ์ help เพื่อดูคำสั่งทั้งหมด")])


def parse_template(msg):
    """แปลง 'key: value' แต่ละบรรทัดเป็น dict"""
    fields = {}
    for line in msg.splitlines()[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            fields[k.strip().lower()] = v.strip()
    return fields


def handle_ec2_request(msg, token):
    f = parse_template(msg)
    owner = f.get("user", "")
    itype = f.get("type", "t3.micro").lower()
    purpose = f.get("purpose", "-")

    errors = []
    if not owner:
        errors.append("• ต้องระบุ user")
    if itype not in INSTANCE_TYPES:
        errors.append("• type ต้องเป็น " + ", ".join(INSTANCE_TYPES))
    if len(owner) > 30 or len(purpose) > 30:
        errors.append("• user และ purpose ยาวได้ไม่เกิน 30 ตัวอักษร")
    if errors:
        return reply(token, [text("คำขอไม่ถูกต้อง\n" + "\n".join(errors) + "\n\nพิมพ์ help เพื่อดูตัวอย่าง")])

    data = urllib.parse.urlencode({"a": "ec2", "t": itype, "u": owner, "p": purpose})
    if len(data) > 300:  # LINE จำกัด postback data 300 ตัวอักษร
        return reply(token, [text("ชื่อหรือ purpose ยาวเกินไป กรุณาย่อให้สั้นลง")])

    summary = (f"สรุปคำขอ EC2\nผู้ขอ: {owner}\nชนิด: {itype} "
               f"({INSTANCE_TYPES[itype]['vcpu']} vCPU)\nOS: Amazon Linux 2023 + nginx\n"
               f"ใช้สำหรับ: {purpose}\nค่าใช้จ่ายประมาณ ${INSTANCE_TYPES[itype]['usd_hr']}/ชม.")
    reply(token, [confirm_message(summary, data)])


# ================================================================ postback
def handle_postback(data, user_id, token, context):
    p = dict(urllib.parse.parse_qsl(data))
    action = p.get("a")

    if action == "cancel":
        return reply(token, [text("ยกเลิกคำขอแล้ว")])

    if action == "ec2":
        ok, why = check_capacity(p["t"])
        if not ok:
            return reply(token, [text("สร้างเครื่องไม่ได้: " + why)])
        lam.invoke(
            FunctionName=context.function_name,
            InvocationType="Event",
            Payload=json.dumps({"task": "create_ec2", "user_id": user_id,
                                "type": p["t"], "owner": p["u"], "purpose": p["p"]}).encode(),
        )
        return reply(token, [text("รับคำขอแล้ว กำลังสร้างเครื่อง โปรดรอประมาณ 1-2 นาที "
                                  "ระบบจะแจ้งกลับเมื่อพร้อมใช้งาน")])

    if action == "term":
        inst = get_owned_instance(p["id"], user_id)
        if not inst:
            return reply(token, [text("ไม่พบเครื่องนี้ หรือไม่ใช่เครื่องของคุณ")])
        ec2.terminate_instances(InstanceIds=[p["id"]])
        return reply(token, [text(f"สั่งลบเครื่อง {p['id']} แล้ว")])


# ================================================================ scenario 1: EC2
def project_instances():
    """เครื่องทั้งหมดของบอทที่ยังไม่ถูกลบ (นับเครื่องที่ stop ด้วย
    เพราะ Learner Lab จะ start ให้อัตโนมัติเมื่อเริ่ม session ใหม่)"""
    resp = ec2.describe_instances(Filters=[
        {"Name": "tag:Project", "Values": [PROJECT_TAG]},
        {"Name": "instance-state-name", "Values": ["pending", "running", "stopping", "stopped"]},
    ])
    return [i for r in resp["Reservations"] for i in r["Instances"]]


def tags_of(inst):
    return {t["Key"]: t["Value"] for t in inst.get("Tags", [])}


def check_capacity(itype):
    insts = project_instances()
    vcpu = sum(INSTANCE_TYPES.get(i["InstanceType"], {"vcpu": 2})["vcpu"] for i in insts)
    if len(insts) + 1 > MAX_INSTANCES:
        return False, f"ระบบมีเครื่องครบเพดาน {MAX_INSTANCES} เครื่องแล้ว"
    if vcpu + INSTANCE_TYPES[itype]["vcpu"] > MAX_VCPU:
        return False, f"vCPU จะเกินเพดาน {MAX_VCPU} (ใช้อยู่ {vcpu})"
    return True, ""


def create_ec2_worker(job):
    user_id = job["user_id"]
    try:
        ok, why = check_capacity(job["type"])  # ตรวจซ้ำก่อนสร้างจริง
        if not ok:
            return push(user_id, [text("สร้างเครื่องไม่ได้: " + why)])

        resp = ec2.run_instances(
            ImageId=AMI_ID,
            InstanceType=job["type"],
            KeyName=KEY_NAME,
            SecurityGroupIds=[SG_ID],
            MinCount=1, MaxCount=1,
            UserData=USER_DATA.format(owner=job["owner"]),
            TagSpecifications=[{"ResourceType": "instance", "Tags": [
                {"Key": "Name", "Value": f"bot-{job['owner']}"[:255]},
                {"Key": "Project", "Value": PROJECT_TAG},
                {"Key": "Owner", "Value": user_id},
                {"Key": "RequestedBy", "Value": job["owner"]},
                {"Key": "Purpose", "Value": job["purpose"]},
            ]}],
        )
        iid = resp["Instances"][0]["InstanceId"]
        ec2.get_waiter("instance_running").wait(
            InstanceIds=[iid], WaiterConfig={"Delay": 10, "MaxAttempts": 24})
        inst = ec2.describe_instances(InstanceIds=[iid])["Reservations"][0]["Instances"][0]
        ip = inst.get("PublicIpAddress", "-")

        push(user_id, [text(
            f"✅ เครื่องพร้อมใช้งาน\nID: {iid}\nชนิด: {job['type']}\nPublic IP: {ip}\n"
            f"เว็บ (รอ nginx ติดตั้งอีก ~1 นาที): http://{ip}\n\n"
            f"ดาวน์โหลด SSH key (อายุ 1 ชม.):\n{presign(KEY_OBJECT)}\n\n"
            f"เชื่อมต่อ:\nchmod 400 {KEY_FILE}\nssh -i {KEY_FILE} ec2-user@{ip}"
        )])
    except Exception as e:
        print("create_ec2 failed:", repr(e))
        push(user_id, [text(f"❌ สร้างเครื่องไม่สำเร็จ: {e}")])


def get_owned_instance(iid, user_id):
    try:
        resp = ec2.describe_instances(InstanceIds=[iid])
    except Exception:
        return None
    for r in resp["Reservations"]:
        for i in r["Instances"]:
            t = tags_of(i)
            if t.get("Project") == PROJECT_TAG and t.get("Owner") == user_id:
                return i
    return None


def change_state(cmd, iid, user_id):
    if not get_owned_instance(iid, user_id):
        return "ไม่พบเครื่องนี้ หรือไม่ใช่เครื่องของคุณ"
    if cmd == "stop":
        ec2.stop_instances(InstanceIds=[iid])
        return f"สั่งหยุดเครื่อง {iid} แล้ว (ข้อมูลยังอยู่ เปิดใหม่ได้ด้วย start)"
    if not check_capacity_running_ok():
        return "ไม่สามารถเปิดเครื่องเพิ่มได้ เพราะจะเกินเพดานของระบบ"
    ec2.start_instances(InstanceIds=[iid])
    return f"สั่งเปิดเครื่อง {iid} แล้ว IP ใหม่จะแสดงในคำสั่ง status ภายใน 1 นาที"


def check_capacity_running_ok():
    running = [i for i in project_instances() if i["State"]["Name"] in ("pending", "running")]
    return len(running) < MAX_INSTANCES


def status_text(user_id):
    mine = [i for i in project_instances() if tags_of(i).get("Owner") == user_id]
    if not mine:
        return "คุณยังไม่มีเครื่อง ส่ง template #ec2 เพื่อขอเครื่อง"
    lines = ["เครื่องของคุณ"]
    for i in mine:
        lines.append(f"• {i['InstanceId']}\n  {i['InstanceType']} | {i['State']['Name']} | "
                     f"IP {i.get('PublicIpAddress', '-')} | {tags_of(i).get('Purpose', '-')}")
    return "\n".join(lines)


# ================================================================ scenario 2: S3
def user_prefix(user_id):
    return f"uploads/{user_id}/"


def bucket_usage_bytes(prefix="uploads/"):
    total, count = 0, 0
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=BUCKET, Prefix=prefix):
        for o in page.get("Contents", []):
            total += o["Size"]
            count += 1
    return total, count


def handle_upload(msg, user_id, token):
    if msg["type"] == "file" and msg.get("fileSize", 0) > MAX_FILE_MB * 1024 * 1024:
        return reply(token, [text(f"ไฟล์ใหญ่เกิน {MAX_FILE_MB} MB")])

    used, _ = bucket_usage_bytes()
    if used / 1024 ** 3 >= S3_QUOTA_GB:
        return reply(token, [text(f"พื้นที่ระบบเต็มเพดาน {S3_QUOTA_GB} GB แล้ว")])

    content = line_get_content(msg["id"])
    if len(content) > MAX_FILE_MB * 1024 * 1024:
        return reply(token, [text(f"ไฟล์ใหญ่เกิน {MAX_FILE_MB} MB")])

    stamp = datetime.now(TH_TZ).strftime("%Y%m%d-%H%M%S")
    name = msg.get("fileName") or f"image-{stamp}.jpg"
    key = f"{user_prefix(user_id)}{stamp}-{name}"
    s3.put_object(Bucket=BUCKET, Key=key, Body=content)
    reply(token, [text(f"📁 เก็บไฟล์แล้ว: {name}\nขนาด {len(content) / 1024:.1f} KB\n"
                       f"ลิงก์แชร์ (อายุ 1 ชม.):\n{presign(key)}")])


def files_text(user_id):
    resp = s3.list_objects_v2(Bucket=BUCKET, Prefix=user_prefix(user_id))
    objs = sorted(resp.get("Contents", []), key=lambda o: o["LastModified"], reverse=True)
    if not objs:
        return "ยังไม่มีไฟล์ ส่งรูปหรือไฟล์เข้ามาในแชทเพื่อฝากเก็บ"
    total = sum(o["Size"] for o in objs)
    lines = [f"ไฟล์ของคุณ {len(objs)} ไฟล์ รวม {total / 1024 ** 2:.2f} MB", "(แสดง 5 ไฟล์ล่าสุด)"]
    for o in objs[:5]:
        lines.append(f"• {o['Key'].split('/')[-1]}\n  {presign(o['Key'])}")
    return "\n".join(lines)


# ================================================================ scenario 3: report
def report_text():
    insts = project_instances()
    running = [i for i in insts if i["State"]["Name"] in ("pending", "running")]
    vcpu = sum(INSTANCE_TYPES.get(i["InstanceType"], {"vcpu": 2})["vcpu"] for i in insts)
    s3_bytes, s3_count = bucket_usage_bytes()
    s3_gb = s3_bytes / 1024 ** 3

    # อัตราค่าใช้จ่ายตอนนี้ (USD/ชม.)
    ec2_hr = sum(INSTANCE_TYPES.get(i["InstanceType"], {"usd_hr": 0})["usd_hr"] for i in running)
    ip_hr = IPV4_USD_HR * len(running)
    ebs_hr = EBS_GB * EBS_USD_GB_MONTH * len(insts) / HOURS_PER_MONTH  # EBS คิดแม้เครื่อง stop
    s3_hr = s3_gb * S3_USD_GB_MONTH / HOURS_PER_MONTH
    total_hr = ec2_hr + ip_hr + ebs_hr + s3_hr

    now = datetime.now(TH_TZ).strftime("%d/%m/%Y %H:%M")
    lines = [f"📊 รายงานระบบ ({now})",
             f"EC2: {len(insts)}/{MAX_INSTANCES} เครื่อง (running {len(running)})",
             f"vCPU: {vcpu}/{MAX_VCPU}",
             f"S3: {s3_gb * 1024:.1f} MB / {S3_QUOTA_GB:.0f} GB ({s3_count} ไฟล์)",
             f"เหลือให้ขอได้อีก: {max(MAX_INSTANCES - len(insts), 0)} เครื่อง, "
             f"{max(MAX_VCPU - vcpu, 0)} vCPU",
             "", "ผู้ใช้งาน:"]
    by_owner = {}
    for i in insts:
        by_owner.setdefault(tags_of(i).get("RequestedBy", "?"), []).append(i)
    if not by_owner:
        lines.append("• ยังไม่มีเครื่องในระบบ")
    for owner, items in by_owner.items():
        for i in items:
            lines.append(f"• {owner} — {i['InstanceType']} ({i['State']['Name']}) "
                         f"{tags_of(i).get('Purpose', '')}")
    lines += ["", "💰 ค่าใช้จ่ายโดยประมาณ",
              f"ตอนนี้ ${total_hr:.4f}/ชม.",
              f"ถ้ารันแบบนี้ทั้งเดือน ≈ ${total_hr * HOURS_PER_MONTH:.2f}",
              "(EC2 + EBS + Public IPv4 + S3, ราคา us-east-1)"]
    return "\n".join(lines)


# ================================================================ helpers
def presign(key):
    return s3.generate_presigned_url(
        "get_object", Params={"Bucket": BUCKET, "Key": key}, ExpiresIn=LINK_TTL)


def text(s):
    return {"type": "text", "text": s[:5000]}


def confirm_message(summary, yes_data):
    return {
        "type": "text",
        "text": summary[:5000],
        "quickReply": {"items": [
            {"type": "action", "action": {"type": "postback", "label": "ยืนยัน",
                                          "data": yes_data, "displayText": "ยืนยัน"}},
            {"type": "action", "action": {"type": "postback", "label": "ยกเลิก",
                                          "data": "a=cancel", "displayText": "ยกเลิก"}},
        ]},
    }


def line_api(url, payload=None):
    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode() if payload is not None else None,
        headers={"Authorization": f"Bearer {ACCESS_TOKEN}", "Content-Type": "application/json"},
        method="POST" if payload is not None else "GET",
    )
    with urllib.request.urlopen(req, timeout=20) as r:
        return r.read()


def reply(token, messages):
    """reply message: ฟรี ไม่นับโควตา (ใช้ reply token ได้ครั้งเดียว)"""
    line_api("https://api.line.me/v2/bot/message/reply",
             {"replyToken": token, "messages": messages})


def push(user_id, messages):
    """push message: นับรวมในโควตาข้อความรายเดือน ใช้เฉพาะแจ้งผลงานเบื้องหลัง"""
    line_api("https://api.line.me/v2/bot/message/push",
             {"to": user_id, "messages": messages})


def line_get_content(message_id):
    return line_api(f"https://api-data.line.me/v2/bot/message/{message_id}/content")