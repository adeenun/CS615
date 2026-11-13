"""
LINE Cloud Resource Request Bot  (CS615 Cloud Project) — ChatOps edition
Runtime : Python 3.12  |  Handler : lambda_function.lambda_handler
Role    : LabRole       |  Timeout : 5 min  |  Memory : 256 MB

Function นี้รับ event 4 แบบ
  1) LINE webhook (ผ่าน API Gateway)          -> คำสั่งในแชท
  2) {"task": "create_ec2"} (เรียกตัวเอง async)  -> สร้างเครื่อง
  3) EventBridge "Scheduled Event" ทุก 5 นาที   -> เตือนและ auto-stop ตามเวลา
  4) EventBridge "CloudWatch Alarm State Change" -> แจ้งเตือน CPU สูงเข้า LINE

ChatOps
  • run <id> <command>  สั่งคำสั่งบนเครื่องผ่าน Systems Manager (ไม่ต้อง SSH)
  • duration ใน template + เตือนก่อนหมดเวลา + stop อัตโนมัติ + ปุ่มต่อเวลา
  • CloudWatch Alarm เมื่อ CPU เกินเกณฑ์ -> push เข้า LINE
  • SSH key แยกรายเครื่อง สร้างใหม่ทุกคำขอ ลบเมื่อ terminate
"""
import base64
import hashlib
import hmac
import json
import os
import time
import urllib.parse
import urllib.request
import uuid
from datetime import datetime, timedelta, timezone

import boto3

# ---------------------------------------------------------------- config
CHANNEL_SECRET = os.environ["LINE_CHANNEL_SECRET"]
ACCESS_TOKEN = os.environ["LINE_CHANNEL_ACCESS_TOKEN"]
ALLOWED_USERS = {u.strip() for u in os.environ.get("ALLOWED_USER_IDS", "").split(",") if u.strip()}
BUCKET = os.environ["BUCKET_NAME"]
AMI_ID = os.environ["AMI_ID"]
SG_ID = os.environ["SECURITY_GROUP_ID"]
INSTANCE_PROFILE = os.environ.get("INSTANCE_PROFILE", "LabInstanceProfile")
MAX_INSTANCES = int(os.environ.get("MAX_INSTANCES", "5"))
MAX_VCPU = int(os.environ.get("MAX_VCPU", "10"))
S3_QUOTA_GB = float(os.environ.get("S3_QUOTA_GB", "5"))
CPU_ALARM_THRESHOLD = float(os.environ.get("CPU_ALARM_THRESHOLD", "70"))
DEFAULT_HOURS = int(os.environ.get("DEFAULT_HOURS", "2"))
MAX_HOURS = int(os.environ.get("MAX_HOURS", "8"))
WARN_MINUTES = int(os.environ.get("WARN_MINUTES", "15"))
MAX_FILE_MB = 10
LINK_TTL = 3600       # ลิงก์ไฟล์ทั่วไป 1 ชั่วโมง
KEY_LINK_TTL = 600    # ลิงก์ SSH key 10 นาที

PROJECT_TAG = "line-resource-bot"
ALARM_PREFIX = "line-bot-cpu-"
KEY_PREFIX = "keys/"
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

# คำสั่งที่อนุญาตให้รันผ่านแชท (whitelist) — ห้ามรับ shell command จากผู้ใช้ตรงๆ
RUN_COMMANDS = {
    "disk": ("พื้นที่ดิสก์", "df -h /"),
    "memory": ("หน่วยความจำ", "free -m"),
    "uptime": ("เวลาทำงานและ load", "uptime"),
    "nginx-status": ("สถานะ nginx", "systemctl is-active nginx; systemctl status nginx --no-pager | head -n 5"),
    "nginx-restart": ("รีสตาร์ต nginx", "systemctl restart nginx && echo restarted && systemctl is-active nginx"),
    "logs": ("access log 20 บรรทัดล่าสุด", "tail -n 20 /var/log/nginx/access.log || echo 'no log yet'"),
    "stress": ("เพิ่มโหลด CPU 5 นาที (ทดสอบ alarm)",
               "nohup timeout 300 sh -c 'yes > /dev/null & yes > /dev/null & wait' > /dev/null 2>&1 & "
               "echo 'CPU load started for 5 minutes'"),
}

ec2 = boto3.client("ec2")
s3 = boto3.client("s3")
lam = boto3.client("lambda")
ssm = boto3.client("ssm")
cw = boto3.client("cloudwatch")

USER_DATA = """#!/bin/bash
dnf install -y nginx
echo "<h1>Provisioned by LINE Resource Bot</h1><p>Owner: {owner}</p>" > /usr/share/nginx/html/index.html
systemctl enable --now nginx
"""

TEMPLATE_TEXT = (
    "คัดลอกข้อความด้านล่าง แก้ค่าแล้วส่งกลับมาครับ\n\n"
    "#ec2\nuser: ชื่อของคุณ\ntype: t3.micro\npurpose: web\nduration: 2h"
)


def menu_quick_reply():
    items = [("ตัวอย่างคำขอ", "template"), ("ลองขอเครื่อง", SAMPLE_REQUEST), ("คำสั่งทั้งหมด", "help"),
             ("เครื่องของฉัน", "status"), ("รายงาน", "report")]
    return {"items": [{"type": "action", "action": {"type": "message", "label": l, "text": t}}
                      for l, t in items]}


HELP_TEXT = (
    "คำสั่งที่ใช้ได้\n"
    "• ขอเครื่อง: ส่งข้อความตาม template\n"
    "#ec2\nuser: ชื่อผู้ขอ\ntype: t3.micro\npurpose: web\nduration: 2h\n\n"
    "• status — ดูเครื่องของฉัน\n"
    "• run <id> <command> — สั่งงานบนเครื่อง\n"
    f"  command: {', '.join(RUN_COMMANDS)}\n"
    "• extend <id> <ชม.> — ต่อเวลาใช้งาน\n"
    "• stop <id> / start <id> / terminate <id>\n"
    "• key <id> — ลิงก์ SSH key ของเครื่อง\n"
    "• ส่งรูปหรือไฟล์ — ฝากเข้า S3 · files — ดูไฟล์ของฉัน\n"
    "• report — รายงานการใช้งานและค่าใช้จ่าย\n"
    "• template — ตัวอย่างคำขอเครื่อง\n"
    f"ชนิดเครื่อง: {', '.join(INSTANCE_TYPES)} · ใช้ได้ 1-{MAX_HOURS} ชม."
)

GREETINGS = {"สวัสดี", "สวัสดีครับ", "สวัสดีค่ะ", "หวัดดี", "ดีจ้า", "hello", "hi", "hey", "เริ่ม"}

SAMPLE_REQUEST = "#ec2\nuser: demo\ntype: t3.micro\npurpose: web\nduration: 1h"

WELCOME_TEXT = (
    "👋 สวัสดีครับ ยินดีต้อนรับสู่ Cloud Resource Bot\n"
    "ระบบขอและจัดการเครื่อง AWS EC2 ผ่าน LINE (CS615 Cloud Project)\n\n"
    "ทำอะไรได้บ้าง\n"
    "• ขอเครื่อง EC2 พร้อม web server และ SSH key เฉพาะเครื่อง\n"
    "• สั่งงานบนเครื่องผ่านแชท โดยไม่ต้อง SSH\n"
    "• หยุดเครื่องอัตโนมัติตามเวลา พร้อมเตือนก่อนและต่อเวลาได้\n"
    "• แจ้งเตือนเมื่อ CPU สูงผิดปกติ\n"
    "• ฝากไฟล์ใน S3 และดูรายงานการใช้งานและค่าใช้จ่าย\n\n"
    "เริ่มต้น: ส่งข้อความนี้เพื่อขอเครื่อง\n"
    "#ec2\nuser: ชื่อของคุณ\ntype: t3.micro\npurpose: web\nduration: 2h\n\n"
    "พิมพ์ help เพื่อดูคำสั่งทั้งหมด หรือกดปุ่มด้านล่าง"
)


# ================================================================ entry point
def lambda_handler(event, context):
    if event.get("task") == "create_ec2":
        create_ec2_worker(event)
        return {"ok": True}
    detail_type = event.get("detail-type")
    if detail_type == "Scheduled Event":
        sweep_schedules()
        return {"ok": True}
    if detail_type == "CloudWatch Alarm State Change":
        handle_alarm(event)
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

    if ev["type"] == "follow":  # ผู้ใช้เพิ่มบอทเป็นเพื่อน
        reply(token, [welcome_message()])
    elif ev["type"] == "postback":
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
    if lower in GREETINGS or lower.startswith(("สวัสดี", "หวัดดี")):
        return reply(token, [welcome_message()])
    if cmd == "template":
        return reply(token, [text(TEMPLATE_TEXT)])
    if cmd in ("help", "เมนู", "menu"):
        return reply(token, [{**text(HELP_TEXT), "quickReply": menu_quick_reply()}])
    if cmd == "status":
        return reply(token, [text(status_text(user_id))])
    if cmd == "run":
        if len(parts) != 3:
            return reply(token, [text(run_help())])
        return reply(token, [text(run_command(parts[1], parts[2], user_id))])
    if cmd == "result" and len(parts) == 2:
        return reply(token, [text(command_result(parts[1], user_id))])
    if cmd == "extend" and len(parts) == 3:
        return reply(token, [text(extend_instance(parts[1], parse_hours(parts[2]), user_id))])
    if cmd in ("stop", "start") and len(parts) == 2:
        return reply(token, [text(change_state(cmd, parts[1], user_id))])
    if cmd == "terminate" and len(parts) == 2:
        if not get_owned_instance(parts[1], user_id):
            return reply(token, [text("ไม่พบเครื่องนี้ หรือไม่ใช่เครื่องของคุณ")])
        return reply(token, [confirm_message(
            f"ยืนยันลบเครื่อง {parts[1]} ถาวร?\nข้อมูลในเครื่องและ SSH key จะถูกลบทั้งหมด",
            "a=term&id=" + parts[1])])
    if cmd == "key" and len(parts) == 2:
        return reply(token, [text(key_link_text(parts[1], user_id))])
    if cmd == "files":
        return reply(token, [text(files_text(user_id))])
    if cmd == "report":
        return reply(token, [text(report_text())])
    reply(token, [{**text("ไม่รู้จักคำสั่งนี้ เลือกจากปุ่มด้านล่าง หรือพิมพ์ help เพื่อดูคำสั่งทั้งหมด"),
                   "quickReply": menu_quick_reply()}])


def parse_template(msg):
    """แปลง 'key: value' แต่ละบรรทัดเป็น dict"""
    fields = {}
    for line in msg.splitlines()[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            fields[k.strip().lower()] = v.strip()
    return fields


def parse_hours(value):
    """'2h', '2', '90m' -> จำนวนชั่วโมง (ปัดขึ้น) หรือ None ถ้าอ่านไม่ได้"""
    v = (value or "").strip().lower()
    try:
        if v.endswith("m"):
            return max(1, -(-int(v[:-1]) // 60))
        return int(v.rstrip("h").strip())
    except ValueError:
        return None


def handle_ec2_request(msg, token):
    f = parse_template(msg)
    owner = f.get("user", "")
    itype = f.get("type", "t3.micro").lower()
    purpose = f.get("purpose", "-")
    hours = parse_hours(f.get("duration", str(DEFAULT_HOURS)))

    errors = []
    if not owner:
        errors.append("• ต้องระบุ user")
    if itype not in INSTANCE_TYPES:
        errors.append("• type ต้องเป็น " + ", ".join(INSTANCE_TYPES))
    if len(owner) > 30 or len(purpose) > 30:
        errors.append("• user และ purpose ยาวได้ไม่เกิน 30 ตัวอักษร")
    if hours is None or not 1 <= hours <= MAX_HOURS:
        errors.append(f"• duration ต้องอยู่ระหว่าง 1h ถึง {MAX_HOURS}h")
    if errors:
        return reply(token, [text("คำขอไม่ถูกต้อง\n" + "\n".join(errors) + "\n\nพิมพ์ help เพื่อดูตัวอย่าง")])

    data = urllib.parse.urlencode({"a": "ec2", "t": itype, "u": owner, "p": purpose, "d": hours})
    if len(data) > 300:  # LINE จำกัด postback data 300 ตัวอักษร
        return reply(token, [text("ชื่อหรือ purpose ยาวเกินไป กรุณาย่อให้สั้นลง")])

    cost = INSTANCE_TYPES[itype]["usd_hr"]
    summary = (f"สรุปคำขอ EC2\nผู้ขอ: {owner}\nชนิด: {itype} ({INSTANCE_TYPES[itype]['vcpu']} vCPU)\n"
               f"OS: Amazon Linux 2023 + nginx\nใช้สำหรับ: {purpose}\n"
               f"ระยะเวลา: {hours} ชม. (หยุดอัตโนมัติ เตือนก่อน {WARN_MINUTES} นาที)\n"
               f"ค่าใช้จ่ายประมาณ ${cost}/ชม. (≈ ${cost * hours:.3f} ตลอดช่วง)")
    reply(token, [confirm_message(summary, data)])


# ================================================================ postback
def handle_postback(data, user_id, token, context):
    p = dict(urllib.parse.parse_qsl(data))
    action = p.get("a")

    if action == "cancel":
        return reply(token, [text("ยกเลิกแล้ว")])

    if action == "ec2":
        ok, why = check_capacity(p["t"])
        if not ok:
            return reply(token, [text("สร้างเครื่องไม่ได้: " + why)])
        lam.invoke(
            FunctionName=context.function_name,
            InvocationType="Event",
            Payload=json.dumps({"task": "create_ec2", "user_id": user_id, "type": p["t"],
                                "owner": p["u"], "purpose": p["p"], "hours": int(p["d"])}).encode(),
        )
        return reply(token, [text("รับคำขอแล้ว กำลังสร้างเครื่อง โปรดรอประมาณ 1-2 นาที "
                                  "ระบบจะแจ้งกลับเมื่อพร้อมใช้งาน")])

    if action == "term":
        return reply(token, [text(terminate_instance(p["id"], user_id))])
    if action == "extend":
        return reply(token, [text(extend_instance(p["id"], int(p["h"]), user_id))])
    if action == "stopnow":
        return reply(token, [text(change_state("stop", p["id"], user_id))])
    if action == "run":
        return reply(token, [text(run_command(p["id"], p["c"], user_id))])


# ================================================================ EC2 helpers
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


def get_owned_instance(iid, user_id):
    try:
        resp = ec2.describe_instances(InstanceIds=[iid])
    except Exception:
        return None
    for r in resp["Reservations"]:
        for i in r["Instances"]:
            t = tags_of(i)
            if (t.get("Project") == PROJECT_TAG and t.get("Owner") == user_id
                    and i["State"]["Name"] != "terminated"):
                return i
    return None


def check_capacity(itype):
    insts = project_instances()
    vcpu = sum(INSTANCE_TYPES.get(i["InstanceType"], {"vcpu": 2})["vcpu"] for i in insts)
    if len(insts) + 1 > MAX_INSTANCES:
        return False, f"ระบบมีเครื่องครบเพดาน {MAX_INSTANCES} เครื่องแล้ว"
    if vcpu + INSTANCE_TYPES[itype]["vcpu"] > MAX_VCPU:
        return False, f"vCPU จะเกินเพดาน {MAX_VCPU} (ใช้อยู่ {vcpu})"
    return True, ""


def utc_now():
    return datetime.now(timezone.utc)


def iso(dt):
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_iso(s):
    return datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def th_time(dt):
    return dt.astimezone(TH_TZ).strftime("%d/%m %H:%M")


def set_tags(iid, **tags):
    ec2.create_tags(Resources=[iid], Tags=[{"Key": k, "Value": str(v)} for k, v in tags.items()])


# ================================================================ scenario 1: create EC2
def create_ec2_worker(job):
    user_id = job["user_id"]
    key_name = None
    try:
        ok, why = check_capacity(job["type"])  # ตรวจซ้ำก่อนสร้างจริง
        if not ok:
            return push(user_id, [text("สร้างเครื่องไม่ได้: " + why)])

        # 1) SSH key ใหม่สำหรับเครื่องนี้เท่านั้น
        key_name = f"bot-{datetime.now(TH_TZ):%Y%m%d%H%M%S}-{uuid.uuid4().hex[:6]}"
        material = ec2.create_key_pair(KeyName=key_name, KeyType="rsa")["KeyMaterial"]
        s3.put_object(Bucket=BUCKET, Key=f"{KEY_PREFIX}{key_name}.pem", Body=material.encode(),
                      ServerSideEncryption="AES256")

        # 2) สร้างเครื่อง พร้อม instance profile (สำหรับ SSM) และ detailed monitoring (alarm 1 นาที)
        stop_at = utc_now() + timedelta(hours=int(job["hours"]))
        resp = ec2.run_instances(
            ImageId=AMI_ID,
            InstanceType=job["type"],
            KeyName=key_name,
            SecurityGroupIds=[SG_ID],
            IamInstanceProfile={"Name": INSTANCE_PROFILE},
            Monitoring={"Enabled": True},
            MinCount=1, MaxCount=1,
            UserData=USER_DATA.format(owner=job["owner"]),
            TagSpecifications=[{"ResourceType": "instance", "Tags": [
                {"Key": "Name", "Value": f"bot-{job['owner']}"[:255]},
                {"Key": "Project", "Value": PROJECT_TAG},
                {"Key": "Owner", "Value": user_id},
                {"Key": "RequestedBy", "Value": job["owner"]},
                {"Key": "Purpose", "Value": job["purpose"]},
                {"Key": "KeyName", "Value": key_name},
                {"Key": "StopAt", "Value": iso(stop_at)},
            ]}],
        )
        iid = resp["Instances"][0]["InstanceId"]

        # 3) CloudWatch alarm เมื่อ CPU สูง (ส่งต่อเข้า LINE ผ่าน EventBridge)
        create_cpu_alarm(iid)

        ec2.get_waiter("instance_running").wait(
            InstanceIds=[iid], WaiterConfig={"Delay": 10, "MaxAttempts": 24})
        inst = ec2.describe_instances(InstanceIds=[iid])["Reservations"][0]["Instances"][0]
        ip = inst.get("PublicIpAddress", "-")

        push(user_id, [{
            **text(
                f"✅ เครื่องพร้อมใช้งาน\nID: {iid}\nชนิด: {job['type']}\nPublic IP: {ip}\n"
                f"เว็บ (รอ nginx ~1 นาที): http://{ip}\n"
                f"หยุดอัตโนมัติ: {th_time(stop_at)} น.\n"
                f"แจ้งเตือนเมื่อ CPU > {CPU_ALARM_THRESHOLD:.0f}%\n\n"
                f"สั่งงานผ่านแชทได้เลย (รอ SSM ลงทะเบียน 1-2 นาที) เช่น\nrun {iid} disk\n\n"
                f"SSH key เฉพาะเครื่องนี้ (ลิงก์อายุ 10 นาที, ขอใหม่: key {iid}):\n"
                f"{presign(f'{KEY_PREFIX}{key_name}.pem', KEY_LINK_TTL)}\n\n"
                f"chmod 400 {key_name}.pem\nssh -i {key_name}.pem ec2-user@{ip}"),
            "quickReply": run_quick_reply(iid),
        }])
    except Exception as e:
        print("create_ec2 failed:", repr(e))
        if key_name:  # สร้างเครื่องไม่สำเร็จ -> ไม่ทิ้ง key ค้าง
            cleanup_key(key_name)
        push(user_id, [text(f"❌ สร้างเครื่องไม่สำเร็จ: {e}")])


def create_cpu_alarm(iid):
    cw.put_metric_alarm(
        AlarmName=f"{ALARM_PREFIX}{iid}",
        AlarmDescription=f"CPU high on {iid} (LINE resource bot)",
        Namespace="AWS/EC2", MetricName="CPUUtilization",
        Dimensions=[{"Name": "InstanceId", "Value": iid}],
        Statistic="Average", Period=60, EvaluationPeriods=1,
        Threshold=CPU_ALARM_THRESHOLD, ComparisonOperator="GreaterThanThreshold",
        TreatMissingData="notBreaching",
    )


def cleanup_key(key_name):
    for fn in (lambda: ec2.delete_key_pair(KeyName=key_name),
               lambda: s3.delete_object(Bucket=BUCKET, Key=f"{KEY_PREFIX}{key_name}.pem")):
        try:
            fn()
        except Exception as e:
            print("cleanup failed:", repr(e))


# ================================================================ manage EC2
def change_state(cmd, iid, user_id):
    inst = get_owned_instance(iid, user_id)
    if not inst:
        return "ไม่พบเครื่องนี้ หรือไม่ใช่เครื่องของคุณ"
    if cmd == "stop":
        ec2.stop_instances(InstanceIds=[iid])
        return f"สั่งหยุดเครื่อง {iid} แล้ว (ข้อมูลยังอยู่ เปิดใหม่ได้ด้วย start)"
    running = [i for i in project_instances() if i["State"]["Name"] in ("pending", "running")]
    if len(running) >= MAX_INSTANCES:
        return "ไม่สามารถเปิดเครื่องเพิ่มได้ เพราะจะเกินเพดานของระบบ"
    stop_at = utc_now() + timedelta(hours=DEFAULT_HOURS)  # เปิดใหม่ได้เวลาใช้งานรอบใหม่
    set_tags(iid, StopAt=iso(stop_at), Warned="")
    ec2.start_instances(InstanceIds=[iid])
    return (f"สั่งเปิดเครื่อง {iid} แล้ว จะหยุดอัตโนมัติเวลา {th_time(stop_at)} น.\n"
            "IP ใหม่จะแสดงในคำสั่ง status ภายใน 1 นาที")


def terminate_instance(iid, user_id):
    inst = get_owned_instance(iid, user_id)
    if not inst:
        return "ไม่พบเครื่องนี้ หรือไม่ใช่เครื่องของคุณ"
    ec2.terminate_instances(InstanceIds=[iid])
    key_name = tags_of(inst).get("KeyName")
    if key_name:
        cleanup_key(key_name)
    try:
        cw.delete_alarms(AlarmNames=[f"{ALARM_PREFIX}{iid}"])
    except Exception as e:
        print("delete alarm failed:", repr(e))
    return f"สั่งลบเครื่อง {iid} แล้ว พร้อมลบ SSH key และ alarm ของเครื่องนี้"


def extend_instance(iid, hours, user_id):
    if hours is None or not 1 <= hours <= MAX_HOURS:
        return f"ระบุจำนวนชั่วโมง 1-{MAX_HOURS} เช่น extend {iid} 1h"
    inst = get_owned_instance(iid, user_id)
    if not inst:
        return "ไม่พบเครื่องนี้ หรือไม่ใช่เครื่องของคุณ"
    now = utc_now()
    current = tags_of(inst).get("StopAt")
    base = max(now, parse_iso(current)) if current else now
    new_stop = min(base + timedelta(hours=hours), now + timedelta(hours=MAX_HOURS))
    set_tags(iid, StopAt=iso(new_stop), Warned="")
    return f"⏱ ต่อเวลาเครื่อง {iid} แล้ว หยุดอัตโนมัติเวลา {th_time(new_stop)} น."


def key_link_text(iid, user_id):
    inst = get_owned_instance(iid, user_id)
    if not inst:
        return "ไม่พบเครื่องนี้ หรือไม่ใช่เครื่องของคุณ"
    key_name = tags_of(inst).get("KeyName")
    if not key_name:
        return "เครื่องนี้ไม่มี SSH key ที่บอทจัดการ"
    return (f"SSH key ของ {iid} (ลิงก์อายุ 10 นาที)\n"
            f"{presign(f'{KEY_PREFIX}{key_name}.pem', KEY_LINK_TTL)}")


def status_text(user_id):
    mine = [i for i in project_instances() if tags_of(i).get("Owner") == user_id]
    if not mine:
        return "คุณยังไม่มีเครื่อง ส่ง template #ec2 เพื่อขอเครื่อง"
    lines = ["เครื่องของคุณ"]
    for i in mine:
        t = tags_of(i)
        stop = f"หยุด {th_time(parse_iso(t['StopAt']))} น." if t.get("StopAt") else "-"
        lines.append(f"• {i['InstanceId']}\n  {i['InstanceType']} | {i['State']['Name']} | "
                     f"IP {i.get('PublicIpAddress', '-')}\n  {t.get('Purpose', '-')} | {stop}")
    return "\n".join(lines)


# ================================================================ ChatOps: run command (SSM)
def run_help():
    lines = ["รูปแบบ: run <instance-id> <command>", "command ที่ใช้ได้:"]
    lines += [f"• {k} — {v[0]}" for k, v in RUN_COMMANDS.items()]
    return "\n".join(lines)


def run_quick_reply(iid):
    items = [{"type": "action", "action": {
        "type": "postback", "label": name[:20], "data": f"a=run&id={iid}&c={name}",
        "displayText": f"run {iid} {name}"}} for name in ("disk", "memory", "uptime", "nginx-status", "logs")]
    return {"items": items}


def run_command(iid, name, user_id):
    if name not in RUN_COMMANDS:
        return "ไม่รู้จัก command นี้\n\n" + run_help()
    inst = get_owned_instance(iid, user_id)
    if not inst:
        return "ไม่พบเครื่องนี้ หรือไม่ใช่เครื่องของคุณ"
    if inst["State"]["Name"] != "running":
        return f"เครื่องอยู่ในสถานะ {inst['State']['Name']} ต้องเป็น running ก่อน (start {iid})"
    managed = ssm.describe_instance_information(
        Filters=[{"Key": "InstanceIds", "Values": [iid]}]).get("InstanceInformationList", [])
    if not managed or managed[0].get("PingStatus") != "Online":
        return "เครื่องยังไม่พร้อมรับคำสั่ง (SSM agent กำลังลงทะเบียน) ลองใหม่ใน 1-2 นาที"

    label, script = RUN_COMMANDS[name]
    cmd_id = ssm.send_command(
        InstanceIds=[iid], DocumentName="AWS-RunShellScript",
        Parameters={"commands": [script]}, TimeoutSeconds=60,
        Comment=f"LINE bot: {name}")["Command"]["CommandId"]

    for _ in range(10):  # รอผลไม่เกินประมาณ 10 วินาที แล้วตอบด้วย reply (ไม่เปลือง push quota)
        time.sleep(1)
        out = read_invocation(cmd_id, iid)
        if out:
            return f"🖥 {label} · {iid}\n$ {name}\n\n{out}"
    return f"คำสั่งยังทำงานไม่เสร็จ ดูผลภายหลังด้วย\nresult {cmd_id}"


def read_invocation(cmd_id, iid):
    try:
        r = ssm.get_command_invocation(CommandId=cmd_id, InstanceId=iid)
    except ssm.exceptions.InvocationDoesNotExist:
        return None
    if r["Status"] in ("Pending", "InProgress", "Delayed"):
        return None
    output = (r.get("StandardOutputContent") or "") + (r.get("StandardErrorContent") or "")
    return f"[{r['Status']}]\n{output.strip()[:2500] or '(ไม่มี output)'}"


def command_result(cmd_id, user_id):
    try:
        invs = ssm.list_command_invocations(CommandId=cmd_id)["CommandInvocations"]
    except Exception:
        return "ไม่พบคำสั่งนี้"
    if not invs or not get_owned_instance(invs[0]["InstanceId"], user_id):
        return "ไม่พบคำสั่งนี้ หรือไม่ใช่เครื่องของคุณ"
    return read_invocation(cmd_id, invs[0]["InstanceId"]) or "คำสั่งยังทำงานไม่เสร็จ ลองใหม่อีกครั้ง"


# ================================================================ ChatOps: auto-stop (EventBridge ทุก 5 นาที)
def sweep_schedules():
    now = utc_now()
    for inst in project_instances():
        if inst["State"]["Name"] not in ("pending", "running"):
            continue
        t = tags_of(inst)
        iid, owner = inst["InstanceId"], t.get("Owner")
        if not t.get("StopAt") or not owner:
            continue
        stop_at = parse_iso(t["StopAt"])
        try:
            if now >= stop_at:
                ec2.stop_instances(InstanceIds=[iid])
                push(owner, [text(f"⏹ หยุดเครื่อง {iid} อัตโนมัติแล้ว เพราะครบเวลาใช้งาน\n"
                                  f"เปิดใหม่ได้ด้วย: start {iid}")])
            elif now >= stop_at - timedelta(minutes=WARN_MINUTES) and t.get("Warned") != t["StopAt"]:
                set_tags(iid, Warned=t["StopAt"])  # เตือนครั้งเดียวต่อรอบเวลา
                mins = int((stop_at - now).total_seconds() // 60)
                push(owner, [{
                    **text(f"⏰ เครื่อง {iid} ({t.get('Purpose', '-')}) จะหยุดอัตโนมัติในอีก "
                           f"{mins} นาที ({th_time(stop_at)} น.)"),
                    "quickReply": {"items": [
                        {"type": "action", "action": {"type": "postback", "label": "ต่อเวลา 1 ชม.",
                                                      "data": f"a=extend&id={iid}&h=1",
                                                      "displayText": "ต่อเวลา 1 ชม."}},
                        {"type": "action", "action": {"type": "postback", "label": "ต่อเวลา 2 ชม.",
                                                      "data": f"a=extend&id={iid}&h=2",
                                                      "displayText": "ต่อเวลา 2 ชม."}},
                        {"type": "action", "action": {"type": "postback", "label": "หยุดเลย",
                                                      "data": f"a=stopnow&id={iid}",
                                                      "displayText": "หยุดเลย"}},
                    ]},
                }])
        except Exception as e:
            print("sweep failed for", iid, repr(e))


# ================================================================ ChatOps: CPU alarm (EventBridge)
def handle_alarm(event):
    d = event.get("detail", {})
    name = d.get("alarmName", "")
    if not name.startswith(ALARM_PREFIX):
        return
    iid = name[len(ALARM_PREFIX):]
    state = d.get("state", {}).get("value")
    previous = d.get("previousState", {}).get("value")
    try:
        inst = ec2.describe_instances(InstanceIds=[iid])["Reservations"][0]["Instances"][0]
    except Exception:
        return
    owner = tags_of(inst).get("Owner")
    if not owner:
        return
    if state == "ALARM":
        cpu = latest_cpu(iid)
        push(owner, [{
            **text(f"🚨 CPU สูงผิดปกติ\nเครื่อง {iid} ({tags_of(inst).get('Purpose', '-')})\n"
                   f"CPU ล่าสุด {cpu} (เกณฑ์ {CPU_ALARM_THRESHOLD:.0f}%)\n"
                   "กดปุ่มด้านล่างเพื่อตรวจสอบเครื่อง"),
            "quickReply": run_quick_reply(iid),
        }])
    elif state == "OK" and previous == "ALARM":
        push(owner, [text(f"✅ CPU ของเครื่อง {iid} กลับสู่ปกติแล้ว")])


def latest_cpu(iid):
    try:
        pts = cw.get_metric_statistics(
            Namespace="AWS/EC2", MetricName="CPUUtilization",
            Dimensions=[{"Name": "InstanceId", "Value": iid}],
            StartTime=utc_now() - timedelta(minutes=10), EndTime=utc_now(),
            Period=60, Statistics=["Average"])["Datapoints"]
        if pts:
            return f"{max(pts, key=lambda p: p['Timestamp'])['Average']:.1f}%"
    except Exception as e:
        print("cpu metric failed:", repr(e))
    return "-"


# ================================================================ S3 file storage
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


# ================================================================ report
def report_text():
    insts = project_instances()
    running = [i for i in insts if i["State"]["Name"] in ("pending", "running")]
    vcpu = sum(INSTANCE_TYPES.get(i["InstanceType"], {"vcpu": 2})["vcpu"] for i in insts)
    s3_bytes, s3_count = bucket_usage_bytes()
    s3_gb = s3_bytes / 1024 ** 3

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
    if not insts:
        lines.append("• ยังไม่มีเครื่องในระบบ")
    for i in insts:
        t = tags_of(i)
        stop = f" · หยุด {th_time(parse_iso(t['StopAt']))}" if t.get("StopAt") and i in running else ""
        lines.append(f"• {t.get('RequestedBy', '?')} — {i['InstanceType']} ({i['State']['Name']}) "
                     f"{t.get('Purpose', '')}{stop}")
    lines += ["", "💰 ค่าใช้จ่ายโดยประมาณ",
              f"ตอนนี้ ${total_hr:.4f}/ชม.",
              f"ถ้ารันแบบนี้ทั้งเดือน ≈ ${total_hr * HOURS_PER_MONTH:.2f}",
              "(EC2 + EBS + Public IPv4 + S3, ราคา us-east-1, ไม่รวม detailed monitoring)"]
    return "\n".join(lines)


# ================================================================ LINE helpers
def presign(key, ttl=LINK_TTL):
    return s3.generate_presigned_url(
        "get_object", Params={"Bucket": BUCKET, "Key": key}, ExpiresIn=ttl)


def text(s):
    return {"type": "text", "text": s[:5000]}


def welcome_message():
    return {**text(WELCOME_TEXT), "quickReply": menu_quick_reply()}


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
    """reply message: ไม่นับโควตา (ใช้ reply token ได้ครั้งเดียว)"""
    line_api("https://api.line.me/v2/bot/message/reply",
             {"replyToken": token, "messages": messages})


def push(user_id, messages):
    """push message: นับรวมในโควตาข้อความรายเดือน ใช้เฉพาะแจ้งผลงานเบื้องหลังและแจ้งเตือน"""
    line_api("https://api.line.me/v2/bot/message/push",
             {"to": user_id, "messages": messages})


def line_get_content(message_id):
    return line_api(f"https://api-data.line.me/v2/bot/message/{message_id}/content")