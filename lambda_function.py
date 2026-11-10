"""
Web Uptime & Security Checker  (CS615 Cloud Project)
-----------------------------------------------------
Lambda function ถูกเรียกผ่าน API Gateway (HTTP API) รองรับ 2 scenarios:
  Scenario 1) เพิ่มเว็บไซต์แล้วตรวจทันที (status code, response time) บันทึกลง DynamoDB
  Scenario 2) ตรวจ SSL certificate + security headers ออกรายงาน และส่งรายงานทางอีเมล (SNS)

Environment variables:
  TABLE_NAME     ชื่อตาราง DynamoDB (default: MonitoredSites)
  TOPIC_ARN      ARN ของ SNS topic สำหรับส่งรายงานทางอีเมล
  SSL_WARN_DAYS  เตือนในรายงานเมื่อ SSL เหลืออายุน้อยกว่ากี่วัน (default: 30)
  CHECK_TIMEOUT  timeout ต่อการเชื่อมต่อ 1 ครั้ง หน่วยวินาที (default: 10)
"""
import base64
import json
import os
import socket
import ssl
import time
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from urllib.parse import urlparse

import boto3

TABLE_NAME = os.environ.get("TABLE_NAME", "MonitoredSites")
TOPIC_ARN = os.environ.get("TOPIC_ARN", "")
SSL_WARN_DAYS = int(os.environ.get("SSL_WARN_DAYS", "30"))
TIMEOUT = int(os.environ.get("CHECK_TIMEOUT", "10"))

table = boto3.resource("dynamodb").Table(TABLE_NAME)
sns = boto3.client("sns")
TH_TZ = timezone(timedelta(hours=7))
USER_AGENT = "Mozilla/5.0 (compatible; WebUptimeChecker/1.0; CS615 project)"

# security header ที่ตรวจ: (คะแนน, ชื่อ, ทำไมต้องมี, ตัวอย่างค่าที่ควรตั้ง)
SECURITY_HEADERS = {
    "strict-transport-security": (
        20, "Strict-Transport-Security (HSTS)",
        "บังคับให้เบราว์เซอร์ใช้ HTTPS เสมอ ป้องกันการถูกดักข้อมูลแบบ downgrade",
        "Strict-Transport-Security: max-age=31536000; includeSubDomains"),
    "content-security-policy": (
        20, "Content-Security-Policy (CSP)",
        "จำกัดแหล่งที่โหลดสคริปต์/รูป/สไตล์ได้ ลดความเสี่ยงจากการโจมตีแบบ XSS",
        "Content-Security-Policy: default-src 'self'"),
    "x-frame-options": (
        15, "X-Frame-Options",
        "ป้องกัน Clickjacking (เว็บถูกนำไปฝังใน iframe ของเว็บอื่นเพื่อหลอกให้คลิก)",
        "X-Frame-Options: DENY  (หรือ SAMEORIGIN)"),
    "x-content-type-options": (
        15, "X-Content-Type-Options",
        "ป้องกันเบราว์เซอร์เดาชนิดไฟล์เอง (MIME sniffing) ซึ่งอาจทำให้รันสคริปต์โดยไม่ตั้งใจ",
        "X-Content-Type-Options: nosniff"),
    "referrer-policy": (
        10, "Referrer-Policy",
        "ควบคุมไม่ให้ URL เต็ม (ซึ่งอาจมีข้อมูลสำคัญ) ถูกส่งต่อไปยังเว็บภายนอก",
        "Referrer-Policy: strict-origin-when-cross-origin"),
    "permissions-policy": (
        10, "Permissions-Policy",
        "จำกัดสิทธิ์การใช้กล้อง ไมโครโฟน และตำแหน่งที่ตั้ง ที่หน้าเว็บไม่จำเป็นต้องใช้",
        "Permissions-Policy: camera=(), microphone=(), geolocation=()"),
}
LEAK_HEADERS = {  # header ที่เปิดเผยข้อมูลซอฟต์แวร์ฝั่งเซิร์ฟเวอร์ (หักข้อละ 5 คะแนน)
    "server": "ซ่อนเลขเวอร์ชันของเว็บเซิร์ฟเวอร์ (เช่น ServerTokens Prod ใน Apache, server_tokens off ใน Nginx)",
    "x-powered-by": "ลบ header X-Powered-By ออก (เช่น expose_php = Off ใน PHP)",
}


# ---------------------------------------------------------------- utilities
def now_iso():
    return datetime.now(TH_TZ).strftime("%Y-%m-%d %H:%M:%S")


def _json_default(o):
    if isinstance(o, Decimal):
        return int(o) if o % 1 == 0 else float(o)
    raise TypeError(str(type(o)))


def respond(status, body):
    return {
        "statusCode": status,
        "headers": {
            "Content-Type": "application/json; charset=utf-8",
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Headers": "Content-Type",
            "Access-Control-Allow-Methods": "GET,POST,DELETE,OPTIONS",
        },
        "body": json.dumps(body, ensure_ascii=False, default=_json_default),
    }


def normalize_url(raw):
    raw = (raw or "").strip()
    if not raw:
        raise ValueError("กรุณาระบุ URL")
    if "://" not in raw:
        raw = "https://" + raw
    p = urlparse(raw)
    if p.scheme not in ("http", "https") or not p.hostname:
        raise ValueError("URL ต้องขึ้นต้นด้วย http:// หรือ https://")
    return raw.rstrip("/") if p.path in ("", "/") else raw


def publish(subject, message):
    if not TOPIC_ARN:
        print("TOPIC_ARN not set, skip email:", subject)
        return False
    sns.publish(TopicArn=TOPIC_ARN, Subject=subject[:99], Message=message)
    print("SNS sent:", subject)
    return True


# ----------------------------------------------------------------- checks
def check_http(url):
    """Scenario 1: ตรวจว่าเว็บตอบสนองไหม, status code, response time"""
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    start = time.time()
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
            code, headers = r.status, r.headers
    except urllib.error.HTTPError as e:      # เว็บตอบกลับมาแต่เป็น 4xx/5xx
        code, headers = e.code, e.headers
    except Exception as e:                   # DNS ไม่เจอ / timeout / ต่อไม่ได้ / SSL เสีย
        return {"status": "DOWN", "status_code": 0,
                "response_ms": int((time.time() - start) * 1000),
                "error": str(getattr(e, "reason", e))[:200], "headers": {}}
    ms = int((time.time() - start) * 1000)
    return {"status": "UP" if code < 400 else "DOWN", "status_code": code,
            "response_ms": ms, "error": "" if code < 400 else f"HTTP {code}",
            "headers": {k.lower(): v for k, v in headers.items()}}


def check_ssl(url):
    """Scenario 2: อ่านใบรับรอง SSL เพื่อดูวันหมดอายุและผู้ออกใบรับรอง"""
    p = urlparse(url)
    if p.scheme != "https":
        return {"ssl_valid": False, "ssl_error": "เว็บไม่ได้ใช้ HTTPS",
                "ssl_expiry": "", "ssl_days_left": None, "ssl_issuer": ""}
    host, port = p.hostname, p.port or 443
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as s:
                cert = s.getpeercert()
        expire_ts = ssl.cert_time_to_seconds(cert["notAfter"])
        issuer = {k: v for rdn in cert.get("issuer", ()) for (k, v) in rdn}
        return {"ssl_valid": True, "ssl_error": "",
                "ssl_expiry": datetime.fromtimestamp(expire_ts, TH_TZ).strftime("%Y-%m-%d"),
                "ssl_days_left": int((expire_ts - time.time()) // 86400),
                "ssl_issuer": issuer.get("organizationName", issuer.get("commonName", ""))}
    except ssl.SSLCertVerificationError as e:
        return {"ssl_valid": False, "ssl_error": f"ใบรับรองไม่ถูกต้อง: {e.verify_message}",
                "ssl_expiry": "", "ssl_days_left": None, "ssl_issuer": ""}
    except Exception as e:
        return {"ssl_valid": False, "ssl_error": f"ตรวจ SSL ไม่ได้: {e}"[:200],
                "ssl_expiry": "", "ssl_days_left": None, "ssl_issuer": ""}


def analyze_security(url, headers, ssl_info):
    """Scenario 2: ให้คะแนน security headers + สร้างคำแนะนำว่าต้องแก้อะไร"""
    score, issues, present, missing = 100, [], [], []
    for key, (pts, name, why, fix) in SECURITY_HEADERS.items():
        if key in headers:
            present.append(name)
        else:
            score -= pts
            missing.append(name)
            issues.append({"level": "HIGH" if pts >= 20 else "MEDIUM",
                           "title": f"ไม่มี {name}", "why": why, "fix": fix})
    for key, fix in LEAK_HEADERS.items():
        val = headers.get(key, "")
        if val and (key == "x-powered-by" or any(c.isdigit() for c in val)):
            score -= 5
            issues.append({"level": "LOW", "title": f"เปิดเผยข้อมูลเซิร์ฟเวอร์ ({key}: {val})",
                           "why": "ผู้โจมตีใช้ข้อมูลเวอร์ชันเพื่อหาช่องโหว่ที่ตรงกับซอฟต์แวร์ได้ง่ายขึ้น",
                           "fix": fix})
    if urlparse(url).scheme != "https":
        issues.insert(0, {"level": "HIGH", "title": "ไม่ได้ใช้ HTTPS",
                          "why": "ข้อมูลที่รับส่งไม่ถูกเข้ารหัส ถูกดักอ่านหรือแก้ไขระหว่างทางได้",
                          "fix": "ติดตั้งใบรับรอง SSL (เช่น Let's Encrypt หรือ AWS Certificate Manager) และ redirect HTTP ไป HTTPS"})
        score = min(score, 50)
    elif not ssl_info["ssl_valid"]:
        issues.insert(0, {"level": "HIGH", "title": "ใบรับรอง SSL มีปัญหา",
                          "why": ssl_info["ssl_error"], "fix": "ต่ออายุหรือติดตั้งใบรับรองใหม่ให้ตรงกับชื่อโดเมน"})
        score = min(score, 50)
    elif ssl_info["ssl_days_left"] is not None and ssl_info["ssl_days_left"] <= SSL_WARN_DAYS:
        issues.insert(0, {"level": "HIGH", "title": f"SSL จะหมดอายุใน {ssl_info['ssl_days_left']} วัน",
                          "why": f"หมดอายุวันที่ {ssl_info['ssl_expiry']} หลังจากนั้นผู้ใช้จะเห็นคำเตือนว่าเว็บไม่ปลอดภัย",
                          "fix": "ต่ออายุใบรับรองก่อนวันหมดอายุ หรือเปิดการต่ออายุอัตโนมัติ"})
    score = max(score, 0)
    grade = "A" if score >= 90 else "B" if score >= 75 else "C" if score >= 60 else "D" if score >= 40 else "F"
    return {"security_score": score, "security_grade": grade, "headers_present": present,
            "headers_missing": missing, "issues": issues}


def full_check(url):
    http = check_http(url)
    ssl_info = check_ssl(url)
    sec = analyze_security(url, http.pop("headers"), ssl_info)
    if http["status"] == "DOWN":   # เว็บล่มจะไม่มี header ให้วิเคราะห์ จึงไม่ให้เกรด
        sec.update(security_score=None, security_grade="-", issues=[])
    return {**http, **ssl_info, **sec}


# ---------------------------------------------------------------- storage
def check_and_update(url):
    """ตรวจ 1 เว็บ (HTTP + SSL + headers) แล้วบันทึกผลล่าสุดลง DynamoDB"""
    old = table.get_item(Key={"url": url}).get("Item") or {}
    res = full_check(url)
    ts = now_iso()
    item = {**old, **res, "url": url, "last_checked": ts,
            "check_count": int(old.get("check_count", 0)) + 1}
    item.setdefault("created_at", ts)
    item = {k: v for k, v in item.items() if v is not None}  # DynamoDB ไม่รับค่า None ในบาง field
    table.put_item(Item=item)
    return item


def build_report_text(item):
    lines = [f"รายงานความปลอดภัยเว็บไซต์: {item['url']}",
             f"ตรวจล่าสุด: {item.get('last_checked', '-')}", "",
             f"สถานะ          : {item.get('status')} (HTTP {item.get('status_code')}, {item.get('response_ms')} ms)",
             f"เกรดความปลอดภัย : {item.get('security_grade')} ({item.get('security_score', '-')}/100)",
             f"SSL           : " + (f"หมดอายุ {item['ssl_expiry']} (เหลือ {item['ssl_days_left']} วัน) โดย {item.get('ssl_issuer', '')}"
                                   if item.get("ssl_valid") else item.get("ssl_error", "-")),
             f"Header ที่มีแล้ว : " + (", ".join(item.get("headers_present", [])) or "-"), "",
             "สิ่งที่ควรแก้ไข:"]
    issues = item.get("issues", [])
    if item.get("status") == "DOWN":
        lines.append(f"  เว็บไม่ตอบสนอง ({item.get('error', '')}) จึงยังวิเคราะห์ security headers ไม่ได้")
    elif not issues:
        lines.append("  ไม่พบประเด็นที่ต้องแก้ไข")
    for i, iss in enumerate(issues, 1):
        lines += [f"{i}. [{iss['level']}] {iss['title']}", f"   เหตุผล : {iss['why']}", f"   วิธีแก้ : {iss['fix']}"]
    lines += ["", "-- Web Uptime & Security Checker"]
    return "\n".join(lines)


def scan_all():
    items, kwargs = [], {}
    while True:
        page = table.scan(**kwargs)
        items += page.get("Items", [])
        if "LastEvaluatedKey" not in page:
            return items
        kwargs["ExclusiveStartKey"] = page["LastEvaluatedKey"]


# ------------------------------------------------------------------ handler
def lambda_handler(event, context):
    # ถูกเรียกจาก API Gateway (รองรับทั้ง payload v1.0 และ v2.0)
    method = (event.get("requestContext", {}).get("http", {}).get("method")
              or event.get("httpMethod") or "GET").upper()
    if method == "OPTIONS":
        return respond(200, {"ok": True})
    qs = event.get("queryStringParameters") or {}
    body = event.get("body") or ""
    if body and event.get("isBase64Encoded"):
        body = base64.b64decode(body).decode("utf-8")
    try:
        data = json.loads(body) if body else {}
    except json.JSONDecodeError:
        data = {}
    action = qs.get("action") or data.get("action") or ("delete" if method == "DELETE" else "list")
    raw_url = data.get("url") or qs.get("url")

    try:
        if action == "list":
            items = sorted(scan_all(), key=lambda i: (i.get("status") != "DOWN", i["url"]))
            return respond(200, {"count": len(items), "items": items})

        if action == "add":                         # Scenario 1
            url = normalize_url(raw_url)
            return respond(200, {"message": "เพิ่มและตรวจเว็บเรียบร้อย", "item": check_and_update(url)})

        if action == "check":                       # ตรวจเว็บเดิมซ้ำทันที
            return respond(200, {"item": check_and_update(normalize_url(raw_url))})

        if action == "report":                      # Scenario 2
            url = normalize_url(raw_url)
            item = check_and_update(url)            # ตรวจใหม่ทุกครั้ง เพื่อให้รายงานเป็นข้อมูลล่าสุด
            return respond(200, {"item": item, "report_text": build_report_text(item)})

        if action == "email_report":                # Scenario 2 ส่งรายงานทางอีเมล
            url = normalize_url(raw_url)
            item = check_and_update(url)
            sent = publish(f"[REPORT] Security report for {urlparse(url).hostname} (grade {item.get('security_grade')})",
                           build_report_text(item))
            return respond(200, {"message": "ส่งรายงานทางอีเมลแล้ว" if sent else "ยังไม่ได้ตั้งค่า TOPIC_ARN",
                                 "item": item})

        if action == "delete":
            url = normalize_url(raw_url)
            table.delete_item(Key={"url": url})
            return respond(200, {"message": f"ลบ {url} ออกจากรายการแล้ว"})

        return respond(400, {"error": f"ไม่รู้จัก action '{action}'"})
    except ValueError as e:
        return respond(400, {"error": str(e)})
    except Exception as e:
        print("ERROR:", repr(e))
        return respond(500, {"error": str(e)})
