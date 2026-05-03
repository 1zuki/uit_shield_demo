from __future__ import annotations

import re
from dataclasses import dataclass
from difflib import SequenceMatcher
from urllib.parse import urlparse

URL_PATTERN = re.compile(r"(https?://[^\s<>()\"']+|www\.[^\s<>()\"']+)", re.IGNORECASE)
EMAIL_PATTERN = re.compile(r"[\w\.-]+@[\w\.-]+\.\w+", re.IGNORECASE)

TRUSTED_DOMAINS = {
    "uit.edu.vn", "student.uit.edu.vn", "courses.uit.edu.vn", "daa.uit.edu.vn",
    "ctsv.uit.edu.vn", "gmail.com", "google.com", "accounts.google.com",
}

URL_SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "ow.ly", "rebrand.ly", "cutt.ly", "shorturl.at"}

PSYCHOLOGICAL_TRIGGERS = {
    "urgency": ["khẩn cấp", "ngay lập tức", "xử lý ngay", "phản hồi ngay", "trong hôm nay", "trong 24 giờ", "chỉ còn", "hạn cuối", "last chance", "urgent", "immediately", "within 24 hours"],
    "fear_threat": ["khóa tài khoản", "tạm ngưng tài khoản", "cấm thi", "hủy đăng ký", "đình chỉ", "vi phạm", "bị phạt", "account suspended", "account locked", "security alert", "unauthorized access"],
    "authority": ["phòng đào tạo", "phòng công tác sinh viên", "ban giám hiệu", "công an", "viện kiểm sát", "admin", "support team", "security team", "official notice"],
    "reward_bait": ["nhận thưởng", "trúng thưởng", "học bổng", "việc nhẹ lương cao", "thực tập lương cao", "cơ hội đặc biệt", "free gift", "reward", "prize", "claim now"],
    "credential_request": ["xác minh tài khoản", "đăng nhập lại", "cập nhật mật khẩu", "mã otp", "mã xác thực", "mật khẩu", "password", "verify your account", "login", "sign in", "otp", "2fa"],
    "payment_request": ["chuyển khoản", "đặt cọc", "phí xử lý", "thanh toán", "payment", "transfer money", "deposit", "processing fee"],
}

@dataclass
class URLFinding:
    url: str
    domain: str
    reasons: list[str]
    risk: float

@dataclass
class TriggerFinding:
    category: str
    matches: list[str]

def normalize_text(text: str) -> str:
    return re.sub(r"\s+", " ", text.lower()).strip()

def extract_urls(text: str) -> list[str]:
    return [u.rstrip(".,;:!?)]}") for u in URL_PATTERN.findall(text or "")]

def extract_emails(text: str) -> list[str]:
    return EMAIL_PATTERN.findall(text or "")

def domain_from_url(url: str) -> str:
    candidate = url if url.lower().startswith(("http://", "https://")) else "http://" + url
    parsed = urlparse(candidate)
    return parsed.netloc.lower().split("@")[-1].split(":")[0]

def similarity(a: str, b: str) -> float:
    return SequenceMatcher(None, a.lower(), b.lower()).ratio()

def looks_like_trusted_domain(domain: str) -> tuple[bool, str | None]:
    if not domain:
        return False, None

    if domain in TRUSTED_DOMAINS or any(domain.endswith("." + d) for d in TRUSTED_DOMAINS):
        return False, None

    for trusted in TRUSTED_DOMAINS:
        if similarity(domain, trusted) >= 0.76:
            return True, trusted

    return False, None

def analyze_url(url: str) -> URLFinding:
    domain = domain_from_url(url)
    reasons: list[str] = []
    risk = 0.0

    if not url.lower().startswith("https://"):
        reasons.append("URL không sử dụng HTTPS.")
        risk += 0.15

    if domain in URL_SHORTENERS:
        reasons.append("URL dùng dịch vụ rút gọn, khó xác minh nguồn thật.")
        risk += 0.25

    if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", domain or ""):
        reasons.append("URL dùng địa chỉ IP thay vì tên miền rõ ràng.")
        risk += 0.35

    if domain.count("-") >= 2:
        reasons.append("Tên miền chứa nhiều dấu gạch nối bất thường.")
        risk += 0.15

    if "xn--" in domain:
        reasons.append("Tên miền dạng punycode, có nguy cơ giả mạo ký tự.")
        risk += 0.35

    similar, trusted = looks_like_trusted_domain(domain)

    if similar and trusted:
        reasons.append(f"Tên miền gần giống domain đáng tin cậy ({trusted}) nhưng không trùng khớp.")
        risk += 0.4

    if any(token in domain for token in ["verify", "login", "secure", "account", "update"]):
        reasons.append("Tên miền chứa từ khóa thường dùng trong trang giả mạo đăng nhập.")
        risk += 0.15

    return URLFinding(url=url, domain=domain, reasons=reasons, risk=min(risk, 1.0))

def find_triggers(text: str) -> list[TriggerFinding]:
    normalized = normalize_text(text)
    findings = []

    for category, keywords in PSYCHOLOGICAL_TRIGGERS.items():
        matches = sorted({kw for kw in keywords if kw.lower() in normalized})
        if matches:
            findings.append(TriggerFinding(category=category, matches=matches))

    return findings

def rule_based_risk(text: str) -> tuple[float, dict]:
    urls = extract_urls(text)
    url_findings = [analyze_url(url) for url in urls]
    trigger_findings = find_triggers(text)
    emails = extract_emails(text)
    risk = 0.0

    if trigger_findings:
        risk += min(0.50, 0.12 * len(trigger_findings))
    for finding in url_findings:
        risk += 0.40 * finding.risk
    if urls and any("login" in u.lower() or "verify" in u.lower() for u in urls):
        risk += 0.15

    suspicious_email_domains = []

    for email in emails:
        domain = email.split("@")[-1].lower()
        similar, trusted = looks_like_trusted_domain(domain)

        if similar:
            suspicious_email_domains.append((email, trusted))

    if suspicious_email_domains:
        risk += 0.2

    details = {
        "urls": [finding.__dict__ for finding in url_findings],
        "triggers": [finding.__dict__ for finding in trigger_findings],
        "emails": emails,
        "suspicious_email_domains": suspicious_email_domains,
    }
    return min(risk, 1.0), details

def stop_recommendation(risk_label: str) -> list[str]:
    base = [
        "S - Stop: Dừng lại, không nhấp link hoặc nhập thông tin ngay.",
        "T - Think: Tự hỏi vì sao thông điệp bắt bạn phản hồi gấp.",
        "O - Observe: Kiểm tra domain, người gửi, lỗi chính tả, HTTPS và biểu mẫu đăng nhập.",
        "P - Proceed: Chỉ tiếp tục khi xác minh qua kênh chính thức, không dùng link trong tin nhắn nghi vấn.",
    ]

    if risk_label == "safe":
        return ["Nội dung có vẻ an toàn, nhưng vẫn nên kiểm tra nguồn nếu có liên kết hoặc yêu cầu đăng nhập.", *base]

    return base
