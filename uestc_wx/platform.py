"""电子科技大学「晚安成电」平台客户端。

接口契约见 MoonCheck 的 dev/docs/api-contract.md。关键点：
- CAS 登录用 AES-128-CBC（明文 = 64 随机字符 + 密码，IV 不发送）
- 免二次验证由 MULTIFACTOR_BROWSER_FINGERPRINT 决定（直接注入 Cookie）
- 登录后必须做门户预热 GET /api/isLoginFailure，否则微应用一律 4001
- 打卡需同时携带 Cookie: SESSION=<H5 会话> 与 X-Checkin-Ticket: <票据>
- 票据链为两段式：code#1 → check-bind 换小程序 SESSION；code#2 → checkin-ticket
"""
from __future__ import annotations

import base64
import http.cookiejar
import json
import os
import random
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# 平台所有时间字段都按北京时间解释。GitHub runner 的本地时区是 UTC，
# 若用 time.localtime() 会得到 UTC 时间（差 8 小时），导致 clientTime 错位。
CHINA_TZ = timezone(timedelta(hours=8))


def china_now() -> str:
    """返回北京时间 'YYYY-MM-DD HH:MM:SS'，不依赖运行机器的时区。"""
    return datetime.now(CHINA_TZ).strftime("%Y-%m-%d %H:%M:%S")

CAS_BASE = "https://idas.uestc.edu.cn/authserver"
PLATFORM_BASE = "https://jzsz.uestc.edu.cn"
SERVICE = "https://jzsz.uestc.edu.cn/"
LOGIN_URL = f"{CAS_BASE}/login?service={urllib.parse.quote(SERVICE, safe='')}"
BFP_URL = f"{CAS_BASE}/bfp/info"

# 微应用 appId（H5 门户）与小程序 appId
H5_APP_ID = 294
MINI_PROGRAM_APP_ID = "wxaa78bf2905f01cee"

CHECK_BIND_PATH = "/platform-app/api/auth/check-bind"
CHECKIN_TICKET_PATH = "/platform-app/api/auth/checkin-ticket"
PORTAL_WARMUP_PATH = "/api/isLoginFailure"
EP_CHECK_LOGIN = f"/daily-checkin/checkLogin?appId={H5_APP_ID}"
H5_URL = f"{PLATFORM_BASE}/daily-checkin-h5/index.html?appId={H5_APP_ID}"
EP_TODAY = "/daily-checkin/api/student-checkin-record/today"
EP_CHECKIN = "/daily-checkin/api/student-checkin-record/checkin"
EP_SCHEDULE = "/daily-checkin/api/checkin-schedule/effective"
EP_LOCATIONS = "/daily-checkin/api/checkin-location/available-locations"

AES_CHARS = "ABCDEFGHJKMNPQRSTWXYZabcdefhijkmnprstwxyz2345678"
DEFAULT_USER_AGENT = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                      "(KHTML, like Gecko) Chrome/155.0.0.0 Safari/537.36")
TIMEOUT = 25

_RE_EXECUTION = re.compile(r'name="execution"\s+value="([^"]+)"')
_RE_SALT = re.compile(r'id="pwdEncryptSalt"\s+value="([^"]+)"')
_RE_ALT_SALT = re.compile(r'pwdEncryptSalt["\']?\s*[:=]\s*["\']([^"\']+)["\']')
_RE_MFA = re.compile(r"isMultifactor|authLogin")

# 响应体含姓名/学号/手机号/辅导员联系方式，只允许解析这些字段
SAFE_TODAY_FIELDS = (
    "businessDate", "recordStatusCode", "checkinTime", "distanceMeter", "abnormalFlag",
    "checkinLocationName", "checkinLocationLatitude", "checkinLocationLongitude",
    "checkinRadiusMeter",
)


class PlatformError(Exception):
    """带阶段的平台错误。"""

    def __init__(self, stage: str, detail: str) -> None:
        super().__init__(detail)
        self.stage = stage
        self.detail = detail


@dataclass
class CheckinProfile:
    """打卡位置与设备诊断字段。"""
    latitude: float
    longitude: float
    reverse_geocode: str = ""
    user_agent: str = DEFAULT_USER_AGENT
    coordinate_system: str = "gcj02"
    accuracy: float = 86
    location_duration_ms: float = 1189
    network_type: str = "4g"
    location_enabled: bool = False

    def payload(self, now: str | None = None) -> dict:
        """按实测成功载荷逐字段构造（不做字段裁剪：裁剪有产生异常记录的风险）。"""
        client_time = now or china_now()
        return {
            "latitude": self.latitude,
            "longitude": self.longitude,
            "reverseGeocode": self.reverse_geocode,
            "clientTime": client_time,
            "userAgent": self.user_agent,
            "coordinateSystemCode": self.coordinate_system,
            "accuracy": self.accuracy,
            "locationDurationMs": self.location_duration_ms,
            "networkTypeCode": self.network_type,
            "locationEnabled": self.location_enabled,
            "locationAuthorized": "",
            "locationAccuracy": "",
            "errorMessage": "",
        }


def random_string(length: int) -> str:
    return "".join(random.choice(AES_CHARS) for _ in range(length))


def encrypt_password(password: str, salt: str) -> str:
    """金智 CAS 密码加密：AES-128-CBC/PKCS7(64 随机串 + 密码)，IV 不发送。"""
    plain = (random_string(64) + password).encode("utf-8")
    iv = random_string(16).encode("utf-8")
    padder = padding.PKCS7(128).padder()
    padded = padder.update(plain) + padder.finalize()
    cipher = Cipher(algorithms.AES(salt.encode("utf-8")), modes.CBC(iv))
    encryptor = cipher.encryptor()
    return base64.b64encode(encryptor.update(padded) + encryptor.finalize()).decode("ascii")


class PlatformClient:
    """带 Cookie 罐的平台客户端。"""

    def __init__(self, user_agent: str = DEFAULT_USER_AGENT) -> None:
        self.user_agent = user_agent
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.jar))

    # ---- 底层 ----

    def _request(self, method: str, url: str, headers: dict[str, str] | None = None,
                 body: bytes | None = None, follow: bool = True) -> tuple[int, dict, bytes]:
        merged = {"User-Agent": self.user_agent}
        if headers:
            merged.update(headers)
        request = urllib.request.Request(url, data=body, headers=merged, method=method)
        opener = self.opener
        if not follow:
            class _NoRedirect(urllib.request.HTTPRedirectHandler):
                def redirect_request(self, *args, **kwargs):
                    return None
            opener = urllib.request.build_opener(
                urllib.request.HTTPCookieProcessor(self.jar), _NoRedirect)
        try:
            with opener.open(request, timeout=TIMEOUT) as response:
                raw = response.read(1024 * 1024 + 1)
                return response.status, dict(response.headers), raw
        except urllib.error.HTTPError as error:
            raw = error.read(1024 * 1024 + 1)
            return error.code, dict(error.headers or {}), raw
        except (urllib.error.URLError, OSError) as error:
            raise PlatformError("network", f"{method} {url} failed: {error}") from error

    def _json(self, response: tuple[int, dict, bytes]) -> dict:
        status, _headers, raw = response
        if len(raw) > 1024 * 1024:
            raise PlatformError("response", "response exceeds 1 MiB")
        try:
            document = json.loads(raw.decode("utf-8-sig"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return {"_httpStatus": status, "_nonJson": True}
        if not isinstance(document, dict):
            return {"_httpStatus": status, "_nonJson": True}
        document["_httpStatus"] = status
        return document

    # ---- CAS 登录 ----

    def login(self, student_id: str, password: str, fingerprint: str) -> None:
        """CAS 登录并建立 H5 会话；随后做门户预热。"""
        if fingerprint:
            # 直接注入可信指纹 Cookie，等价于浏览器已上报并获批（跳过 bfp/info）
            self.jar.set_cookie(self._make_cookie(
                "MULTIFACTOR_BROWSER_FINGERPRINT", fingerprint,
                domain="idas.uestc.edu.cn"))
        status, _headers, raw = self._request(
            "GET", LOGIN_URL,
            headers={"Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
                     "Upgrade-Insecure-Requests": "1"})
        if status >= 400:
            raise PlatformError("cas_page", f"login page HTTP {status}")
        html = raw.decode("utf-8", "replace")
        execution_match = _RE_EXECUTION.search(html)
        if not execution_match:
            raise PlatformError("cas_page", "execution field not found")
        salt = None
        for pattern in (_RE_SALT, _RE_ALT_SALT):
            match = pattern.search(html)
            if match:
                salt = match.group(1)
                break
        if not salt:
            raise PlatformError("cas_page", "pwdEncryptSalt not found")

        form = urllib.parse.urlencode({
            "username": student_id,
            "password": encrypt_password(password, salt),
            "captcha": "",
            "_eventId": "submit",
            "cllt": "userNameLogin",
            "dllt": "generalLogin",
            "lt": "",
            "execution": execution_match.group(1),
        }).encode("utf-8")
        status, headers, raw = self._request(
            "POST", LOGIN_URL, body=form, follow=False,
            headers={"Content-Type": "application/x-www-form-urlencoded",
                     "Referer": LOGIN_URL})
        location = headers.get("Location", "") or headers.get("location", "")
        if status not in (301, 302, 303, 307):
            # 200 且含多因素标记 → 需要验证码
            text = raw.decode("utf-8", "replace")
            if _RE_MFA.search(text):
                raise PlatformError(
                    "mfa", "login requires MFA; refresh MULTIFACTOR_BROWSER_FINGERPRINT")
            raise PlatformError("cas_login", f"unexpected login status {status}")
        if "ticket=ST-" not in location:
            raise PlatformError("cas_login", "login did not return a CAS ticket")
        # 票据换会话
        self._request("GET", location)
        if not self._session_cookie():
            raise PlatformError("cas_session", "SESSION cookie not issued")

    def _make_cookie(self, name: str, value: str, domain: str):
        return http.cookiejar.Cookie(
            version=0, name=name, value=value, port=None, port_specified=False,
            domain=domain, domain_specified=True, domain_initial_dot=False,
            path="/", path_specified=True, secure=False, expires=None,
            discard=False, comment=None, comment_url=None, rest={})

    def _session_cookie(self) -> str | None:
        for cookie in self.jar:
            if cookie.name == "SESSION" and "jzsz" in cookie.domain:
                return cookie.value
        return None

    def warm_up_portal(self) -> None:
        """门户预热：微应用授权的前提，否则一律 4001（措辞极具误导性）。"""
        url = f"{PLATFORM_BASE}{PORTAL_WARMUP_PATH}?_t={int(time.time() * 1000)}"
        status, _headers, _raw = self._request("GET", url, headers={
            "Accept": "application/json, text/plain, */*",
            "Content-Type": "application/json;charset=UTF-8",
            "Origin": PLATFORM_BASE,
            "Referer": PLATFORM_BASE + "/",
        })
        if status != 200:
            raise PlatformError("portal_warmup", f"warmup HTTP {status}")

    def check_authorized(self) -> bool:
        """GET checkLogin：放行表示微应用已授权。"""
        status, headers, _raw = self._request(
            "GET", PLATFORM_BASE + EP_CHECK_LOGIN, follow=False)
        location = headers.get("Location", "") or headers.get("location", "")
        if status in (301, 302, 303, 307):
            return "daily-checkin-h5" in location
        return 200 <= status < 300

    # ---- 今日状态 / 时段 ----

    def today_record(self) -> dict:
        document = self._json(self._request("GET", PLATFORM_BASE + EP_TODAY, headers={
            "Platform": "h5", "Accept": "*/*",
            "Referer": H5_URL, "Origin": PLATFORM_BASE,
        }))
        data = document.get("data")
        if not isinstance(data, dict):
            return {"_code": document.get("code"), "_msg": document.get("msg")}
        safe = {key: data.get(key) for key in SAFE_TODAY_FIELDS if key in data}
        safe["_code"] = document.get("code")
        safe["_msg"] = document.get("msg")
        return safe

    def effective_schedule(self) -> dict:
        document = self._json(self._request("GET", PLATFORM_BASE + EP_SCHEDULE, headers={
            "Platform": "h5", "Accept": "*/*", "Referer": H5_URL,
        }))
        data = document.get("data")
        if not isinstance(data, dict):
            raise PlatformError("schedule", "schedule response missing data")
        return {
            "startMinute": data.get("studentCheckinStartOffsetMinute"),
            "endMinute": data.get("studentCheckinEndOffsetMinute"),
            "effective": data.get("effective"),
        }

    # ---- 微信票据链（两段式） ----

    def check_bind(self, code: str) -> str:
        """code#1 → 换小程序 SESSION。返回 mp session id（空串表示未绑定）。"""
        body = json.dumps({"code": code, "sn": ""}, separators=(",", ":")).encode("utf-8")
        document = self._json(self._request(
            "POST", PLATFORM_BASE + CHECK_BIND_PATH, body=body,
            headers={"Content-Type": "application/json", "platform": "mp-weixin"}))
        if document.get("ok") is not True:
            raise PlatformError("check_bind", f"check-bind rejected ok={document.get('ok')}")
        data = document.get("data")
        if not isinstance(data, dict):
            raise PlatformError("check_bind", "check-bind response missing data")
        bound = data.get("bind")
        session_id = data.get("sessionId")
        if bound is not True:
            raise PlatformError("check_bind", "WeChat account is not bound to this student")
        if not isinstance(session_id, str) or not session_id:
            raise PlatformError("check_bind", "check-bind did not return sessionId")
        return session_id

    def request_checkin_ticket(self, code: str, mp_session_id: str) -> str:
        """code#2 + 小程序 SESSION → 43 字符操作票据。"""
        body = json.dumps({"code": code}, separators=(",", ":")).encode("utf-8")
        document = self._json(self._request(
            "POST", PLATFORM_BASE + CHECKIN_TICKET_PATH, body=body,
            headers={"Content-Type": "application/json", "platform": "mp-weixin",
                     "Cookie": f"SESSION={mp_session_id}"}))
        if document.get("ok") is not True:
            raise PlatformError("checkin_ticket",
                                f"checkin-ticket rejected ok={document.get('ok')}")
        data = document.get("data")
        ticket = data.get("ticket") if isinstance(data, dict) else None
        if not isinstance(ticket, str) or len(ticket) != 43:
            raise PlatformError("checkin_ticket", "ticket is not 43 characters")
        if not re.fullmatch(r"[A-Za-z0-9_-]{43}", ticket):
            raise PlatformError("checkin_ticket", "ticket has unexpected characters")
        return ticket

    # ---- 提交打卡 ----

    def submit_checkin(self, profile: CheckinProfile, ticket: str,
                       now: str | None = None) -> dict:
        session = self._session_cookie()
        if not session:
            raise PlatformError("checkin", "no SESSION cookie available")
        payload = profile.payload(now)
        body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        document = self._json(self._request(
            "POST", PLATFORM_BASE + EP_CHECKIN, body=body,
            headers={
                "Content-Type": "application/json",
                "Accept": "*/*",
                "Cookie": f"SESSION={session}",
                "X-Checkin-Ticket": ticket,
                "Platform": "h5",
                "Origin": PLATFORM_BASE,
                "Referer": H5_URL,
            }))
        return document
