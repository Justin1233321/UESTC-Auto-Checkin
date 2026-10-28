"""应用宝（YYB）HTTPS 接入层。

移植自 UESTC-MoonCheck 的 firmware/src/wx_oauth.cpp。

- 凭据刷新：pcyyb_refresh_token_auth（轮换 access/refresh token）
- login_buffer 拉取：pcyyb_get_wx_login_buffer_auth（MMTLS ManualAuth 的输入）
签名：Ual-Access-Signature = MD5(body + timestamp + 公开接入键 + nonce)
"""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from dataclasses import dataclass

from .crypto import md5, to_hex

BASE_URL = "https://yybadaccess.3g.qq.com"
REFRESH_PATH = "/pc_yyb_auth/pcyyb_refresh_token_auth"
LOGIN_BUFFER_PATH = "/pc_yyb_auth/pcyyb_get_wx_login_buffer_auth"
BUSINESS_ID = "pc_yyb_auth"
# 应用宝网页端公开发布的接入键（非密码学秘密）
ACCESS_KEY = "wgrdg373hy26ww2"
TIMEOUT = 20


class OauthResult:
    OK = 0
    NETWORK = 1
    REJECTED = 2
    INVALID = 3


class OauthError(Exception):
    def __init__(self, result: int, detail: str) -> None:
        super().__init__(detail)
        self.result = result
        self.detail = detail


@dataclass
class OauthCredentials:
    openid: str = ""
    access_token: str = ""
    refresh_token: str = ""
    expires_at: int = 0  # Unix 秒

    def valid(self) -> bool:
        return bool(self.openid) and bool(self.access_token)

    def needs_refresh(self, now: int | None = None, margin: int = 60) -> bool:
        now = now if now is not None else int(time.time())
        return not self.valid() or self.expires_at - margin <= now


def _signed_headers(body: str) -> dict[str, str]:
    timestamp = str(int(time.time()) * 1000)
    nonce = str(int(time.time() * 1000) % 10000).zfill(4)
    digest = md5((body + timestamp + ACCESS_KEY + nonce).encode("utf-8"))
    return {
        "Ual-Access-Businessid": BUSINESS_ID,
        "Ual-Access-Timestamp": timestamp,
        "Ual-Access-Nonce": nonce,
        "Ual-Access-Signature": to_hex(digest),
    }


def _post_json(path: str, body: str, cookie: str) -> dict:
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
    }
    headers.update(_signed_headers(body))
    if cookie:
        headers["Cookie"] = cookie
    request = urllib.request.Request(
        BASE_URL + path, data=body.encode("utf-8"), headers=headers, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT) as response:
            raw = response.read(256 * 1024 + 1)
            status = response.status
    except urllib.error.HTTPError as error:
        raw = error.read(256 * 1024 + 1)
        status = error.code
    except (urllib.error.URLError, OSError) as error:
        raise OauthError(OauthResult.NETWORK, f"{path} transport failed: {error}") from error
    if len(raw) > 256 * 1024:
        raise OauthError(OauthResult.INVALID, f"{path} response too large")
    if status == 403:
        # 服务端拒绝该凭据（实测新扫码账号的 access token 可能被提前作废）
        raise OauthError(OauthResult.REJECTED, f"{path} rejected with 403")
    if not 200 <= status < 300:
        raise OauthError(OauthResult.NETWORK, f"{path} http {status}")
    try:
        document = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise OauthError(OauthResult.INVALID, f"{path} returned non-JSON") from error
    if not isinstance(document, dict):
        raise OauthError(OauthResult.INVALID, f"{path} returned unexpected JSON shape")
    return document


def refresh_credentials(cred: OauthCredentials) -> OauthCredentials:
    """刷新凭据（服务端轮换，调用方必须保存返回值）。"""
    if not cred.valid() or not cred.refresh_token:
        raise OauthError(OauthResult.REJECTED, "credentials unusable for refresh")
    body = json.dumps({
        "userInfo": {
            "openId": cred.openid,
            "refreshToken": cred.refresh_token,
            "accessToken": cred.access_token,
            "loginType": "WX",
        }
    }, separators=(",", ":"))
    document = _post_json(REFRESH_PATH, body, "")
    if document.get("code") != 0:
        raise OauthError(OauthResult.REJECTED,
                         f"refresh rejected code={document.get('code')}")
    user_info = document.get("user_info")
    if not isinstance(user_info, dict):
        raise OauthError(OauthResult.INVALID, "refresh response missing user_info")
    access = user_info.get("access_token")
    if not isinstance(access, str) or not access:
        raise OauthError(OauthResult.INVALID, "refresh response missing access_token")
    refresh = user_info.get("refresh_token")
    rotated = OauthCredentials()
    rotated.openid = cred.openid
    rotated.access_token = access
    rotated.refresh_token = refresh if isinstance(refresh, str) and refresh else cred.refresh_token
    expires_in = user_info.get("expires_in")
    if isinstance(expires_in, str):
        try:
            expires_in = int(expires_in)
        except ValueError:
            expires_in = 7200
    elif not isinstance(expires_in, int):
        expires_in = 7200
    if expires_in <= 0:
        expires_in = 7200
    rotated.expires_at = int(time.time()) + expires_in
    return rotated


def fetch_login_buffer(cred: OauthCredentials) -> str:
    """拉取 login_buffer（ManualAuth 输入，短时效，现取现用）。"""
    if not cred.valid():
        raise OauthError(OauthResult.REJECTED, "credentials invalid")
    body = json.dumps({
        "extInfo": {
            "listS": {
                "unionid": {"value": [cred.openid]},
                "user_id": {"value": [cred.openid]},
                "access_token": {"value": [cred.access_token]},
            },
            "listI": {"user_type": {"value": [0]}},
        }
    }, separators=(",", ":"))
    cookie = (f"openid={cred.openid}; accesstoken={cred.access_token}; "
              f"refreshtoken={cred.refresh_token}")
    document = _post_json(LOGIN_BUFFER_PATH, body, cookie)
    if document.get("code") != 0:
        raise OauthError(OauthResult.REJECTED,
                         f"login-buffer rejected code={document.get('code')}")
    try:
        value = document["ext_info"]["list_s"]["login_buffer"]["value"][0]
    except (KeyError, IndexError, TypeError) as error:
        raise OauthError(OauthResult.INVALID, "login-buffer missing in response") from error
    if not isinstance(value, str) or not value:
        raise OauthError(OauthResult.INVALID, "login-buffer is empty")
    return value


def fetch_login_buffer_with_selfheal(cred: OauthCredentials
                                     ) -> tuple[str, OauthCredentials]:
    """拉取 login_buffer；被拒时强制刷新凭据并重试一次。

    参考实现注释：实测新扫码账号的 access token 可能在有效期内被提前作废
    （首次授权后约 8 分钟），refresh token 仍有效即可自愈。
    返回 (login_buffer, 有效凭据) —— 凭据可能已轮换，调用方必须持久化。
    """
    try:
        return fetch_login_buffer(cred), cred
    except OauthError as error:
        if error.result != OauthResult.REJECTED:
            raise
    rotated = refresh_credentials(cred)
    return fetch_login_buffer(rotated), rotated
