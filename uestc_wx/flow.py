"""主流程：凭据 → login_buffer → MMTLS 取码 ×2 → 两段式换票 → 打卡。

两段式换票（对应 MoonCheck 的 command_router.cpp ensureWxTicket）：
  code#1 → POST /platform-app/api/auth/check-bind   → 小程序 SESSION
  code#2 → POST /platform-app/api/auth/checkin-ticket (Cookie: SESSION=<mpSession>)
                                                    → X-Checkin-Ticket

注意 login_buffer 是一次性登录票据：两次取码必须分别重新拉取。
"""
from __future__ import annotations

import json
import os
import time
from dataclasses import asdict
from pathlib import Path

from . import mmtls, platform, yyb


class FlowError(Exception):
    def __init__(self, stage: str, detail: str) -> None:
        super().__init__(detail)
        self.stage = stage
        self.detail = detail


def load_credentials(path: Path) -> yyb.OauthCredentials:
    document = json.loads(path.read_text(encoding="utf-8"))
    cred = yyb.OauthCredentials(
        openid=document.get("openid", ""),
        access_token=document.get("access_token", ""),
        refresh_token=document.get("refresh_token", ""),
        expires_at=int(document.get("expires_at", 0)),
    )
    if not cred.valid():
        raise FlowError("credentials", "credentials file missing openid/access_token")
    # 记录基线：persist 模块据此判断是否发生轮换，避免每次运行都重写 Secret
    baseline = path.with_name(path.stem + "-baseline" + path.suffix)
    try:
        baseline.write_text(json.dumps(document, indent=2), encoding="utf-8")
        os.chmod(baseline, 0o600)
    except OSError:
        pass
    return cred


def save_credentials(path: Path, cred: yyb.OauthCredentials) -> None:
    """凭据轮换后必须立即落盘，否则下一个 runner 拿到的是失效令牌。"""
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(json.dumps({
        "openid": cred.openid,
        "access_token": cred.access_token,
        "refresh_token": cred.refresh_token,
        "expires_at": cred.expires_at,
    }, indent=2), encoding="utf-8")
    os.chmod(temporary, 0o600)
    temporary.replace(path)


def ensure_credentials(cred: yyb.OauthCredentials,
                       path: Path) -> yyb.OauthCredentials:
    """按需刷新凭据并把轮换结果持久化。"""
    if not cred.needs_refresh():
        return cred
    rotated = yyb.refresh_credentials(cred)
    save_credentials(path, rotated)
    return rotated


def get_code(login_buffer: str, app_id: str = platform.MINI_PROGRAM_APP_ID,
             timeout_ms: int = 30000) -> str:
    result = mmtls.get_code(login_buffer, app_id, timeout_ms)
    if result.result != mmtls.WxResult.OK:
        raise FlowError("get_code", result.error_detail or "code request failed")
    return result.code


def acquire_ticket(cred: yyb.OauthCredentials, cred_path: Path,
                   timeout_ms: int = 30000) -> tuple[str, yyb.OauthCredentials]:
    """两段式获取操作票据。返回 (ticket, 可能已轮换的凭据)。"""
    client = platform.PlatformClient()

    # --- code#1：建立小程序会话 ---
    login_buffer, cred = yyb.fetch_login_buffer_with_selfheal(cred)
    save_credentials(cred_path, cred)  # fetch 可能触发过自愈刷新
    code1 = get_code(login_buffer, timeout_ms=timeout_ms)
    mp_session = client.check_bind(code1)

    # --- code#2：换票（login_buffer 一次性，必须重新拉取） ---
    login_buffer2, cred = yyb.fetch_login_buffer_with_selfheal(cred)
    save_credentials(cred_path, cred)
    code2 = get_code(login_buffer2, timeout_ms=timeout_ms)
    ticket = client.request_checkin_ticket(code2, mp_session)
    return ticket, cred


def run_checkin(student_id: str, password: str, fingerprint: str,
                profile: platform.CheckinProfile, cred_path: Path,
                dry_run: bool = False) -> dict:
    """完整打卡流程。返回脱敏结果字典。

    dry_run=True 时只取票不提交（对应 MoonCheck 的 wx.test）。
    """
    result: dict = {
        "ok": False,
        "stage": "credentials",
        "usesWechatProcess": False,
        "automaticRetries": False,
        "requestCounts": {"code": 0, "ticket": 0, "checkin": 0},
        "startedAt": time.strftime("%Y-%m-%d %H:%M:%S"),
    }
    try:
        cred = load_credentials(cred_path)
        cred = ensure_credentials(cred, cred_path)

        result["stage"] = "cas_login"
        client = platform.PlatformClient(user_agent=profile.user_agent)
        client.login(student_id, password, fingerprint)
        client.warm_up_portal()

        if not client.check_authorized():
            raise FlowError("authorization",
                            "mini-program entry not authorized after portal warmup")

        result["stage"] = "today_record"
        today = client.today_record()
        result["today"] = today
        if today.get("recordStatusCode") == "CHECKED_IN":
            result["ok"] = True
            result["stage"] = "already_checked_in"
            result["skipped"] = True
            return result

        result["stage"] = "acquiring_ticket"
        result["requestCounts"]["code"] = 2
        result["requestCounts"]["ticket"] = 1
        ticket, cred = acquire_ticket(cred, cred_path)
        result["ticketLength"] = len(ticket)

        if dry_run:
            result["ok"] = True
            result["stage"] = "ticket_only"
            return result

        result["stage"] = "checkin_sending"
        result["requestCounts"]["checkin"] = 1
        response = client.submit_checkin(profile, ticket)
        result["checkinResponse"] = {
            "httpStatus": response.get("_httpStatus"),
            "code": response.get("code"),
            "msg": response.get("msg"),
            "ok": response.get("ok"),
        }
        accepted = response.get("code") == 0 or response.get("ok") is True
        if not accepted:
            code = response.get("code")
            if code in (46001, 46002, 46003):
                raise FlowError("checkin_ticket_rejected",
                                f"platform rejected ticket (code {code})")
            raise FlowError("checkin_rejected",
                            f"checkin rejected (code {code}, msg {response.get('msg')})")

        result["stage"] = "checkin_verifying"
        after = client.today_record()
        result["after"] = after
        result["ok"] = after.get("recordStatusCode") == "CHECKED_IN"
        result["stage"] = "checkin_accepted" if result["ok"] else "checkin_unverified"
    except FlowError as error:
        result["stage"] = error.stage
        result["error"] = error.detail
    except (yyb.OauthError, platform.PlatformError) as error:
        result["stage"] = getattr(error, "stage", "error")
        result["error"] = getattr(error, "detail", str(error))
    except Exception as error:  # 兜底：绝不让凭据或位置进入日志
        result["stage"] = "error"
        result["error"] = f"{type(error).__name__}: {error}"
    finally:
        result["finishedAt"] = time.strftime("%Y-%m-%d %H:%M:%S")
    return result


def load_profile(path: Path) -> platform.CheckinProfile:
    document = json.loads(path.read_text(encoding="utf-8"))
    payload = document.get("payload", document)
    return platform.CheckinProfile(
        latitude=float(payload["latitude"]),
        longitude=float(payload["longitude"]),
        reverse_geocode=str(payload.get("reverseGeocode", "")),
        user_agent=str(payload.get("userAgent", platform.DEFAULT_USER_AGENT)),
        coordinate_system=str(payload.get("coordinateSystemCode", "gcj02")),
        accuracy=float(payload.get("accuracy", 86)),
        location_duration_ms=float(payload.get("locationDurationMs", 1189)),
        network_type=str(payload.get("networkTypeCode", "4g")),
        location_enabled=bool(payload.get("locationEnabled", False)),
    )
