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
from pathlib import Path

from . import mmtls, platform, yyb


class FlowError(Exception):
    def __init__(self, stage: str, detail: str) -> None:
        super().__init__(detail)
        self.stage = stage
        self.detail = detail


def load_config(path: Path) -> tuple[yyb.OauthCredentials, platform.CheckinProfile]:
    """读取合并配置（微信凭据 + 打卡位置）。

    必需字段只有 5 个：openid / access_token / refresh_token / latitude / longitude。
    expires_at 可省略（视为 0，首次运行自动刷新），reverseGeocode 建议填写。
    """
    document = json.loads(path.read_text(encoding="utf-8"))
    cred = yyb.OauthCredentials(
        openid=str(document.get("openid", "")),
        access_token=str(document.get("access_token", "")),
        refresh_token=str(document.get("refresh_token", "")),
        expires_at=int(document.get("expires_at", 0)),
    )
    if not cred.valid():
        raise FlowError("credentials",
                        "config missing openid/access_token")

    # 记录基线：便于人工对比本次运行是否发生凭据轮换
    baseline = path.with_name(path.stem + "-baseline" + path.suffix)
    try:
        baseline.write_text(json.dumps(document, indent=2), encoding="utf-8")
        os.chmod(baseline, 0o600)
    except OSError:
        pass

    if "latitude" not in document or "longitude" not in document:
        raise FlowError("profile", "config missing latitude/longitude")
    profile = platform.CheckinProfile(
        latitude=float(document["latitude"]),
        longitude=float(document["longitude"]),
        reverse_geocode=str(document.get("reverseGeocode", "")),
        user_agent=str(document.get("userAgent", platform.DEFAULT_USER_AGENT)),
        coordinate_system=str(document.get("coordinateSystemCode", "gcj02")),
        accuracy=float(document.get("accuracy", 86)),
        location_duration_ms=float(document.get("locationDurationMs", 1189)),
        network_type=str(document.get("networkTypeCode", "4g")),
        location_enabled=bool(document.get("locationEnabled", False)),
    )
    return cred, profile


def load_cas_account(path: Path) -> tuple[str, str, str]:
    """读取 CAS 账号配置，返回 (student_id, password, fingerprint)。"""
    document = json.loads(path.read_text(encoding="utf-8"))
    student_id = str(document.get("student_id", "")).strip()
    password = str(document.get("password", ""))
    fingerprint = str(document.get("fingerprint", "")).strip()
    if not student_id:
        raise FlowError("cas_account", "cas config missing student_id")
    if not password:
        raise FlowError("cas_account", "cas config missing password")
    return student_id, password, fingerprint


def save_credentials(path: Path, cred: yyb.OauthCredentials) -> None:
    """凭据轮换后必须立即落盘，否则下一个 runner 拿到的是失效令牌。

    只更新凭据字段，保留配置里的其他字段（位置等），避免覆盖用户数据。
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        document = {}
    document.update({
        "openid": cred.openid,
        "access_token": cred.access_token,
        "refresh_token": cred.refresh_token,
        "expires_at": cred.expires_at,
    })
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(json.dumps(document, indent=2, ensure_ascii=False),
                         encoding="utf-8")
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
                config_path: Path,
                dry_run: bool = False,
                wait_for_window: bool = False,
                max_wait_minutes: int = 150) -> dict:
    """完整打卡流程。返回脱敏结果字典。

    配置从单个文件读取（微信凭据 + 打卡位置合并）。

    dry_run=True 时只取票不提交（对应 MoonCheck 的 wx.test）。

    wait_for_window=True 时，若当前不在打卡窗口内则在进程内等待，
    直到进入窗口或超过 max_wait_minutes。这是为了应对 GitHub 定时任务
    可能延迟数小时的情况：延迟到窗口外时干等会白跑一次，等待到窗口重开
    反而能救回当天的打卡。
    """
    result: dict = {
        "ok": False,
        "stage": "credentials",
        "usesWechatProcess": False,
        "automaticRetries": False,
        "requestCounts": {"code": 0, "ticket": 0, "checkin": 0},
        "startedAt": platform.china_now(),
    }
    try:
        cred, profile = load_config(config_path)
        cred = ensure_credentials(cred, config_path)

        result["stage"] = "cas_login"
        client = platform.PlatformClient(user_agent=profile.user_agent)
        client.login(student_id, password, fingerprint)
        client.warm_up_portal()

        if not client.check_authorized():
            raise FlowError("authorization",
                            "mini-program entry not authorized after portal warmup")

        # --- 幂等检查（先查今日记录，已打卡直接退出）---
        result["stage"] = "today_record"
        today = client.today_record()
        result["today"] = today
        if today.get("recordStatusCode") == "CHECKED_IN":
            result["ok"] = True
            result["stage"] = "already_checked_in"
            result["skipped"] = True
            return result

        # --- 时间窗检查（避免像 4006 那样白跑一次）---
        if not dry_run:
            schedule = client.effective_schedule()
            result["schedule"] = schedule
            start = schedule.get("startMinute")
            end = schedule.get("endMinute")
            if isinstance(start, int) and isinstance(end, int):
                if not platform.in_checkin_window(start, end):
                    waited = 0
                    if wait_for_window and _minutes_until_window(start) <= max_wait_minutes:
                        while not platform.in_checkin_window(start, end):
                            remaining = _minutes_until_window(start)
                            if remaining <= 0:
                                break
                            sleep_minutes = min(remaining, 5)
                            print(
                                f"[wait] 当前不在打卡窗口内，"
                                f"等待 {sleep_minutes} 分钟后重试"
                                f"（已等待 {waited} 分钟）", flush=True)
                            time.sleep(sleep_minutes * 60)
                            waited += sleep_minutes
                            if waited > max_wait_minutes:
                                raise FlowError(
                                    "window_expired",
                                    f"waited {waited} minutes without entering window")
                            cred = ensure_credentials(cred, config_path)
                            client.login(student_id, password, fingerprint)
                            client.warm_up_portal()
                            today = client.today_record()
                            result["today"] = today
                            if today.get("recordStatusCode") == "CHECKED_IN":
                                result["ok"] = True
                                result["stage"] = "already_checked_in"
                                result["skipped"] = True
                                return result
                        result["waitedMinutes"] = waited
                    else:
                        raise FlowError(
                            "outside_window",
                            f"current time is outside check-in window "
                            f"({start // 60:02d}:{start % 60:02d}-"
                            f"{end // 60:02d}:{end % 60:02d} Beijing); "
                            f"nothing submitted")

        result["stage"] = "acquiring_ticket"
        result["requestCounts"]["code"] = 2
        result["requestCounts"]["ticket"] = 1
        ticket, cred = acquire_ticket(cred, config_path)
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
            if code == 4006:
                raise FlowError("outside_window",
                                "platform rejected: not within check-in window (4006)")
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
        result["finishedAt"] = platform.china_now()
    return result


def _minutes_until_window(start_minute: int) -> int:
    """距下一次窗口开启还有多少分钟；已在窗口内返回 0。"""
    current = platform.china_minutes_now()
    if current < start_minute:
        return start_minute - current
    return 24 * 60 - current + start_minute
