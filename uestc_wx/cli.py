"""命令行入口：本地验证与 GitHub Actions 共用。

用法：
    python -m uestc_wx.cli selftest
    python -m uestc_wx.cli code --creds creds.json
    python -m uestc_wx.cli ticket --creds creds.json
    python -m uestc_wx.cli checkin --creds creds.json --profile profile.json
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import flow, mmtls, platform, yyb


_BLOCKED_KEYS = {"ticket", "password", "access_token", "refresh_token",
                 "fingerprint", "cookie", "loginBuffer", "login_buffer",
                 "checkinPayload", "profile", "code"}


def _redact(document: dict) -> dict:
    """确保输出不含凭据明文；只处理字符串值，避免误伤计数字段。"""
    redacted = {}
    for key, value in document.items():
        if isinstance(value, dict):
            redacted[key] = _redact(value)
        elif key in _BLOCKED_KEYS and isinstance(value, str):
            redacted[key] = "***"
        else:
            redacted[key] = value
    return redacted


def cmd_selftest(_args) -> int:
    """离线自检：确认协议核心与黄金向量一致。"""
    import unittest
    loader = unittest.TestLoader()
    suite = loader.discover(str(Path(__file__).resolve().parent.parent / "tests"),
                            pattern="test_vectors.py")
    runner = unittest.TextTestRunner(verbosity=1)
    result = runner.run(suite)
    return 0 if result.wasSuccessful() else 1


def cmd_code(args) -> int:
    """只取一个 code，验证 MMTLS 链路。"""
    cred_path = Path(args.creds)
    cred = flow.load_credentials(cred_path)
    cred = flow.ensure_credentials(cred, cred_path)
    login_buffer, cred = yyb.fetch_login_buffer_with_selfheal(cred)
    flow.save_credentials(cred_path, cred)
    result = mmtls.get_code(login_buffer, platform.MINI_PROGRAM_APP_ID,
                            args.timeout_ms)
    if result.result != mmtls.WxResult.OK:
        print(json.dumps({"ok": False, "error": result.error_detail},
                         ensure_ascii=True), file=sys.stderr)
        return 1
    print(json.dumps({
        "ok": True,
        "codeLength": len(result.code),
        "codePrefix": result.code[:4],
    }, ensure_ascii=True))
    return 0


def cmd_ticket(args) -> int:
    """两段式取票（不提交打卡），对应 MoonCheck 的 wx.test。"""
    cred_path = Path(args.creds)
    cred = flow.load_credentials(cred_path)
    cred = flow.ensure_credentials(cred, cred_path)
    try:
        ticket, _cred = flow.acquire_ticket(cred, cred_path, args.timeout_ms)
    except (flow.FlowError, yyb.OauthError, platform.PlatformError) as error:
        print(json.dumps({"ok": False,
                          "stage": getattr(error, "stage", "error"),
                          "error": getattr(error, "detail", str(error))},
                         ensure_ascii=True), file=sys.stderr)
        return 1
    print(json.dumps({"ok": True, "ticketLength": len(ticket),
                      "ticketFormat": bool(len(ticket) == 43)}, ensure_ascii=True))
    return 0


def cmd_checkin(args) -> int:
    profile = flow.load_profile(Path(args.profile))
    result = flow.run_checkin(
        student_id=args.student_id,
        password=args.password,
        fingerprint=args.fingerprint,
        profile=profile,
        cred_path=Path(args.creds),
        dry_run=args.dry_run,
    )
    print(json.dumps(_redact(result), ensure_ascii=True, indent=2))
    return 0 if result.get("ok") else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    selftest = sub.add_parser("selftest", help="离线黄金向量自检")
    selftest.set_defaults(func=cmd_selftest)

    code = sub.add_parser("code", help="只取一个 wx.login code")
    code.add_argument("--creds", required=True)
    code.add_argument("--timeout-ms", type=int, default=30000)
    code.set_defaults(func=cmd_code)

    ticket = sub.add_parser("ticket", help="两段式取票（不提交）")
    ticket.add_argument("--creds", required=True)
    ticket.add_argument("--timeout-ms", type=int, default=30000)
    ticket.set_defaults(func=cmd_ticket)

    checkin = sub.add_parser("checkin", help="完整打卡")
    checkin.add_argument("--creds", required=True)
    checkin.add_argument("--profile", required=True)
    checkin.add_argument("--student-id", required=True)
    checkin.add_argument("--password", required=True)
    checkin.add_argument("--fingerprint", default="")
    checkin.add_argument("--dry-run", action="store_true",
                         help="只取票不提交")
    checkin.set_defaults(func=cmd_checkin)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
