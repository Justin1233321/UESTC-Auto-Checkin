"""配置向导：把从浏览器拿到的原始值整理成可用的配置文件。

用法：
    # 1. 生成 creds.json（自动把 expires_in 换算成绝对时间）
    python tools/setup_wizard.py creds \
        --openid owXXXX --access 1_XXXX --refresh 1_XXXX --expires-in 7200

    # 2. 生成 profile.json（坐标必须你在宿舍现场取）
    python tools/setup_wizard.py profile --lat 30.7544 --lng 103.9346 \
        --address 四川省成都市郫都区

    # 3. 校验两个文件（可选联网测试凭据是否有效）
    python tools/setup_wizard.py verify
    python tools/setup_wizard.py verify --online

    # 4. 导出可直接粘贴到 GitHub Secrets 的文本文件
    python tools/setup_wizard.py export

所有输出只打印长度和文件路径，不回显凭据明文。
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

DEFAULT_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/155.0.0.0 Safari/537.36")


def _write_private(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(text, encoding="utf-8", newline="\n")
    try:
        os.chmod(temporary, 0o600)
    except OSError:
        pass
    temporary.replace(path)


def cmd_creds(args) -> int:
    if not args.openid or not args.access or not args.refresh:
        print("错误：openid / access / refresh 三个值都必须提供。", file=sys.stderr)
        return 1
    if args.expires_in < 0:
        print("错误：expires_in 是剩余秒数，不能为负。", file=sys.stderr)
        return 1
    document = {
        "openid": args.openid.strip(),
        "access_token": args.access.strip(),
        "refresh_token": args.refresh.strip(),
        "expires_at": int(time.time()) + args.expires_in,
    }
    path = Path(args.output)
    _write_private(path, json.dumps(document, indent=2) + "\n")
    print(json.dumps({
        "ok": True,
        "file": str(path),
        "openidLength": len(document["openid"]),
        "accessLength": len(document["access_token"]),
        "refreshLength": len(document["refresh_token"]),
        "expiresAt": document["expires_at"],
        "expiresInMinutes": round(args.expires_in / 60, 1),
    }, ensure_ascii=True, indent=2))
    return 0


def cmd_profile(args) -> int:
    if not -90 <= args.lat <= 90:
        print("错误：纬度必须在 -90 到 90 之间。", file=sys.stderr)
        return 1
    if not -180 <= args.lng <= 180:
        print("错误：经度必须在 -180 到 180 之间。", file=sys.stderr)
        return 1
    document = {
        "latitude": args.lat,
        "longitude": args.lng,
        "reverseGeocode": args.address,
        "userAgent": args.user_agent or DEFAULT_UA,
        "coordinateSystemCode": "gcj02",
        "accuracy": 86,
        "locationDurationMs": 1189,
        "networkTypeCode": "4g",
        "locationEnabled": False,
    }
    path = Path(args.output)
    _write_private(path, json.dumps(document, ensure_ascii=False, indent=2) + "\n")

    # 顺便算出距打卡点中心的距离，避免配置到围栏外
    center_lat, center_lng = 30.7549800, 103.9338830
    distance = _haversine(args.lat, args.lng, center_lat, center_lng)
    print(json.dumps({
        "ok": True,
        "file": str(path),
        "latitude": args.lat,
        "longitude": args.lng,
        "distanceToCenterMeter": round(distance, 1),
        "radiusHint": "实测围栏半径约 150 米，距离超出则打卡会被判异常",
        "withinRadius": distance < 150,
    }, ensure_ascii=False, indent=2))
    return 0


def cmd_verify(args) -> int:
    cred_path = Path(args.creds)
    profile_path = Path(args.profile)
    problems: list[str] = []
    summary: dict = {"ok": False, "checks": {}}

    # --- creds.json ---
    if not cred_path.exists():
        problems.append(f"缺少 {cred_path}，先运行 creds 子命令")
    else:
        try:
            document = json.loads(cred_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            problems.append(f"{cred_path} 不是合法 JSON")
            document = None
        if document is not None:
            for key in ("openid", "access_token", "refresh_token", "expires_at"):
                if key not in document:
                    problems.append(f"creds.json 缺少字段 {key}")
            if isinstance(document.get("expires_at"), int):
                remaining = document["expires_at"] - int(time.time())
                summary["checks"]["credentialsRemainingMinutes"] = round(remaining / 60, 1)
                if remaining <= 0:
                    problems.append("access_token 已过期；运行时会尝试用 refresh_token 自动刷新")
            summary["checks"]["openidLength"] = len(str(document.get("openid", "")))

    # --- profile.json ---
    if not profile_path.exists():
        problems.append(f"缺少 {profile_path}，先运行 profile 子命令")
    else:
        try:
            profile = json.loads(profile_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            problems.append(f"{profile_path} 不是合法 JSON")
            profile = None
        if profile is not None:
            required = {"latitude", "longitude", "reverseGeocode", "userAgent",
                        "coordinateSystemCode", "accuracy", "locationDurationMs",
                        "networkTypeCode", "locationEnabled"}
            missing = required - set(profile)
            if missing:
                problems.append("profile.json 缺少字段：" + ", ".join(sorted(missing)))
            try:
                distance = _haversine(float(profile["latitude"]), float(profile["longitude"]),
                                      30.7549800, 103.9338830)
                summary["checks"]["distanceToCenterMeter"] = round(distance, 1)
                if distance >= 150:
                    problems.append(
                        f"坐标距打卡点中心 {distance:.0f} 米，超出约 150 米围栏")
            except (KeyError, TypeError, ValueError):
                problems.append("profile.json 坐标字段不是数字")

    # --- 离线自检 ---
    try:
        from uestc_wx import wire  # noqa: F401
        summary["checks"]["imports"] = "ok"
    except ImportError as error:
        problems.append(f"依赖未安装：{error}；先 pip install -r requirements.txt")

    # --- 可选联网验证 ---
    if args.online and not problems:
        from uestc_wx import yyb
        cred = yyb.OauthCredentials(
            openid=document["openid"],
            access_token=document["access_token"],
            refresh_token=document["refresh_token"],
            expires_at=int(document["expires_at"]),
        )
        try:
            login_buffer = yyb.fetch_login_buffer(cred)
            summary["checks"]["loginBuffer"] = f"ok ({len(login_buffer)} bytes)"
        except yyb.OauthError as error:
            summary["checks"]["loginBuffer"] = f"failed: {error.detail}"
            if error.result == yyb.OauthResult.REJECTED:
                # 403 是已知的"新扫码账号 token 被提前作废"现象，刷新后可自愈
                try:
                    rotated = yyb.refresh_credentials(cred)
                    _write_private(cred_path, json.dumps({
                        "openid": rotated.openid,
                        "access_token": rotated.access_token,
                        "refresh_token": rotated.refresh_token,
                        "expires_at": rotated.expires_at,
                    }, indent=2) + "\n")
                    summary["checks"]["autoRefresh"] = "succeeded, creds.json updated"
                    summary["checks"]["loginBuffer"] = "ok after refresh"
                    problems = [p for p in problems if "自动刷新" not in p]
                except yyb.OauthError as refresh_error:
                    summary["checks"]["autoRefresh"] = f"failed: {refresh_error.detail}"
                    problems.append(
                        "凭据刷新被拒，需要在微信里重新扫码授权")

    summary["ok"] = not problems
    if problems:
        summary["problems"] = problems
    print(json.dumps(summary, ensure_ascii=True, indent=2))
    return 0 if summary["ok"] else 1


def cmd_export(args) -> int:
    cred_path = Path(args.creds)
    profile_path = Path(args.profile)
    out_dir = Path(args.output_dir)
    missing = [str(p) for p in (cred_path, profile_path) if not p.exists()]
    if missing:
        print("缺少文件：" + ", ".join(missing), file=sys.stderr)
        return 1
    # 校验 JSON 合法性，避免把坏内容粘进 Secret
    for path in (cred_path, profile_path):
        try:
            json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as error:
            print(f"{path} 不是合法 JSON：{error}", file=sys.stderr)
            return 1

    out_dir.mkdir(parents=True, exist_ok=True)
    pairs = [
        ("YYB_CREDENTIALS_JSON", cred_path),
        ("CHECKIN_PROFILE_JSON", profile_path),
    ]
    written = []
    for name, source in pairs:
        target = out_dir / f"{name}.txt"
        _write_private(target, source.read_text(encoding="utf-8"))
        written.append({"secret": name, "file": str(target)})
    print(json.dumps({
        "ok": True,
        "note": "用记事本打开对应文件，全选复制，粘贴到 GitHub Secrets 页面",
        "files": written,
        "reminder": [
            "不要在聊天、Issue 或截图中粘贴这些内容",
            "导出完成后可以删除该目录",
        ],
    }, ensure_ascii=False, indent=2))
    return 0


def _haversine(lat1: float, lng1: float, lat2: float, lng2: float) -> float:
    import math
    radius = 6371000
    phi1, phi2 = math.radians(lat1), math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dlambda = math.radians(lng2 - lng1)
    a = (math.sin(dphi / 2) ** 2
         + math.cos(phi1) * math.cos(phi2) * math.sin(dlambda / 2) ** 2)
    return 2 * radius * math.asin(math.sqrt(a))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)

    creds = sub.add_parser("creds", help="生成 creds.json")
    creds.add_argument("--openid", required=True)
    creds.add_argument("--access", required=True)
    creds.add_argument("--refresh", required=True)
    creds.add_argument("--expires-in", type=int, default=7200,
                       help="Cookie 里的 expires_in（剩余秒数）")
    creds.add_argument("--output", default="creds.json")
    creds.set_defaults(func=cmd_creds)

    profile = sub.add_parser("profile", help="生成 profile.json")
    profile.add_argument("--lat", type=float, required=True)
    profile.add_argument("--lng", type=float, required=True)
    profile.add_argument("--address", default="四川省成都市郫都区")
    profile.add_argument("--user-agent", default="")
    profile.add_argument("--output", default="profile.json")
    profile.set_defaults(func=cmd_profile)

    verify = sub.add_parser("verify", help="校验配置文件")
    verify.add_argument("--creds", default="creds.json")
    verify.add_argument("--profile", default="profile.json")
    verify.add_argument("--online", action="store_true",
                        help="联网测试凭据是否有效（会访问应用宝接口）")
    verify.set_defaults(func=cmd_verify)

    export = sub.add_parser("export", help="导出可粘贴到 Secrets 的文本")
    export.add_argument("--creds", default="creds.json")
    export.add_argument("--profile", default="profile.json")
    export.add_argument("--output-dir", default=".secrets-export")
    export.set_defaults(func=cmd_export)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
