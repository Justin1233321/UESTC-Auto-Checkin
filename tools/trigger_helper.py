"""生成外部定时服务（cron-job.org 等）所需的触发配置。

GitHub 的 schedule 不可靠（实测延迟数小时甚至完全不触发），
推荐用外部服务定时调用 workflow_dispatch API。

用法：
    # 打印触发所需的 URL / headers / body
    python tools/trigger_helper.py --repo Justin1233321/UESTC-Auto-Checkin

    # 顺便查询 workflow ID（需要 PAT）
    python tools/trigger_helper.py --repo 用户名/仓库名 --token github_pat_xxx

    # 直接测试一次触发（确认配置正确）
    python tools/trigger_helper.py --repo 用户名/仓库名 --token github_pat_xxx --test
"""
from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request

API = "https://api.github.com"


def _request(url: str, token: str | None, method: str = "GET",
             payload: dict | None = None) -> tuple[int, dict]:
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "uestc-autocheck-helper",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if payload is not None:
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=25) as response:
            raw = response.read()
            body = json.loads(raw) if raw else {}
            return response.status, body
    except urllib.error.HTTPError as error:
        raw = error.read()
        try:
            body = json.loads(raw) if raw else {}
        except json.JSONDecodeError:
            body = {"raw": raw[:200].decode("utf-8", "replace")}
        return error.code, body
    except (urllib.error.URLError, OSError) as error:
        return 0, {"error": str(error)}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--repo", required=True, help="owner/name")
    parser.add_argument("--token", default="", help="带 Actions:write 权限的 PAT")
    parser.add_argument("--workflow", default="", help="workflow ID 或文件名，留空则自动查询")
    parser.add_argument("--ref", default="main")
    parser.add_argument("--mode", default="submit", choices=("submit", "ticket", "validate"))
    parser.add_argument("--test", action="store_true", help="实际触发一次以验证配置")
    args = parser.parse_args(argv)

    workflow_id = args.workflow
    if not workflow_id:
        status, body = _request(
            f"{API}/repos/{args.repo}/actions/workflows", args.token or None)
        if status != 200:
            print(f"查询 workflow 失败：HTTP {status}", file=sys.stderr)
            print(json.dumps(body, ensure_ascii=False, indent=2), file=sys.stderr)
            return 1
        workflows = body.get("workflows") or []
        if not workflows:
            print("仓库里没有 workflow", file=sys.stderr)
            return 1
        workflow_id = str(workflows[0]["id"])
        print(f"找到 workflow: {workflows[0]['name']} (id={workflow_id}, "
              f"state={workflows[0]['state']})", file=sys.stderr)
        if len(workflows) > 1:
            print("注意：仓库有多个 workflow，已取第一个；可用 --workflow 指定",
                  file=sys.stderr)

    url = f"{API}/repos/{args.repo}/actions/workflows/{workflow_id}/dispatches"
    payload = {"ref": args.ref, "inputs": {"mode": args.mode}}

    print(json.dumps({
        "外部定时服务配置": {
            "URL": url,
            "Method": "POST",
            "Headers": {
                "Authorization": "Bearer <你的PAT>",
                "Accept": "application/vnd.github+json",
                "Content-Type": "application/json",
            },
            "Body": json.dumps(payload, separators=(",", ":")),
        },
        "北京时间的四个触发点": ["21:05", "21:50", "22:35", "23:20"],
        "对应的UTC时间": ["13:05", "13:50", "14:35", "15:20"],
        "说明": [
            "cron-job.org 的时间要按其界面的 UTC 设置",
            "四个任务幂等，第一个成功后其余会秒退",
            "成功触发返回 HTTP 204，无响应体",
        ],
    }, ensure_ascii=False, indent=2))

    if args.test:
        if not args.token:
            print("\n--test 需要 --token", file=sys.stderr)
            return 1
        print("\n=== 测试触发 ===", file=sys.stderr)
        status, body = _request(url, args.token, "POST", payload)
        if status == 204:
            print("触发成功（HTTP 204）。去 Actions 页面确认运行已开始。",
                  file=sys.stderr)
            return 0
        print(f"触发失败：HTTP {status}", file=sys.stderr)
        if status == 403:
            print("→ PAT 缺少 Actions: Write 权限", file=sys.stderr)
        elif status == 404:
            print("→ 仓库名或 workflow ID 不对，或 PAT 没有该仓库的访问权",
                  file=sys.stderr)
        elif status == 422:
            print("→ ref 或 inputs 不匹配。确认分支名是 main、"
                  "mode 是 submit/ticket/validate", file=sys.stderr)
        print(json.dumps(body, ensure_ascii=False, indent=2), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
