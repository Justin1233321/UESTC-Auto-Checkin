"""把轮换后的应用宝凭据回写为 GitHub Secret。

这是无状态 GitHub Actions 方案的关键：refreshtoken 会轮换，新值只存在于
当前 runner；若不回写，下一轮 runner 拿到的就是失效令牌。

用法（由 workflow 在 always() 步骤调用）：
    GH_TOKEN=<fine-grained PAT, actions:write> python -m uestc_wx.persist

GitHub Secret 使用 libsodium sealed box（X25519 + XSalsa20-Poly1305），
因此依赖 PyNaCl 而非 cryptography。
"""
from __future__ import annotations

import base64
import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path

SECRET_NAME = "YYB_CREDENTIALS_JSON"


def _github_api(method: str, path: str, token: str,
                payload: dict | None = None) -> tuple[int, dict]:
    url = f"https://api.github.com{path}"
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    request = urllib.request.Request(url, data=data, method=method, headers={
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {token}",
        "X-GitHub-Api-Version": "2022-11-28",
        "Content-Type": "application/json",
        "User-Agent": "uestc-autocheck",
    })
    try:
        with urllib.request.urlopen(request, timeout=25) as response:
            raw = response.read()
            return response.status, (json.loads(raw) if raw else {})
    except urllib.error.HTTPError as error:
        raw = error.read()
        try:
            body = json.loads(raw) if raw else {}
        except json.JSONDecodeError:
            body = {}
        return error.code, body


def seal(public_key_b64: str, value: bytes) -> str:
    """libsodium crypto_box_seal —— GitHub Actions Secret 要求的加密方式。"""
    from nacl.public import PublicKey, SealedBox

    recipient = PublicKey(base64.b64decode(public_key_b64))
    sealed = SealedBox(recipient).encrypt(value)
    return base64.b64encode(sealed).decode("ascii")


def main() -> int:
    token = os.environ.get("GH_TOKEN", "").strip()
    repository = os.environ.get("GITHUB_REPOSITORY", "").strip()
    cred_path = Path(".private/creds.json")
    baseline_path = Path(".private/creds-baseline.json")

    if not token or not repository:
        print(json.dumps({"persisted": False,
                          "reason": "GH_TOKEN or GITHUB_REPOSITORY missing"}))
        return 0
    if not cred_path.exists() or not baseline_path.exists():
        # 没有 baseline 说明本次运行没有加载端凭据（例如 validate 模式）
        print(json.dumps({"persisted": False,
                          "reason": "no credentials were loaded this run"}))
        return 0

    current_text = cred_path.read_text(encoding="utf-8")
    try:
        current = json.loads(current_text)
        baseline = json.loads(baseline_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        print(json.dumps({"persisted": False, "reason": "malformed credentials file"}))
        return 0
    if current == baseline:
        print(json.dumps({"persisted": False, "reason": "credentials unchanged"}))
        return 0

    status, key_body = _github_api(
        "GET", f"/repos/{repository}/actions/secrets/public-key", token)
    if status != 200:
        print(json.dumps({"persisted": False,
                          "error": f"public-key HTTP {status}"}),
              file=sys.stderr)
        return 1
    try:
        sealed = seal(key_body["key"], current_text.encode("utf-8"))
    except ImportError:
        print(json.dumps({"persisted": False,
                          "error": "PyNaCl not installed"}),
              file=sys.stderr)
        return 1
    except (KeyError, ValueError) as error:
        print(json.dumps({"persisted": False, "error": f"seal failed: {error}"}),
              file=sys.stderr)
        return 1

    status, body = _github_api(
        "PUT", f"/repos/{repository}/actions/secrets/{SECRET_NAME}", token,
        {"encrypted_value": sealed, "key_id": key_body["key_id"]})
    if status not in (201, 204):
        print(json.dumps({"persisted": False,
                          "error": f"update HTTP {status}: {body.get('message')}"}),
              file=sys.stderr)
        return 1
    print(json.dumps({"persisted": True, "secret": SECRET_NAME,
                      "expiresAt": current.get("expires_at")}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
