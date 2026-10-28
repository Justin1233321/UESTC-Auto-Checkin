# UESTC 自动打卡（无硬件 / GitHub Actions）

通过腾讯应用宝（YYB）PC 端开放协议在云端生成 `wx.login` code，
完成「取码 → 两段式换票 → CAS 登录 → 门户预热 → 提交打卡」全链路。

**不需要 Windows 微信、不需要 Frida、不需要 ESP32。** 全部是 HTTP。

协议层移植自 [UESTC-MoonCheck](https://github.com/richard297779/UESTC-MoonCheck)（MIT）
的固件实现，其本身移植自 `moon-uestc` 的 Python 参考实现。

## 为什么这条路能通

学校平台自 2026-10-23 起要求打卡携带 `X-Checkin-Ticket`，票据源头是
`wx.login` code。社区普遍认为 code 只能由微信运行时产生，因此退化为
「注入微信进程抓会话」或「手机中转抓票」——前者被微信的反调试封堵，
后者需要常驻设备。

MoonCheck 的关键洞察是：**腾讯应用宝 PC 端本身就是腾讯官方运营的非微信运行时**。
其开放协议（scope `snsapi_runtime_pcsdk`）允许持票方为**任意**小程序申请登录 code。
身份仍是用户本人（微信扫码授权），不含伪造。

我们把这个协议用纯 Python 重新实现，于是它就能跑在任何能上网的机器上，
包括 GitHub Actions 的 Ubuntu runner。

## 已验证到什么程度

| 环节 | 状态 |
| --- | --- |
| 协议编解码（38 项黄金向量逐字节对拍） | ✅ 与 MoonCheck C++ 实现一致 |
| 微信 HTTPDNS 发现（`aedns.weixin.qq.com`） | ✅ 实测拿到 9 个域名与服务器列表 |
| MMTLS ECDHE 握手 + 密钥派生 + ServerFinished 校验 | ✅ 实测对 `longcloud.weixin.com` 握手成功，拿到 2 个 session ticket |
| ManualAuth 建会话、0-RTT 取码 | ⚠️ 代码完整但**未经真实凭据验证**（需要你自己的扫码授权） |
| 两段式换票、CAS 登录、打卡提交 | ⚠️ 代码完整但**未经真实账号验证** |

前两项是纯协议、不含账号，所以可以离线证明。后两项必须有你的凭据才能验证——
这是设计使然，不是缺陷。

## 快速开始

### 1. 本地准备

```bash
python -m venv .venv
.venv/bin/pip install -r requirements.txt      # Windows: .venv\Scripts\pip
python -m uestc_wx.cli selftest                # 离线自检，应 38 项全通过
```

### 2. 获取微信授权凭据（一次性）

在**电脑浏览器**打开二维码授权页（核对域名是 `open.weixin.qq.com` 且为 HTTPS）：

```text
https://open.weixin.qq.com/connect/qrconnect?appid=wxd44977328b36e647&redirect_uri=https%3A%2F%2Fyybadaccess.3g.qq.com%2Fpc_yyb%2Fpcyyb_oauth%3Flogin_type%3DWX&response_type=code&scope=snsapi_login,snsapi_runtime_pcsdk&state=web&fast_login=1&self_redirect=true
```

用**你本人的微信**扫码并确认。完成后：

1. F12 → Application → Cookies → 选中 `static.pc.yyb.qq.com`
2. 复制 `openid`、`accesstoken`、`refreshtoken`、`expires_in` 四个值
3. **加当前 Unix 时间换算 `expires_at`**：`int(time.time()) + expires_in`
4. **关闭这个授权页面**——同一组凭据只能有一个客户端保活，否则互相挤掉线

写成 `creds.json`：

```json
{
  "openid": "...",
  "access_token": "...",
  "refresh_token": "...",
  "expires_at": 1761300000
}
```

> `refresh_token` 等同登录凭据。只放本机或 GitHub Secrets，不要提交、截图、发群。

### 3. 验证取码链路

```bash
python -m uestc_wx.cli code --creds creds.json
```

成功会输出 `{"ok": true, "codeLength": 32, ...}`（只回显长度和前 4 字符）。
这一步跑通说明 MMTLS + ManualAuth + 0-RTT 全部正常——**这是最难的部分**。

### 4. 验证换票链路

```bash
python -m uestc_wx.cli ticket --creds creds.json
```

成功输出 `ticketLength: 43`。这一步会消耗两次 code，对应 MoonCheck 的 `wx.test`。
它**不提交打卡**，可以放心在白天跑。

### 5. 准备位置配置

`profile.json`：

```json
{
  "latitude": 30.7549800,
  "longitude": 103.9338830,
  "reverseGeocode": "四川省成都市郫都区",
  "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/155.0.0.0 Safari/537.36",
  "coordinateSystemCode": "gcj02",
  "accuracy": 86,
  "locationDurationMs": 1189,
  "networkTypeCode": "4g",
  "locationEnabled": false
}
```

坐标必须**在宿舍现场取**（围栏半径 130 m）。取法：浏览器打开
`https://jzsz.uestc.edu.cn/daily-checkin-h5/index.html?appId=294`，
F12 → Network → 过滤 `reverse` → 从 `map/reverse?lat=…&lng=…` 读取。

### 6. 完整打卡（先 dry-run）

```bash
python -m uestc_wx.cli checkin \
  --creds creds.json --profile profile.json \
  --student-id 你的学号 --password 你的密码 \
  --fingerprint 32位指纹 --dry-run
```

`--dry-run` 只取票不提交。确认无误后去掉它，在 21:00–23:30 窗口内实跑。

浏览器指纹的取法：Chrome 登录 `jzsz.uestc.edu.cn` → F12 → Application →
Cookies → `https://idas.uestc.edu.cn` → `MULTIFACTOR_BROWSER_FINGERPRINT`（32 位十六进制）。
它是 HttpOnly，`document.cookie` 看不到。这个值决定 CAS 登录是否要短信验证。

### 7. 部署到 GitHub Actions

需要两类 Secret：

| Secret | 内容 |
| --- | --- |
| `YYB_CREDENTIALS_JSON` | `creds.json` 全文 |
| `STUDENT_ID` / `STUDENT_PASSWORD` | 学号 / 统一身份认证密码 |
| `BROWSER_FINGERPRINT` | 32 位指纹 |
| `CHECKIN_PROFILE_JSON` | `profile.json` 全文 |
| `CREDENTIALS_PAT` | 细粒度 PAT，仅需 **Actions: write**（用于回写轮换后的凭据） |

`CREDENTIALS_PAT` 是这套方案能长期无人值守的关键：`refresh_token`
约每 2 小时轮换，新值只存在于当前 runner。workflow 在 `always()` 步骤里
调用 `python -m uestc_wx.persist`，用 PAT 把新凭据加密写回
`YYB_CREDENTIALS_JSON`。**不配它，第二轮就会失败。**

首次运行请保持 `mode: validate`（只跑离线自检），确认通过后再手动选
`mode: submit` 在窗口内实跑一次。

## 目录结构

```text
uestc_wx/
  crypto.py     哈希 / HKDF / AES-GCM / ECDH / varint / protobuf / LZ4
  wire.py       MMTLS 记录帧、握手、密钥派生、WPKG、ManualAuth、js-login
  dns.py        微信 HTTPDNS + 明文 HTTP/1.0 客户端
  mmtls.py      连接编排：握手 → ManualAuth → 0-RTT 取码
  yyb.py        应用宝 HTTPS：凭据刷新 + login_buffer（MD5 签名）
  platform.py   CAS 登录、门户预热、两段式换票、打卡提交
  flow.py       主流程编排
  persist.py    轮换凭据回写 GitHub Secret（libsodium sealed box）
  cli.py        命令行入口
tests/
  test_vectors.py   38 项黄金向量对拍（离线，无需账号）
```

## 已知限制与风险

- **协议维护风险**。微信侧 MMTLS 改版会使取码失效。这是把赌注押在腾讯
  协议稳定性上；好在 YYB 生态是多项目共同维护（`YYB-Go-Enhanced`、
  `moon-uestc`），跟进成本低于单点逆向微信二进制。
- **跨日未经长期验证**。MoonCheck 作者自己也只完成单日闭环，跨日凭据轮换、
  微信掉线恢复需要更长的运行数据。
- **凭据轮换冲突**。同一组 `refresh_token` 同时被多个客户端刷新会互相挤掉。
  部署后请停掉本地测试、关闭扫码页面。
- **打卡失败的业务码**。`46001/46002/46003` 表示票据被拒，需重取。
  `4006` 表示不在打卡时间内。
- **自动化打卡可能不符合学校规定**，请自行评估并承担后果。
- 本项目仅用于**本人账号**。

## 安全约定

- 所有日志只输出阶段名、HTTP 状态、整数业务码和长度，不输出凭据、
  code、票据、坐标或响应原文。
- CI 中 Secret 写入临时目录，作业结束删除。
- 分页返回的 `today` 接口含姓名/学号/手机号/辅导员联系方式，代码只解析
  `SAFE_TODAY_FIELDS` 白名单字段，不整包落盘。

## 许可

MIT。协议实现源自 UESTC-MoonCheck（MIT）。
