# 电子科技大学自动打卡（无硬件版）

每晚自动完成「晚安成电」打卡。**不需要电脑常开、不需要 ESP32、不需要安卓手机挂着。**

跑在 GitHub Actions 的免费 runner 上，每天北京时间 21:20 自动执行。

> 本项目基于 [fanrea/uestc-checkin-actions-public](https://github.com/fanrea/uestc-checkin-actions-public)
> 与 [richard297779/UESTC-MoonCheck](https://github.com/richard297779/UESTC-MoonCheck) 的工作，
> 把后者的应用宝协议实现移植为纯 Python。详见[致谢与来源](#致谢与来源)。

---

## 它是怎么做到的

平台从 2026-10-23 起要求打卡携带微信小程序签发的操作票据，票据源头是 `wx.login` code。

社区普遍认为 code 只能由微信运行时产生，所以常见方案是「注入微信进程抓会话」或「用旧手机抓票中转」——前者会被微信的反调试静默终止，后者需要常驻设备。

但腾讯应用宝（YYB）PC 端本身就是腾讯官方运营的**非微信运行时**，它的开放协议允许为任意小程序申请登录 code。本项目把这个协议用纯 Python 实现，于是整条链变成纯 HTTP，可以跑在任何能上网的机器上。

身份仍然是你本人：微信扫码授权，微信真实签发 code，学校服务端正常验票。改变的只是产生 code 的运行时，和你在电脑上用微信登录应用宝是同一件事。

---

## 你会用到的东西

| 项目 | 说明 |
| --- | --- |
| GitHub 账号 | 免费，用来跑定时任务 |
| 你的微信 | 只需扫码授权一次 |
| 学号 + 统一身份认证密码 | 打卡平台登录用 |
| 常开设备 | **不需要** |

---

## 五步上手

### 第 0 步：拿一份自己的代码

点仓库右上角 **Fork**，或 **Use this template** → Create a new repository。

**强烈建议设为 Private。** 公开仓库的 Actions 日志任何人都能看。

### 第 1 步：在自己电脑上装依赖

需要 Python 3.10+。**打开终端**（Windows 用 PowerShell，macOS 用 Terminal），`cd` 到项目根目录后运行：

```powershell
# Windows PowerShell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt

# macOS / Linux
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
```

先跑一次离线自检，确认协议实现正常（38 项，不联网、不需要账号）。**继续在终端里运行**：

```powershell
.\.venv\Scripts\python.exe -m uestc_wx.cli selftest
```

看到 `OK` 就对了。

### 第 2 步：扫码拿微信授权凭据

> **关于「终端」：** 本文中凡是 `powershell` 代码块，都要在你自己电脑上打开终端（Windows 用 PowerShell，macOS 用 Terminal）运行，而不是在浏览器里。运行前先 `cd` 到项目根目录。需要点网页的地方会明确写「浏览器」或「去 Actions 页面」。

在**电脑浏览器**打开下面这个地址（注意核对域名是 `open.weixin.qq.com`，协议是 HTTPS）：

```text
https://open.weixin.qq.com/connect/qrconnect?appid=wxd44977328b36e647&redirect_uri=https%3A%2F%2Fyybadaccess.3g.qq.com%2Fpc_yyb%2Fpcyyb_oauth%3Flogin_type%3DWX&response_type=code&scope=snsapi_login,snsapi_runtime_pcsdk&state=web&fast_login=1&self_redirect=true
```

用**你本人的微信**扫码，手机上点确认。

然后按 F12 打开开发者工具：

1. 选 **Application（应用程序）** → 左侧 **Cookies** → 点开 `static.pc.yyb.qq.com`
2. 找到这四项，复制它们的 Value：`openid`、`accesstoken`、`refreshtoken`、`expires_in`

> `expires_in` 是**剩余秒数**（常见 7200），不是时间戳。下面的向导会自动换算。

**复制完立刻关掉这个授权页面。** 同一组凭据只能有一个客户端保活，页面开着会和后续的自动任务互相挤掉线。

用向导生成配置文件。**回到终端运行**，把 `owXXXX` 等替换成你刚才复制的真实值：

```powershell
.\.venv\Scripts\python.exe tools/setup_wizard.py creds `
  --openid owXXXX `
  --access 1_XXXX `
  --refresh 1_XXXX `
  --expires-in 7200
```

它只显示长度和文件名，不回显凭据内容。

> **向导是干什么的：** `tools/setup_wizard.py` 是配置助手，只在准备阶段用一次，打卡运行时不需要它。它解决三个手工容易出错的地方：① `expires_in` 是剩余秒数，它会自动换算成绝对时间；② 坐标会算出距打卡点中心的距离，超出围栏当场告警；③ Secret 内容导成干净的 txt，避免手抄漏字符。你可以跳过它纯手工写 JSON，但上述三个坑要自己留意。

### 第 3 步：填你的宿舍坐标

**必须在宿舍现场取。** 围栏半径约 150 米，站在宿舍里取的值才可靠。

在宿舍用浏览器打开 <https://jzsz.uestc.edu.cn/daily-checkin-h5/index.html?appId=294>，登录后：

1. F12 → **Network（网络）**
2. 过滤框输入 `reverse`
3. 找到 `map/reverse?lat=...&lng=...` 这条请求，URL 里的 `lat` 和 `lng` 就是你的坐标

取到坐标后，**在终端里运行**（把经纬度换成你自己的）：

```powershell
.\.venv\Scripts\python.exe tools/setup_wizard.py profile `
  --lat 30.7544 --lng 103.9346 --address 四川省成都市郫都区
```

向导会自动算出距打卡点中心的距离，超出 150 米会提示你重取。

### 第 4 步：配 GitHub Secrets

先验证一遍配置。**在终端里运行**（`--online` 会真的访问应用宝接口，确认凭据可用）：

```powershell
.\.venv\Scripts\python.exe tools/setup_wizard.py verify --online
```

看到 `"ok": true` 就好。

然后导出可直接粘贴的文本。**继续在终端里运行**：

```powershell
.\.venv\Scripts\python.exe tools/setup_wizard.py export
```

它会生成 `.secrets-export/` 目录，里面两个 txt 文件分别是两个 Secret 的内容。

去你的仓库 **Settings → Secrets and variables → Actions → New repository secret**，逐个添加：

| Secret 名称 | 值 |
| --- | --- |
| `YYB_CREDENTIALS_JSON` | `YYB_CREDENTIALS_JSON.txt` 的全文 |
| `CHECKIN_PROFILE_JSON` | `CHECKIN_PROFILE_JSON.txt` 的全文 |
| `STUDENT_ID` | 你的学号 |
| `STUDENT_PASSWORD` | 统一身份认证密码 |
| `BROWSER_FINGERPRINT` | 见下方说明 |
| `CREDENTIALS_PAT` | 见下方说明，**这个不能省** |

导出的两个文件用记事本打开、全选复制、粘贴即可。**不要贴到聊天、Issue 或截图里。** 配完删掉 `.secrets-export/` 目录。

#### 浏览器指纹怎么取

它决定 CAS 登录是否要短信验证。

用你**平时打卡的那个浏览器**，登录 <https://jzsz.uestc.edu.cn/>，然后：

1. F12 → Application → Cookies → `https://idas.uestc.edu.cn`
2. 找 `MULTIFACTOR_BROWSER_FINGERPRINT`，复制 32 位十六进制值

它是 HttpOnly，`document.cookie` 看不到，必须用 Application 面板。

> 如果登录时弹了二次验证，勾选「信任此浏览器」再通过，之后这个指纹才会被服务端认作可信设备。

#### `CREDENTIALS_PAT` 为什么必须配

微信的 `refresh_token` 大约每 2 小时轮换一次，新值只存在于当次运行的 runner 里。runner 跑完就销毁，如果不把新值写回 Secret，下一轮拿到的就是已经作废的旧 token，然后整条链断掉。

配置方法：

1. 右上角头像 → Settings → Developer settings → Personal access tokens → **Fine-grained tokens** → Generate new token
2. Repository access → Only select repositories → 只选你这个打卡仓库
3. Repository permissions → 找到 **Secrets** → 设为 **Read and write**
4. 生成后复制，存为 Secret `CREDENTIALS_PAT`

> 是 **Secrets** 权限，不是 Actions。选错了会在几天后静默失效。

### 第 5 步：验证并启用

去 **Actions → Daily check-in → Run workflow**，依次跑这三步：

**① mode 选 `validate`** — 只跑离线自检，不碰平台。绿了就说明代码和环境正常。

**② mode 选 `ticket`** — 真实取码换票，但**不提交打卡**。成功会输出 `ticketLength: 43`。白天也能跑，不消耗打卡机会。

**③ mode 选 `submit`** — 必须在 **21:00–23:30** 之间跑，这才真正打卡。

之后就交给定时任务了。

#### 重要：GitHub 的 schedule 不可靠，必须配外部触发

GitHub 的 `schedule` 是 **best-effort**，不保证执行。实测数据：

| 事件 | 结果 | 备注 |
| --- | --- | --- |
| `schedule` | 延迟 5.6 小时 | 计划 21:20，实际 02:54，被 4006 拒绝 |
| `schedule` | 完全不触发 | 配置的 21:05 / 21:50 两个点均未出现 |

一周内只有 1 次 `schedule` 真正触发，且失败。对低频、新建的私有仓库，这个调度器基本不可用。

**所以不要把可靠性寄托在 cron 上。** 正确做法是用外部定时服务主动调用 GitHub API 触发 workflow。

**本项目的 workflow 已停用 `schedule`**，只保留 `workflow_dispatch`（手动 + 外部服务触发）。

停用的原因是体验问题：schedule 有时延迟到凌晨才触发，落在窗口外失败，半夜给人发失败邮件。原 cron 配置以注释形式保留在 workflow 文件里，需要时可取消注释恢复。

**重复触发不会重复打卡。** 每次运行第一步就查今日记录，若 `recordStatusCode` 已是 `CHECKED_IN` 立即退出（`stage: already_checked_in`）。所以多次触发最多只有一个真正提交。

此外每次提交前会先读服务端时段接口（EP07），确认当前确实在窗口内。不在窗口就**不提交**，直接报 `outside_window` 退出。

`submit` 模式还带 `--wait-for-window`：延迟到窗口外时会在进程内等待窗口开启（最长 30 分钟）。

#### 配置外部触发（推荐，10 分钟）

用 [cron-job.org](https://cron-job.org)（免费）每天在窗口内多次调用 GitHub API，绕开 GitHub 的调度队列。

**第一步：创建一个仅供此用途的 PAT**

GitHub → Settings → Developer settings → Fine-grained tokens → Generate new token：

- Repository access：只选你的打卡仓库
- Repository permissions → **Actions: Read and write**
- 生成后复制，形如 `github_pat_xxx`

**第二步：在 cron-job.org 建任务**

注册后在 Dashboard 点 **Create cronjob**，按下表填：

| 字段 | 值 |
| --- | --- |
| Title | `UESTC checkin` |
| URL | `https://api.github.com/repos/你的用户名/你的仓库名/actions/workflows/399402942/dispatches` |
| Execution schedule | **Every day at** `21` : `05` |
| Timezone | `Asia/Shanghai` |

> **时区是关键。** cron-job.org 支持逐任务设置时区，界面右下角会显示
> `In this job's individual timezone (Asia/Shanghai)`。
>
> - 时区设为 `Asia/Shanghai` → 填 `21:05` / `21:50` / `22:35` / `23:20`
> - 时区保持 `UTC` → 填 `13:05` / `13:50` / `14:35` / `15:20`
>
> 两种都可以，但**千万别混**。填完看右侧 **Next executions** 预览，
> 它显示的就是真实执行时间。如果填的是 21:05 却预览成 `1:05 PM`，
> 说明时区是 UTC，改成 Shanghai 或把时间改成 13:05。

**Advanced** 标签页里设置：

| 字段 | 值 |
| --- | --- |
| Request method | `POST` |
| Request body | `{"ref":"main","inputs":{"mode":"submit"}}` |
| Headers | `Authorization: Bearer github_pat_xxx`<br>`Accept: application/vnd.github+json`<br>`Content-Type: application/json` |

保存后点 **TEST RUN**，看到 `HTTP 204` 就说明通了。随后去 Actions 页面确认有新的运行记录。

**第三步：照同样方式再建 3 个**

时间分别是 `21:50`、`22:35`、`23:20`（时区同为 Asia/Shanghai）。

四个任务幂等，第一个成功后其余会秒退，不会重复打卡。

> `399402942` 是 workflow 的 ID，你的仓库可能不同。用这条命令查：
> ```bash
> curl -H "Authorization: Bearer 你的PAT" \
>   https://api.github.com/repos/你的用户名/你的仓库名/actions/workflows
> ```
> 返回中的 `id` 字段就是。

配置完成后，每天 21:05 起会有 4 次真实触发，不再依赖 GitHub 的调度器。

---

## 日常怎么用

**什么都不用做。** 窗口内会自动跑，见上节的四个触发点。

想确认结果，去 Actions 页面点最近一次运行，看 `Run check-in` 步骤：

| 输出 | 含义 |
| --- | --- |
| `"stage": "checkin_accepted"` | 打卡成功 |
| `"stage": "already_checked_in"` | 当天已打过，自动跳过（正常，四个触发点里后三个通常都是这个） |
| `"stage": "outside_window"` | 当前不在窗口内，**未提交**（正常，不是错误） |
| `"stage": "cas_login"` + 401 | 密码错了，或改了密码没更新 Secret |
| `refresh rejected` / `403` | 微信授权失效，需要重新扫码 |
| `"stage": "checkin_rejected"` + `code: 4006` | 服务端认为不在窗口（通常是调度延迟到窗口外） |

---

## 出问题怎么办

| 现象 | 原因与处理 |
| --- | --- |
| `Missing secrets: ...` | 有 Secret 没配，看提示补上 |
| `persisted: false, error: public-key HTTP 401` | `CREDENTIALS_PAT` 权限不对或过期，重做一个 |
| `persisted: false, reason: GH_TOKEN ... missing` | `CREDENTIALS_PAT` 这个 Secret 根本没加 |
| `refresh rejected` / `403` 反复出现 | 微信授权失效，重新扫码走第 2 步 |
| `cas_login` 返回 401 | `STUDENT_PASSWORD` 不对，或密码改过了 |
| 打卡被判异常 / 距离过大 | 坐标不在围栏内，回宿舍重取；确认 `profile.json` 的坐标 |
| 定时任务不跑 | 检查仓库 Actions 是否被停用；公开仓库连续 60 天无活动会被自动停用 |
| `ticket_rejected` | 学校 Cookie 和微信账号不是同一个人，或票据过期 |

---

## 安全须知

- 微信凭据（`openid` / `accesstoken` / `refreshtoken`）等同于你微信的登录授权。**只放 GitHub Secrets，不要提交到 Git、不要发群、不要截图。**
- 学号密码同理。本项目只在 Actions 的临时目录里使用，作业结束即删除。
- 所有日志只输出阶段名、HTTP 状态、整数业务码和长度，不输出凭据、code、票据、坐标或响应原文。
- `today` 接口的响应含姓名、学号、手机号和辅导员联系方式，代码只解析 9 个白名单字段，不整包落盘。
- 设备遗失或凭据疑似泄露时，去应用宝授权管理里撤销授权，重新扫码。

---

## 已知限制

- **协议维护风险**：微信若改版 MMTLS，取码会失效。YYB 生态是多项目共同维护，跟进成本低于单点逆向微信二进制，但不保证永久可用。
- **凭据会过期**：`refresh_token` 轮换失败时需要重新扫码，这是授权模型决定的，不是 bug。
- **围栏限制**：坐标固定，人不在宿舍范围内打卡会被判异常。本项目不做位置伪造。
- **定时延迟**：GitHub 的 cron 不保证准时，实测有过数小时延迟。本项目用窗口内四个触发点 + 窗内等待来缓解，但仍无法完全避免极端延迟。
- **未打卡会体现为失败**：如果某天所有触发点都落在窗口外，作业会标红（`outside_window`）。这是有意的——不打卡应该让你知道，而不是静默通过。看到红叉请手动补打。
- **同一组凭据只能一个客户端用**：部署后不要再开着扫码页面，也不要同时跑本地测试和 Actions。

---

## 仅供本人使用

本项目按电子科技大学「晚安成电」平台实现，其他学校平台不同，需自行适配。

自动化打卡**可能不符合学校规定**，请自行评估并承担后果。不要用它代替他人打卡，不要用于营利。

---

## 目录结构

```text
uestc_wx/
  crypto.py     哈希 / HKDF / AES-GCM / ECDH / varint / protobuf / LZ4
  wire.py       MMTLS 记录帧、握手、密钥派生、WPKG、ManualAuth、js-login
  dns.py        微信 HTTPDNS + 明文 HTTP/1.0 客户端
  mmtls.py      连接编排：握手 → ManualAuth → 0-RTT 取码
  yyb.py        应用宝 HTTPS：凭据刷新 + login_buffer
  platform.py   CAS 登录、门户预热、两段式换票、打卡提交
  flow.py       主流程编排
  persist.py    轮换凭据回写 GitHub Secret
  cli.py        命令行入口
tools/
  setup_wizard.py  配置向导（生成、校验、导出配置文件）
tests/
  test_vectors.py  38 项黄金向量对拍（离线，无需账号）
```

---

## 致谢与来源

本项目是站在三个项目肩上做的，请注意各自的角色和许可。

### [fanrea/uestc-checkin-actions-public](https://github.com/fanrea/uestc-checkin-actions-public) — 起点

这是本项目最初的起点。它确立了「微信 code → Ticket → 打卡」这条链路，
以及「Windows 采集 + 云端重放」的整体架构，并提供了学校侧的字段契约、
`checkin-request-profile` 配置格式、以及那套脱敏日志的约定（只输出阶段、
HTTP 状态、整数业务码，不输出凭据与位置）。

本项目沿用了它的学校侧接口认知和隐私处理思路，但**鉴权方式完全不同**：
它依赖注入 Windows 微信进程抓取会话（绑定微信 4.1.15.56 / RadiumWMPF 25799，
需 Frida 注入原生偏移），本项目改用应用宝开放协议，因此不再需要 Windows 微信、
不再绑定微信版本、也不再受微信反调试影响。

如果你只想在 Windows 上跑、且微信版本恰好匹配，可以优先考虑原项目。

### [richard297779/UESTC-MoonCheck](https://github.com/richard297779/UESTC-MoonCheck)（MIT） — 协议实现

本项目 `uestc_wx/` 下的协议栈（`wire.py` / `mmtls.py` / `crypto.py` /
`dns.py` / `yyb.py`）移植自该项目的 ESP32 C++ 固件实现。
它首次证明了这个关键洞察：`wx.login` code 不必由微信运行时产生，
应用宝 PC 端作为腾讯官方运营的非微信运行时，同样能签发。

它同时也提供了本项目最重要的验证手段：`golden_vectors.h` 与
`aesgcm_vectors.h` 里的测试向量，让协议移植可以离线逐字节对拍，
而不必等到联网才发现握手错误。

### [moon-uestc](https://github.com/MioYiSama/moon-uestc) 与 YYB-Go-Enhanced

MoonCheck 的协议实现本身移植自 `moon-uestc`，并与 `YYB-Go-Enhanced` 的 Go 参考逐字节一致。
本项目是这条移植链的第三环：C++ → Python。

### 本项目的贡献

把上述协议用纯 Python 重写，并补齐了脱离硬件运行所需的部分：

- 38 项黄金向量对拍测试，保证移植正确性
- 真实服务器验证：MMTLS 握手、ManualAuth、0-RTT 取码、两段式换票
- 两段式换票（`check-bind` + `checkin-ticket`）与入口票据的完整实现
- 凭据轮换的持久化（回写 GitHub Secret），这是无状态 runner 长期运行的前提
- 配置向导与面向非开发者的文档

### 许可

本项目与原项目均为 MIT License。

