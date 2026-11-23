# 安全实验工作台

在本机查看已保存的页面记录和检测报告。工作台沿用校园系统的 Flask、Jinja 和原生 JavaScript 技术栈，在独立的 `127.0.0.1:5080` 运行。

## 在 Windows 上启动

使用 Python 3.11 或以上版本。打开 PowerShell，切换到工作台目录并启动服务。

```powershell
Set-Location .\workbench
python app.py
```

看到 `Running on http://127.0.0.1:5080` 后，保持 PowerShell 窗口打开，在浏览器访问 [安全实验工作台](http://127.0.0.1:5080/)。

- 首页会显示标记为“仅用于演示”的示例数据。点击 **载入源码审查**，可以查看从压缩包核对的 5 条发现。
- 点击 **导入文件**，选择已有的 HAR 或报告 JSON。导入 HAR 时，填写实际使用的 DVWA 地址作为页面范围。首次成功导入后会显示导入记录，可继续添加其他目标的文件。
- 刷新页面前，可以点击 **导出记录**，将当前记录保存为可重新导入的 `course-evidence.json`。导出前检查手填证据及来源文件名是否含有个人信息。
- 要停止服务，回到 PowerShell 按 **Ctrl+C**。

如果启动时提示 `No module named 'flask'`，在同一目录安装依赖后重新启动。

```powershell
python -m pip install -r ..\requirements.txt
python app.py
```

## 运行测试

```powershell
python -B -m unittest -v
node --check static/workspace.js
```

## 在线采集本机 DVWA

先确认 [本机 DVWA 登录页](http://127.0.0.1:8085/login.php) 能打开。在仓库根目录运行以下命令。

```powershell
python .\workbench\crawl_dvwa.py
```

终端会用你输入的账号创建一次独立的 DVWA 会话，输入密码时屏幕不会显示字符。报告只保存页面元数据。采集范围固定为本机 `127.0.0.1:8085`，记录登录、首页、普通 SQL Injection 和 Blind 页面，并沿导航查找说明和关于页面。报告保留页面中出现的同站链接，未采集的链接在工作台显示为“未记录此页面的响应”。

采集完成后，在工作台点击 **导入文件**，选择 `workbench/evidence/dvwa-live-pages.json`。进入 **页面清单**，打开两个 SQL 页面，核对 **HTTP 200**、字段 `id` 以及入链和出链。采集生成的 JSON 由 Git 忽略，保存在本机作为实验记录。

## 归档页面记录

1. 在浏览器自己的会话中登录本地 DVWA。打开开发者工具的 Network 面板，按课程要求手动浏览需要记录的页面。导出 HAR 时选择 **Export HAR (sanitized)**。详情见 [Chrome DevTools HAR 导出说明](https://developer.chrome.com/docs/devtools/network/reference#save-as-har)。
2. 在工作台选择“导入文件”，选择 HAR，并填写自己的 DVWA 地址作为页面范围。若 DVWA 安装在子目录，请包含子目录，例如 `http://127.0.0.1:8080/dvwa/`。
3. 在页面清单查看名称、URL、见过的 HTTP 状态、表单及参数。页面详情显示入链和出链。归档里只有链接、没有对应响应的页面会标为“未记录此页面的响应”。

HAR 在本机解析。范围按协议、主机、端口和路径匹配。输出只保留查询参数名和表单字段名及类型，舍弃查询值、Cookie、请求体和表单值。标题、路径及参数名称仍可能含有个人信息，分享导出材料前应检查。页面清单的覆盖范围取决于手动访问记录以及 HAR 中保留的 HTML 正文。HTTP 状态来自记录，HTML 只用于解析标题、初始表单和链接。登录会话留在原浏览器，工作台从归档中读取已获得的页面，不回放登录请求。

## 检测报告

- **OWASP ZAP** 可导入已有的 [Traditional JSON 报告](https://www.zaproxy.org/docs/desktop/addons/report-generation/report-traditional-json/)。告警按实例存入视图，初始状态为“待复核”。详情保留规则、URL、方法、参数及证据位置，原始证据在原报告中查阅。导入时选填目标，覆盖对照中会登记该工具已有报告。这个状态仅说明报告已提供。
- **Nikto、sqlmap、长亭 xray** 当前通过 `course-evidence/v1` JSON 整理已有结果。以下是单条记录的结构，示例所用地址和证据均为虚构。`tool` 也接受 `OWASP ZAP` 和 `静态代码审查`。`review` 支持 `待复核`、`已确认`、`误报` 和 `漏报`，省略时默认为 `待复核`。

```json
{
  "schema": "course-evidence/v1",
  "findings": [
    {
      "tool": "Nikto",
      "target": "校园设备借用管理系统",
      "type": "响应头配置",
      "title": "配置检查记录",
      "url": "https://lab.example.test/",
      "method": "GET",
      "parameter": "",
      "severity": "信息",
      "review": "待复核",
      "reference": "报告第 1 条",
      "evidence": "在此填写脱敏后的证据摘要或复核结论。"
    }
  ]
}
```

文件可选包含 `pages`，样式见 [内置示例](examples/demo.json)。记录支持按目标、工具、漏洞类型和复核状态组合筛选。源码审查的原始结构化记录见 [source-audit.json](evidence/source-audit.json)。

### 工具覆盖对照

扫描报告页列出 4 个工具与 2 个目标的 8 格对照。仅有报告时登记“已有报告”，可通过 `coverage` 另行导入核对结果。`target` 接受 `DVWA` 或 `校园设备借用管理系统`。`state` 接受 `已有报告`、`已核对覆盖范围`、`未覆盖`，后两项需要填写 `scope` 和 `reference`。没有覆盖记录的格子显示“待补证据”。以下记录仅说明字段结构。

```json
{
  "schema": "course-evidence/v1",
  "coverage": [
    {
      "target": "DVWA",
      "tool": "Nikto",
      "state": "已核对覆盖范围",
      "scope": "从已保存的记录填写实际覆盖范围",
      "reference": "填写对应记录文件与条目"
    }
  ]
}
```

在独立基线确认问题存在、且有证据表明工具覆盖了对应目标和入口时，才可将缺失的告警标为“漏报”。若入口没有覆盖，应留在覆盖对照中记录。

## 源码交接核对

- 业务后端为 Python Flask，页面用 Jinja，交互为原生 JavaScript，存储为 SQLite。已实现登录、学生和管理员角色、设备搜索、借用申请与审批、留言、附件及资料修改。
- `app.py` 第 180–198 行定义需登入的 `GET /equipment`。第 183 行读取 `q`，第 192 行在漏洞分支将其拼入 SQL，第 189 行的修复分支使用 `LIKE ?`。`category` 在查询返回后由 Python 筛选。其余四项源码中的漏洞模式差异为存储型 XSS、对象级访问控制缺失、可同源打开的 HTML 附件和 CSRF。
- 有 `Dockerfile`、`compose.yaml`、`.dockerignore` 和 `deploy/nginx-course.conf`。本地启动脚本使用 5000 和 5001，Compose 也将这两个主机端口绑定到回环地址。Nginx 文件是默认拒绝访问的草案，压缩包无法证明跨组隔离部署已经完成。
- 包内的 `verify_http.py` 和 `verify_browser.py` 是定向验证脚本。四个指定工具的实际报告、工具集成模块和 DVWA 页面记录均未随包提供。

## 后续开发顺序

1. 收集 DVWA 和校园系统已有的 HAR 与检测报告，在材料清单中补齐目标、版本、时间、页面覆盖范围及证据文件名。保留校园系统漏洞模式和修复模式的来源标签。
2. 按源码与人工复核证据建立基线，给每条报告告警记录真伪、依据和范围。针对 DVWA 的普通 SQL Injection 和 Blind 页面，分别记录页面、字段、状态及证据来源。
3. 取得 Nikto、sqlmap、长亭 xray 的实际导出样本后逐个增加离线适配器，使用脱敏样本测试字段映射。用覆盖对照维护证据，并导出 `course-evidence.json` 供合稿复核。
4. 课程的跨组验收单独确认隔离环境、授权范围、访问限制和测试数据恢复。保留验收记录作为部署证据。
