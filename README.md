# 校园设备借用管理系统与安全实验工作台

这个仓库包含校园设备借用管理系统的修复版，以及一个离线页面和报告展示工作台。两个应用均使用 Flask，默认只在本机运行。

| 目录 | 内容 |
| --- | --- |
| [`campus/`](campus/) | 登录、设备目录、借用申请、审批、留言、资料与附件管理 |
| [`workbench/`](workbench/) | HAR 和报告导入、页面清单、链接关系、工具筛选与结果导出 |
| [`workbench/verification/`](workbench/verification/) | 使用临时 SQLite 数据库的业务和安全回归 |

## 安装依赖

在仓库根目录使用 Python 3.11 或以上版本运行。

```powershell
python -m pip install -r requirements.txt
```

## 启动工作台

```powershell
python .\workbench\app.py
```

在浏览器访问 [安全实验工作台](http://127.0.0.1:5080/)。首页会显示虚构的演示记录。导入自己的 HAR 时填写实际的地址范围，导入已有报告时选择对应的目标。更多字段说明见 [工作台使用说明](workbench/README.md)。

## 启动校园系统修复版

首次启动前为本地的三个虚构演示账号设置一个口令。以下命令在 PowerShell 7 运行。

```powershell
$env:CAMPUS_DEMO_PASSWORD = Read-Host '设置本机演示账号口令' -MaskInput
python .\campus\app.py
```

浏览器访问 [校园系统修复版](http://127.0.0.1:5001/)。学生账号为 `alice` 和 `bob`，管理员账号为 `admin`。登录口令使用首次初始化时设置的值。SQLite 数据库和附件存放在 `campus/instance/`。在启动窗口按 `Ctrl+C` 停止服务。

## 运行验证

```powershell
python -B -m unittest discover -s workbench -v
python -B .\workbench\verification\check_campus_fixed.py
python -B .\workbench\verification\check_campus_fixed_controls.py
```

仓库中的 `workbench/evidence/source-audit.json` 记录课程原始源码的静态审查，行号沿用原始版本。公开演示数据在 `workbench/examples/`。实际抓包、实验报告、数据库和用户附件应留在各自的本机工作区中。
