# 防火墙日志分析平台
一款基于 Streamlit 的交互式防火墙日志分析工具，支持自定义白名单、Payload 命中确认、威胁情报集成。
功能特性
支持上传 .xlsx / .csv 日志（自动跳过前7行头）

动态列白名单规则（支持 IP CIDR、端口范围、排除匹配 !）

Payload 内容匹配 + HTTP 状态码判断，自动标记“已确认”

集成 VirusTotal API 威胁情报（可选）

快速加白、规则克隆、筛选导出

<img width="1920" height="911" alt="主界面" src="https://github.com/user-attachments/assets/95e0b38d-dc02-4541-92b9-b4fb37acb29e" />
<img width="1266" height="839" alt="分析后" src="https://github.com/user-attachments/assets/551ec472-f3ae-4422-96bf-de9b05e0619d" />
<img width="1289" height="826" alt="分析后2" src="https://github.com/user-attachments/assets/66b08a04-475f-41ac-8335-23e1bb81a43b" />

## 快速开始

### 前提条件
- Python 3.8+
- pip

### 安装依赖
```bash
pip install -r requirements.txt

streamlit run sangforAF日志分析.py

浏览器访问 http://localhost:8501

