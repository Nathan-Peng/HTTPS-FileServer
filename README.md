# HTTPS-FileServer

![Python](https://img.shields.io/badge/Python-3.8%2B-blue)
![License](https://img.shields.io/badge/License-MIT-green)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey)
![Auto-SSL](https://img.shields.io/badge/SSL-Auto%20Generate-success)
![Version](https://img.shields.io/badge/Version-v6.5-Inline)


轻量、安全、开箱即用的**纯 Python 局域网 HTTPS 文件服务**。  
无 OpenSSL 依赖、无需静态页面、单文件部署、自动生成 SSL 证书，适合内网设备互传、资源托管、私有文件共享。

## ✨ 项目亮点

- **全自动 SSL 证书**：基于 `cryptography` 纯代码生成，跨平台零依赖，启动即用
- **全站 HTTPS 加密**：禁用明文 HTTP，仅保留高强度 TLS 加密，内网传输安全
- **单文件极简部署**：所有前端页面内嵌代码，仓库干净无冗余静态文件
- **分级权限控制**：本机回环 IP 只读，局域网设备可上传/删除，安全隔离
- **双重上传防护**：后缀黑名单 + 文件魔数校验，拦截伪装与可执行文件
- **现代化自适应 UI**：明暗主题自动切换，移动端/桌面端完美适配
- **智能日志清洗**：自动过滤乱码与无效字符，日志整洁易排查

## 📁 项目结构

```
HTTPS-FileServer/
├── main.py        # 主程序（后端逻辑 + 全部内嵌前端页面）
├── LICENSE        # MIT 开源协议
└── .gitignore     # 项目忽略规则
```

运行自动生成（已忽略）：
- `server.crt / server.key`：自动生成 SSL 证书
- `uploaded/`：按日期归档的上传文件目录
- `server.log`：服务运行日志

## 🚀 快速开始

### 环境依赖
Python 3.8+

### 安装依赖
```bash
pip install cryptography
```

### 启动服务
```bash
python main.py
```

### 访问地址
- 本机：`https://127.0.0.1:8443`
- 局域网：`https://[内网IP]:8443`

> 自签名证书浏览器提示不安全为正常现象，选择「继续访问」即可正常加密使用。

## 📌 功能路由

| 路由 | 功能 |
|------|------|
| `/` | 目录文件浏览器 |
| `/upload.html` | 批量文件上传页 |
| `/uploaded` | 上传文件归档目录 |
| `/dashboard` | 服务监控面板 |
| `/zip.html` | 目录在线打包工具 |
| `/api/status` | 服务状态接口 |

## 🛡️ 安全机制

- **传输安全**：仅启用 TLS 安全协议，关闭老旧弱加密套件，全程 HTTPS
- **上传安全**：禁止可执行文件上传，校验文件真实二进制类型，防止伪装文件
- **权限安全**：本地 IP 只读保护，仅局域网设备具备写入、删除权限
- **路径防护**：严格路径规范化，杜绝目录穿越攻击

## 📊 服务能力

- 目录浏览、文件下载、在线删除
- 拖拽批量上传、自动日期归档
- 目录一键 ZIP 压缩下载
- 实时监控运行时长、连接数、请求统计、上传统计
- Gzip 压缩 + 静态资源缓存，访问速度更快
- 异常连接容错，稳定后台运行

## 📝 更新日志

### v6.5
- 全部前端页面内嵌，彻底剥离静态 HTML 文件
- 全站 UI 统一现代化风格，适配深浅色主题
- 优化上传交互与控制台输出
- 精简项目结构，轻量化、易部署

### v6.4
- 移除 OpenSSL 依赖，实现纯代码自动签发 SSL 证书
- 优化依赖检测与启动容错逻辑

## ⚠️ 使用说明
本项目为**内网私有服务**，适用于家庭、办公局域网、本地开发场景，**不建议直接暴露至公网**。

## 📄 开源协议
基于 [MIT License](LICENSE) 开源，可自由使用、修改与分发。
