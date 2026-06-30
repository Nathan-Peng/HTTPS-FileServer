from http.server import HTTPServer, SimpleHTTPRequestHandler
from socketserver import ThreadingMixIn
import json
import os
import ssl
import socket
import threading
import re
import warnings
import sys
import gzip
import zipfile
from io import BytesIO
from urllib.parse import urlparse, unquote, quote
from datetime import datetime, timedelta
import string

# ===================== 全局基础配置 =====================
HOST = "0.0.0.0"
PORT_HTTPS = 8443
STATIC_ROOT = os.path.abspath(".")
UPLOAD_ROOT = os.path.join(STATIC_ROOT, "uploaded")
LOG_FILE = os.path.join(STATIC_ROOT, "server.log")
ENCODING = "utf-8"
REQUEST_TIMEOUT = 8
REQUEST_QUEUE_SIZE = 64
MAX_SINGLE_FILE_SIZE = 10 * 1024 * 1024
MAX_TOTAL_REQUEST_SIZE = 20 * 1024 * 1024
MAX_CONCURRENT = 30
CERT_FILE = "server.crt"
KEY_FILE = "server.key"

# 禁止上传的可执行后缀
BLOCK_EXT = {".exe", ".bat", ".cmd", ".sh", ".ps1", ".vbs", ".dll", ".sys", ".com"}
# 文件魔数白名单校验
MAGIC_WHITELIST = {
    b'\xff\xd8\xff': ".jpg", b'\x89PNG': ".png", b'GIF89a': ".gif", b'RIFF': ".webp",
    b'%PDF': ".pdf", b'PK': ".zip", b'\x1f\x8b': ".gz", b'\x00\x00\x00\x18ftyp': ".mp4",
}
# 静态资源长缓存
CACHE_LONG_EXT = {".jpg", ".jpeg", ".png", ".gif", ".webp", ".mp4", ".mp3", ".zip", ".gz"}
CACHE_LONG_SEC = 30 * 24 * 60 * 60
# 跨域头部
CORS_HEADERS = [
    ("Access-Control-Allow-Origin", "*"),
    ("Access-Control-Allow-Methods", "GET,POST,OPTIONS,DELETE"),
    ("Access-Control-Allow-Headers", "Content-Type"),
    ("Access-Control-Max-Age", "86400"),
]
JSON_TYPE = f"application/json; charset={ENCODING}"
HTML_TYPE = f"text/html; charset={ENCODING}"
ZIP_TYPE = "application/zip"
# 路由正则
ROUTE_STATUS = re.compile(r"/api/status")
ROUTE_DASHBOARD = re.compile(r"/dashboard")
UPLOAD_ROUTE = re.compile(r"/upload")
ZIP_ROUTE = re.compile(r"/zip")
ZIP_HTML_ROUTE = re.compile(r"/zip\.html")
UPLOAD_PAGE_ROUTE = re.compile(r"/upload\.html")

# 控制台UTF8编码修复
sys.stdout.reconfigure(encoding="utf-8")
sys.stderr.reconfigure(encoding="utf-8")
warnings.filterwarnings("ignore")

# 初始化上传文件夹
os.makedirs(UPLOAD_ROOT, exist_ok=True)

# ===================== 内置SSL证书自动生成模块 =====================
def auto_generate_ssl_certificate():
    print("\n🔍 未检测到 SSL 证书文件，正在自动生成证书...")
    try:
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
    except ModuleNotFoundError:
        print("\n❌ 依赖库 [cryptography] 未安装！")
        print("👉 执行安装命令：pip install cryptography")
        sys.exit(1)

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    with open(KEY_FILE, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "CN"),
        x509.NameAttribute(NameOID.COMMON_NAME, "localhost")
    ])
    now = datetime.datetime.now(datetime.UTC)
    cert = x509.CertificateBuilder()\
        .subject_name(subject)\
        .issuer_name(issuer)\
        .public_key(private_key.public_key())\
        .serial_number(x509.random_serial_number())\
        .not_valid_before(now)\
        .not_valid_after(now + datetime.timedelta(days=365))\
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), False)\
        .sign(private_key, hashes.SHA256())

    with open(CERT_FILE, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    print("✅ SSL证书生成成功！有效期365天")
    print(f"📄 生成文件: {CERT_FILE} / {KEY_FILE}\n")

# ===================== 日志乱码清洗工具 =====================
def clean_log_text(raw_text: str) -> str:
    printable_chars = set(string.printable)
    cleaned = []
    for char in raw_text:
        if char in printable_chars or ("\u4e00" <= char <= "\u9fff"):
            cleaned.append(char)
        else:
            cleaned.append("�")
    return "".join(cleaned)

def log_write(raw_text):
    time_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    safe_text = clean_log_text(raw_text)
    line = f"[{time_str}] {safe_text}\n"
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(line)
    except Exception:
        pass
    print(line.rstrip("\n"))

# ===================== 通用工具函数 =====================
def gzip_compress(raw: bytes) -> bytes:
    buf = BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb") as gz:
        gz.write(raw)
    return buf.getvalue()

def fmt_size(size: int) -> str:
    if size < 1024:
        return f"{size} B"
    elif size < 1024 * 1024:
        return f"{round(size/1024, 1)} KB"
    else:
        return f"{round(size/1024/1024, 2)} MB"

def get_file_icon(name: str, is_dir: bool) -> str:
    if is_dir:
        return "📁"
    ext = os.path.splitext(name.lower())[1]
    if ext in {".jpg", ".png", ".gif", ".webp"}: return "🖼️"
    if ext in {".mp4", ".mov"}: return "🎬"
    if ext in {".mp3", ".wav"}: return "🎵"
    if ext in {".txt", ".md", ".js", ".html", ".json"}: return "📄"
    if ext in {".zip", ".gz", ".rar", ".7z"}: return "📦"
    return "📎"

def check_file_magic(data: bytes, ext: str) -> bool:
    head = data[:12]
    for magic, allow_ext in MAGIC_WHITELIST.items():
        if head.startswith(magic):
            return ext.lower() == allow_ext
    text_ext = {".txt", ".html", ".js", ".css", ".json", ".md", ".csv"}
    return ext.lower() in text_ext

# ===================== 服务全局统计类 =====================
class ServerStats:
    start_time = datetime.now()
    active_conn = 0
    sem = threading.Semaphore(MAX_CONCURRENT)
    method_count = {"GET":0,"OPTIONS":0,"POST":0,"PUT":0,"DELETE":0}
    lock = threading.Lock()
    ssl_cert_exist = False

    @classmethod
    def conn_inc(cls):
        with cls.lock: cls.active_conn += 1
    @classmethod
    def conn_dec(cls):
        with cls.lock:
            if cls.active_conn > 0: cls.active_conn -= 1
    @classmethod
    def record_req(cls, method):
        with cls.lock:
            if method in cls.method_count: cls.method_count[method] += 1
    @classmethod
    def get_upload_info(cls):
        total_size, file_cnt = 0, 0
        for root, _, files in os.walk(UPLOAD_ROOT):
            for f in files:
                fp = os.path.join(root, f)
                st = os.stat(fp)
                file_cnt += 1
                total_size += st.st_size
        return {
            "file_count": file_cnt,
            "total_size_mb": round(total_size / 1024 / 1024, 2),
            "max_single_mb": MAX_SINGLE_FILE_SIZE // 1024 // 1024
        }
    @classmethod
    def get_info(cls):
        with cls.lock:
            run_sec = int((datetime.now() - cls.start_time).total_seconds())
            upload_info = cls.get_upload_info()
            return {
                "service_start_time": cls.start_time.strftime("%Y-%m-%d %H:%M:%S"),
                "run_time_human": str(timedelta(seconds=run_sec)),
                "active_connections": cls.active_conn,
                "max_concurrent": MAX_CONCURRENT,
                "method_statistics": cls.method_count,
                "total_requests": sum(cls.method_count.values()),
                "dirs": {"root": STATIC_ROOT, "upload": UPLOAD_ROOT},
                "upload_stat": upload_info,
                "ssl_cert_ready": cls.ssl_cert_exist
            }

# ===================== 获取局域网IP =====================
def get_lan_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(1)
        s.connect(("8.8.8.8", 53))
        ip = s.getsockname()[0]
        s.close()
        if not ip.startswith("127."):
            return ip
    except Exception:
        pass
    try:
        host = socket.gethostname()
        ips = socket.gethostbyname_ex(host)[2]
        for ip in ips:
            if not ip.startswith("127.") and ip.count(".") == 3:
                return ip
    except Exception:
        pass
    return "127.0.0.1"

LAN_IP = get_lan_ip()
URLS = {
    "https_local": f"https://127.0.0.1:{PORT_HTTPS}",
    "https_lan": f"https://{LAN_IP}:{PORT_HTTPS}"
}

# ===================== 表单解析工具 =====================
def parse_multipart(boundary: bytes, raw_body: bytes):
    parts = raw_body.split(b'--' + boundary)
    file_data = None
    filename = None
    for p in parts:
        if not p or p in (b'--\r\n', b'--'):
            continue
        head_body_split = p.split(b'\r\n\r\n', 1)
        if len(head_body_split) < 2:
            continue
        header_raw, content = head_body_split
        htxt = header_raw.decode(ENCODING, errors="ignore")
        fn_match = re.search(r'filename="([^"]+)"', htxt)
        field_match = re.search(r'name="([^"]+)"', htxt)
        if fn_match and field_match and field_match.group(1) == "file":
            filename = fn_match.group(1)
            file_data = content.rstrip(b'\r\n')
            break
    return filename, file_data

# ==============================================================================
# 【统一优化风格 · 全部内嵌HTML页面】现代化圆角、hover动效、深浅自适应
# ==============================================================================

# 1. 目录打包页面 /zip.html
ZIP_HTML = """
<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>目录ZIP打包工具 | HTTPS FileServer</title>
<style>
*{margin:0;padding:0;box-sizing:border-box;font-family:system-ui,-apple-system,Segoe UI}
:root{
    --bg:#f7f8fa;--card:#ffffff;--text:#1d2129;--sub:#6e7681;
    --border:#e5e6eb;--primary:#2563eb;--primary-light:rgba(37,99,235,0.1);
    --shadow:0 2px 12px rgba(0,0,0,0.06);--radius:14px;
}
@media (prefers-color-scheme: dark){
    :root{--bg:#141414;--card:#1f1f1f;--text:#f2f3f5;--sub:#86909c;
    --border:#333333;--primary:#60a5fa;--primary-light:rgba(96,165,250,0.1);}
}
body{background:var(--bg);padding:32px 16px;color:var(--text);min-height:100vh}
.container{max-width:680px;margin:0 auto}
.card{background:var(--card);border-radius:var(--radius);padding:32px;box-shadow:var(--shadow);border:1px solid var(--border)}
h1{text-align:center;font-size:26px;margin-bottom:32px;color:var(--primary);font-weight:600}
.form-group{margin-bottom:24px}
label{display:block;margin-bottom:10px;font-weight:500;font-size:15px}
.input{width:100%;padding:15px 16px;border:1px solid var(--border);border-radius:10px;background:transparent;color:var(--text);font-size:16px;transition:0.2s}
.input:focus{outline:none;border-color:var(--primary);box-shadow:0 0 0 3px var(--primary-light)}
.btn-primary{width:100%;padding:15px;background:var(--primary);color:#fff;border:none;border-radius:10px;font-size:16px;font-weight:500;cursor:pointer;transition:0.2s}
.btn-primary:hover{opacity:0.92;transform:translateY(-1px)}
.quick-box{margin-top:20px;display:flex;gap:12px;flex-wrap:wrap}
.btn-quick{padding:9px 14px;border:1px solid var(--border);border-radius:8px;background:transparent;color:var(--text);cursor:pointer;font-size:14px;transition:0.2s}
.btn-quick:hover{border-color:var(--primary);background:var(--primary-light)}
.tip-box{margin-top:24px;padding:16px;border-radius:10px;background:var(--primary-light);font-size:14px;line-height:1.7;color:var(--sub)}
</style>
</head>
<body>
<div class="container">
    <div class="card">
        <h1>📦 目录一键打包 ZIP 下载</h1>
        <div class="form-group">
            <label>目标目录路径（根目录填 / 上传文件夹填 /uploaded）</label>
            <input class="input" id="pathInput" placeholder="/uploaded">
        </div>
        <button class="btn-primary" onclick="downloadZip()">生成并下载压缩包</button>
        <div class="quick-box">
            <button class="btn-quick" onclick="setPath('/')">根目录 /</button>
            <button class="btn-quick" onclick="setPath('/uploaded')">上传文件目录</button>
        </div>
        <div class="tip-box">
            1. 仅支持文件夹打包，单个文件无法打包<br>
            2. 目录体积较大时打包需要等待几秒<br>
            3. 打包完成浏览器自动弹出下载
        </div>
    </div>
</div>
<script>
const baseUrl = "{{HTTPS_LOCAL}}";
function setPath(p){document.getElementById("pathInput").value = p;}
async function downloadZip(){
    const path = document.getElementById("pathInput").value.trim();
    if(!path){alert("请填写目录路径");return;}
    window.open(`${baseUrl}/zip?path=${encodeURIComponent(path)}`);
}
</script>
</body>
</html>
"""

# 2. 404错误页面
RAW_404_HTML = """
<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>404 页面不存在</title>
<style>
*{margin:0;padding:0;box-sizing:border-box;font-family:system-ui}
:root{
    --bg:#f7f8fa;--card:#ffffff;--text:#1d2129;--sub:#6e7681;
    --border:#e5e6eb;--danger:#ef4444;--primary:#2563eb;--shadow:0 2px 12px rgba(0,0,0,0.06);
}
@media(prefers-color-scheme:dark){
    :root{--bg:#141414;--card:#1f1f1f;--text:#f2f3f5;--sub:#86909c;--border:#333;--primary:#60a5fa}
}
body{background:var(--bg);padding:40px 16px;min-height:100vh;display:flex;align-items:center;justify-content:center}
.box{max-width:760px;width:100%;background:var(--card);border-radius:16px;padding:40px;box-shadow:var(--shadow);border:1px solid var(--border)}
h1{font-size:80px;color:var(--danger);text-align:center;margin:0 0 16px;font-weight:700}
.desc{text-align:center;font-size:18px;color:var(--sub);margin-bottom:28px}
.path-block{background:#27272a;color:#e4e4e7;padding:14px 16px;border-radius:10px;font-family:Consolas;word-break:break-all;margin-bottom:24px}
.btn-group{display:flex;gap:14px;flex-wrap:wrap;margin-top:32px}
.btn{flex:1;min-width:140px;text-align:center;padding:14px;border-radius:10px;text-decoration:none;font-weight:500;transition:0.2s}
.btn.main{background:var(--primary);color:#fff;border:none}
.btn.main:hover{opacity:0.92}
.btn.secondary{border:1px solid var(--border);color:var(--text);background:transparent}
.btn.secondary:hover{border-color:var(--primary)}
</style>
</head>
<body>
<div class="box">
    <h1>404</h1>
    <p class="desc">您访问的路径不存在，服务仅支持 HTTPS 加密访问</p>
    <div class="path-block">请求路径：{{PATH}}</div>
    <div class="btn-group">
        <a class="btn main" href="{{HTTPS_LOCAL}}">返回首页</a>
        <a class="btn secondary" href="/dashboard">监控面板</a>
        <a class="btn secondary" href="/zip.html">打包工具</a>
    </div>
</div>
</body>
</html>
"""

# 3. 文件目录浏览页面
def generate_dir_html(dir_path, file_list):
    items = '<li class="back"><a href="../">⬆ 返回上级目录</a></li>'
    entries = []
    for name in file_list:
        full = os.path.join(dir_path, name)
        st = os.stat(full)
        is_dir = os.path.isdir(full)
        size = fmt_size(st.st_size)
        mtime = datetime.fromtimestamp(st.st_mtime).strftime("%Y-%m-%d %H:%M")
        icon = get_file_icon(name, is_dir)
        url = quote(name)
        entries.append((is_dir, name, url, icon, size, mtime))
    entries.sort(key=lambda x: (0 if x[0] else 1, x[1].lower()))
    for is_dir, name, url, icon, size, mtime in entries:
        items += f'''
<li>
    <a href="{url}">
        <span class="icon">{icon}</span>
        <span class="name">{name}</span>
        <span class="meta">{size} · {mtime}</span>
    </a>
</li>'''

    html = f"""
<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>目录 {os.path.basename(dir_path)}</title>
<style>
*{margin:0;padding:0;box-sizing:border-box;font-family:system-ui}
:root{{
    --bg:#f7f8fa;--card:#fff;--text:#1d2129;--line:#e5e6eb;--primary:#2563eb;--radius:12px
}}
@media(prefers-color-scheme:dark){{
    :root{{--bg:#141414;--card:#1f1f1f;--text:#f2f3f5;--line:#333;--primary:#60a5fa}}
}}
body{{background:var(--bg);padding:24px 16px;color:var(--text);max-width:900px;margin:0 auto}}
h2{{font-size:22px;margin-bottom:20px;font-weight:600}}
ul{{list-style:none;background:var(--card);border-radius:var(--radius);overflow:hidden;border:1px solid var(--line)}}
li{{border-bottom:1px solid var(--line)}}
li.back{{background:rgba(37,99,235,0.08)}}
li:last-child{{border-bottom:none}}
a{{display:flex;align-items:center;padding:16px 18px;color:var(--text);text-decoration:none;gap:14px;transition:0.15s}}
a:hover{{background:rgba(120,120,120,0.05)}}
.icon{{font-size:22px;width:30px;text-align:center}}
.name{{flex:1;word-break:break-all}}
.meta{{font-size:13px;opacity:0.7;white-space:nowrap}}
</style>
</head>
<body>
<h2>📁 {dir_path}</h2>
<ul>{items}</ul>
</body>
</html>
"""
    return html.encode(ENCODING)

# 4. 监控面板页面 /dashboard
DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>服务监控面板 | HTTPS FileServer</title>
<style>
*{margin:0;padding:0;box-sizing:border-box;font-family:system-ui}
:root{
    --bg:#f7f8fa;--card:#ffffff;--text:#1d2129;--sub:#6e7681;
    --border:#e5e6eb;--primary:#2563eb;--shadow:0 2px 12px rgba(0,0,0,0.06);--radius:14px
}
@media(prefers-color-scheme:dark){
    :root{--bg:#141414;--card:#1f1f1f;--text:#f2f3f5;--sub:#86909c;--border:#333;--primary:#60a5fa}
}
body{background:var(--bg);padding:32px 16px;min-height:100vh}
.container{max-width:740px;margin:0 auto}
h1{text-align:center;font-size:28px;margin-bottom:30px;color:var(--primary);font-weight:600}
.card{background:var(--card);border-radius:var(--radius);padding:24px;margin-bottom:20px;border:1px solid var(--border);box-shadow:var(--shadow)}
.card h3{font-size:17px;margin-bottom:16px;padding-bottom:10px;border-bottom:1px solid var(--border)}
.grid-row{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:14px}
.grid-item{padding:14px;border-radius:10px;background:rgba(120,120,120,0.05)}
.grid-item .label{font-size:13px;color:var(--sub);margin-bottom:6px}
.grid-item .val{font-size:16px;font-weight:600}
.btn-row{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:12px;margin-top:8px}
.btn{padding:12px;text-align:center;border-radius:10px;text-decoration:none;font-weight:500;font-size:15px;transition:0.2s}
.btn.primary{background:var(--primary);color:#fff}
.btn.primary:hover{opacity:0.92}
.btn.outline{border:1px solid var(--border);color:var(--text);background:transparent}
.btn.outline:hover{border-color:var(--primary)}
</style>
</head>
<body>
<div class="container">
    <h1>📊 HTTPS 文件服务监控面板</h1>

    <div class="card">
        <h3>运行状态信息</h3>
        <div class="grid-row">
            <div class="grid-item"><div class="label">启动时间</div><div class="val" id="start"></div></div>
            <div class="grid-item"><div class="label">运行时长</div><div class="val" id="runtime"></div></div>
            <div class="grid-item"><div class="label">活跃连接</div><div class="val" id="active"></div></div>
            <div class="grid-item"><div class="label">总请求次数</div><div class="val" id="totalreq"></div></div>
        </div>
    </div>

    <div class="card">
        <h3>上传文件统计</h3>
        <div class="grid-row">
            <div class="grid-item"><div class="label">文件总数</div><div class="val" id="upcnt"></div></div>
            <div class="grid-item"><div class="label">占用空间</div><div class="val" id="upsize"></div></div>
            <div class="grid-item"><div class="label">单文件上限</div><div class="val" id="uplimit"></div></div>
        </div>
    </div>

    <div class="card">
        <h3>快捷功能入口</h3>
        <div class="btn-row">
            <a class="btn primary" href="{{HTTPS_LOCAL}}">根目录浏览</a>
            <a class="btn primary" href="/upload.html">文件上传</a>
            <a class="btn outline" href="/zip.html">目录打包</a>
            <a class="btn outline" href="/uploaded">上传文件库</a>
            <a class="btn outline" href="/api/status">JSON接口</a>
        </div>
    </div>
</div>

<script>
async function loadData(){
    try{
        const res = await fetch("/api/status");
        const json = await res.json();
        const info = json.info;
        document.getElementById("start").innerText = info.service_start_time;
        document.getElementById("runtime").innerText = info.run_time_human;
        document.getElementById("active").innerText = info.active_connections + "/" + info.max_concurrent;
        document.getElementById("totalreq").innerText = info.total_requests;
        const up = info.upload_stat;
        document.getElementById("upcnt").innerText = up.file_count;
        document.getElementById("upsize").innerText = up.total_size_mb + " MB";
        document.getElementById("uplimit").innerText = up.max_single_mb + " MB";
    }catch(err){console.error("数据加载失败",err)}
}
loadData();
setInterval(loadData, 5000);
</script>
</body>
</html>
"""

# 5. 【重点改造】上传页面 /upload.html 完全内嵌
UPLOAD_HTML = """
<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>文件批量上传 | HTTPS FileServer</title>
<style>
*{margin:0;padding:0;box-sizing:border-box;font-family:system-ui}
:root{
    --bg:#f7f8fa;--card:#ffffff;--text:#1d2129;--sub:#6e7681;--danger:#ef4444;
    --border:#e5e6eb;--primary:#2563eb;--primary-light:rgba(37,99,235,0.1);
    --shadow:0 2px 12px rgba(0,0,0,0.06);--radius:14px
}
@media(prefers-color-scheme:dark){
    :root{--bg:#141414;--card:#1f1f1f;--text:#f2f3f5;--sub:#86909c;--border:#333;--primary:#60a5fa}
}
body{background:var(--bg);padding:32px 16px;min-height:100vh}
.container{max-width:720px;margin:0 auto}
.card{background:var(--card);border-radius:var(--radius);padding:32px;box-shadow:var(--shadow);border:1px solid var(--border)}
h1{text-align:center;font-size:26px;margin-bottom:28px;color:var(--primary);font-weight:600}
.drop-area{border:2px dashed var(--border);border-radius:12px;padding:64px 20px;text-align:center;margin-bottom:22px;transition:0.2s}
.drop-area.active{border-color:var(--primary);background:var(--primary-light)}
.drop-area p{color:var(--sub);font-size:15px}
#fileInput{display:none}
.btn-upload{width:100%;padding:15px;background:var(--primary);color:#fff;border:none;border-radius:10px;font-size:16px;font-weight:500;cursor:pointer;transition:0.2s;margin-bottom:24px}
.btn-upload:hover{opacity:0.92;transform:translateY(-1px)}
.file-list{margin-bottom:24px}
.file-item{display:flex;justify-content:space-between;align-items:center;padding:14px;border:1px solid var(--border);border-radius:10px;margin-bottom:10px}
.file-name{word-break:break-all;padding-right:12px}
.btn-del{padding:8px 12px;background:var(--danger);color:#fff;border:none;border-radius:8px;cursor:pointer;font-size:14px}
.tip-block{padding:16px;border-radius:10px;background:rgba(239,68,68,0.1);font-size:14px;line-height:1.7;color:var(--danger);margin-bottom:24px}
.nav-row{display:flex;gap:12px;flex-wrap:wrap}
.nav-btn{flex:1;min-width:120px;padding:12px;text-align:center;border:1px solid var(--border);border-radius:10px;background:transparent;color:var(--text);text-decoration:none;font-size:15px;transition:0.2s}
.nav-btn:hover{border-color:var(--primary);background:var(--primary-light)}
</style>
</head>
<body>
<div class="container">
    <div class="card">
        <h1>📤 批量文件上传</h1>
        <div class="drop-area" id="dropZone">
            <p>点击区域选择文件 ｜ 直接拖拽文件到此上传</p>
            <p style="margin-top:8px">单文件最大 10MB，禁止可执行程序上传</p>
        </div>
        <input type="file" id="fileInput" multiple>
        <button class="btn-upload" onclick="startUpload()">开始上传全部选中文件</button>

        <div class="file-list" id="fileList"></div>

        <div class="tip-block">
            安全限制：<br>
            1. 本机127.0.0.1禁止上传文件，需要局域网其他设备访问<br>
            2. 文件会校验真实二进制类型，修改后缀伪装病毒会拦截<br>
            3. 上传文件自动按日期归档至 /uploaded 目录
        </div>

        <div class="nav-row">
            <a class="nav-btn" href="/">根目录浏览</a>
            <a class="nav-btn" href="/dashboard">监控面板</a>
            <a class="nav-btn" href="/zip.html">打包工具</a>
            <a class="nav-btn" href="/uploaded">查看已上传文件</a>
        </div>
    </div>
</div>

<script>
const baseUrl = window.location.origin;
const dropZone = document.getElementById('dropZone');
const fileInput = document.getElementById('fileInput');
const fileListEl = document.getElementById('fileList');
let selectedFiles = [];

// 拖拽高亮
dropZone.addEventListener('dragover', e=>{e.preventDefault();dropZone.classList.add('active')})
dropZone.addEventListener('dragleave', ()=>dropZone.classList.remove('active'))
dropZone.addEventListener('drop', e=>{
    e.preventDefault();dropZone.classList.remove('active');
    [...e.dataTransfer.files].forEach(f=>selectedFiles.push(f));
    renderFileList();
})
dropZone.onclick = ()=>fileInput.click();
fileInput.onchange = ()=>{
    [...fileInput.files].forEach(f=>selectedFiles.push(f));
    renderFileList();
}

// 渲染选中文件列表
function renderFileList(){
    fileListEl.innerHTML = "";
    selectedFiles.forEach((file,idx)=>{
        const div = document.createElement('div');
        div.className = "file-item";
        div.innerHTML = `
            <div class="file-name">${file.name} (${(file.size/1024/1024).toFixed(2)} MB)</div>
            <button class="btn-del" onclick="removeFile(${idx})">移除</button>
        `;
        fileListEl.appendChild(div);
    })
}
function removeFile(idx){
    selectedFiles.splice(idx,1);
    renderFileList();
}

// 批量上传接口请求
async function startUpload(){
    if(selectedFiles.length === 0){alert("请先选择需要上传的文件");return;}
    for(const file of selectedFiles){
        const formData = new FormData();
        formData.append("file", file);
        try{
            const res = await fetch(`${baseUrl}/upload`,{method:"POST",body:formData});
            const data = await res.json();
            if(data.code === 0){
                alert(`✅ ${file.name} 上传成功\n访问地址：${data.access_url}`);
            }else{
                alert(`❌ ${file.name} 上传失败：${data.msg}`);
            }
        }catch(err){
            alert(`❌ ${file.name} 请求异常：${err.message}`);
        }
    }
    selectedFiles = [];
    renderFileList();
}
</script>
</body>
</html>
"""

# ===================== 请求处理器核心类 =====================
class CustomHandler(SimpleHTTPRequestHandler):
    timeout = REQUEST_TIMEOUT
    server_version = "FileServer-V6.5-AllInlineHTML"
    sys_version = ""

    def get_real_client_ip(self):
        if hasattr(self, "headers") and self.headers is not None:
            xff = self.headers.get("X-Forwarded-For")
            if xff: return xff.split(",")[0].strip()
        return self.client_address[0]

    def is_localhost(self, ip):
        return ip.startswith("127.") or ip == "::1"

    def log_message(self, fmt, *args):
        cip = self.get_real_client_ip()
        cport = self.client_address[1]
        raw_log_line = fmt % args
        if "301" in raw_log_line and self.path == "/" and not raw_log_line.endswith("/ /"):
            raw_log_line = raw_log_line.replace('"GET / ', f'"GET / -> {self.path}index.html ')
        final_log_str = f"IP:{cip}:{cport} | {raw_log_line}"
        log_write(final_log_str)

    def log_error(self, *a): return

    def setup(self):
        try:
            if not ServerStats.sem.acquire(blocking=False):
                self.send_error(503, "服务繁忙")
                self.finish()
                return
            super().setup()
            ServerStats.conn_inc()
        except Exception: pass

    def finish(self):
        try:
            ServerStats.conn_dec()
            ServerStats.sem.release()
            super().finish()
        except (ValueError, BrokenPipeError, OSError):
            log_write(f"[连接提前关闭] 客户端 {self.client_address} 流已关闭，正常忽略")
        except Exception: pass

    def add_cors(self):
        for k, v in CORS_HEADERS: self.send_header(k, v)

    def resp_json(self, code, data):
        try:
            payload = json.dumps(data, ensure_ascii=False, indent=2).encode(ENCODING)
            self.send_response(code)
            self.add_cors()
            self.send_header("Content-Type", JSON_TYPE)
            self._write_compressed(payload)
        except (BrokenPipeError, OSError): return

    def _write_compressed(self, raw: bytes):
        accept = self.headers.get("Accept-Encoding", "") if hasattr(self, "headers") else ""
        if "gzip" in accept and len(raw) > 300:
            compressed = gzip_compress(raw)
            self.send_header("Content-Encoding", "gzip")
            self.send_header("Content-Length", str(len(compressed)))
            self.end_headers()
            self.wfile.write(compressed)
        else:
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

    def resp_404(self):
        html = RAW_404_HTML.replace("{{PATH}}", unquote(self.path))
        html = html.replace("{{HTTPS_LOCAL}}", URLS["https_local"])
        html = html.replace("{{HTTPS_LAN}}", URLS["https_lan"])
        self.send_response(404)
        self.add_cors()
        self.send_header("Content-Type", HTML_TYPE)
        self._write_compressed(html.encode(ENCODING))

    def translate_path(self, path):
        p = unquote(path).lstrip("/")
        full = os.path.normpath(os.path.join(STATIC_ROOT, p))
        if not full.startswith(STATIC_ROOT): raise FileNotFoundError()
        return full

    def stream_file(self, file_path, ctype):
        CHUNK = 65536
        stat = os.stat(file_path)
        ext = os.path.splitext(file_path)[1].lower()
        self.send_response(200)
        self.add_cors()
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(stat.st_size))
        if ext in CACHE_LONG_EXT:
            self.send_header("Cache-Control", f"public,max-age={CACHE_LONG_SEC}")
        self.end_headers()
        try:
            with open(file_path, "rb") as f:
                while chunk := f.read(CHUNK):
                    self.wfile.write(chunk)
        except BrokenPipeError:
            log_write(f"[文件流中断] 客户端提前断开 {self.client_address}")

    def stream_zip(self, target_path):
        bio = BytesIO()
        with zipfile.ZipFile(bio, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            for root, _, files in os.walk(target_path):
                for fn in files:
                    fp = os.path.join(root, fn)
                    rel = os.path.relpath(fp, STATIC_ROOT)
                    zf.write(fp, rel)
        bio.seek(0)
        zip_data = bio.read()
        name = os.path.basename(target_path) + ".zip"
        self.send_response(200)
        self.add_cors()
        self.send_header("Content-Type", ZIP_TYPE)
        self.send_header("Content-Disposition", f'attachment; filename="{quote(name)}"')
        self.send_header("Content-Length", str(len(zip_data)))
        self.end_headers()
        try:
            self.wfile.write(zip_data)
        except BrokenPipeError:
            log_write(f"[ZIP下载中断] 客户端提前断开 {self.client_address}")

    def list_directory(self, path):
        try: lst = os.listdir(path)
        except OSError: self.resp_404(); return
        html = generate_dir_html(path, lst)
        self.send_response(200)
        self.add_cors()
        self.send_header("Content-Type", HTML_TYPE)
        self._write_compressed(html)

    def do_GET(self):
        ServerStats.record_req("GET")
        upath = urlparse(self.path)
        p = upath.path

        # 内嵌上传页面路由
        if UPLOAD_PAGE_ROUTE.fullmatch(p):
            html = UPLOAD_HTML.replace("{{HTTPS_LOCAL}}", URLS["https_local"])
            self.send_response(200)
            self.add_cors()
            self.send_header("Content-Type", HTML_TYPE)
            self._write_compressed(html.encode(ENCODING))
            return

        # 打包页面
        if ZIP_HTML_ROUTE.fullmatch(p):
            html = ZIP_HTML.replace("{{HTTPS_LOCAL}}", URLS["https_local"])
            self.send_response(200)
            self.add_cors()
            self.send_header("Content-Type", HTML_TYPE)
            self._write_compressed(html.encode(ENCODING))
            return

        # 监控面板
        if ROUTE_DASHBOARD.fullmatch(p):
            dash_html = DASHBOARD_HTML.replace("{{HTTPS_LOCAL}}", URLS["https_local"])
            self.send_response(200)
            self.add_cors()
            self.send_header("Content-Type", HTML_TYPE)
            self._write_compressed(dash_html.encode(ENCODING))
            return

        # 状态接口
        if ROUTE_STATUS.fullmatch(p):
            self.resp_json(200, {"code":0,"msg":"HTTPS服务正常运行","info":ServerStats.get_info(),"urls":URLS})
            return

        # ZIP打包接口
        if ZIP_ROUTE.fullmatch(p):
            q = upath.query
            match = re.search(r'path=([^&]+)', q)
            if not match:
                self.resp_json(400, {"code":400,"msg":"缺少path参数"})
                return
            target = unquote(match.group(1))
            target_full = self.translate_path(target)
            if not os.path.isdir(target_full):
                self.resp_json(400, {"code":400,"msg":"仅支持目录打包"})
                return
            self.stream_zip(target_full)
            return

        file_full = self.translate_path(p)
        if os.path.isdir(file_full):
            self.list_directory(file_full)
            return
        if not os.path.exists(file_full):
            self.resp_404()
            return
        if os.path.isfile(file_full):
            ctype = self.guess_type(file_full)
            if ctype.startswith(("text/","application/javascript","application/json")):
                ctype += f"; charset={ENCODING}"
            self.stream_file(file_full, ctype)
            return
        self.list_directory(file_full)

    def do_POST(self):
        ServerStats.record_req("POST")
        p = urlparse(self.path).path
        if UPLOAD_ROUTE.fullmatch(p):
            client_ip = self.get_real_client_ip()
            if self.is_localhost(client_ip):
                self.resp_json(403, {"code":403,"msg":"本机127段禁止上传"})
                return
            try:
                cl = int(self.headers.get("Content-Length", 0))
                if cl <=0 or cl > MAX_TOTAL_REQUEST_SIZE:
                    self.resp_json(413,{"code":413,"msg":"文件体积超限"})
                    return
                ct = self.headers.get("Content-Type","")
                if "multipart/form-data" not in ct:
                    self.resp_json(415,{"code":415,"msg":"仅支持表单上传"})
                    return
                bm = re.search(r'boundary=([\w\-]+)', ct)
                if not bm:
                    self.resp_json(400,{"code":400,"msg":"表单解析失败"})
                    return
                bnd = bm.group(1).encode()
                raw = self.rfile.read(cl)
                fname, fbin = parse_multipart(bnd, raw)
                if not fname or not fbin:
                    self.resp_json(400,{"code":400,"msg":"无文件字段"})
                    return
                raw_name = os.path.basename(fname)
                if any(c in r"\./" for c in raw_name):
                    self.resp_json(400,{"code":400,"msg":"非法文件名"})
                    return
                ext = os.path.splitext(raw_name).lower()
                if ext in BLOCK_EXT:
                    self.resp_json(400,{"code":400,"msg":"禁止可执行文件"})
                    return
                if len(fbin) > MAX_SINGLE_FILE_SIZE:
                    self.resp_json(413,{"code":413,"msg":"单文件超限"})
                    return
                if not check_file_magic(fbin, ext):
                    self.resp_json(400,{"code":400,"msg":"文件头校验失败，禁止伪装后缀文件"})
                    return
                date_dir = os.path.join(UPLOAD_ROOT, datetime.now().strftime("%Y%m%d"))
                os.makedirs(date_dir, exist_ok=True)
                ts = datetime.now().strftime("%H%M%S_%f")
                safe_name = f"{os.path.splitext(raw_name)[0]}_{ts}{ext}"
                save_fp = os.path.join(date_dir, safe_name)
                with open(save_fp, "wb") as out:
                    out.write(fbin)
                rel_url = f"/uploaded/{os.path.basename(os.path.dirname(save_fp))}/{safe_name}"
                self.resp_json(200, {
                    "code":0,"msg":"上传成功",
                    "client_ip":client_ip,"origin_name":raw_name,"saved_name":safe_name,
                    "size_mb":round(len(fbin)/1024/1024,3),"access_url":rel_url
                })
            except Exception as e:
                self.resp_json(500,{"code":500,"msg":f"上传异常:{str(e)}"})
            return
        self.resp_404()

    def do_DELETE(self):
        ServerStats.record_req("DELETE")
        p = urlparse(self.path).path
        if p.startswith("/uploaded/"):
            client_ip = self.get_real_client_ip()
            if self.is_localhost(client_ip):
                self.resp_json(403,{"code":403,"msg":"本机127段禁止删除文件"})
                return
            full_target = self.translate_path(p)
            if not os.path.isfile(full_target):
                self.resp_json(400,{"code":400,"msg":"文件不存在"})
                return
            try:
                os.remove(full_target)
                self.resp_json(200,{"code":0,"msg":"删除成功"})
            except Exception as e:
                self.resp_json(500,{"code":500,"msg":f"删除失败:{str(e)}"})
            return
        self.resp_404()

    def do_OPTIONS(self):
        ServerStats.record_req("OPTIONS")
        try:
            self.send_response(200)
            self.add_cors()
            self.end_headers()
        except Exception:
            self.resp_404()
    def do_PUT(self):
        ServerStats.record_req("PUT")
        self.resp_404()

# ===================== HTTPS服务容器 =====================
class SingleHttpsServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    request_queue_size = REQUEST_QUEUE_SIZE
    def server_bind(self):
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        super().server_bind()
