#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
LemeHost Auto Renewal — GitHub Action 版本
===========================================
自动登录 LemeHost，检查所有免费服务器：
  - 倒计时 < 阈值 → 自动续期（含验证码识别）
  - 服务器离线 → 自动开机（WebSocket）
  - 结果 → Telegram 通知

用法：配置 GitHub Secrets 后，workflow 自动按 cron 调度运行。
"""

import hashlib
import os
import re
import ssl
import sys
import time
import json
import pickle
import random
import io
import ddddocr
import requests
import websocket
import requests.utils
from PIL import Image, ImageFilter
from datetime import datetime, timezone, timedelta

# ============================================================
# 环境变量（从 GitHub Secrets 注入）
# ============================================================
LEME = os.environ.get("LEME", "")
TG_BOT_TOKEN = os.environ.get("TG_BOT_TOKEN", "")
TG_CHAT_ID = os.environ.get("TG_CHAT_ID", "")
TG_API = os.environ.get("TG_API", "https://api.telegram.org")
_RT = os.environ.get("RENEW_THRESHOLD", "900")
try:
    RENEW_THRESHOLD = int(_RT)
except ValueError:
    print(f"::error::❌ RENEW_THRESHOLD 不是有效数字: '{_RT}'")
    sys.exit(1)
COOKIE_DIR = os.environ.get("COOKIE_DIR", "/tmp/lemehost_cookies")
DEBUG_DIR = os.environ.get("DEBUG_DIR", "/tmp/lemehost_debug")

# ============================================================
# 常量
# ============================================================
BASE_URL = "https://lemehost.com"
LOGIN_URL = f"{BASE_URL}/site/login"
SERVER_INDEX_URL = f"{BASE_URL}/server/index"
MAX_LOGIN_RETRY = 30
SIGNATURE = "Leme Host Auto Renewal"

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/146.0.0.0 Safari/537.36"
)

# ============================================================
# 全局统计
# ============================================================
STATS = {
    "accounts": 0,
    "servers": 0,
    "renewals": 0,
    "skipped": 0,
    "failures": 0,
    "starts": 0,
}

STEPS = []


def step(name: str, ok: bool, detail: str = ""):
    STEPS.append({"name": name, "ok": ok, "detail": detail})
    emoji = "✅" if ok else "❌"
    ts = datetime.now().strftime("%H:%M:%S")
    print(f"[{ts}] [STEP] {emoji} {name} — {detail}")


def log(msg: str):
    """打印日志（GitHub Action 会自动捕获 stdout）"""
    ts = datetime.now().strftime("%H:%M:%S")
    print(f"[{ts}] {msg}")


def notice(msg: str):
    """GitHub Action 的 notice 注解"""
    ts = datetime.now().strftime("%H:%M:%S")
    print(f"::notice::[{ts}] {msg}")


def error(msg: str):
    """GitHub Action 的 error 注解"""
    ts = datetime.now().strftime("%H:%M:%S")
    print(f"::error::[{ts}] {msg}")


def save_html(name: str, html: str, resp=None):
    try:
        os.makedirs(DEBUG_DIR, exist_ok=True)
        path = os.path.join(DEBUG_DIR, f"{name}.html")
        with open(path, "w", encoding="utf-8") as f:
            f.write(html[:100000])
        if resp is not None:
            meta = {"url": getattr(resp, "url", ""), "status": getattr(resp, "status_code", 0)}
            with open(os.path.join(DEBUG_DIR, f"{name}_meta.json"), "w") as f:
                json.dump(meta, f, indent=2)
    except Exception as e:
        log(f"[DEBUG] 保存 HTML {name} 失败: {e}")


def mask(text: str) -> str:
    if not text:
        return "***"
    if "@" in text:
        local, domain = text.split("@", 1)
        return f"{local[:3]}***@{domain}"
    return "***"


# ============================================================
# 账号解析
# ============================================================
def parse_accounts(raw: str) -> list:
    accounts = []
    for line in raw.strip().splitlines():
        line = line.strip()
        if not line or "-----" not in line:
            continue
        parts = line.split("-----", 1)
        if len(parts) == 2 and parts[0].strip() and parts[1].strip():
            accounts.append({"email": parts[0].strip(), "password": parts[1].strip()})
    return accounts


# ============================================================
# Telegram 通知
# ============================================================
def send_telegram(text: str):
    if not TG_BOT_TOKEN or not TG_CHAT_ID:
        return
    try:
        resp = requests.post(
            f"{TG_API}/bot{TG_BOT_TOKEN}/sendMessage",
            data={"chat_id": TG_CHAT_ID, "text": text},
            timeout=30,
        )
        if resp.status_code == 200:
            log("[TG] ✅ 通知已发送")
        else:
            log(f"[TG] ⚠️ 发送失败: {resp.status_code}")
    except Exception as e:
        log(f"[TG] ❌ {e}")


# ============================================================
# 时间工具
# ============================================================
def ts_to_cn(ts_ms: int) -> str:
    dt = datetime.fromtimestamp(ts_ms / 1000, tz=timezone(timedelta(hours=8)))
    return dt.strftime("%Y年%m月%d日 %H时%M分")


def ts_remaining(ts_ms: int) -> int:
    now_ms = int(datetime.now(timezone.utc).timestamp() * 1000)
    return max(0, (ts_ms - now_ms) // 1000)


def fmt_seconds(s: int) -> str:
    if s <= 0:
        return "已过期"
    if s < 60:
        return f"{s}秒"
    if s < 3600:
        return f"{s // 60}分{s % 60}秒"
    return f"{s // 3600}时{(s % 3600) // 60}分"


# ============================================================
# 验证码图片预处理
# ============================================================
def preprocess_captcha(img_bytes: bytes) -> bytes:
    try:
        img = Image.open(io.BytesIO(img_bytes)).convert("L")
        img = img.point(lambda x: 0 if x < 160 else 255)
        img = img.filter(ImageFilter.MedianFilter(size=3))
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        return buf.getvalue()
    except Exception:
        return img_bytes


# ============================================================
# 类
# ============================================================
class LemeHostRenewer:
    def __init__(self, email: str, password: str):
        self.email = email
        self.password = password
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": USER_AGENT,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,"
                      "image/avif,image/webp,image/apng,*/*;q=0.8",
            "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
            "Accept-Encoding": "gzip, deflate",
        })
        self.ocr_new = ddddocr.DdddOcr(show_ad=False)
        self.ocr_old = ddddocr.DdddOcr(show_ad=False, old=True)
        self.logged_in = False
        self._started_servers = set()
        # 尝试从缓存恢复 cookie 会话
        self._load_cookies()

    # ── Cookie 持久化 ──
    def _load_cookies(self) -> bool:
        """从缓存加载 cookie，成功且有效则返回 True"""
        hash_val = hashlib.md5(self.email.encode()).hexdigest()[:8]
        pkl = os.path.join(COOKIE_DIR, f"cookies_{hash_val}.pkl")
        if not os.path.exists(pkl):
            return False
        try:
            with open(pkl, "rb") as f:
                data = pickle.load(f)
            self.session.cookies = data["cookies"]
            # 测试会话是否有效
            resp = self.session.get(SERVER_INDEX_URL, timeout=30)
            if "Logout" in resp.text:
                log(f"[COOKIE] ✅ {mask(self.email)} cookie 有效，跳过登录")
                self.logged_in = True
                return True
            else:
                log(f"[COOKIE] ⏳ {mask(self.email)} cookie 已过期")
                return False
        except Exception as e:
            log(f"[COOKIE] ⚠️ 加载失败: {e}")
            return False

    def _save_cookies(self):
        """将当前会话 cookie 持久化到缓存文件"""
        try:
            os.makedirs(COOKIE_DIR, exist_ok=True)
            hash_val = hashlib.md5(self.email.encode()).hexdigest()[:8]
            path = os.path.join(COOKIE_DIR, f"cookies_{hash_val}.pkl")
            data = {"cookies": self.session.cookies, "email": self.email, "saved_at": time.time()}
            with open(path, "wb") as f:
                pickle.dump(data, f)
            log(f"[COOKIE] 💾 已保存 cookie")
        except Exception as e:
            log(f"[COOKIE] ⚠️ 保存失败: {e}")

    # ── 正则提取 ──
    @staticmethod
    def _ex(pattern: str, html: str) -> str:
        m = re.search(pattern, html)
        return m.group(1) if m else ""

    # ── 验证码识别（双模型集成） ──
    def _solve_captcha_multi(self, img_bytes, min_len=6, max_len=7):
        """对同一张图跑 4 种组合，返回第一个合法结果"""
        raw = img_bytes
        proc = preprocess_captcha(img_bytes)
        for label, ocr, data in [
            ("新+原", self.ocr_new, raw),
            ("新+预处理", self.ocr_new, proc),
            ("旧+原", self.ocr_old, raw),
            ("旧+预处理", self.ocr_old, proc),
        ]:
            try:
                r = ocr.classification(data)
                if r and re.match(rf'^[a-zA-Z]{{{min_len},{max_len}}}$', r):
                    return r, label
            except Exception:
                pass
        return "", ""

    # ── 验证码识别（通用，含预处理） ──
    def _solve_captcha(self, cap_url, min_len=6, max_len=7, max_try=15):
        for ct in range(1, max_try + 1):
            try:
                img_resp = self.session.get(cap_url, timeout=15)
                result, label = self._solve_captcha_multi(img_resp.content, min_len, max_len)
                if result:
                    log(f"    [OCR] #{ct} ({label}): '{result}' ✅")
                    return result
                else:
                    log(f"    [OCR] #{ct}: 全部失败")
            except Exception as e:
                log(f"    [OCR] #{ct}: 异常 {e}")
            try:
                ref = self.session.get(f"{BASE_URL}/site/captcha?refresh=1", timeout=10)
                u = ref.json().get("url", "")
                if u:
                    cap_url = u if u.startswith("http") else BASE_URL + u
            except Exception:
                pass
            time.sleep(random.uniform(0.3, 0.6))
        return ""

    # ── 登录 ──
    def login(self) -> bool:
        if self.logged_in:
            log(f"[LOGIN] ⏭️ {mask(self.email)} 已通过 cookie 登录")
            return True
        total_captcha = [0]
        for attempt in range(1, MAX_LOGIN_RETRY + 1):
            log(f"[LOGIN] 尝试 {attempt}/{MAX_LOGIN_RETRY}: {mask(self.email)}")
            try:
                try:
                    self.session.get(BASE_URL, timeout=15)
                    time.sleep(random.uniform(1, 2))
                except Exception:
                    pass

                resp = self.session.get(LOGIN_URL, timeout=30)
                html = resp.text
                save_html(f"login_{hashlib.md5(self.email.encode()).hexdigest()[:8]}_page", html, resp)

                if "loginform-email" not in html:
                    if "challenge" in html.lower() or "cloudflare" in html.lower() or len(html) < 1000:
                        wait = 10 + attempt * 3
                        step(f"login_page_{attempt}", False, f"CF 拦截 ({len(html)}b)")
                        log(f"[LOGIN] ⚠️ CF 拦截，等待 {wait}s...")
                        time.sleep(wait)
                    else:
                        step(f"login_page_{attempt}", False, "登录页无表单")
                        log("[LOGIN] ❌ 登录页无表单")
                        time.sleep(3)
                    continue

                csrf = self._ex(r'name="_csrf-frontend"\s+value="([^"]+)"', html)
                if not csrf:
                    csrf = self._ex(r'<meta\s+name="csrf-token"\s+content="([^"]+)"', html)
                if not csrf:
                    step(f"login_csrf_{attempt}", False, "CSRF 提取失败")
                    log("[LOGIN] ❌ CSRF 失败")
                    continue

                key = self._ex(r'id="loginform-key"[^>]*value="([^"]*)"', html) or ""
                cap_url = self._ex(r'id="loginform-verifycode-image"\s+src="([^"]+)"', html)
                if not cap_url:
                    step(f"login_captcha_{attempt}", False, "验证码元素未找到")
                    continue
                if cap_url.startswith("/"):
                    cap_url = BASE_URL + cap_url

                # 识别验证码（双模型集成）
                captcha = ""
                for ct in range(1, 10):
                    total_captcha[0] += 1
                    try:
                        img_resp = self.session.get(cap_url, timeout=15)
                        result, label = self._solve_captcha_multi(img_resp.content)
                        if result:
                            captcha = result
                            log(f"  [OCR] #{total_captcha[0]} ({label}): '{result}' ✅")
                            break
                        else:
                            log(f"  [OCR] #{total_captcha[0]}: 全部失败")
                    except Exception as e:
                        log(f"  [OCR] #{total_captcha[0]}: 异常 {e}")
                    try:
                        ref = self.session.get(f"{BASE_URL}/site/captcha?refresh=1", timeout=10)
                        u = ref.json().get("url", "")
                        if u:
                            cap_url = u if u.startswith("http") else BASE_URL + u
                    except Exception:
                        pass
                    time.sleep(random.uniform(0.3, 0.6))

                if not captcha:
                    step(f"login_ocr_{attempt}", False, "无6位验证码结果")
                    log("[LOGIN] ⏭️ 本轮无6位结果")
                    continue

                resp = self.session.post(LOGIN_URL, data={
                    "_csrf-frontend": csrf,
                    "LoginForm[email]": self.email,
                    "LoginForm[password]": self.password,
                    "LoginForm[verifyCode]": captcha,
                    "LoginForm[key]": key,
                    "LoginForm[key2]": "",
                    "LoginForm[rememberMe]": "1",
                    "login-button": "",
                }, timeout=30, allow_redirects=True, headers={
                    "Referer": LOGIN_URL, "Origin": BASE_URL,
                    "Content-Type": "application/x-www-form-urlencoded",
                })

                if "Logout" in resp.text:
                    log(f"[LOGIN] ✅ 成功: {mask(self.email)} (第{attempt}次, 共{total_captcha[0]}次OCR)")
                    step("login", True, f"{mask(self.email)} 第{attempt}次成功")
                    self.logged_in = True
                    self._save_cookies()
                    return True
                save_html(f"login_{hashlib.md5(self.email.encode()).hexdigest()[:8]}_post_{attempt}", resp.text, resp)
                if "verification code is incorrect" in resp.text.lower() or "Invalid CAPTCHA" in resp.text:
                    step(f"login_captcha_err_{attempt}", False, f"验证码错误 '{captcha}'")
                    log(f"[LOGIN] ❌ 验证码错误 '{captcha}'")
                    time.sleep(random.uniform(0.5, 1.5))
                    continue
                if "Incorrect email or password" in resp.text:
                    step("login", False, "密码错误")
                    log(f"[LOGIN] ❌ 密码错误: {mask(self.email)}")
                    return False
                step(f"login_post_{attempt}", False, f"未知结果, 页面大小{len(resp.text)}b")
            except Exception as e:
                step(f"login_exception_{attempt}", False, str(e)[:80])
                log(f"[LOGIN] ❌ 异常: {e}")
                time.sleep(random.uniform(3, 6))

        step("login", False, f"{mask(self.email)} 全部{MAX_LOGIN_RETRY}次尝试失败")
        log(f"[LOGIN] ❌ 失败: {mask(self.email)}")
        return False

    def ensure_login(self) -> bool:
        try:
            resp = self.session.get(SERVER_INDEX_URL, timeout=30)
            if "Logout" in resp.text:
                return True
        except Exception:
            pass
        log(f"[SESSION] 🔄 重新登录: {mask(self.email)}")
        self.logged_in = False
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": USER_AGENT,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,"
                      "image/avif,image/webp,image/apng,*/*;q=0.8",
            "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
            "Accept-Encoding": "gzip, deflate",
        })
        ok = self.login()
        if ok:
            self._save_cookies()
        return ok

    # ── 获取服务器列表 ──
    def get_servers(self) -> list:
        log("[SERVERS] 获取列表...")
        try:
            resp = self.session.get(SERVER_INDEX_URL, timeout=30)
            html = resp.text
        except Exception as e:
            log(f"[SERVERS] ❌ {e}")
            return []
        servers, seen = [], set()
        for m in re.finditer(r"/server/view\?id=(\d+)", html):
            sid = m.group(1)
            if sid in seen:
                continue
            seen.add(sid)
            nm = re.search(rf'data-key="{sid}".*?<h3[^>]*>(.*?)</h3>', html, re.DOTALL)
            name = re.sub(r"<[^>]+>", "", nm.group(1)).strip() if nm else "Unknown"
            servers.append((sid, name))
            log(f"[SERVERS] 🖥️ {sid} - {name}")
        log(f"[SERVERS] 共 {len(servers)} 台")
        return servers

    # ── WS 检查状态 + 开机 ──
    def _check_and_start_via_ws(self, server_id: str) -> str:
        """返回: 'started' / 'already_running' / 'failed'"""
        view_url = f"{BASE_URL}/server/view?id={server_id}"
        try:
            resp = self.session.get(view_url, timeout=30)
            html = resp.text

            ws_url_raw = self._ex(r'data-ws="([^"]+)"', html)
            if not ws_url_raw:
                log(f"  [WS] ❌ 未找到 data-ws")
                return "failed"

            ws_url = re.sub(r':\d+', '', ws_url_raw)
            page_token = self._ex(r'data-token="([^"]+)"', html)
            token_url = self._ex(r'data-token_url="([^"]+)"', html)
            csrf = self._ex(r'<meta\s+name="csrf-token"\s+content="([^"]+)"', html)

            # 获取新鲜 token
            ws_token = page_token
            if token_url:
                token_url = token_url.replace("&amp;", "&")
                if "force=true" not in token_url:
                    token_url = token_url.replace("force=", "force=true")
                try:
                    tr = self.session.get(token_url, timeout=15, headers={
                        "Accept": "*/*", "X-Requested-With": "XMLHttpRequest",
                        "X-CSRF-TOKEN": csrf or "", "Referer": view_url,
                    })
                    if tr.status_code == 200:
                        td = tr.json()
                        ws_token = td.get("websocket_token", page_token)
                        ret_ws = td.get("websocket_url", "")
                        if ret_ws:
                            ws_url = re.sub(r':\d+', '', ret_ws)
                except Exception:
                    pass

            if not ws_token:
                log(f"  [WS] ❌ 无 token")
                return "failed"

            log(f"  [WS] 连接 {server_id}...")

            ws = websocket.WebSocket()
            ws.connect(
                ws_url,
                origin="https://lemehost.com",
                host=re.search(r'wss://([^/]+)', ws_url).group(1),
                header=[f"User-Agent: {USER_AGENT}", "Cache-Control: no-cache"],
                sslopt={"cert_reqs": ssl.CERT_NONE},
                timeout=15,
            )

            ws.send(json.dumps({"event": "auth", "args": [ws_token]}))

            start_time = time.time()
            authed = False
            sent_start = False

            while time.time() - start_time < 15:
                try:
                    ws.settimeout(3)
                    msg = ws.recv()
                    if not msg:
                        break

                    data = json.loads(msg)
                    event = data.get("event", "")
                    args = data.get("args", [])

                    if event == "auth success":
                        authed = True

                    elif event == "status":
                        status = args[0] if args else ""
                        log(f"  [WS] {server_id} 状态: {status}")

                        if status == "offline":
                            log(f"  [WS] ✅ 确认 offline，开机...")
                            ws.send(json.dumps({"event": "set state", "args": ["start"]}))
                            sent_start = True
                            time.sleep(2)
                            try:
                                ws.close()
                            except Exception:
                                pass
                            self._started_servers.add(server_id)
                            STATS["starts"] += 1
                            return "started"

                        elif status == "stopping":
                            log(f"  [WS] ⏳ 正在停止，等待...")

                        elif status in ["starting", "running"]:
                            log(f"  [WS] ✅ 已在线 ({status})")
                            try:
                                ws.close()
                            except Exception:
                                pass
                            self._started_servers.add(server_id)
                            return "already_running"

                    elif event == "stats":
                        try:
                            stats = json.loads(args[0]) if args else {}
                            state = stats.get("state", "")
                            if state == "offline" and authed and not sent_start:
                                log(f"  [WS] stats offline，开机...")
                                ws.send(json.dumps({"event": "set state", "args": ["start"]}))
                                sent_start = True
                                time.sleep(2)
                                try:
                                    ws.close()
                                except Exception:
                                    pass
                                self._started_servers.add(server_id)
                                STATS["starts"] += 1
                                return "started"
                            elif state in ["starting", "running"]:
                                try:
                                    ws.close()
                                except Exception:
                                    pass
                                self._started_servers.add(server_id)
                                return "already_running"
                        except Exception:
                            pass

                    elif event == "token expired":
                        break

                except websocket.WebSocketTimeoutException:
                    continue
                except Exception:
                    break

            try:
                ws.close()
            except Exception:
                pass
            return "failed"

        except Exception as e:
            log(f"  [WS] ❌ {e}")
            return "failed"

    # ── 检查 + 开机 + 续期 ──
    def check_and_renew(self, server_id, server_name=""):
        def _snap(tag, h, r=None):
            save_html(f"s{server_id}_{tag}", h, r)
        result = {
            "success": False, "server_id": server_id, "server_name": server_name,
            "old_expiry": "", "new_expiry": "", "message": "", "remaining": "",
            "email": self.email, "skipped": False, "remain_seconds": -1, "started": False,
        }
        url = f"{BASE_URL}/server/{server_id}/free-plan"
        try:
            resp = self.session.get(url, timeout=30)
            html = resp.text
            _snap("plan_page", html, resp)
            auto_ts = 0
            m = re.search(r'id="countdown"\s+data-timestamp="(\d+)"', html)
            if m:
                auto_ts = int(m.group(1))
            if not auto_ts:
                m = re.search(r'data-timestamp="(\d+)"[^>]*id="countdown"', html)
                if m:
                    auto_ts = int(m.group(1))
            remain = ts_remaining(auto_ts) if auto_ts else -1
            del_ts = 0
            m = re.search(r'countdown-free-plan-delete[^>]*data-timestamp="(\d+)"', html)
            if m:
                del_ts = int(m.group(1))

            # ── 是否需要开机 ──
            need_check = False
            if remain == 0:
                need_check = True
                step(f"check_{server_id}", True, f"倒计时过期(remain=0)")
                log(f"  [CHECK] {server_id} ⚠️ 倒计时过期")
                self._started_servers.discard(server_id)
            if "was recently stopped" in html or "reason of inactivity" in html:
                need_check = True
                step(f"check_{server_id}", True, "停机提示")
                log(f"  [CHECK] {server_id} ⚠️ 停机提示")
            if server_id in self._started_servers and remain > 0:
                need_check = False
            if need_check:
                ws_result = self._check_and_start_via_ws(server_id)
                if ws_result == "started":
                    result["started"] = True
                    step(f"ws_{server_id}", True, "已发送开机指令")
                    log("  [CHECK] ⏳ 等待开机...")
                    time.sleep(10)
                    resp = self.session.get(url, timeout=30)
                    html = resp.text
                    _snap("after_start", html, resp)
                    auto_ts = 0
                    m = re.search(r'id="countdown"\s+data-timestamp="(\d+)"', html)
                    if m:
                        auto_ts = int(m.group(1))
                    remain = ts_remaining(auto_ts) if auto_ts else -1
                    del_ts = 0
                    m = re.search(r'countdown-free-plan-delete[^>]*data-timestamp="(\d+)"', html)
                    if m:
                        del_ts = int(m.group(1))
                elif ws_result == "already_running":
                    step(f"ws_{server_id}", True, "已在运行")
                    pass
                else:
                    step(f"ws_{server_id}", False, "检查失败")
                    log(f"  [CHECK] {server_id} ⚠️ WS 检查失败")
            if remain > 0:
                self._started_servers.discard(server_id)
            result["remain_seconds"] = remain
            if remain >= 0:
                result["remaining"] = fmt_seconds(remain)
                log(f"  [CHECK] {server_id} 剩余: {fmt_seconds(remain)} ({remain}s)")
                if remain > RENEW_THRESHOLD:
                    step(f"renew_{server_id}", True, f"跳过，剩余{fmt_seconds(remain)}")
                    result["skipped"] = True
                    result["message"] = f"剩余 {fmt_seconds(remain)}，无需续期"
                    if del_ts:
                        result["old_expiry"] = result["new_expiry"] = ts_to_cn(del_ts)
                    return result
            else:
                step(f"check_{server_id}", False, "未获取到倒计时")
                log(f"  [CHECK] {server_id} 未获取到倒计时")
            if del_ts:
                result["old_expiry"] = ts_to_cn(del_ts)
            csrf = self._ex(r'name="_csrf-frontend"\s+value="([^"]+)"', html)
            if not csrf:
                csrf = self._ex(r'<meta\s+name="csrf-token"\s+content="([^"]+)"', html)
            if not csrf:
                step(f"renew_{server_id}", False, "CSRF 获取失败")
                result["message"] = "CSRF 获取失败"
                _snap("no_csrf", html)
                return result

            # ── 检测续期页是否需要验证码 ──
            has_captcha = "extendfreeplanform-captcha-image" in html
            captcha_value = ""
            if has_captcha:
                step(f"renew_{server_id}_captcha", True, "续期需要验证码")
                log(f"  [RENEW] ⚠️ 续期需要验证码!")
                cap_url = self._ex(r'id="extendfreeplanform-captcha-image"\s+src="([^"]+)"', html)
                if cap_url and cap_url.startswith("/"):
                    cap_url = BASE_URL + cap_url
                if cap_url:
                    captcha_value = self._solve_captcha(cap_url, min_len=6, max_len=7, max_try=15)
                if not captcha_value:
                    step(f"renew_{server_id}", False, "续期验证码识别失败")
                    log("  [RENEW] ❌ 续期验证码识别失败")
                    result["message"] = "续期验证码识别失败"
                    return result

            log(f"  [RENEW] 🔄 续期: {server_id}" + (f" (captcha={captcha_value})" if captcha_value else ""))
            time.sleep(random.uniform(0.5, 1.5))

            # ── 提交续期（最多重试30轮验证码） ──
            for renew_try in range(30):
                post_resp = self.session.post(url, data={
                    "_csrf-frontend": csrf,
                    "ExtendFreePlanForm[captcha]": captcha_value,
                }, timeout=30, headers={
                    "Referer": url, "Origin": BASE_URL,
                    "Content-Type": "application/x-www-form-urlencoded",
                    "X-Requested-With": "XMLHttpRequest",
                    "X-PJAX": "true", "X-PJAX-Container": "#p0",
                })
                _snap(f"renew_post_{renew_try}", post_resp.text, post_resp)
                time.sleep(random.uniform(1, 2))
                resp3 = self.session.get(url, timeout=30)
                html3 = resp3.text
                _snap(f"renew_verify_{renew_try}", html3, resp3)
                # 检查验证码是否错误
                if has_captcha and ("verification code is incorrect" in html3.lower() or "Captcha cannot be blank" in html3):
                    step(f"renew_{server_id}_try{renew_try}", False, f"验证码错误")
                    log(f"  [RENEW] ❌ 续期验证码错误 (第{renew_try + 1}次)")
                    csrf = self._ex(r'name="_csrf-frontend"\s+value="([^"]+)"', html3)
                    if not csrf:
                        csrf = self._ex(r'<meta\s+name="csrf-token"\s+content="([^"]+)"', html3)
                    cap_url = self._ex(r'id="extendfreeplanform-captcha-image"\s+src="([^"]+)"', html3)
                    if cap_url and cap_url.startswith("/"):
                        cap_url = BASE_URL + cap_url
                    if cap_url and csrf:
                        captcha_value = self._solve_captcha(cap_url, min_len=6, max_len=7, max_try=15)
                        if captcha_value:
                            continue
                    break
                else:
                    break

            # ── 验证结果 ──
            new_del = 0
            m = re.search(r'countdown-free-plan-delete[^>]*data-timestamp="(\d+)"', html3)
            if m:
                new_del = int(m.group(1))
            new_auto = 0
            m = re.search(r'id="countdown"\s+data-timestamp="(\d+)"', html3)
            if m:
                new_auto = int(m.group(1))
            if new_del:
                result["new_expiry"] = ts_to_cn(new_del)
            if new_auto:
                nr = ts_remaining(new_auto)
                result["remaining"] = fmt_seconds(nr)
                result["remain_seconds"] = nr
            if del_ts > 0 and new_del > del_ts:
                result["success"] = True
                result["message"] = "续期成功"
                step(f"renew_{server_id}", True, f"{result['old_expiry']} -> {result['new_expiry']}")
                log(f"  [RENEW] ✅ 成功! {result['old_expiry']} -> {result['new_expiry']}")
            elif new_del > 0 and del_ts == 0:
                result["success"] = True
                result["message"] = "续期成功"
                step(f"renew_{server_id}", True, "新到期时间")
            elif del_ts > 0 and new_del == del_ts:
                now_ms = int(datetime.now(timezone.utc).timestamp() * 1000)
                if new_del > now_ms:
                    result["success"] = True
                    result["message"] = "续期成功（有效期内）"
                    step(f"renew_{server_id}", True, "有效期内")
                else:
                    result["message"] = "到期时间未变化"
                    step(f"renew_{server_id}", False, "到期时间未变化")
            else:
                result["message"] = "续期结果未知"
                step(f"renew_{server_id}", False, f"del_ts={del_ts} new_del={new_del}")
        except Exception as e:
            result["message"] = f"异常: {e}"
            step(f"renew_{server_id}", False, str(e)[:80])
            log(f"  [RENEW] ❌ {e}")
        return result


# ============================================================
# 主流程（单次执行，非循环）
# ============================================================
def main():
    print("=" * 60)
    print("  🎮 Leme Host Auto Renewal — GitHub Action")
    print("=" * 60)
    log(f"DEBUG_DIR={DEBUG_DIR}")
    os.makedirs(DEBUG_DIR, exist_ok=True)

    if not LEME:
        error("❌ LEME 环境变量未设置")
        step("startup", False, "LEME 为空")
        print("格式：邮箱-----密码 （每行一个账号）")
        sys.exit(1)

    accounts = parse_accounts(LEME)
    STATS["accounts"] = len(accounts)
    log(f"📋 账号: {len(accounts)} | 阈值: {RENEW_THRESHOLD}s")

    if not accounts:
        error("❌ 未配置 LEME 环境变量")
        step("startup", False, "解析后账号数为 0")
        print("格式：邮箱-----密码 （每行一个账号）")
        sys.exit(1)

    # 为每个账号创建续期器并登录
    renewers = []
    server_map = {}

    for acc in accounts:
        r = LemeHostRenewer(acc["email"], acc["password"])
        if r.login():
            servers = r.get_servers()
            server_map[acc["email"]] = servers
            STATS["servers"] += len(servers)
            renewers.append(r)
        else:
            error(f"登录失败: {mask(acc['email'])}")
            send_telegram(f"❌ 登录失败\n\n账号：{acc['email']}\n\n{SIGNATURE}")

    if not renewers:
        error("❌ 所有账号登录均失败")
        sys.exit(1)

    notice(
        f"启动完成 | 账号: {len(renewers)} | "
        f"服务器: {STATS['servers']} | 阈值: {RENEW_THRESHOLD}s"
    )

    send_telegram(
        f"🎮 Leme Host Renewal 已启动\n\n"
        f"账号: {len(renewers)} | 服务器: {STATS['servers']}\n"
        f"阈值: {RENEW_THRESHOLD}s\n\n{SIGNATURE}"
    )

    # 检查所有账号的所有服务器（单次）
    for renewer in renewers:
        email = renewer.email
        if not renewer.ensure_login():
            STATS["failures"] += 1
            continue

        for sid, sname in server_map.get(email, []):
            r = renewer.check_and_renew(sid, sname)

            if r.get("skipped"):
                STATS["skipped"] += 1
                log(f"  [SKIP] {sid} — {r['message']}")
                continue

            if r["success"]:
                STATS["renewals"] += 1
            else:
                STATS["failures"] += 1

            # 发送 Telegram 通知
            emoji = "✅ 续期成功" if r["success"] else "❌ 续期失败"
            exp = ""
            if r["old_expiry"] and r["new_expiry"]:
                exp = f"到期: {r['old_expiry']} -> {r['new_expiry']}"
            elif r["new_expiry"]:
                exp = f"到期: {r['new_expiry']}"

            lines = [
                emoji, "",
                f"账号：{email}",
                f"服务器: {sid}",
            ]
            if r.get("started"):
                lines.append("🟢 已自动开机")
            if exp:
                lines.append(exp)
            if not r["success"] and r["message"]:
                lines.append(f"原因: {r['message']}")
            lines += ["", SIGNATURE]
            send_telegram("\n".join(lines))
            time.sleep(random.uniform(1, 2))

    # 输出最终统计
    print()
    print("=" * 60)
    print("  📊 本轮统计")
    print("=" * 60)
    print(f"  账号:     {STATS['accounts']}")
    print(f"  服务器:   {STATS['servers']}")
    print(f"  续期:     {STATS['renewals']} ✅")
    print(f"  跳过:     {STATS['skipped']} ⏭️")
    print(f"  失败:     {STATS['failures']} ❌")
    print(f"  开机:     {STATS['starts']} 🟢")
    print("=" * 60)

    # 输出步骤追踪汇总
    print()
    print("  📋 步骤追踪")
    fail_cnt = sum(1 for s in STEPS if not s["ok"])
    print(f"  总计 {len(STEPS)} 步, 失败 {fail_cnt} 步")
    for s in STEPS:
        emoji = "✅" if s["ok"] else "❌"
        print(f"  {emoji} {s['name']}: {s['detail']}")
    print("=" * 60)

    # 列出调试文件
    try:
        files = [f for f in os.listdir(DEBUG_DIR) if not f.endswith(".meta.json")]
        if files:
            print(f"  📎 调试文件 ({len(files)} 个):")
            for f in sorted(files):
                sz = os.path.getsize(os.path.join(DEBUG_DIR, f))
                print(f"    {f} ({sz}b)")
        print("=" * 60)
    except Exception:
        pass

    # 总结通知
    summary = (
        f"📊 Leme Host 本轮完成\n\n"
        f"✅ 续期: {STATS['renewals']}\n"
        f"⏭️ 跳过: {STATS['skipped']}\n"
        f"❌ 失败: {STATS['failures']}\n"
        f"🟢 开机: {STATS['starts']}\n\n"
        f"{SIGNATURE}"
    )
    send_telegram(summary)

    # 保存步骤追踪到调试目录
    try:
        with open(os.path.join(DEBUG_DIR, "steps_summary.json"), "w") as f:
            json.dump({"steps": STEPS, "stats": STATS, "fail_count": sum(1 for s in STEPS if not s["ok"])}, f, indent=2, ensure_ascii=False)
    except Exception:
        pass

    # 如果有失败，以非零退出码让 GitHub Action 标记为失败
    if STATS["failures"] > 0:
        error(f"本轮有 {STATS['failures']} 个失败")
        sys.exit(1)

    notice("本轮全部完成 ✅")
    sys.exit(0)


if __name__ == "__main__":
    main()