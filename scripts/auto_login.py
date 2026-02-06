"""
ClawCloud 自动登录脚本 (完整修改版)
- 策略: 优先使用 GH_SESSION (Cookie) 登录
- 降级: 若 Cookie 失效，自动切换为账号密码登录
- 功能: 自动检测区域、Telegram 通知、Cookie 自动保活更新
- 验证: 支持设备验证(Device Verification) 与 两步验证(2FA)
"""

import base64
import os
import random
import re
import sys
import time
from urllib.parse import urlparse

import requests
from playwright.sync_api import sync_playwright

# ==================== 配置 ====================
# 代理配置 (留空则不使用)
PROXY_DSN = os.environ.get("PROXY_DSN", "").strip()

# 登录相关 URL
LOGIN_ENTRY_URL = "https://console.run.claw.cloud/login"
SIGNIN_URL = f"{LOGIN_ENTRY_URL}/signin"

# 等待时间配置
DEVICE_VERIFY_WAIT = 30  # Mobile设备验证等待时间
TWO_FACTOR_WAIT = int(os.environ.get("TWO_FACTOR_WAIT", "120"))  # 2FA验证等待时间


class Telegram:
    """Telegram 通知模块"""
    
    def __init__(self):
        self.token = os.environ.get('TG_BOT_TOKEN')
        self.chat_id = os.environ.get('TG_CHAT_ID')
        self.ok = bool(self.token and self.chat_id)
    
    def send(self, msg):
        if not self.ok:
            return
        try:
            requests.post(
                f"https://api.telegram.org/bot{self.token}/sendMessage",
                data={"chat_id": self.chat_id, "text": msg, "parse_mode": "HTML"},
                timeout=30
            )
        except:
            pass
    
    def photo(self, path, caption=""):
        if not self.ok or not os.path.exists(path):
            return
        try:
            with open(path, 'rb') as f:
                requests.post(
                    f"https://api.telegram.org/bot{self.token}/sendPhoto",
                    data={"chat_id": self.chat_id, "caption": caption[:1024]},
                    files={"photo": f},
                    timeout=60
                )
        except:
            pass
    
    def flush_updates(self):
        """刷新 offset，丢弃旧消息"""
        if not self.ok:
            return 0
        try:
            r = requests.get(
                f"https://api.telegram.org/bot{self.token}/getUpdates",
                params={"timeout": 0},
                timeout=10
            )
            data = r.json()
            if data.get("ok") and data.get("result"):
                return data["result"][-1]["update_id"] + 1
        except:
            pass
        return 0
    
    def wait_code(self, timeout=120):
        """等待 Telegram 发送 /code 123456"""
        if not self.ok:
            return None
        
        offset = self.flush_updates()
        deadline = time.time() + timeout
        pattern = re.compile(r"^/code\s+(\d{6,8})$")
        
        while time.time() < deadline:
            try:
                r = requests.get(
                    f"https://api.telegram.org/bot{self.token}/getUpdates",
                    params={"timeout": 20, "offset": offset},
                    timeout=30
                )
                data = r.json()
                if not data.get("ok"):
                    time.sleep(2)
                    continue
                
                for upd in data.get("result", []):
                    offset = upd["update_id"] + 1
                    msg = upd.get("message") or {}
                    chat = msg.get("chat") or {}
                    if str(chat.get("id")) != str(self.chat_id):
                        continue
                    
                    text = (msg.get("text") or "").strip()
                    m = pattern.match(text)
                    if m:
                        return m.group(1)
            except Exception:
                pass
            time.sleep(2)
        return None


class SecretUpdater:
    """GitHub Secret 自动更新模块"""
    
    def __init__(self):
        self.token = os.environ.get('REPO_TOKEN')
        self.repo = os.environ.get('GITHUB_REPOSITORY')
        self.ok = bool(self.token and self.repo)
        if self.ok:
            print("✅ Secret 自动更新已启用")
        else:
            print("⚠️ Secret 自动更新未启用（需要 REPO_TOKEN）")
    
    def update(self, name, value):
        if not self.ok:
            return False
        try:
            from nacl import encoding, public
            headers = {
                "Authorization": f"token {self.token}",
                "Accept": "application/vnd.github.v3+json"
            }
            # 获取公钥
            r = requests.get(
                f"https://api.github.com/repos/{self.repo}/actions/secrets/public-key",
                headers=headers, timeout=30
            )
            if r.status_code != 200:
                return False
            
            key_data = r.json()
            pk = public.PublicKey(key_data['key'].encode(), encoding.Base64Encoder())
            encrypted = public.SealedBox(pk).encrypt(value.encode())
            
            # 更新 Secret
            r = requests.put(
                f"https://api.github.com/repos/{self.repo}/actions/secrets/{name}",
                headers=headers,
                json={"encrypted_value": base64.b64encode(encrypted).decode(), "key_id": key_data['key_id']},
                timeout=30
            )
            return r.status_code in [201, 204]
        except Exception as e:
            print(f"更新 Secret 失败: {e}")
            return False


class AutoLogin:
    """主逻辑类"""
    
    def __init__(self):
        self.username = os.environ.get('GH_USERNAME')
        self.password = os.environ.get('GH_PASSWORD')
        self.gh_session = os.environ.get('GH_SESSION', '').strip()
        self.tg = Telegram()
        self.secret = SecretUpdater()
        self.shots = []
        self.logs = []
        self.n = 0
        
        # 区域相关
        self.detected_region = 'eu-central-1'
        self.region_base_url = 'https://eu-central-1.run.claw.cloud'
        
    def log(self, msg, level="INFO"):
        icons = {"INFO": "ℹ️", "SUCCESS": "✅", "ERROR": "❌", "WARN": "⚠️", "STEP": "🔹"}
        line = f"{icons.get(level, '•')} {msg}"
        print(line)
        self.logs.append(line)
    
    def shot(self, page, name):
        self.n += 1
        f = f"{self.n:02d}_{name}.png"
        try:
            page.screenshot(path=f)
            self.shots.append(f)
        except:
            pass
        return f
    
    def click(self, page, sels, desc=""):
        for s in sels:
            try:
                el = page.locator(s).first
                if el.is_visible(timeout=3000):
                    time.sleep(random.uniform(0.5, 1.5))
                    el.hover()
                    time.sleep(random.uniform(0.2, 0.5))
                    el.click()
                    self.log(f"已点击: {desc}", "SUCCESS")
                    return True
            except:
                pass
        return False
    
    def detect_region(self, url):
        """检测当前区域"""
        try:
            parsed = urlparse(url)
            host = parsed.netloc
            
            if host.endswith('.console.claw.cloud'):
                region = host.replace('.console.claw.cloud', '')
                if region and region != 'console':
                    self.detected_region = region
                    self.region_base_url = f"https://{host}"
                    self.log(f"检测到区域: {region}", "SUCCESS")
                    return region
            
            if 'console.run.claw.cloud' in host or 'claw.cloud' in host:
                path = parsed.path
                region_match = re.search(r'/(?:region|r)/([a-z]+-[a-z]+-\d+)', path)
                if region_match:
                    region = region_match.group(1)
                    self.detected_region = region
                    self.region_base_url = f"https://{region}.console.claw.cloud"
                    self.log(f"从路径检测到区域: {region}", "SUCCESS")
                    return region
            
            self.region_base_url = f"{parsed.scheme}://{parsed.netloc}"
            return None
        except Exception as e:
            self.log(f"区域检测异常: {e}", "WARN")
            return None
    
    def get_base_url(self):
        if self.region_base_url:
            return self.region_base_url
        return LOGIN_ENTRY_URL
    
    def get_session(self, context):
        try:
            for c in context.cookies():
                if c['name'] == 'user_session' and 'github' in c.get('domain', ''):
                    return c['value']
        except:
            pass
        return None
    
    def save_cookie(self, value):
        if not value:
            return
        self.log(f"新 Cookie: {value[:15]}...{value[-8:]}", "SUCCESS")
        
        if self.secret.update('GH_SESSION', value):
            self.log("已自动更新 GH_SESSION", "SUCCESS")
            self.tg.send("🔑 <b>Cookie 已自动更新</b>\n\nGH_SESSION 已保存")
        else:
            self.tg.send(f"""🔑 <b>新 Cookie</b>\n\n请更新 Secret <b>GH_SESSION</b>:\n<tg-spoiler>{value}</tg-spoiler>""")
            self.log("已通过 Telegram 发送 Cookie", "SUCCESS")

    def wait_device(self, page):
        """处理设备验证 (Device Verification)"""
        self.log(f"触发设备验证，等待 {DEVICE_VERIFY_WAIT} 秒...", "WARN")
        self.shot(page, "设备验证")
        self.tg.send(f"""⚠️ <b>需要设备验证</b>\n\n用户 {self.username} 正在登录，请在 {DEVICE_VERIFY_WAIT} 秒内：\n1. 检查邮箱链接\n2. 或在 GitHub App 批准\n3. 或在 TG 发送 /code""")
        
        deadline = time.time() + DEVICE_VERIFY_WAIT
        offset = self.tg.flush_updates()
        
        while time.time() < deadline:
            if 'verified-device' not in page.url and 'device-verification' not in page.url:
                self.log("设备验证通过！", "SUCCESS")
                self.tg.send("✅ <b>设备验证通过</b>")
                return True
            
            # 检查 TG 验证码
            if int(time.time()) % 5 == 0:
                code = self.tg.wait_code(timeout=1)
                if code:
                    self.log(f"填入 TG 验证码: {code}", "INFO")
                    # 尝试寻找输入框
                    for sel in ['input[name="otp"]', 'input[name="code"]', 'input[type="text"]']:
                        try:
                            el = page.locator(sel).first
                            if el.is_visible():
                                el.fill(code)
                                page.locator('button[type="submit"]').click()
                                break
                        except: pass
            time.sleep(1)
            
        self.log("设备验证超时", "ERROR")
        return False

    def wait_two_factor_mobile(self, page):
        """处理 GitHub Mobile 2FA"""
        self.log(f"触发 GitHub Mobile 验证...", "WARN")
        shot = self.shot(page, "2FA_Mobile")
        self.tg.send(f"""⚠️ <b>需要 Mobile 验证</b>\n\n请打开 GitHub App 批准登录。\n等待 {TWO_FACTOR_WAIT} 秒""")
        if shot: self.tg.photo(shot)
        
        for i in range(TWO_FACTOR_WAIT):
            if "two-factor" not in page.url:
                self.log("Mobile 验证通过！", "SUCCESS")
                return True
            if i % 10 == 0: self.log(f"等待中... {i}s")
            time.sleep(1)
        return False

    def handle_2fa_code_input(self, page):
        """处理 2FA 验证码 (TOTP)"""
        self.log("需要 2FA 验证码", "WARN")
        self.shot(page, "2FA_Code")
        
        # 尝试切换到 App 验证码模式
        try:
            page.locator('button:has-text("Use an authentication app")').click(timeout=2000)
        except: pass

        self.tg.send(f"""🔐 <b>需要 2FA 验证码</b>\n\n请发送：\n<code>/code 6位验证码</code>""")
        
        code = self.tg.wait_code(timeout=TWO_FACTOR_WAIT)
        if not code:
            self.log("未收到验证码", "ERROR")
            return False
        
        try:
            page.locator('input[autocomplete="one-time-code"]').fill(code)
            # 有时候填完会自动提交，有时候需要点 Verify
            try:
                page.locator('button:has-text("Verify")').click(timeout=1000)
            except: pass
            
            time.sleep(3)
            if "two-factor" not in page.url:
                self.log("2FA 验证通过！", "SUCCESS")
                self.tg.send("✅ <b>2FA 验证通过</b>")
                return True
        except Exception as e:
            self.log(f"填入验证码失败: {e}", "ERROR")
        
        return False

    def login_github_password(self, page, context):
        """
        降级处理：使用账号密码登录
        """
        self.log("🔄 执行账号密码登录...", "STEP")
        self.shot(page, "login_page")
        
        try:
            # 填写账号
            page.locator('input[name="login"]').fill(self.username)
            # 填写密码
            page.locator('input[name="password"]').fill(self.password)
            # 提交
            page.locator('input[type="submit"], button[type="submit"]').first.click()
            self.log("已提交账号密码", "SUCCESS")
        except Exception as e:
            self.log(f"输入账号密码失败: {e}", "ERROR")
            return False
        
        time.sleep(3)
        page.wait_for_load_state('networkidle')
        
        # 后续验证流程交给主循环的通用检测（run 方法中的 2FA/Device check）
        return True

    def oauth(self, page):
        """处理 OAuth 授权页"""
        if 'github.com/login/oauth/authorize' in page.url:
            self.log("检测到 OAuth 授权页，点击授权...", "STEP")
            self.shot(page, "oauth")
            if self.click(page, ['button[name="authorize"]', 'button:has-text("Authorize")'], "Authorize"):
                time.sleep(3)
                page.wait_for_load_state('networkidle')

    def keepalive(self, page):
        """保活访问"""
        base_url = self.get_base_url()
        self.log(f"执行保活，访问: {base_url}", "INFO")
        try:
            page.goto(base_url, timeout=30000)
            if self.detected_region:
                # 尝试访问一个子页面确保 Session 活跃
                page.goto(f"{base_url}/apps", timeout=20000)
        except:
            pass

    def notify(self, ok, err=""):
        if not self.tg.ok: return
        status = "✅ 登录成功" if ok else "❌ 登录失败"
        msg = f"<b>🤖 ClawCloud 自动登录</b>\n\n{status}\n<b>用户:</b> {self.username}"
        if self.detected_region: msg += f"\n<b>区域:</b> {self.detected_region}"
        if err: msg += f"\n<b>错误:</b> {err}"
        msg += "\n\n<b>日志:</b>\n" + "\n".join(self.logs[-5:])
        self.tg.send(msg)
        if self.shots and not ok:
            self.tg.photo(self.shots[-1], "最后截图")

    def run(self):
        print("\n" + "="*50)
        print("🚀 ClawCloud 自动登录 (混合模式)")
        print("="*50 + "\n")
        
        if not self.username or not self.password:
            self.log("未配置账号密码，无法运行", "ERROR")
            sys.exit(1)

        with sync_playwright() as p:
            # 浏览器配置
            launch_args = {
                "headless": True,
                "args": ['--no-sandbox', '--disable-blink-features=AutomationControlled']
            }
            if PROXY_DSN:
                try:
                    p_url = urlparse(PROXY_DSN)
                    launch_args["proxy"] = {"server": f"{p_url.scheme}://{p_url.hostname}:{p_url.port}"}
                    if p_url.username:
                        launch_args["proxy"].update({"username": p_url.username, "password": p_url.password})
                except: pass

            browser = p.chromium.launch(**launch_args)
            context = browser.new_context(viewport={'width': 1920, 'height': 1080})
            
            # 注入 Session Cookie (尝试免密登录的关键)
            if self.gh_session:
                try:
                    context.add_cookies([
                        {'name': 'user_session', 'value': self.gh_session, 'domain': 'github.com', 'path': '/'},
                        {'name': 'logged_in', 'value': 'yes', 'domain': 'github.com', 'path': '/'}
                    ])
                    self.log("已注入 Session Cookie", "SUCCESS")
                except: pass

            page = context.new_page()
            
            try:
                # 1. 访问登录入口
                self.log("访问登录页...", "STEP")
                page.goto(SIGNIN_URL, timeout=60000)
                
                # 2. 点击 GitHub 按钮
                self.log("点击 GitHub...", "STEP")
                if not self.click(page, ['button:has-text("GitHub")', 'a:has-text("GitHub")', '[data-provider="github"]'], "GitHub"):
                    raise Exception("找不到 GitHub 按钮")
                
                # 等待跳转反应
                page.wait_for_load_state('networkidle')
                time.sleep(3)
                url = page.url
                self.log(f"跳转后 URL: {url}")
                
                # ================= 核心判定逻辑 =================
                
                # 情况A: 直接成功 (Cookie有效)
                if 'claw.cloud' in url and 'signin' not in url.lower() and 'github' not in url:
                    self.log("Session 有效，直接登录成功！", "SUCCESS")
                
                # 情况B: 需要授权 (Cookie有效，但需OAuth确认)
                elif 'oauth/authorize' in url:
                    self.log("Session 有效，需要 OAuth 授权", "SUCCESS")
                    self.oauth(page)
                
                # 情况C: 需要登录 (Cookie无效，降级到密码登录)
                else:
                    self.log("⚠️ Session 失效或未登录，切换到账号密码模式", "WARN")
                    if 'github.com/login' not in url and 'session' not in url:
                        # 如果当前既不是登录页也不是成功页，可能还在加载，强制跳转 github login 兜底
                        pass 
                    
                    if not self.login_github_password(page, context):
                        raise Exception("账号密码登录提交失败")
                
                # ================= 通用验证处理 (无论何种方式登录) =================
                
                # 循环检查直到进入控制台，处理中间可能出现的 2FA / Device Check
                self.log("等待登录完成...", "STEP")
                for i in range(20): # 循环检查几轮
                    url = page.url
                    
                    # 1. 成功结束
                    if 'claw.cloud' in url and 'signin' not in url.lower():
                        break
                    
                    # 2. OAuth 授权 (密码登录后也可能出现)
                    if 'oauth/authorize' in url:
                        self.oauth(page)
                    
                    # 3. 设备验证
                    if 'verified-device' in url or 'device-verification' in url:
                        if not self.wait_device(page): raise Exception("设备验证失败")
                    
                    # 4. 两步验证 (Mobile / App / SMS)
                    if 'two-factor' in url:
                        if 'two-factor/mobile' in url:
                            if not self.wait_two_factor_mobile(page): raise Exception("Mobile 2FA 失败")
                        else:
                            if not self.handle_2fa_code_input(page): raise Exception("Code 2FA 失败")
                            
                    time.sleep(2)
                
                # 最终检查
                if 'claw.cloud' not in page.url or 'signin' in page.url.lower():
                     raise Exception("最终未能进入控制台")
                
                self.log("登录流程完成！", "SUCCESS")
                self.detect_region(page.url)
                
                # 保活与更新 Cookie
                self.keepalive(page)
                
                new_cookie = self.get_session(context)
                if new_cookie and new_cookie != self.gh_session:
                    self.save_cookie(new_cookie)
                
                self.notify(True)

            except Exception as e:
                self.log(f"流程异常: {e}", "ERROR")
                self.shot(page, "error")
                self.notify(False, str(e))
                sys.exit(1)
            finally:
                browser.close()

if __name__ == "__main__":
    AutoLogin().run()
