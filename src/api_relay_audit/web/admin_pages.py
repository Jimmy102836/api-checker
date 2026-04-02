"""Admin authentication and content management for API Checker."""

from __future__ import annotations

import hashlib
import os
import secrets
from pathlib import Path

import yaml
from fastapi import APIRouter, Form, Request, Response
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

router = APIRouter(prefix="/admin", include_in_schema=False)

# ─────────────────────────────────────────
# Content Config
# ─────────────────────────────────────────

_CONTENT_FILE = Path(__file__).parent.parent.parent.parent / "content.yaml"

_default_content = {
    "site": {
        "title": "API Checker",
        "subtitle": "中转 API 安全审计平台",
        "description": "检测中转 API 服务是否存在提示词注入、上下文截断、指令覆盖、数据窃取等作恶行为",
    },
    "landing": {
        "title": "🛡️ API Checker",
        "subtitle": "检测中转 API 是否在暗中作恶",
    },
    "messages": {
        "safe": "✅ 安全",
        "medium": "⚠️ 中等",
        "high": "🔴 高风险",
        "critical": "☠️ 极危险",
    },
    "footer": "API Checker · 开源安全审计工具",
}


def _load_content() -> dict:
    if not _CONTENT_FILE.exists():
        _save_content(_default_content)
    with open(_CONTENT_FILE) as f:
        return yaml.safe_load(f) or _default_content


def _save_content(data: dict) -> None:
    with open(_CONTENT_FILE, "w") as f:
        yaml.dump(data, f, allow_unicode=True, default_flow_style=False)


# ─────────────────────────────────────────
# Auth
# ─────────────────────────────────────────

ADMIN_PASSWORD_HASH = os.environ.get(
    "ADMIN_PASSWORD",
    # Default password for first setup - MUST change via env or admin panel
    "pbkdf2:sha256:600000$salt$"
    + hashlib.pbkdf2_hmac("sha256", b"admin", b"salt", 600000).hex(),
)

_session_tokens: dict[str, str] = {}  # token -> "admin"


def _hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    h = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 600000).hex()
    return f"pbkdf2:sha256:600000${salt}${h}"


def _verify_password(password: str, stored: str) -> bool:
    if stored.startswith("pbkdf2:sha256:"):
        parts = stored.split("$")
        # Format: pbkdf2:sha256:600000$salt$hash
        if len(parts) == 3:
            _, salt, stored_hash = parts
            computed = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 600000).hex()
            return computed == stored_hash
    return False


def _create_session() -> str:
    token = secrets.token_urlsafe(32)
    _session_tokens[token] = "admin"
    return token


def _delete_session(token: str) -> None:
    _session_tokens.pop(token, None)


def get_session(request: Request) -> str | None:
    token = request.cookies.get("admin_session")
    if token and _session_tokens.get(token) == "admin":
        return token
    return None


# ─────────────────────────────────────────
# Login Page
# ─────────────────────────────────────────

@router.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    if get_session(request):
        return RedirectResponse("/admin/dashboard", status_code=302)

    return f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>管理登录 - API Checker</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, sans-serif; background: #0f1117; color: #e0e0e0; min-height: 100vh; display: flex; align-items: center; justify-content: center; }}
  .login-box {{ background: #1a1d27; border: 1px solid #2a2d3a; border-radius: 16px; padding: 40px; width: 360px; }}
  h1 {{ font-size: 1.4em; margin-bottom: 8px; color: #fff; }}
  p {{ color: #666; margin-bottom: 32px; font-size: 0.9em; }}
  label {{ display: block; font-size: 0.85em; color: #888; margin-bottom: 6px; }}
  input {{ width: 100%; padding: 12px; background: #12141c; border: 1px solid #2a2d3a; border-radius: 8px; color: #fff; font-size: 1em; box-sizing: border-box; }}
  .btn {{ width: 100%; padding: 14px; background: #6366f1; color: #fff; border: none; border-radius: 8px; font-size: 1em; font-weight: 600; cursor: pointer; margin-top: 20px; }}
  .btn:hover {{ background: #4f46e5; }}
  .error {{ color: #f87171; font-size: 0.85em; margin-top: 10px; text-align: center; }}
  .default-hint {{ background: #1e2a1e; border: 1px solid #2a4a2a; border-radius: 8px; padding: 12px; margin-bottom: 20px; font-size: 0.8em; color: #6a6; }}
</style>
</head>
<body>
<div class="login-box">
  <h1>🔐 管理登录</h1>
  <p>API Checker 管理后台</p>
  <div class="default-hint">首次设置请使用环境变量 <code>ADMIN_PASSWORD</code> 设置密码</div>
  <form method="post" action="/admin/login">
    <label>管理密码</label>
    <input type="password" name="password" placeholder="请输入密码" required>
    <button class="btn" type="submit">登录</button>
    <div class="error" id="err"></div>
  </form>
</div>
</body>
</html>"""


@router.post("/login")
def login_submit(request: Request, response: Response, password: str = Form(...)):
    stored = os.environ.get("ADMIN_PASSWORD", ADMIN_PASSWORD_HASH)
    if _verify_password(password, stored):
        token = _create_session()
        response = RedirectResponse("/admin/dashboard", status_code=302)
        response.set_cookie(
            key="admin_session", value=token,
            httponly=True, samesite="lax",
            max_age=60 * 60 * 24 * 7  # 7 days
        )
        return response
    return HTMLResponse(
        """<script>alert("密码错误"); location.href="/admin/login";</script>""",
        status_code=400
    )


@router.get("/logout")
def logout(request: Request):
    token = request.cookies.get("admin_session")
    if token:
        _delete_session(token)
    response = RedirectResponse("/admin/login", status_code=302)
    response.delete_cookie("admin_session")
    return response


# ─────────────────────────────────────────
# Dashboard
# ─────────────────────────────────────────

@router.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request):
    if not get_session(request):
        return RedirectResponse("/admin/login", status_code=302)

    content = _load_content()
    c = content.get("site", {})
    reports_dir = Path(__file__).parent.parent.parent.parent / "reports"
    reports_dir.mkdir(exist_ok=True)
    report_files = sorted(reports_dir.glob("*.json"), reverse=True)[:20]

    reports_html = ""
    for rf in report_files:
        try:
            import json
            data = json.loads(rf.read_text())
            score = data.get("risk", {}).get("score", "?")
            risk = data.get("risk", {}).get("overall", "?")
            url = data.get("audit", {}).get("target_url", "?")
            ts = data.get("audit", {}).get("timestamp", "?")[:19]
            risk_colors = {"low": "#22c55e", "medium": "#f59e0b", "high": "#ef4444", "critical": "#e11d48"}
            color = risk_colors.get(risk, "#888")
            reports_html += f"""
            <tr onclick="window.open('/admin/report/{rf.name}', '_blank')" style="cursor:pointer">
              <td style="padding:10px; border-bottom:1px solid #2a2d3a; font-family:monospace; font-size:0.85em">{ts}</td>
              <td style="padding:10px; border-bottom:1px solid #2a2d3a; font-size:0.9em">{url}</td>
              <td style="padding:10px; border-bottom:1px solid #2a2d3a; color:{color}; font-weight:700">{risk.upper()}</td>
              <td style="padding:10px; border-bottom:1px solid #2a2d3a">{score}</td>
            </tr>"""
        except Exception:
            pass

    if not reports_html:
        reports_html = "<tr><td colspan=4 style='padding:20px; color:#555; text-align:center'>暂无审计报告</td></tr>"

    return f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>管理后台 - {c.get('title', 'API Checker')}</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, sans-serif; background: #0f1117; color: #e0e0e0; }}
  nav {{ background: #1a1d27; border-bottom: 1px solid #2a2d3a; padding: 0 24px; display: flex; align-items: center; justify-content: space-between; }}
  nav .brand {{ color: #fff; font-size: 1.1em; font-weight: 700; text-decoration: none; }}
  nav .brand span {{ color: #6366f1; }}
  nav a {{ color: #888; text-decoration: none; font-size: 0.9em; padding: 16px 0 16px 24px; }}
  nav a:hover {{ color: #fff; }}
  .container {{ max-width: 1100px; margin: 0 auto; padding: 32px 24px; }}
  h1 {{ color: #fff; font-size: 1.5em; margin-bottom: 24px; }}
  h2 {{ color: #ccc; font-size: 1.1em; margin: 28px 0 16px; }}
  .grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }}
  .card {{ background: #1a1d27; border: 1px solid #2a2d3a; border-radius: 12px; padding: 24px; }}
  .card h3 {{ color: #fff; font-size: 0.95em; margin-bottom: 16px; }}
  label {{ display: block; font-size: 0.82em; color: #666; margin-bottom: 6px; }}
  input, textarea, select {{ width: 100%; padding: 10px 12px; background: #12141c; border: 1px solid #2a2d3a; border-radius: 6px; color: #fff; font-size: 0.95em; margin-bottom: 14px; }}
  textarea {{ resize: vertical; min-height: 80px; }}
  .btn {{ padding: 10px 20px; background: #6366f1; color: #fff; border: none; border-radius: 8px; font-size: 0.9em; cursor: pointer; }}
  .btn:hover {{ background: #4f46e5; }}
  .btn.green {{ background: #16a34a; }}
  .btn.green:hover {{ background: #15803d; }}
  .btn.red {{ background: #dc2626; }}
  .btn.red:hover {{ background: #b91c1c; }}
  .msg {{ padding: 10px 14px; background: #1e2a1e; border: 1px solid #2a4a2a; border-radius: 8px; color: #6a6; margin-bottom: 16px; font-size: 0.9em; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 0.9em; }}
  th {{ text-align: left; padding: 10px; border-bottom: 1px solid #333; color: #666; font-weight: 600; }}
  tr:hover {{ background: #1e2030; }}
  .tab-nav {{ display: flex; gap: 4px; margin-bottom: 24px; }}
  .tab-btn {{ padding: 10px 20px; background: #1a1d27; border: 1px solid #2a2d3a; border-radius: 8px 8px 0 0; color: #888; cursor: pointer; font-size: 0.9em; text-decoration: none; }}
  .tab-btn.active {{ background: #1a1d27; border-bottom: 2px solid #6366f1; color: #fff; }}
  .tab-content {{ background: #1a1d27; border: 1px solid #2a2d3a; border-top: none; border-radius: 0 12px 12px 12px; padding: 24px; }}
  .danger-zone {{ border-color: #7f1d1d; background: #1a0a0a; }}
  @media (max-width: 700px) {{ .grid {{ grid-template-columns: 1fr; }} }}
</style>
</head>
<body>
<nav>
  <a class="brand" href="/">API <span>Checker</span></a>
  <div>
    <a href="/admin/dashboard">📊 管理后台</a>
    <a href="/admin/logout">🚪 退出</a>
  </div>
</nav>

<div class="container">
  <h1>📊 管理后台</h1>

  <div class="tab-nav">
    <a href="#content" class="tab-btn active" onclick="showTab('content'); return false;">📝 内容管理</a>
    <a href="#reports" class="tab-btn" onclick="showTab('reports'); return false;">📋 审计报告</a>
    <a href="#settings" class="tab-btn" onclick="showTab('settings'); return false;">⚙️ 系统设置</a>
  </div>

  <div id="tab-content" class="tab-content">
    <!-- Content Tab -->
    <div id="tab-content-tab">
      <form method="post" action="/admin/api/content" onsubmit="return confirm('保存内容配置？')">
        <h2>📝 站点信息</h2>
        <div class="grid">
          <div>
            <label>网站标题</label>
            <input name="site_title" value="{c.get('title', '')}">
          </div>
          <div>
            <label>副标题</label>
            <input name="site_subtitle" value="{c.get('subtitle', '')}">
          </div>
        </div>
        <label>网站描述</label>
        <textarea name="site_description">{c.get('description', '')}</textarea>

        <h2>💬 提示信息</h2>
        <div class="grid">
          <div>
            <label>安全状态文字</label>
            <input name="msg_safe" value="{content.get('messages', {}).get('safe', '')}">
          </div>
          <div>
            <label>中等风险文字</label>
            <input name="msg_medium" value="{content.get('messages', {}).get('medium', '')}">
          </div>
          <div>
            <label>高风险文字</label>
            <input name="msg_high" value="{content.get('messages', {}).get('high', '')}">
          </div>
          <div>
            <label>极危险文字</label>
            <input name="msg_critical" value="{content.get('messages', {}).get('critical', '')}">
          </div>
        </div>

        <h2>📌 页脚</h2>
        <input name="footer" value="{content.get('footer', '')}">

        <div style="margin-top: 20px">
          <button class="btn green" type="submit">💾 保存内容配置</button>
        </div>
      </form>

      <!-- Reports Tab -->
      <div id="tab-reports-tab" style="display:none">
        <h2>📋 最近审计报告</h2>
        <table>
          <tr>
            <th>时间</th>
            <th>目标地址</th>
            <th>风险</th>
            <th>分数</th>
          </tr>
          {reports_html}
        </table>
      </div>

      <!-- Settings Tab -->
      <div id="tab-settings-tab" style="display:none">
        <h2>🔑 修改管理员密码</h2>
        <form method="post" action="/admin/api/password" onsubmit="return confirm('修改密码？')">
          <label>新密码</label>
          <input type="password" name="new_password" placeholder="留空则不修改">
          <button class="btn" type="submit">更新密码</button>
        </form>

        <h2>🔧 系统信息</h2>
        <div class="card danger-zone">
          <h3 style="color:#f87171">⚠️ 危险操作</h3>
          <p style="color:#888; font-size:0.85em; margin: 8px 0 14px">以下操作不可逆，请谨慎操作</p>
          <form method="post" action="/admin/api/reset-reports" onsubmit="return confirm('确定删除所有报告？此操作不可恢复！')">
            <button class="btn red" type="submit">🗑️ 清空所有审计报告</button>
          </form>
        </div>
      </div>
    </div>
  </div>
</div>

<script>
function showTab(name) {{
  document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
  document.querySelectorAll('[id$="-tab"]').forEach(d => d.style.display = 'none');
  if (name === 'content') {{
    document.getElementById('tab-content-tab').style.display = 'block';
    document.querySelector('a[href="#content"]').classList.add('active');
  }} else if (name === 'reports') {{
    document.getElementById('tab-reports-tab').style.display = 'block';
    document.querySelector('a[href="#reports"]').classList.add('active');
  }} else if (name === 'settings') {{
    document.getElementById('tab-settings-tab').style.display = 'block';
    document.querySelector('a[href="#settings"]').classList.add('active');
  }}
}}

// Parse hash on load
if (location.hash === '#reports') showTab('reports');
else if (location.hash === '#settings') showTab('settings');
else showTab('content');
</script>
</body>
</html>"""


# ─────────────────────────────────────────
# Admin APIs
# ─────────────────────────────────────────

@router.post("/api/content")
def save_content(request: Request, response: Response):
    if not get_session(request):
        return RedirectResponse("/admin/login", status_code=302)

    import copy
    form = dict(request._form)
    content = _load_content()

    # Update site info
    if "site_title" in form:
        content.setdefault("site", {})
        content["site"]["title"] = form["site_title"][0]
        content["site"]["subtitle"] = form.get("site_subtitle", [""])[0]
        content["site"]["description"] = form.get("site_description", [""])[0]

    # Update messages
    if "msg_safe" in form:
        content.setdefault("messages", {})
        content["messages"]["safe"] = form["msg_safe"][0]
        content["messages"]["medium"] = form.get("msg_medium", [""])[0]
        content["messages"]["high"] = form.get("msg_high", [""])[0]
        content["messages"]["critical"] = form.get("msg_critical", [""])[0]

    if "footer" in form:
        content["footer"] = form["footer"][0]

    _save_content(content)
    return RedirectResponse("/admin/dashboard?msg=saved", status_code=302)


@router.post("/api/password")
def change_password(request: Request, response: Response, new_password: str = Form(...)):
    if not get_session(request):
        return RedirectResponse("/admin/login", status_code=302)
    if new_password:
        os.environ["ADMIN_PASSWORD"] = _hash_password(new_password)
    return RedirectResponse("/admin/dashboard?msg=password_updated", status_code=302)


@router.post("/api/reset-reports")
def reset_reports(request: Request):
    if not get_session(request):
        return RedirectResponse("/admin/login", status_code=302)
    reports_dir = Path(__file__).parent.parent.parent.parent / "reports"
    for f in reports_dir.glob("*.json"):
        f.unlink()
    return RedirectResponse("/admin/dashboard?msg=reports_cleared", status_code=302)
