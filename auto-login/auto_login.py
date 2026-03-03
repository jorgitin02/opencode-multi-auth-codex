#!/usr/bin/env python3
"""
Auto-login for opencode-multi-auth-codex plugin.
Automates ChatGPT OAuth via Playwright, including email verification via Outlook Web.

Usage:
    python3 auto_login.py                 # Login all enabled accounts
    python3 auto_login.py --account 0     # Login specific account by index
    python3 auto_login.py --email user@x  # Login specific account by email
    python3 auto_login.py --check         # Check which accounts need login
    python3 auto_login.py --visible       # Run browser in visible mode
"""

import argparse
import base64
import hashlib
import json
import os
import re
import secrets
import shutil
import ssl
import sys
import time
import threading
import urllib.parse
import urllib.request
from http.server import HTTPServer, BaseHTTPRequestHandler
from datetime import datetime, timezone
from pathlib import Path

# ── Constants (matching opencode-multi-auth-codex plugin exactly) ───────────
OPENAI_ISSUER = "https://auth.openai.com"
AUTHORIZE_URL = f"{OPENAI_ISSUER}/oauth/authorize"
TOKEN_URL = f"{OPENAI_ISSUER}/oauth/token"
CLIENT_ID = "app_EMoamEEZ73f0CkXaXp7hrann"
SCOPES = ["openid", "profile", "email", "offline_access"]
REDIRECT_PORT = 1455

# Store paths (matching the plugin)
STORE_DIR = Path.home() / ".config" / "opencode-multi-auth"
STORE_FILE = STORE_DIR / "accounts.json"

# Credentials file
SCRIPT_DIR = Path(__file__).resolve().parent
CREDENTIALS_FILE = SCRIPT_DIR / "credentials.json"

# Timing
BETWEEN_ACCOUNTS_DELAY = 5  # seconds between accounts


# ── PKCE (RFC 7636) ────────────────────────────────────────────────────────
def generate_pkce():
    raw = secrets.token_bytes(32)
    code_verifier = base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")
    digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
    code_challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return code_verifier, code_challenge


def generate_state():
    return (
        base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode("ascii")
    )


def build_auth_url(code_challenge, state, redirect_uri):
    params = {
        "client_id": CLIENT_ID,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "scope": " ".join(SCOPES),
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
        "id_token_add_organizations": "true",
        "codex_cli_simplified_flow": "true",
        "state": state,
        "originator": "opencode",
    }
    return f"{AUTHORIZE_URL}?{urllib.parse.urlencode(params)}"


# ── JWT helpers ─────────────────────────────────────────────────────────────
def decode_jwt_payload(token):
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        payload = parts[1].replace("-", "+").replace("_", "/")
        padding = 4 - len(payload) % 4
        if padding != 4:
            payload += "=" * padding
        return json.loads(base64.b64decode(payload).decode("utf-8"))
    except Exception:
        return None


def get_email_from_claims(claims):
    if not claims:
        return None
    if isinstance(claims.get("email"), str):
        return claims["email"]
    profile = claims.get("https://api.openai.com/profile")
    if profile and isinstance(profile.get("email"), str):
        return profile["email"]
    return None


def get_account_id_from_claims(claims):
    if not claims:
        return None
    auth = claims.get("https://api.openai.com/auth")
    return auth.get("chatgpt_account_id") if auth else None


def get_expiry_from_claims(claims):
    if not claims:
        return None
    exp = claims.get("exp")
    return int(exp * 1000) if isinstance(exp, (int, float)) else None


# ── Token exchange ──────────────────────────────────────────────────────────
def get_ssl_context(no_ssl_verify=False):
    context = ssl.create_default_context()
    if no_ssl_verify:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    return context


def exchange_code_for_tokens(code, redirect_uri, code_verifier, ssl_context=None):
    if ssl_context is None:
        ssl_context = get_ssl_context()
    data = urllib.parse.urlencode(
        {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri,
            "client_id": CLIENT_ID,
            "code_verifier": code_verifier,
        }
    ).encode("utf-8")

    req = urllib.request.Request(
        TOKEN_URL,
        data=data,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=30, context=ssl_context) as resp:
        return json.loads(resp.read().decode("utf-8"))


def fetch_userinfo_email(access_token, ssl_context=None):
    if ssl_context is None:
        ssl_context = get_ssl_context()
    try:
        req = urllib.request.Request(
            f"{OPENAI_ISSUER}/userinfo",
            headers={"Authorization": f"Bearer {access_token}"},
        )
        with urllib.request.urlopen(req, timeout=10, context=ssl_context) as resp:
            return json.loads(resp.read().decode("utf-8")).get("email")
    except Exception:
        return None


# ── Account store (v2 format compatible with plugin) ───────────────────────
def default_store():
    return {
        "version": 2,
        "accounts": {},
        "activeAlias": None,
        "rotationIndex": 0,
        "lastRotation": int(time.time() * 1000),
    }


def build_alias(email, existing_aliases):
    base = email.split("@")[0] if isinstance(email, str) and email else "account"
    candidate = base or "account"
    suffix = 1
    while candidate in existing_aliases:
        candidate = f"{base}-{suffix}"
        suffix += 1
    return candidate


def normalize_store(raw):
    store = default_store()
    if not isinstance(raw, dict):
        return store

    accounts_raw = raw.get("accounts")
    accounts = {}
    ordered_aliases = []

    if isinstance(accounts_raw, dict):
        for key, value in accounts_raw.items():
            if not isinstance(value, dict):
                continue
            alias = (
                value.get("alias")
                if isinstance(value.get("alias"), str) and value.get("alias")
                else str(key)
            )
            if alias in accounts:
                alias = build_alias(value.get("email"), set(accounts.keys()))
            entry = dict(value)
            entry["alias"] = alias
            entry["usageCount"] = entry.get("usageCount", 0)
            entry["enabled"] = entry.get("enabled", True)
            accounts[alias] = entry
            ordered_aliases.append(alias)
    elif isinstance(accounts_raw, list):
        for value in accounts_raw:
            if not isinstance(value, dict):
                continue
            preferred_alias = (
                value.get("alias")
                if isinstance(value.get("alias"), str) and value.get("alias")
                else None
            )
            alias = (
                preferred_alias
                if preferred_alias and preferred_alias not in accounts
                else build_alias(value.get("email"), set(accounts.keys()))
            )
            entry = dict(value)
            entry["alias"] = alias
            entry["usageCount"] = entry.get("usageCount", 0)
            entry["enabled"] = entry.get("enabled", True)
            accounts[alias] = entry
            ordered_aliases.append(alias)

    store["accounts"] = accounts

    active_alias = raw.get("activeAlias")
    if not (isinstance(active_alias, str) and active_alias in accounts):
        active_index = raw.get("activeIndex")
        if (
            isinstance(active_index, int)
            and active_index >= 0
            and active_index < len(ordered_aliases)
        ):
            active_alias = ordered_aliases[active_index]
        else:
            active_alias = None

    if not active_alias and ordered_aliases:
        active_alias = ordered_aliases[0]

    store["activeAlias"] = active_alias

    if isinstance(raw.get("rotationIndex"), int):
        store["rotationIndex"] = raw["rotationIndex"]
    if isinstance(raw.get("lastRotation"), int):
        store["lastRotation"] = raw["lastRotation"]
    if isinstance(raw.get("version"), int):
        store["version"] = raw["version"]

    return store


def load_store():
    if not STORE_FILE.exists():
        return default_store()
    with open(STORE_FILE, "r") as f:
        return normalize_store(json.load(f))


def save_store(store):
    STORE_DIR.mkdir(parents=True, exist_ok=True)
    if STORE_FILE.exists():
        shutil.copy2(STORE_FILE, STORE_FILE.with_suffix(".json.bak"))
    tmp = STORE_FILE.with_suffix(f".tmp-{os.getpid()}-{int(time.time() * 1000)}")
    with open(tmp, "w") as f:
        json.dump(store, f, indent=2)
    tmp.rename(STORE_FILE)
    os.chmod(STORE_FILE, 0o600)


def add_account_to_store(tokens, ssl_context=None):
    now = int(time.time() * 1000)
    access_claims = decode_jwt_payload(tokens["access_token"])
    id_claims = (
        decode_jwt_payload(tokens["id_token"]) if tokens.get("id_token") else None
    )

    expires_at = (
        get_expiry_from_claims(access_claims)
        or get_expiry_from_claims(id_claims)
        or now + tokens.get("expires_in", 3600) * 1000
    )
    email = (
        get_email_from_claims(id_claims)
        or get_email_from_claims(access_claims)
        or fetch_userinfo_email(tokens["access_token"], ssl_context=ssl_context)
    )
    account_id = get_account_id_from_claims(id_claims) or get_account_id_from_claims(
        access_claims
    )

    new_account = {
        "accessToken": tokens["access_token"],
        "refreshToken": tokens["refresh_token"],
        "idToken": tokens.get("id_token"),
        "accountId": account_id,
        "expiresAt": expires_at,
        "email": email,
        "lastRefresh": datetime.now(timezone.utc).isoformat(),
        "lastSeenAt": now,
        "addedAt": now,
        "source": "opencode",
        "authInvalid": False,
        "usageCount": 0,
        "enabled": True,
    }

    store = load_store()
    existing_aliases = set(store["accounts"].keys())

    if email:
        for alias, acc in store["accounts"].items():
            if acc.get("email") == email:
                store["accounts"][alias] = {
                    **acc,
                    **new_account,
                    "alias": alias,
                    "usageCount": acc.get("usageCount", 0),
                    "addedAt": acc.get("addedAt", now),
                    "rateLimitHistory": acc.get("rateLimitHistory", []),
                }
                if not store.get("activeAlias"):
                    store["activeAlias"] = alias
                save_store(store)
                return email, alias, False

    alias = build_alias(email, existing_aliases)
    new_account["alias"] = alias
    store["accounts"][alias] = new_account
    if not store.get("activeAlias"):
        store["activeAlias"] = alias
    save_store(store)
    return email, alias, True


# ── Credentials ─────────────────────────────────────────────────────────────
def load_credentials():
    if not CREDENTIALS_FILE.exists():
        print(f"[ERROR] Credentials file not found: {CREDENTIALS_FILE}")
        sys.exit(1)
    with open(CREDENTIALS_FILE, "r") as f:
        return json.load(f)


# ── Outlook email verification code retrieval ──────────────────────────────
def _outlook_login(context, outlook_email, outlook_password):
    """Login to Outlook Web and get past all Microsoft interstitials.
    Returns the mail_page with inbox loaded, or None on failure."""
    mail_page = context.new_page()
    try:
        mail_page.goto(
            "https://login.live.com/login.srf?"
            "wa=wsignin1.0&wreply=https://outlook.live.com/mail/",
            wait_until="networkidle",
            timeout=30000,
        )
        time.sleep(2)

        # Enter email
        print(f"    [outlook] Entering email...")
        email_input = mail_page.wait_for_selector(
            "input[name='loginfmt'], input[type='email'], input#i0116",
            timeout=15000,
        )
        email_input.fill(outlook_email)
        time.sleep(0.5)
        mail_page.wait_for_selector(
            "input#idSIButton9, button#idSIButton9, button:has-text('Next')",
            timeout=10000,
        ).click()
        mail_page.wait_for_timeout(3000)

        # Enter password
        print(f"    [outlook] Entering password...")
        pw_input = mail_page.wait_for_selector(
            "input[name='passwd'], input[type='password'], input#i0118",
            timeout=15000,
        )
        pw_input.fill(outlook_password)
        time.sleep(0.5)
        mail_page.wait_for_selector(
            "input#idSIButton9, button#idSIButton9, "
            "button:has-text('Sign in'), button:has-text('Next')",
            timeout=10000,
        ).click()
        mail_page.wait_for_timeout(3000)

        # Handle "Stay signed in?"
        try:
            mail_page.wait_for_selector(
                "input#idSIButton9, button:has-text('Yes')",
                timeout=5000,
            ).click()
            mail_page.wait_for_timeout(2000)
        except Exception:
            pass

        # Handle all Microsoft interstitial prompts
        for _ in range(8):
            mail_page.wait_for_timeout(1500)
            current_url = mail_page.url.lower()

            # Already at inbox?
            if "outlook.live.com/mail" in current_url or "outlook.office.com" in current_url:
                break

            try:
                # FIDO / passkey creation page
                if "fido/create" in current_url or "passkey" in current_url:
                    fido_skip = mail_page.query_selector(
                        "button:has-text('Not now'), a:has-text('Not now'), "
                        "button:has-text('Skip for now'), a:has-text('Skip for now'), "
                        "button:has-text('Cancel'), a:has-text('Cancel'), "
                        "button:has-text('Skip'), a:has-text('Skip'), "
                        "#cancelBtn, button[data-testid='cancelBtn'], "
                        "button[data-testid='notNowBtn']"
                    )
                    if fido_skip:
                        print(f"    [outlook] Skipping FIDO/passkey prompt...")
                        fido_skip.click()
                        mail_page.wait_for_timeout(2000)
                        continue

                # Generic "Skip for now" / "Cancel" / "Not now" on any interstitial
                skip = mail_page.query_selector(
                    "a:has-text('Skip for now'), button:has-text('Skip for now'), "
                    "a[id='iCancel'], #iCancel, "
                    "button:has-text('Not now'), a:has-text('Not now'), "
                    "a:has-text('Skip'), button:has-text('Skip')"
                )
                if skip:
                    print(f"    [outlook] Skipping security prompt...")
                    skip.click()
                    mail_page.wait_for_timeout(2000)
                    continue

                cancel = mail_page.query_selector(
                    "button:has-text('Cancel'), a:has-text('Cancel'), "
                    "button:has-text('No thanks'), a:has-text('Not now'), "
                    "button:has-text('I don\\'t want to'), a:has-text('I don\\'t want to')"
                )
                if cancel:
                    print(f"    [outlook] Clicking '{cancel.inner_text().strip()}'...")
                    cancel.click()
                    mail_page.wait_for_timeout(2000)
                    continue

            except Exception:
                pass

        # If still not on inbox, force-navigate there
        if "outlook.live.com/mail" not in mail_page.url.lower():
            print(f"    [outlook] Not on inbox yet ({mail_page.url[:60]}), navigating...")
            try:
                mail_page.goto(
                    "https://outlook.live.com/mail/0/",
                    wait_until="domcontentloaded",
                    timeout=20000,
                )
                mail_page.wait_for_timeout(5000)
            except Exception as e:
                print(f"    [outlook] Navigation to inbox failed: {e}")

        print(f"    [outlook] Inbox loaded. URL: {mail_page.url[:80]}")
        mail_page.wait_for_timeout(3000)
        return mail_page

    except Exception as e:
        print(f"    [outlook] Login failed: {e}")
        _save_debug_screenshot_page(mail_page, outlook_email, "outlook_login_fail")
        mail_page.close()
        return None


def _outlook_read_latest_code(mail_page, max_attempts=4):
    """Refresh Outlook inbox and extract the verification code from the latest email.
    Returns the 6-digit code or None."""
    for attempt in range(max_attempts):
        if attempt > 0:
            print(f"    [outlook] Attempt {attempt + 1}/{max_attempts}...")

        # Refresh inbox (use "load" - webmail never reaches networkidle)
        try:
            mail_page.reload(wait_until="load", timeout=20000)
        except Exception:
            pass  # reload might timeout but page is still usable
        mail_page.wait_for_timeout(5000)

        # Try to click the first (newest) email
        clicked = False
        selectors = [
            "[role='option']:first-child",
            "[data-convid]:first-child",
            "[role='listbox'] [role='option']:first-child",
            "[role='list'] [role='listitem']:first-child",
        ]
        for sel in selectors:
            try:
                el = mail_page.query_selector(sel)
                if el:
                    el.click()
                    clicked = True
                    break
            except Exception:
                continue

        if not clicked:
            # Fallback: click any mail item
            items = mail_page.query_selector_all("[role='option'], [data-convid]")
            if items:
                items[0].click()
                clicked = True

        if clicked:
            mail_page.wait_for_timeout(2000)

        # Extract code from visible content
        body_text = mail_page.evaluate("() => document.body.innerText")

        # Precise patterns for OpenAI verification emails
        patterns = [
            r"(?:verification\s+code\s*(?:is)?[:\s]+)(\d{6})",
            r"(?:your\s+code\s*(?:is)?[:\s]+)(\d{6})",
            r"(?:enter\s+(?:this\s+)?code[:\s]+)(\d{6})",
            r"(?:code[:\s]+)(\d{6})",
        ]
        for pat in patterns:
            matches = re.findall(pat, body_text, re.IGNORECASE)
            if matches:
                return matches[-1]  # Last match = most recent

        # Fallback: any 6-digit number (skip year-like numbers)
        all_codes = re.findall(r"\b(\d{6})\b", body_text)
        valid = [c for c in all_codes if not c.startswith("20")]
        if valid:
            return valid[-1]
        if all_codes:
            return all_codes[-1]

        if attempt < max_attempts - 1:
            print(f"    [outlook] Code not found yet, waiting 6s...")
            mail_page.wait_for_timeout(6000)

    return None


def _save_debug_screenshot_page(page, identifier, step):
    safe_name = identifier.split("@")[0]
    path = SCRIPT_DIR / f"debug_{safe_name}_{step}.png"
    try:
        page.screenshot(path=str(path))
        print(f"    [DEBUG] Screenshot: {path}")
    except Exception:
        pass


class CallbackServer(BaseHTTPRequestHandler):
    """HTTP handler that captures the OAuth callback code into a shared list."""

    captured_codes = []  # Class-level shared storage

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        query = urllib.parse.parse_qs(parsed.query)
        code = query.get("code", [None])[0]
        if code:
            CallbackServer.captured_codes.append(code)
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"<h1>Login successful!</h1><p>Close this window.</p>")
        else:
            self.send_response(400)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"No code found in URL.")

    def log_message(self, format, *args):
        pass


# ── Main Playwright login flow ─────────────────────────────────────────────
def login_account(
    email,
    chatgpt_password,
    outlook_password=None,
    headless=True,
    ssl_context=None,
):
    """
    Full OAuth login. Strategy:
    1. Navigate to OpenAI auth
    2. Enter email
    3. Try "Log in with a one-time code" (sends code to email → read from Outlook)
    4. Fallback: password + handle email verification if needed
    """
    from playwright.sync_api import sync_playwright

    code_verifier, code_challenge = generate_pkce()
    state = generate_state()
    redirect_uri = f"http://localhost:{REDIRECT_PORT}/auth/callback"
    auth_url = build_auth_url(code_challenge, state, redirect_uri)

    with sync_playwright() as p:
        browser = p.chromium.launch(
            headless=headless,
            args=["--disable-blink-features=AutomationControlled", "--no-sandbox"],
        )
        context = browser.new_context(
            user_agent=(
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/131.0.0.0 Safari/537.36"
            ),
            viewport={"width": 1280, "height": 800},
        )

        # Start the callback server before navigation
        CallbackServer.captured_codes = []  # Reset for this run
        server = HTTPServer(("localhost", REDIRECT_PORT), CallbackServer)
        server.timeout = 1
        server_thread = threading.Thread(target=server.serve_forever, daemon=True)
        server_thread.start()

        page = context.new_page()

        # ── Step 1: Navigate to OpenAI auth
        print(f"  [1/5] Navigating to OpenAI auth...")
        page.goto(auth_url, wait_until="domcontentloaded", timeout=30000)
        page.wait_for_timeout(3000)  # let page fully render

        # ── Step 2: Enter email
        print(f"  [2/5] Entering email: {email}")
        try:
            email_input = page.wait_for_selector(
                "input[name='email'], input[type='email'], "
                "input#email, input[name='username']",
                timeout=15000,
            )
            email_input.fill(email)
            time.sleep(0.5)
            page.wait_for_selector(
                "button[type='submit'], button:has-text('Continue')",
                timeout=10000,
            ).click()
        except Exception as e:
            _save_debug_screenshot_page(page, email, "email_step")
            raise RuntimeError(f"Email step failed: {e}")

        page.wait_for_timeout(3000)

        # ── Step 3: Try "Log in with a one-time code" (preferred method)
        otp_login_done = False
        otp_link = page.query_selector(
            "button:has-text('one-time code'), a:has-text('one-time code'), "
            "button:has-text('Log in with a one-time code'), "
            "a:has-text('Log in with a one-time code')"
        )

        if otp_link and outlook_password:
            print(f"  [3/5] Using one-time code login (preferred)...")
            try:
                otp_link.click()
                page.wait_for_timeout(3000)

                # Check if we need to enter email again on OTP page
                otp_email_input = page.query_selector(
                    "input[name='email'], input[type='email']"
                )
                if otp_email_input:
                    otp_email_input.fill(email)
                    time.sleep(0.3)
                    submit = page.query_selector(
                        "button[type='submit'], button:has-text('Continue')"
                    )
                    if submit:
                        submit.click()
                        page.wait_for_timeout(3000)

                # Now OpenAI should send a one-time code to the email
                # Login to Outlook and read the code
                print(f"  [3/5] Logging into Outlook to read one-time code...")
                mail_page = _outlook_login(context, email, outlook_password)
                if mail_page:
                    # Wait for the email to arrive
                    print(f"  [3/5] Waiting 10s for code email to arrive...")
                    page.wait_for_timeout(10000)

                    print(f"  [3/5] Reading code from Outlook...")
                    otp_code = _outlook_read_latest_code(mail_page)
                    mail_page.close()

                    if otp_code:
                        print(f"  [3/5] Entering one-time code: {otp_code}")
                        code_input = page.wait_for_selector(
                            "input[name='code'], input[type='text'], "
                            "input[inputmode='numeric'], "
                            "input[placeholder*='ode']",
                            timeout=10000,
                        )
                        code_input.fill(otp_code)
                        time.sleep(0.5)
                        page.wait_for_selector(
                            "button[type='submit'], button:has-text('Continue')",
                            timeout=10000,
                        ).click()
                        page.wait_for_timeout(5000)
                        otp_login_done = True
                    else:
                        print(
                            f"  [3/5] Could not read OTP from Outlook, trying password..."
                        )
                else:
                    print(f"  [3/5] Outlook login failed, trying password...")
            except Exception as e:
                print(f"  [3/5] OTP login error: {e}, trying password...")

        # ── Fallback: Password login
        if not otp_login_done and not CallbackServer.captured_codes:
            # Check if we're still on a page that needs password
            if "password" in page.url or page.query_selector("input[type='password']"):
                print(f"  [3/5] Entering password (fallback)...")
                try:
                    pw_input = page.wait_for_selector(
                        "input[name='password'], input[type='password']",
                        timeout=10000,
                    )
                    pw_input.fill(chatgpt_password)
                    time.sleep(0.5)
                    page.wait_for_selector(
                        "button[type='submit'], button:has-text('Continue'), "
                        "button:has-text('Log in'), button:has-text('Sign in')",
                        timeout=10000,
                    ).click()
                    page.wait_for_timeout(5000)

                    # Check for "Incorrect password" error
                    error_el = page.query_selector("[class*='error'], [role='alert']")
                    if error_el:
                        err_text = error_el.inner_text().strip()
                        if "incorrect" in err_text.lower():
                            print(f"  [WARNING] {err_text}")
                            print(f"  [3/5] Password rejected. Trying one-time code...")
                            # Try one-time code as last resort
                            otp_link2 = page.query_selector(
                                "button:has-text('one-time code'), a:has-text('one-time code')"
                            )
                            if otp_link2 and outlook_password:
                                otp_link2.click()
                                page.wait_for_timeout(3000)
                                mail_page = _outlook_login(
                                    context, email, outlook_password
                                )
                                if mail_page:
                                    page.wait_for_timeout(10000)
                                    otp_code = _outlook_read_latest_code(mail_page)
                                    mail_page.close()
                                    if otp_code:
                                        print(f"  [3/5] Entering OTP code: {otp_code}")
                                        ci = page.wait_for_selector(
                                            "input[name='code'], input[type='text']",
                                            timeout=10000,
                                        )
                                        ci.fill(otp_code)
                                        time.sleep(0.5)
                                        page.wait_for_selector(
                                            "button[type='submit'], button:has-text('Continue')",
                                            timeout=10000,
                                        ).click()
                                        page.wait_for_timeout(5000)
                                        otp_login_done = True

                except Exception as e:
                    _save_debug_screenshot_page(page, email, "password_step")
                    raise RuntimeError(f"Password step failed: {e}")

        # ── Step 4: Handle email verification (after password login)
        if not CallbackServer.captured_codes and not otp_login_done:
            current_url = page.url
            needs_verification = "email-verification" in current_url
            if not needs_verification:
                try:
                    h = page.query_selector("h1, h2")
                    if h and "check your inbox" in h.inner_text().lower():
                        needs_verification = True
                except Exception:
                    pass

            if needs_verification and outlook_password:
                print(
                    f"  [4/5] Email verification required, getting code from Outlook..."
                )
                mail_page = _outlook_login(context, email, outlook_password)
                if mail_page:
                    # Resend for fresh code
                    resend = page.query_selector(
                        "button:has-text('Resend'), a:has-text('Resend')"
                    )
                    if resend:
                        resend.click()
                    page.wait_for_timeout(10000)

                    vcode = _outlook_read_latest_code(mail_page)
                    mail_page.close()
                    if vcode:
                        print(f"  [4/5] Entering verification code: {vcode}")
                        ci = page.wait_for_selector(
                            "input[name='code'], input[type='text']",
                            timeout=10000,
                        )
                        ci.fill(vcode)
                        time.sleep(0.5)
                        page.wait_for_selector(
                            "button[type='submit'], button:has-text('Continue')",
                            timeout=10000,
                        ).click()
                        page.wait_for_timeout(5000)

        # ── Step 5: Wait for OAuth callback
        print(f"  [5/5] Waiting for OAuth callback...")

        # First, handle consent page if present
        def _try_handle_consent():
            """Check if we're on a consent page and click Continue. Returns True if clicked."""
            try:
                current = page.url
                # Check URL pattern
                on_consent = "consent" in current.lower()
                if not on_consent:
                    # Also check page content
                    heading = page.query_selector("h1, h2, h3")
                    if heading:
                        text = heading.inner_text().lower()
                        if (
                            "authorize" in text
                            or "consent" in text
                            or "allow" in text
                            or "access" in text
                        ):
                            on_consent = True

                if on_consent:
                    btn = page.query_selector(
                        "button:has-text('Continue'), button:has-text('Allow'), "
                        "button:has-text('Authorize'), button[type='submit'], "
                        "input[type='submit']"
                    )
                    if btn:
                        print(
                            f"  [5/5] Consent page detected, clicking '{btn.inner_text().strip()}'..."
                        )
                        btn.click()
                        return True
            except Exception:
                pass
            return False

        # Try consent immediately (common case after OTP)
        page.wait_for_timeout(2000)
        _try_handle_consent()

        # Poll for callback, periodically re-checking for consent/interstitials
        deadline = time.time() + 45
        checks = 0
        while not CallbackServer.captured_codes and time.time() < deadline:
            page.wait_for_timeout(1500)
            checks += 1

            # Every few iterations, re-check for consent or other buttons
            if checks % 3 == 0 and not CallbackServer.captured_codes:
                _try_handle_consent()

            # Also check for any stray "Continue" / "Accept" buttons on unknown pages
            if checks % 5 == 0 and not CallbackServer.captured_codes:
                try:
                    stray = page.query_selector(
                        "button:has-text('Continue'), button:has-text('Accept')"
                    )
                    if stray and "consent" not in page.url.lower():
                        # Only click if page is NOT localhost (callback already handled)
                        if "localhost" not in page.url:
                            print(
                                f"  [5/5] Clicking stray button: '{stray.inner_text().strip()}'..."
                            )
                            stray.click()
                except Exception:
                    pass

        if not CallbackServer.captured_codes:
            _save_debug_screenshot_page(page, email, "no_callback")
            print(f"  [ERROR] No OAuth code. URL: {page.url[:200]}")
            server.shutdown()
            browser.close()
            return None

        captured_code = CallbackServer.captured_codes[0]
        print(f"  [CALLBACK] Got OAuth code: {captured_code[:20]}...")
        server.shutdown()
        browser.close()

    # ── Exchange code for tokens
    print(f"  [DONE] Exchanging code for tokens...")
    tokens = exchange_code_for_tokens(
        captured_code,
        redirect_uri,
        code_verifier,
        ssl_context=ssl_context,
    )

    stored_email, alias, is_new = add_account_to_store(
        tokens, ssl_context=ssl_context
    )
    action = "Added new" if is_new else "Updated existing"
    print(f"  {action} account '{alias}': {stored_email}")
    return stored_email


# ── Commands ────────────────────────────────────────────────────────────────
def cmd_check(accounts):
    store = load_store()
    now = int(time.time() * 1000)

    print(f"\n  Credentials file: {len(accounts)} account(s)")
    print(f"  Plugin store:     {len(store['accounts'])} account(s)\n")

    for i, acc in enumerate(accounts):
        email = acc["email"]
        enabled = acc.get("enabled", True)
        store_acc = next(
            (s for s in store["accounts"].values() if s.get("email") == email), None
        )

        if not store_acc:
            status = "NOT IN STORE"
        elif store_acc.get("authInvalid"):
            status = "AUTH INVALID"
        elif store_acc.get("expiresAt", 0) < now:
            status = "EXPIRED"
        else:
            exp = datetime.fromtimestamp(store_acc["expiresAt"] / 1000, tz=timezone.utc)
            status = f"OK (expires {exp.strftime('%Y-%m-%d %H:%M')} UTC)"

        print(f"  #{i} [{'ON' if enabled else 'OFF'}] {email}")
        print(f"       -> {status}")
    print()


def cmd_login(targets, defaults, headless=True, ssl_context=None):
    print(f"\n{'=' * 55}")
    print(f"  Auto-Login: {len(targets)} account(s)")
    print(f"{'=' * 55}\n")

    success, failed = 0, 0

    for i, acc in enumerate(targets):
        email = acc["email"]
        chatgpt_pw = acc.get("chatgpt_password") or defaults.get("chatgpt_password")
        outlook_pw = acc.get("outlook_password")

        if not chatgpt_pw:
            print(f"[{i + 1}/{len(targets)}] {email}: SKIPPED (no ChatGPT password)")
            failed += 1
            continue

        print(f"[{i + 1}/{len(targets)}] {email}")

        try:
            result = login_account(
                email,
                chatgpt_pw,
                outlook_password=outlook_pw,
                headless=headless,
                ssl_context=ssl_context,
            )
            if result:
                print(f"  -> SUCCESS\n")
                success += 1
            else:
                print(f"  -> FAILED\n")
                failed += 1
        except Exception as e:
            print(f"  -> ERROR: {e}\n")
            failed += 1

        if i < len(targets) - 1:
            print(f"  (waiting {BETWEEN_ACCOUNTS_DELAY}s...)\n")
            time.sleep(BETWEEN_ACCOUNTS_DELAY)

    print(f"{'=' * 55}")
    print(f"  Results: {success} success, {failed} failed")
    print(f"{'=' * 55}\n")
    return success, failed


# ── Main ────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="Auto-login for opencode-multi-auth-codex"
    )
    parser.add_argument("--account", type=int, help="Login by credential index")
    parser.add_argument("--email", type=str, help="Login by email")
    parser.add_argument("--check", action="store_true", help="Check account status")
    parser.add_argument("--visible", action="store_true", help="Show browser window")
    parser.add_argument(
        "--no-ssl-verify",
        action="store_true",
        help="Disable TLS certificate verification (unsafe)",
    )
    args = parser.parse_args()

    creds = load_credentials()
    accounts = creds.get("accounts", [])
    defaults = creds.get("defaults", {})

    if not accounts:
        print("[ERROR] No accounts in credentials.json")
        sys.exit(1)

    if args.check:
        cmd_check(accounts)
        return

    if args.email:
        targets = [a for a in accounts if a["email"] == args.email]
        if not targets:
            print(f"[ERROR] Email '{args.email}' not found")
            sys.exit(1)
    elif args.account is not None:
        if not (0 <= args.account < len(accounts)):
            print(f"[ERROR] Index {args.account} out of range")
            sys.exit(1)
        targets = [accounts[args.account]]
    else:
        targets = [a for a in accounts if a.get("enabled", True)]

    if not targets:
        print("No enabled accounts to login.")
        return

    headless = not args.visible
    if args.no_ssl_verify:
        print("[WARNING] SSL verification disabled via --no-ssl-verify")
    ssl_context = get_ssl_context(no_ssl_verify=args.no_ssl_verify)
    success, failed = cmd_login(
        targets, defaults, headless=headless, ssl_context=ssl_context
    )
    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
