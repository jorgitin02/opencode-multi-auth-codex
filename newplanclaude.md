# Fix All Identified Issues + Dashboard UI Sizing — Research-Informed Plan

**Date:** 2026-03-02
**Scope:** 13 fixes across 9 files + 1 Python script
**Status:** Amended + implemented (2026-03-02)

---

## Research Findings Summary

### JWT Decoding
- Node.js natively supports `Buffer.from(str, 'base64url')` since v16+ — no manual `-`→`+`/`_`→`/` replacement needed
- The current `codex-auth.ts` does manual replacement, which works but is unnecessary. The `index.ts` version does neither and is broken
- **Decision:** Use `Buffer.from(payload, 'base64url')` everywhere (simplest, most correct)

### OAuth Token Refresh
- OpenAI refresh tokens are **single-use** — once consumed, they cannot be reused (returns 401)
- `invalid_grant` errors should **immediately** mark auth-invalid, no retry
- Transient errors (500/502/503) should retry with exponential backoff (3 attempts, 500ms/750ms/1125ms)
- Token refresh 400 errors after inactivity = refresh token expired, must re-auth
- Multiple processes refreshing simultaneously can cause token invalidation — need locking
- **Decision:** Fix A3 is even more critical than originally planned. Token failures must distinguish grant errors from transient errors

### Rotation Safety (Post-Review Amendment)
- Weighted strategy should not stop after one selected alias if that alias token refresh fails
- A weighted pick should still fallback to other healthy aliases in the same request cycle
- **Decision:** Weighted selection remains first choice, but candidate list now includes healthy fallbacks

### OpenCode Plugin Conventions
- Token refresh failures should `throw new Error()`, not return Response objects
- API error responses should be returned as-is (don't consume/wrap them)
- `id_token` is required for account detection (extracting `chatgpt_account_id` from JWT claims)
- The Codex CLI `auth.json` expects `id_token` in the tokens object
- **Decision:** For B1 (probe idToken), we should gracefully skip probing for accounts without `idToken` rather than using empty string. The `idToken` IS needed by the Codex CLI

### Cross-Process File Locking
- `proper-lockfile` is still the standard (8.7M weekly downloads), uses `mkdir` strategy
- No built-in Node.js cross-process locking API exists
- **Decision:** Not adding `proper-lockfile` in this PR (would be a new dependency). Instead, document the limitation. The existing atomic rename approach prevents data loss

### Python SSL
- `truststore` package (uses OS cert store) is the 2025 best practice for Python 3.10+
- `certifi` is the fallback for older Python
- `ssl.create_default_context()` works on Python 3.10+ with system certs
- **Decision:** Use `ssl.create_default_context()` as default, add `--no-ssl-verify` flag as explicit opt-in

### Dashboard UI/Accessibility (WCAG 2.2)
- WCAG AA minimum touch target: **24x24px** hit area
- Recommended button height: **36-40px** for desktop
- Dashboard body text minimum: **13px** (0.8125rem)
- Absolute label minimum: **11px** (0.6875rem)
- Dark backgrounds: avoid pure black/white, use `#111`-`#1a1a1a` bg + `#e8e8e8` text
- `rem` units are better for accessibility (respects browser font-size settings)
- **Decision:** Bump sizes ~20% using px (converting to rem would be a larger refactor). Ensure nothing is below 12px. Ensure buttons meet 36px minimum height

---

## Implementation Plan

### Group A — Quick Surgical Fixes

#### A1. Fix `decodeJWT` base64url handling in `src/index.ts`
**File:** `src/index.ts` (lines 52-62)
**Change:** Remove inline `decodeJWT` function. Import `decodeJwtPayload` from `./codex-auth.js` and use it at all call sites in index.ts.
**Research insight:** Could also modernize to `Buffer.from(payload, 'base64url')` but reusing the existing tested function is safer.

#### A2. Fix CLI status hardcoded strategy in `src/cli.ts`
**File:** `src/cli.ts` (line 71)
**Change:** Import `getRuntimeSettings` from `./settings.js`. Replace `console.log('Strategy: round-robin')` with:
```typescript
const { settings } = getRuntimeSettings()
console.log(`Strategy: ${settings.rotationStrategy}`)
```

#### A3. Fix token failure handling in `src/rotation.ts`
**File:** `src/rotation.ts` (lines 279-285)
**Change:** When `ensureValidToken` returns null, mark as `authInvalid` with cooldown instead of `rateLimitedUntil`:
```typescript
if (!token) {
  store = updateAccount(candidate, {
    authInvalid: true,
    authInvalidatedAt: now,
    limitError: '[multi-auth] Token unavailable (refresh failed?)',
    lastLimitErrorAt: now
  })
  continue
}
```
**Research insight:** OpenAI refresh tokens are single-use. A failed refresh likely means the token is permanently invalid, not temporarily rate-limited. Using `authInvalid` correctly prevents the account from being retried until re-authenticated.

**Amendment applied:** This fix now depends on structured refresh failure classification in `src/auth.ts`:
- `invalid_grant` (400) and `401/403` => permanent auth invalidation
- `429/500/502/503/504` + network errors => transient with retry backoff (500ms/750ms/1125ms)
- rotation only marks `authInvalid` for permanent failures, and applies cooldown for transient failures

#### A4. Fix undefined `expiresAt` in `src/auth-sync.ts`
**File:** `src/auth-sync.ts` (lines 74-81)
**Change:** Guard `expiresAt` against undefined by falling back to the existing account's value:
```typescript
const existingAccount = store.accounts[existingAlias]
updateAccount(existingAlias, {
  accessToken: auth.access,
  refreshToken: auth.refresh,
  expiresAt: auth.expires ?? existingAccount?.expiresAt ?? (Date.now() + 3600_000),
  email: derivedEmail,
  accountId: derivedAccountId
})
```
Also apply the same guard at line 101 for the `addAccount` call.

#### A5. Make `CODEX_AUTH_FILE` lazy in `src/codex-auth.ts`
**File:** `src/codex-auth.ts` (line 30)
**Change:** Replace `const CODEX_AUTH_FILE = getCodexAuthFilePath()` with a lazy getter:
```typescript
let _codexAuthFile: string | null = null
function getCodexAuthFile(): string {
  if (!_codexAuthFile) _codexAuthFile = getCodexAuthFilePath()
  return _codexAuthFile
}
```
Replace all references to `CODEX_AUTH_FILE` with `getCodexAuthFile()`.

**Amendment applied:** Ensure directory creation uses `dirname(getCodexAuthFile())` so env-overridden auth file paths work outside `~/.codex`.

#### A6. Weighted strategy fallback safety in `src/rotation.ts`
**File:** `src/rotation.ts`
**Change:** In `weighted-round-robin`, keep weighted-selected alias first, but append healthy fallback aliases. This prevents false `No available accounts` when only the first choice fails token refresh.

---

### Group B — Medium Fixes

#### B1. Fix `probe-limits.ts` idToken requirement
**File:** `src/probe-limits.ts` (lines 44-47)
**Change:** Instead of throwing when `idToken` is missing, skip the probe gracefully:
```typescript
function writeAuthJson(dir: string, account: AccountCredentials): boolean {
  if (!account.accessToken || !account.refreshToken || !account.idToken) {
    return false  // Can't probe without full token set
  }
  // ... write auth.json as before
  return true
}
```
Update `probeRateLimitsForAccount` to check the return value and return an error result if `writeAuthJson` returns false.
**Research insight:** The Codex CLI requires `id_token` for account detection. Accounts synced from OpenCode (which lack `idToken`) genuinely cannot be probed — this is expected, not a bug.

**Amendment applied:** `/api/limits/refresh` now returns explicit errors for:
- requested alias missing `idToken`
- no probeable aliases in store

#### B2. Fix auto-login store format incompatibility
**File:** `auto-login/auto_login.py` (lines 41-42, 158-238)
**Changes:**
1. Fix store path: `~/.config/opencode-multi-auth/accounts.json` (matching Node.js plugin)
2. Fix store format: `accounts: {}` dict keyed by alias (not list)
3. Use `activeAlias` instead of `activeIndex`
4. Build alias from email prefix (matching `codex-auth.ts` `buildAlias` logic)
5. Handle reading existing dict-format stores
```python
STORE_DIR = Path.home() / ".config" / "opencode-multi-auth"
STORE_FILE = STORE_DIR / "accounts.json"

def load_store():
    if not STORE_FILE.exists():
        return {
            "version": 2,
            "accounts": {},
            "activeAlias": None,
            "rotationIndex": 0,
            "lastRotation": int(time.time() * 1000),
        }
    with open(STORE_FILE, "r") as f:
        return json.load(f)

def build_alias(email, existing_aliases):
    base = email.split("@")[0] if email else "account"
    candidate = base or "account"
    suffix = 1
    while candidate in existing_aliases:
        candidate = f"{base}-{suffix}"
        suffix += 1
    return candidate

def add_account_to_store(tokens):
    # ... build new_account dict as before ...
    store = load_store()
    existing_aliases = set(store["accounts"].keys())

    # Check for existing account by email
    if email:
        for alias, acc in store["accounts"].items():
            if acc.get("email") == email:
                store["accounts"][alias] = {**acc, **new_account, ...}
                save_store(store)
                return email, alias, False

    alias = build_alias(email, existing_aliases)
    new_account["alias"] = alias
    store["accounts"][alias] = new_account
    if not store.get("activeAlias"):
        store["activeAlias"] = alias
    save_store(store)
    return email, alias, True
```

**Amendment applied:** `cmd_check` and login output paths were updated for dict/alias store shape (no remaining `activeIndex` assumptions in runtime logic).

#### B3. Verify cross-field settings validation
**File:** `src/settings.ts` (line 110)
**Change:** The existing code already merges `current.settings` with `updates` before calling `validateSettings`. Verify that `validateSettings` in `types.ts` actually checks `criticalThreshold < lowThreshold`. If it does, this is already handled. If not, add explicit check:
```typescript
if (newSettings.criticalThreshold >= newSettings.lowThreshold) {
  errors.push({ field: 'criticalThreshold', message: 'Critical threshold must be less than low threshold' })
}
```

#### B4. Add probe directory cleanup
**File:** `src/probe-limits.ts`
**Changes:**
1. Add `cleanupProbeHome(alias: string)` function:
```typescript
export function cleanupProbeHome(alias: string): void {
  const dir = getAliasHome(alias)
  try {
    fs.rmSync(dir, { recursive: true, force: true })
  } catch {
    // ignore cleanup errors
  }
}

export function cleanupAllProbeHomes(): void {
  if (!fs.existsSync(CODEX_HOME_ROOT)) return
  try {
    const entries = fs.readdirSync(CODEX_HOME_ROOT)
    for (const entry of entries) {
      const full = path.join(CODEX_HOME_ROOT, entry)
      fs.rmSync(full, { recursive: true, force: true })
    }
  } catch {
    // ignore
  }
}
```
2. Call `cleanupProbeHome(account.alias)` at the end of `probeRateLimitsForAccount` after getting results
3. Optionally expose `cleanupAllProbeHomes` via the dashboard API

**Amendment applied:** cleanup now runs in a `finally` block so directories are removed on every return path (success/failure/early exit).

#### B5. Fix SSL in `auto_login.py`
**File:** `auto-login/auto_login.py` (lines 141, 151)
**Changes:**
1. Replace `ssl._create_unverified_context()` with `ssl.create_default_context()`:
```python
def get_ssl_context(no_ssl_verify=False):
    if no_ssl_verify:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx
    return ssl.create_default_context()
```
2. Add `--no-ssl-verify` CLI flag in argparse
3. Thread the SSL context through `exchange_code_for_tokens` and `fetch_userinfo_email`
4. Print a warning when `--no-ssl-verify` is used

---

### Group C — Dashboard UI Sizing (~20% moderate bump)

#### C1. CSS size increases in `src/web.ts`
**File:** `src/web.ts` (CSS section, approximately lines 46-610)

| Element | Current | New |
|---------|---------|-----|
| `button` padding | `10px 14px` | `12px 17px` |
| `button` font-size (implicit ~14px) | default | `14px` explicit |
| `button.small` padding | `6px 10px` | `8px 12px` |
| `button.small` font-size | `12px` | `13px` |
| `.meta-item` padding | `12px 14px` | `14px 16px` |
| `.meta-item span` font-size | `12px` | `13px` |
| `.meta-item strong` font-size | `16px` | `18px` |
| `.filters input/select` padding | `10px 12px` | `12px 14px` |
| `.filters input/select` font-size (implicit) | default | `14px` explicit |
| `.account-card` padding | `16px` | `18px` |
| `.badge` / tag padding | `4px 8px` | `5px 10px` |
| `.badge` / tag font-size | `11px` | `12px` |
| Smallest text (9px tags) | `9px` | `11px` |
| Section label font-sizes | `12px` | `13px` |
| Card detail font-sizes | `13px` | `14px` |
| Force mode / strategy selects | inline styles | bump padding to `10px 14px` |
| `header h1` font-size | `28px` | `30px` |
| `.subtitle` font-size | `14px` | `15px` |
| `.add-row input` padding | `12px 14px` | `14px 16px` |
| `.add-row input` font-size | `14px` | `15px` |

**Principles:**
- Nothing below 11px (WCAG floor)
- Buttons at least 36px effective height (padding + line-height)
- All increases are proportional — dense layout preserved, just slightly more spacious

**Amendment applied:** Included missed tiny text (`.confidence-badge` 9px -> 11px), plus force/help controls so interactive affordances are consistently sized.

---

## Files Modified Summary

| File | Fixes | Risk |
|------|-------|------|
| `src/index.ts` | A1 (JWT decode) | Low — removing duplicate, using existing tested function |
| `src/cli.ts` | A2 (status strategy) | Low — display-only change |
| `src/rotation.ts` | A3 (token failure category) | Medium — changes error classification behavior |
| `src/auth.ts` | A3 support (refresh classification + retry backoff) | Medium — auth refresh control flow changes |
| `src/auth-sync.ts` | A4 (expiresAt guard) | Low — adds fallback, no behavior change when value exists |
| `src/codex-auth.ts` | A5 (lazy CODEX_AUTH_FILE) | Low — same result, deferred evaluation |
| `src/probe-limits.ts` | B1 (idToken handling), B4 (cleanup) | Low — graceful degradation + cleanup |
| `auto-login/auto_login.py` | B2 (store format), B5 (SSL) | Medium — changes Python store I/O format |
| `src/settings.ts` | B3 (cross-field validation) | Low — verify/add validation |
| `src/web.ts` | B1 API UX + C1 (UI sizing) | Low — API message clarity + CSS-only changes |

## Implementation Order

1. **A1, A2, A4, A5** — Independent quick fixes, can be done in parallel
2. **A3** — Rotation behavior change, test after A1-A5
3. **B1, B3, B4** — Medium fixes on Node.js side
4. **B2, B5** — Python script fixes (independent from Node.js)
5. **C1** — Dashboard CSS (independent, do last)

## Not In Scope (Future Work)

- Cross-process file locking with `proper-lockfile` (new dependency, needs discussion)
- Splitting `web.ts` into separate frontend/backend files (major refactor)
- Converting CSS from `px` to `rem` units (accessibility improvement but large change)
- Background token keep-alive pings (discovered in research — prevents token expiry during inactivity)
- Encrypting LKG file when store encryption is active
