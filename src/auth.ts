import { generatePKCE } from '@openauthjs/openauth/pkce'
import { randomBytes } from 'node:crypto'
import * as http from 'http'
import * as url from 'url'
import { addAccount, updateAccount, loadStore } from './store.js'
import { clearAuthInvalid } from './rotation.js'
import {
  decodeJwtPayload,
  getAccountIdFromClaims,
  getEmailFromClaims,
  getExpiryFromClaims
} from './codex-auth.js'
import type { AccountCredentials } from './types.js'

const OPENAI_ISSUER = 'https://auth.openai.com'
const AUTHORIZE_URL = `${OPENAI_ISSUER}/oauth/authorize`
const TOKEN_URL = `${OPENAI_ISSUER}/oauth/token`
const CLIENT_ID = 'app_EMoamEEZ73f0CkXaXp7hrann'
const DEFAULT_REDIRECT_PORTS = [1455, 1456, 1457, 1458, 1459]
const SCOPES = ['openid', 'profile', 'email', 'offline_access']

function getRedirectUri(port: number): string {
  return `http://localhost:${port}/auth/callback`
}

interface TokenResponse {
  access_token: string
  refresh_token?: string
  id_token?: string
  expires_in: number
  token_type: string
  error?: string
  error_description?: string
}

interface AuthorizationFlow {
  pkce: { verifier: string; challenge: string }
  state: string
  url: string
  redirectUri: string
  port: number
}

export type TokenRefreshFailureKind =
  | 'invalid_grant'
  | 'unauthorized'
  | 'transient'
  | 'network'
  | 'unknown'

export interface TokenRefreshFailure {
  kind: TokenRefreshFailureKind
  status?: number
  error?: string
}

export interface RefreshTokenDetailedResult {
  account: AccountCredentials | null
  failure?: TokenRefreshFailure
}

export interface EnsureValidTokenResult {
  token: string | null
  failure?: TokenRefreshFailure
}

const TRANSIENT_REFRESH_STATUSES = new Set([429, 500, 502, 503, 504])
const REFRESH_RETRY_DELAYS_MS = [500, 750, 1125]

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => {
    setTimeout(resolve, ms)
  })
}

export async function createAuthorizationFlow(port?: number): Promise<AuthorizationFlow> {
  const pkce = await generatePKCE()
  const state = randomBytes(16).toString('hex')
  const redirectPort = port || DEFAULT_REDIRECT_PORTS[0]
  const redirectUri = getRedirectUri(redirectPort)
  
  const authUrl = new URL(AUTHORIZE_URL)
  authUrl.searchParams.set('client_id', CLIENT_ID)
  authUrl.searchParams.set('redirect_uri', redirectUri)
  authUrl.searchParams.set('response_type', 'code')
  authUrl.searchParams.set('scope', SCOPES.join(' '))
  authUrl.searchParams.set('code_challenge', pkce.challenge)
  authUrl.searchParams.set('code_challenge_method', 'S256')
  authUrl.searchParams.set('state', state)
  authUrl.searchParams.set('audience', 'https://api.openai.com/v1')
  authUrl.searchParams.set('id_token_add_organizations', 'true')
  authUrl.searchParams.set('codex_cli_simplified_flow', 'true')
  authUrl.searchParams.set('originator', 'codex_cli_rs')

  return { pkce, state, url: authUrl.toString(), redirectUri, port: redirectPort }
}

function tryListenOnPort(server: http.Server, port: number): Promise<void> {
  return new Promise((resolve, reject) => {
    const onError = (err: NodeJS.ErrnoException) => {
      server.off('error', onError)
      reject(err)
    }
    server.on('error', onError)
    server.listen(port, () => {
      server.off('error', onError)
      resolve()
    })
  })
}

async function findAvailablePort(
  server: http.Server,
  ports: number[]
): Promise<number> {
  for (const port of ports) {
    try {
      await tryListenOnPort(server, port)
      return port
    } catch (err: any) {
      if (err.code === 'EADDRINUSE') {
        continue
      }
      throw err
    }
  }
  throw new Error(`All ports ${ports.join(', ')} are in use. Stop Codex CLI if running.`)
}

export async function loginAccount(
  alias: string,
  flow?: AuthorizationFlow
): Promise<AccountCredentials> {
  const ports = DEFAULT_REDIRECT_PORTS
  let activeFlow = flow
  let server: http.Server | null = null
  let actualPort: number

  return new Promise(async (resolve, reject) => {
    const cleanup = () => {
      if (server) {
        server.close()
        server = null
      }
    }

    server = http.createServer(async (req, res) => {
      if (!req.url?.startsWith('/auth/callback')) {
        res.writeHead(404)
        res.end('Not found')
        return
      }

      if (!activeFlow) {
        res.writeHead(500)
        res.end('No active flow')
        cleanup()
        reject(new Error('No active flow'))
        return
      }

      const parsedUrl = url.parse(req.url, true)
      const code = parsedUrl.query.code as string
      const returnedState = parsedUrl.query.state as string | undefined

      if (!code) {
        res.writeHead(400)
        res.end('No authorization code received')
        cleanup()
        reject(new Error('No authorization code'))
        return
      }
      if (returnedState && returnedState !== activeFlow.state) {
        res.writeHead(400)
        res.end('Invalid state')
        cleanup()
        reject(new Error('Invalid state'))
        return
      }

      try {
        const tokenRes = await fetch(TOKEN_URL, {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: new URLSearchParams({
            grant_type: 'authorization_code',
            client_id: CLIENT_ID,
            code,
            code_verifier: activeFlow.pkce.verifier,
            redirect_uri: activeFlow.redirectUri
          })
        })

        if (!tokenRes.ok) {
          throw new Error(`Token exchange failed: ${tokenRes.status}`)
        }

        const tokens = (await tokenRes.json()) as TokenResponse
        if (!tokens.refresh_token) {
          throw new Error('Token exchange did not return a refresh_token')
        }
        const now = Date.now()
        const accessClaims = decodeJwtPayload(tokens.access_token)
        const idClaims = tokens.id_token ? decodeJwtPayload(tokens.id_token) : null
        const expiresAt = getExpiryFromClaims(accessClaims) || getExpiryFromClaims(idClaims) || now + tokens.expires_in * 1000

        let email: string | undefined = getEmailFromClaims(idClaims) || getEmailFromClaims(accessClaims)
        try {
          const userRes = await fetch(`${OPENAI_ISSUER}/userinfo`, {
            headers: { Authorization: `Bearer ${tokens.access_token}` }
          })
          if (userRes.ok) {
            const user = (await userRes.json()) as { email?: string }
            email = user.email || email
          }
        } catch {
          /* user info fetch is non-critical */
        }

        const accountId =
          getAccountIdFromClaims(idClaims) ||
          getAccountIdFromClaims(accessClaims)

        const store = addAccount(alias, {
          accessToken: tokens.access_token,
          refreshToken: tokens.refresh_token,
          idToken: tokens.id_token,
          accountId,
          expiresAt,
          email,
          lastRefresh: new Date(now).toISOString(),
          lastSeenAt: now,
          source: 'opencode',
          authInvalid: false,
          authInvalidatedAt: undefined
        })

        const account = store.accounts[alias]

        res.writeHead(200, { 'Content-Type': 'text/html' })
        res.end(`
          <html>
            <body style="font-family: system-ui; padding: 40px; text-align: center;">
              <h1>Account "${alias}" authenticated!</h1>
              <p>${email || 'Unknown email'}</p>
              <p>You can close this window.</p>
            </body>
          </html>
        `)

        cleanup()
        resolve(account)
      } catch (err) {
        res.writeHead(500)
        res.end('Authentication failed')
        cleanup()
        reject(err)
      }
    })

    try {
      actualPort = await findAvailablePort(server, ports)
      
      if (!activeFlow || activeFlow.port !== actualPort) {
        activeFlow = await createAuthorizationFlow(actualPort)
      }

      console.log(`\n[multi-auth] Login for account "${alias}"`)
      console.log(`[multi-auth] Open this URL in your browser:\n`)
      console.log(`  ${activeFlow.url}\n`)
      console.log(`[multi-auth] Waiting for callback on port ${actualPort}...`)
    } catch (err) {
      cleanup()
      reject(err)
      return
    }

    setTimeout(() => {
      cleanup()
      reject(new Error('Login timeout - no callback received'))
    }, 5 * 60 * 1000)
  })
}

async function refreshTokenAttempt(alias: string): Promise<RefreshTokenDetailedResult> {
  const store = loadStore()
  const account = store.accounts[alias]

  if (!account?.refreshToken) {
    console.error(`[multi-auth] No refresh token for ${alias}`)
    return {
      account: null,
      failure: {
        kind: 'unknown',
        error: 'No refresh token'
      }
    }
  }

  try {
    const tokenRes = await fetch(TOKEN_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'refresh_token',
        client_id: CLIENT_ID,
        refresh_token: account.refreshToken
      })
    })

    if (!tokenRes.ok) {
      let parsedCode = ''
      let parsedMessage = ''

      try {
        const bodyText = await tokenRes.text()
        if (bodyText) {
          const parsed = JSON.parse(bodyText) as TokenResponse & { error?: { code?: string; message?: string }; message?: string }
          parsedCode =
            (typeof parsed.error === 'string' && parsed.error) ||
            (typeof parsed.error?.code === 'string' && parsed.error.code) ||
            ''
          parsedMessage =
            (typeof parsed.error_description === 'string' && parsed.error_description) ||
            (typeof parsed.error?.message === 'string' && parsed.error.message) ||
            (typeof parsed.message === 'string' && parsed.message) ||
            ''
        }
      } catch {
        // ignore parse failures, status code still drives classification
      }

      const normalizedError = `${parsedCode} ${parsedMessage}`.toLowerCase()
      console.error(`[multi-auth] Refresh failed for ${alias}: ${tokenRes.status}${parsedCode ? ` (${parsedCode})` : ''}`)

      if (tokenRes.status === 400 && normalizedError.includes('invalid_grant')) {
        try {
          updateAccount(alias, {
            authInvalid: true,
            authInvalidatedAt: Date.now()
          })
        } catch {
          // ignore
        }
        return {
          account: null,
          failure: {
            kind: 'invalid_grant',
            status: tokenRes.status,
            error: parsedMessage || parsedCode || 'invalid_grant'
          }
        }
      }

      if (tokenRes.status === 401 || tokenRes.status === 403) {
        try {
          updateAccount(alias, {
            authInvalid: true,
            authInvalidatedAt: Date.now()
          })
        } catch {
          // ignore
        }
        return {
          account: null,
          failure: {
            kind: 'unauthorized',
            status: tokenRes.status,
            error: parsedMessage || 'Unauthorized refresh response'
          }
        }
      }

      if (TRANSIENT_REFRESH_STATUSES.has(tokenRes.status)) {
        return {
          account: null,
          failure: {
            kind: 'transient',
            status: tokenRes.status,
            error: parsedMessage || `Refresh returned ${tokenRes.status}`
          }
        }
      }

      return {
        account: null,
        failure: {
          kind: 'unknown',
          status: tokenRes.status,
          error: parsedMessage || `Refresh returned ${tokenRes.status}`
        }
      }
    }

    const tokens = (await tokenRes.json()) as TokenResponse
    const accessClaims = decodeJwtPayload(tokens.access_token)
    const idClaims = tokens.id_token ? decodeJwtPayload(tokens.id_token) : null
    const expiresAt = getExpiryFromClaims(accessClaims) || getExpiryFromClaims(idClaims) || Date.now() + tokens.expires_in * 1000

    const updates: Partial<AccountCredentials> = {
      accessToken: tokens.access_token,
      refreshToken: tokens.refresh_token || account.refreshToken,
      expiresAt,
      lastRefresh: new Date().toISOString(),
      idToken: tokens.id_token || account.idToken,
      accountId:
        getAccountIdFromClaims(idClaims) ||
        getAccountIdFromClaims(accessClaims) ||
        account.accountId
    }

    const updatedStore = updateAccount(alias, updates)
    clearAuthInvalid(alias)

    return { account: updatedStore.accounts[alias] }
  } catch (err) {
    console.error(`[multi-auth] Refresh error for ${alias}:`, err)
    return {
      account: null,
      failure: {
        kind: 'network',
        error: err instanceof Error ? err.message : String(err)
      }
    }
  }
}

export async function refreshTokenDetailed(alias: string): Promise<RefreshTokenDetailedResult> {
  for (let attempt = 0; attempt <= REFRESH_RETRY_DELAYS_MS.length; attempt += 1) {
    const result = await refreshTokenAttempt(alias)
    if (result.account) {
      return result
    }

    const shouldRetry =
      (result.failure?.kind === 'transient' || result.failure?.kind === 'network') &&
      attempt < REFRESH_RETRY_DELAYS_MS.length
    if (!shouldRetry) {
      return result
    }

    await sleep(REFRESH_RETRY_DELAYS_MS[attempt])
  }

  return {
    account: null,
    failure: {
      kind: 'unknown',
      error: 'Refresh failed'
    }
  }
}

export async function refreshToken(alias: string): Promise<AccountCredentials | null> {
  const result = await refreshTokenDetailed(alias)
  return result.account
}

export async function ensureValidToken(alias: string): Promise<EnsureValidTokenResult> {
  const store = loadStore()
  const account = store.accounts[alias]

  if (!account) {
    return {
      token: null,
      failure: {
        kind: 'unknown',
        error: 'Account not found'
      }
    }
  }

  const bufferMs = 5 * 60 * 1000
  if (account.expiresAt < Date.now() + bufferMs) {
    console.log(`[multi-auth] Refreshing token for ${alias}`)
    const refreshed = await refreshTokenDetailed(alias)
    if (!refreshed.account) {
      return { token: null, failure: refreshed.failure }
    }
    return { token: refreshed.account.accessToken }
  }

  return { token: account.accessToken }
}
