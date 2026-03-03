import * as fs from 'node:fs'
import * as os from 'node:os'
import * as path from 'node:path'
import { spawn } from 'node:child_process'
import { findLatestSessionRateLimits } from './sessions-limits.js'
import type { AccountCredentials, AccountRateLimits } from './types.js'

const CODEX_HOME_ROOT = path.join(os.homedir(), '.codex-multi')
const CODEX_CONFIG_PATH = path.join(os.homedir(), '.codex', 'config.toml')

const DEFAULT_PROMPT = 'Reply ONLY with OK. Do not run any commands.'
const EXEC_TIMEOUT_MS = 120_000
// Reordered to prefer gpt-5.3-codex first (Phase C requirement)
const DEFAULT_PROBE_MODELS = ['gpt-5.3-codex', 'gpt-5.2-codex', 'gpt-5-codex']
const DEFAULT_PROBE_EFFORT = 'low'

export interface ProbeResult {
  rateLimits?: AccountRateLimits
  eventTs?: number
  sourceFile?: string
  // Phase C: Add probe source diagnostics
  probeModel?: string
  probeEffort?: string
  probeDurationMs?: number
  error?: string
  // Phase C: Track if probe was authoritative (successful completion)
  isAuthoritative?: boolean
}

function ensureDir(dir: string): void {
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 })
  }
}

function sanitizeAlias(alias: string): string {
  return alias.replace(/[^a-zA-Z0-9._-]/g, '_')
}

function getAliasHome(alias: string): string {
  return path.join(CODEX_HOME_ROOT, sanitizeAlias(alias))
}

function writeAuthJson(dir: string, account: AccountCredentials): boolean {
  if (!account.accessToken || !account.refreshToken || !account.idToken) {
    return false
  }
  const auth = {
    OPENAI_API_KEY: null,
    tokens: {
      id_token: account.idToken,
      access_token: account.accessToken,
      refresh_token: account.refreshToken,
      account_id: account.accountId
    },
    last_refresh: new Date().toISOString()
  }
  const authPath = path.join(dir, 'auth.json')
  fs.writeFileSync(authPath, JSON.stringify(auth, null, 2), { mode: 0o600 })
  return true
}

function copyConfigToml(dir: string): void {
  if (!fs.existsSync(CODEX_CONFIG_PATH)) return
  const target = path.join(dir, 'config.toml')
  try {
    fs.copyFileSync(CODEX_CONFIG_PATH, target)
  } catch {
    // ignore config copy errors
  }
}

export function shouldRetryWithFallback(error?: string): boolean {
  if (!error) return false
  const text = error.toLowerCase()
  return (
    text.includes('model_not_found') ||
    text.includes('model is not supported') ||
    text.includes('requested model') ||
    text.includes('does not exist') ||
    // Phase C: Handle reasoning.effort and unsupported_value errors
    text.includes('unsupported_value') ||
    text.includes('reasoning.effort') ||
    text.includes('reasoning effort')
  )
}

// Phase C: Get probe effort from environment or default to 'low'
export function getProbeEffort(): string {
  const envEffort = process.env.OPENCODE_MULTI_AUTH_PROBE_EFFORT
  if (envEffort && ['low', 'medium', 'high'].includes(envEffort.toLowerCase())) {
    return envEffort.toLowerCase()
  }
  return DEFAULT_PROBE_EFFORT
}

export function getProbeModels(): string[] {
  const raw = (process.env.OPENCODE_MULTI_AUTH_LIMITS_PROBE_MODELS || '').trim()
  const fromEnv = raw
    .split(',')
    .map((item) => item.trim())
    .filter(Boolean)

  const candidates = fromEnv.length > 0 ? fromEnv : DEFAULT_PROBE_MODELS
  return Array.from(new Set(candidates))
}

async function runCodexExec(
  codexHome: string,
  model?: string,
  effort?: string
): Promise<{ ok: boolean; error?: string; durationMs?: number }> {
  return new Promise((resolve) => {
    const args = [
      'exec',
      '--skip-git-repo-check',
      '--cd',
      codexHome,
      '--sandbox',
      'read-only'
    ]
    if (model) {
      args.push('-m', model)
    }
    // Phase C: Add reasoning effort configuration
    if (effort) {
      args.push('-c', `model_reasoning_effort="${effort}"`)
    }
    args.push(DEFAULT_PROMPT)

    let stderr = ''
    let stdout = ''
    const startTime = Date.now()

    const child = spawn('codex', args, {
      env: { ...process.env, CODEX_HOME: codexHome },
      stdio: ['ignore', 'pipe', 'pipe']
    })

    const timer = setTimeout(() => {
      child.kill('SIGTERM')
      const durationMs = Date.now() - startTime
      resolve({ ok: false, error: 'codex exec timed out', durationMs })
    }, EXEC_TIMEOUT_MS)

    child.stdout.on('data', (data) => {
      stdout += data.toString()
      if (stdout.length > 4000) stdout = stdout.slice(-4000)
    })
    child.stderr.on('data', (data) => {
      stderr += data.toString()
      if (stderr.length > 4000) stderr = stderr.slice(-4000)
    })

    child.on('error', (err) => {
      clearTimeout(timer)
      const durationMs = Date.now() - startTime
      resolve({ ok: false, error: String(err), durationMs })
    })

    child.on('close', (code) => {
      clearTimeout(timer)
      const durationMs = Date.now() - startTime
      if (code === 0) {
        resolve({ ok: true, durationMs })
      } else {
        const message = stderr.trim() || stdout.trim() || `codex exec failed (code ${code})`
        resolve({ ok: false, error: message, durationMs })
      }
    })
  })
}

export async function probeRateLimitsForAccount(account: AccountCredentials): Promise<ProbeResult> {
  const codexHome = getAliasHome(account.alias)
  ensureDir(codexHome)
  try {
    const wroteAuth = writeAuthJson(codexHome, account)
    if (!wroteAuth) {
      return {
        error: `Alias ${account.alias} missing token set for probe (requires accessToken, refreshToken, idToken)`,
        isAuthoritative: false
      }
    }
    copyConfigToml(codexHome)

    const sessionsDir = path.join(codexHome, 'sessions')
    const probeModels = getProbeModels()
    const probeEffort = getProbeEffort()
    let lastError = 'No token_count events found in alias sessions'
    const attemptErrors: string[] = []

    for (let idx = 0; idx < probeModels.length; idx++) {
      const probeModel = probeModels[idx]
      const startedAt = Date.now()
      
      // Phase C: Pass effort config and track duration
      const execResult = await runCodexExec(codexHome, probeModel, probeEffort)
      const latest = findLatestSessionRateLimits({
        sessionsDir,
        sinceMs: startedAt - 5_000
      })

      // Phase C: Only accept authoritative data from successful completions
      if (execResult.ok && latest?.rateLimits) {
        return {
          rateLimits: latest.rateLimits,
          eventTs: latest.eventTs,
          sourceFile: latest.sourceFile,
          probeModel,
          probeEffort,
          probeDurationMs: execResult.durationMs,
          isAuthoritative: true
        }
      }

      if (execResult.error) {
        lastError = execResult.error
        attemptErrors.push(`[model=${probeModel}, effort=${probeEffort}] ${execResult.error}`)
      }

      const hasNext = idx < probeModels.length - 1
      if (!hasNext) break
      
      // Phase C: Retry with fallback on unsupported_value / reasoning.effort errors
      if (shouldRetryWithFallback(execResult.error)) {
        // Try with 'low' effort explicitly if current effort failed
        if (probeEffort !== 'low' && execResult.error?.toLowerCase().includes('reasoning')) {
          const lowEffortResult = await runCodexExec(codexHome, probeModel, 'low')
          const lowEffortLatest = findLatestSessionRateLimits({
            sessionsDir,
            sinceMs: Date.now() - 5_000
          })
          
          if (lowEffortResult.ok && lowEffortLatest?.rateLimits) {
            return {
              rateLimits: lowEffortLatest.rateLimits,
              eventTs: lowEffortLatest.eventTs,
              sourceFile: lowEffortLatest.sourceFile,
              probeModel,
              probeEffort: 'low',
              probeDurationMs: lowEffortResult.durationMs,
              isAuthoritative: true
            }
          }
          
          if (lowEffortResult.error) {
            attemptErrors.push(`[model=${probeModel}, effort=low] ${lowEffortResult.error}`)
          }
        }
        continue
      }
      
      // Don't retry if it's not a fallback-eligible error
      break
    }

    if (attemptErrors.length > 0) {
      return { 
        error: attemptErrors[attemptErrors.length - 1],
        isAuthoritative: false
      }
    }

    return { 
      error: lastError,
      isAuthoritative: false
    }
  } finally {
    cleanupProbeHome(account.alias)
  }
}

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
    // ignore cleanup errors
  }
}

export function getProbeHomeRoot(): string {
  return CODEX_HOME_ROOT
}
