import { clearToken, getToken } from "@/lib/auth-storage"

/* ------------------------------------------------------------------ */
/* Types — mirror src/aipocket/web/schemas.py and models.py            */
/* ------------------------------------------------------------------ */

export type ScanSourceItem = "fofa" | "shodan" | "github" | "manual"
export type ScanSource = ScanSourceItem | "all"
export type ScanMode = "full" | "incremental"
/** Hostname reverse-lookup engines for source=manual (custom hunt). */
export type ManualEnrichEngine = "fofa" | "shodan"
export type GitHubPackId =
  | "all"
  | "gemini"
  | "xai"
  | "qoder"
  | "kiro"
  | "aws_bedrock"
  | "cursor"
  | "windsurf"
  | "glm"
  | "kimi"
  | "qwen"
  | "cohere"
  | "replicate"
  | "together"
  | "fireworks"
  | "deepseek"
  | "openai"
  | "anthropic"
  | "azure_openai"
  | "minimax"
  | "longcat"
export type ExportFormat = "json" | "csv" | "sub2api"
export type ExportDataset = "selected" | "run" | "high-value" | "all"
export type ResultKind = "valid" | "suspicious" | "unavailable" | "candidates"

export interface LoginResponse {
  token: string
  token_type: string
  expires_in: number
}

export interface KeyRef {
  apikey: string
  apiurl?: string
  result_id?: number
  high_value?: boolean
}

/** Live balance probe; pass result_id / high_value to persist onto stored rows. */
export interface BalanceRequest {
  apikey: string
  apiurl?: string
  result_id?: number
  high_value?: boolean
}

export interface ModelsResponse {
  models: string[]
  status_code: number | null
  provider: string
  key_state: "active" | "expired" | "rate_limited" | "invalid_response" | "unavailable"
  error: string
  expired: boolean
  high_value_removed: boolean
}

export interface BalanceResponse {
  gateway: string
  balance_usd: string
  tier: string
  detail: Record<string, unknown>
  persisted?: boolean
  result_id?: number | null
  high_value_updated?: boolean
  key_state?: "expired"
  expired?: boolean
  high_value_removed?: boolean
}

export interface BatchBalanceResponse {
  requested: number
  succeeded: number
  failed: number
  results: Array<{
    result_id: number
    ok: boolean
    balance?: BalanceResponse
    error?: string
  }>
}

export interface ChatRequest {
  apikey: string
  apiurl?: string
  model: string
}

export interface ChatResponse {
  success: boolean
  status_code: number | null
  model: string
  snippet: string
  error: string
  consumes_credit: boolean
}

export interface RevealRequest {
  run_id: string
  masked?: string
  apiurl?: string
  index?: number
  kind: ResultKind
}

export interface RevealResponse {
  apikey: string
  apiurl: string
}

export interface ExportRequest {
  dataset: ExportDataset
  format?: ExportFormat
  run_id?: string
  kind?: ResultKind
  /** For dataset="selected": 0-based indices into the run file (server reads plaintext). */
  indices?: number[]
  /** Legacy path for dataset="selected": explicit plaintext key rows. */
  keys?: KeyRef[]
}

export interface ScanProgress {
  raw_hits: number
  unique_targets: number
  candidates: number
  active_requests: number
  final_verified: number
  suspicious: number
  high_value_final: number
  valid: number
  total: number
}

export type ScanState = "idle" | "running" | "stopping" | "finished" | "interrupted"

export interface ScanStatusResponse {
  state: ScanState | string
  source: string | null
  mode: ScanMode
  github_pack_ids: GitHubPackId[]
  /** FOFA/Shodan hostname enrich for manual scans (empty otherwise). */
  manual_enrich?: ManualEnrichEngine[]
  run_id: string | null
  started_at: string | null
  finished_at: string | null
  progress: ScanProgress
  /** Coarse human-readable stage, e.g. "GitHub · cohere · file history 12/300". */
  phase?: string
  error: string | null
  log_seq: number
}

export interface ScanLogLine {
  seq: number
  line: string
}

export interface ScanLogsResponse {
  lines: ScanLogLine[]
  last_seq: number
}

export interface CveSyncResponse {
  total: number
  added: number
}

export interface CveAddRequest {
  url?: string
  id?: string
  product?: string
  type?: string
  description?: string
  cvss?: number
  huntable?: string
}

export interface CveAddResponse {
  created: boolean
  total: number
  cve: CveRecord
}

export interface SettingsView {
  fofa_keys: string
  fofa_base_url: string
  fofa_page_size: number
  fofa_max_pages: number
  fofa_timeout: number
  shodan_keys: string
  shodan_base_url: string
  shodan_max_pages: number
  shodan_timeout: number
  shodan_page_delay: number
  github_tokens: string
  github_api_base_url: string
  github_hunter_enabled: boolean
  validate_concurrency: number
  prober_concurrency: number
}

export type SettingsUpdate = Partial<SettingsView>

export interface SettingsUpdateResponse {
  updated: string[]
  hot_reloaded: string[]
  restart_required: string[]
  settings: SettingsView
}

export interface FofaCheckResponse {
  status: "ok" | "quota_exhausted" | "invalid"
  message: string
  consumes_quota: boolean
}

export interface ShodanKeyInfo {
  key_masked: string
  plan: string
  query_credits: number
  alive: boolean
}

export interface ShodanCheckResponse {
  keys: ShodanKeyInfo[]
  total_query_credits: number
  n_keys: number
  n_dead: number
  consumes_quota: boolean
}

export interface GithubCheckResponse {
  status: "ok" | "invalid" | "disabled"
  message: string
  core_remaining: number | null
  search_remaining: number | null
  code_search_remaining: number | null
  n_tokens: number
}

/** Credential sub-object of a scan result record (models.py Credential). */
export interface Credential {
  apikey: string
  apiurl: string
  source: string
  source_type: string
  backend: string
  host: string
  ip: string
  port: string
  product: string
  raw_context: string
  leak_host: string
  routed_to_official: boolean
}

export interface ProviderInfo {
  provider: string
  validation_provider?: string
  category: string
  models_available: string[]
  models_verified: string[]
  balance_provider: string
  credential_issuer?: string
  issuer_evidence?: string
  served_model_families?: string[]
  evidence_source?: string
  evidence_kind?: string
  evidence_observed_at?: string
}

/**
 * A validated-key record (models.py ValidationResult). The backend returns the
 * raw JSONL dict, so extra fields may appear — kept open via the index signature.
 */
export interface KeyRecord {
  credential: Credential
  valid: boolean
  /** Provider state-machine status (preferred over bare valid). */
  validation_state?: string
  credential_kind?: string
  scope?: string
  tier_evidence?: string
  status_code: number | null
  error: string
  tier: string
  gateway: string
  balance: string
  rate_limit_headers: Record<string, string>
  model_available: string
  response_snippet: string
  provider_info: ProviderInfo
  provider_evidence?: ProviderEvidence
  result_id?: number
  created_at?: string
  saved_at?: string
  validated_at: string
  suspicious: boolean
  suspicious_reason: string
  /** Originating run for cross-run aggregate lists (reveal/export). */
  source_run_id?: string
  source_index?: number
  manual_status?: KeyStatus
  [key: string]: unknown
}

export interface ProviderEvidence {
  provider?: string
  source?: string
  evidence_kind?: string
  balance_usd?: string | number
  balance_native?: string | number
  currency?: string
  plan?: string
  tier?: string
  account_type?: string
  quota?: Record<string, unknown>
  usage?: Record<string, unknown>
  entitlements?: Record<string, unknown>
  identity?: Record<string, unknown>
  observed_at?: string
  detail?: Record<string, unknown>
}


export type KeyStatus = "valid" | "suspicious" | "unavailable"

export interface TransitionKeysResponse {
  transitioned: number[]
  skipped: number[]
}

export interface DeleteRunResponse {
  run_id: string
  deleted: boolean
  disk_removed: boolean
}

export interface AllKeysResponse {
  kind: ResultKind
  results: KeyRecord[]
}

export interface RunSummary {
  run_id: string
  started_at: string
  valid_count: number
  suspicious_count: number
  has_log: boolean
  raw_hits: number
  unique_targets: number
  candidates: number
  active_requests: number
  final_verified: number
  suspicious: number
  sources: string[]
  scan_mode: ScanMode
  high_value_final: number
  deletable: boolean
}

export interface RunDay {
  day: string
  runs: RunSummary[]
}

export interface RunsResponse {
  days: RunDay[]
}

export interface RunResultsResponse {
  run_id: string
  results: KeyRecord[]
}

export interface GptFailedFileInfo {
  name: string
  hits: number
  batch_idx: number | null
}

export interface RetryGptFailedReport {
  run_id: string
  failed_files: number
  failed_hits: number
  credentials_found: number
  valid_appended: number
  suspicious_appended: number
  high_value_final: number
  archived_files: string[]
  jsonl_paths: string[]
  message: string
}

export interface RetryGptFailedJobStatus {
  state: "idle" | "running" | "finished" | "error" | string
  run_id: string | null
  started_at: string | null
  finished_at: string | null
  error: string | null
  report: RetryGptFailedReport | null
}

export interface GptFailedStatusResponse {
  run_id: string
  failed_files: number
  failed_hits: number
  files: GptFailedFileInfo[]
  retry: RetryGptFailedJobStatus
}

export interface HighValueResponse {
  results: KeyRecord[]
}

/** CVE records are loose dicts from the backend. */
export type CveRecord = Record<string, unknown>

export interface CveResponse {
  cves: CveRecord[]
}

export type HoneypotSource = "auto" | "manual" | string

export interface HoneypotSite {
  host_key: string
  host: string
  reason: string
  source: HoneypotSource
  first_seen: string
  last_seen: string
  hit_count: number
  run_id: string
  notes: string
  member_count?: number
}

export interface HoneypotListResponse {
  results: HoneypotSite[]
  total: number
  limit: number
  offset: number
}

export interface HoneypotCreateRequest {
  host: string
  reason?: string
  notes?: string
}

export interface HoneypotUpdateRequest {
  host_key: string
  reason?: string | null
  notes?: string | null
}

export interface ManualTarget {
  url: string
  host_key: string
  scheme: string
  hostname: string
  port: number
  enabled: boolean
  notes: string
  first_seen: string
  last_seen: string
}

export interface ManualTargetListResponse {
  results: ManualTarget[]
  total: number
  limit: number
  offset: number
}

export interface ManualTargetBulkRequest {
  urls: string
  notes?: string
  replace?: boolean
}

export interface ManualTargetBulkResponse {
  added: number
  updated: number
  rejected: string[]
  targets: ManualTarget[]
}

/* ------------------------------------------------------------------ */
/* Core request machinery                                              */
/* ------------------------------------------------------------------ */

export class ApiError extends Error {
  status: number
  code: string

  constructor(message: string, status: number, code: string) {
    super(message)
    this.name = "ApiError"
    this.status = status
    this.code = code
  }
}

type UnauthorizedHandler = () => void
let onUnauthorized: UnauthorizedHandler | null = null

/** Register a callback invoked whenever the API returns 401 (token cleared). */
export function setUnauthorizedHandler(handler: UnauthorizedHandler | null): void {
  onUnauthorized = handler
}

function authHeaders(extra?: HeadersInit): Headers {
  const headers = new Headers(extra)
  const token = getToken()
  if (token) headers.set("Authorization", `Bearer ${token}`)
  return headers
}

async function parseError(res: Response): Promise<ApiError> {
  let message = res.statusText || "request failed"
  let code = "http_error"
  try {
    const body = (await res.json()) as { error?: { code?: string; message?: string } }
    if (body?.error) {
      message = body.error.message ?? message
      code = body.error.code ?? code
    }
  } catch {
    /* non-JSON error body */
  }
  return new ApiError(message, res.status, code)
}

async function handle<T>(res: Response): Promise<T> {
  if (res.status === 401) {
    clearToken()
    onUnauthorized?.()
    throw await parseError(res)
  }
  if (!res.ok) throw await parseError(res)
  if (res.status === 204) return undefined as T
  const contentType = res.headers.get("content-type") ?? ""
  if (contentType.includes("application/json")) return (await res.json()) as T
  return (await res.text()) as unknown as T
}

interface RequestOptions {
  method?: string
  body?: unknown
  signal?: AbortSignal
}

async function request<T>(path: string, options: RequestOptions = {}): Promise<T> {
  const { method = "GET", body, signal } = options
  const headers = authHeaders()
  if (body !== undefined) headers.set("Content-Type", "application/json")
  const res = await fetch(`/api${path}`, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
    signal,
  })
  return handle<T>(res)
}

/* ------------------------------------------------------------------ */
/* File download helper (export)                                       */
/* ------------------------------------------------------------------ */

function filenameFromDisposition(header: string | null, fallback: string): string {
  if (!header) return fallback
  const utf8 = header.match(/filename\*=UTF-8''([^;]+)/i)
  if (utf8?.[1]) return decodeURIComponent(utf8[1])
  const plain = header.match(/filename="?([^";]+)"?/i)
  return plain?.[1] ?? fallback
}

function triggerBlobDownload(blob: Blob, filename: string): void {
  const url = URL.createObjectURL(blob)
  const link = document.createElement("a")
  link.href = url
  link.download = filename
  document.body.appendChild(link)
  link.click()
  link.remove()
  URL.revokeObjectURL(url)
}

/* ------------------------------------------------------------------ */
/* SSE helper (scan logs stream)                                       */
/* ------------------------------------------------------------------ */

export interface ScanStreamHandlers {
  onLog?: (line: ScanLogLine) => void
  onStatus?: (state: string) => void
  onError?: (event: Event) => void
}

/**
 * Open a native EventSource against the scan-log stream. The bearer token is
 * passed as a `token` query param because EventSource cannot set headers.
 * Returns the EventSource so callers can `.close()` it on cleanup.
 */
export function openScanLogStream(since: number, handlers: ScanStreamHandlers): EventSource {
  const params = new URLSearchParams({ since: String(since) })
  const token = getToken()
  if (token) params.set("token", token)
  const source = new EventSource(`/api/scan/logs/stream?${params.toString()}`)

  source.addEventListener("log", (event) => {
    const messageEvent = event as MessageEvent<string>
    handlers.onLog?.({ seq: Number(messageEvent.lastEventId) || 0, line: messageEvent.data })
  })
  source.addEventListener("status", (event) => {
    handlers.onStatus?.((event as MessageEvent<string>).data)
  })
  source.onerror = (event) => handlers.onError?.(event)

  return source
}

/* ------------------------------------------------------------------ */
/* Public API surface                                                  */
/* ------------------------------------------------------------------ */

export const api = {
  // Auth
  login: (password: string) =>
    request<LoginResponse>("/auth/login", { method: "POST", body: { password } }),
  logout: () => request<{ ok: boolean }>("/auth/logout", { method: "POST" }),

  // Runs
  getRuns: () => request<RunsResponse>("/runs"),
  getRunResults: (runId: string, kind: ResultKind) =>
    request<RunResultsResponse>(`/runs/${runId}/${kind}`),
  getRunCandidates: (runId: string) =>
    request<RunResultsResponse>(`/runs/${runId}/candidates`),
  deleteRun: (runId: string) =>
    request<DeleteRunResponse>(`/runs/${encodeURIComponent(runId)}`, { method: "DELETE" }),
  getRunLog: (runId: string) => request<string>(`/runs/${runId}/log`),
  getGptFailed: (runId: string) =>
    request<GptFailedStatusResponse>(`/runs/${runId}/gpt-failed`),
  retryGptFailed: (runId: string) =>
    request<RetryGptFailedJobStatus>(`/runs/${runId}/retry-gpt-failed`, { method: "POST" }),

  // High-value
  getHighValue: () => request<HighValueResponse>("/high-value"),
  highValueReveal: (body: { masked: string; apiurl?: string }) =>
    request<RevealResponse>("/high-value/reveal", { method: "POST", body }),

  // Cross-run keys (deduped valid / suspicious)
  getAllKeys: (kind: ResultKind) => request<AllKeysResponse>(`/keys/${kind}`),
  transitionKeys: (resultIds: number[], status: KeyStatus, note = "") =>
    request<TransitionKeysResponse>("/keys/status", {
      method: "POST",
      body: { result_ids: resultIds, status, note },
    }),

  // Single-key testing
  keyModels: (body: KeyRef) => request<ModelsResponse>("/key/models", { method: "POST", body }),
  keyBalance: (body: BalanceRequest) =>
    request<BalanceResponse>("/key/balance", { method: "POST", body }),
  keysBalance: (resultIds: number[], provider: string) =>
    request<BatchBalanceResponse>("/keys/balance", {
      method: "POST",
      body: { result_ids: resultIds, provider },
    }),
  keyChat: (body: ChatRequest) => request<ChatResponse>("/key/chat", { method: "POST", body }),
  keyReveal: (body: RevealRequest) => request<RevealResponse>("/key/reveal", { method: "POST", body }),

  // Export (file download)
  async export(body: ExportRequest): Promise<void> {
    const res = await fetch("/api/export", {
      method: "POST",
      headers: authHeaders({ "Content-Type": "application/json" }),
      body: JSON.stringify(body),
    })
    if (res.status === 401) {
      clearToken()
      onUnauthorized?.()
      throw await parseError(res)
    }
    if (!res.ok) throw await parseError(res)
    const blob = await res.blob()
    const fallback = `aipocket-export.${body.format === "sub2api" ? "sub2api.json" : body.format ?? "json"}`
    triggerBlobDownload(blob, filenameFromDisposition(res.headers.get("content-disposition"), fallback))
  },

  // Scan
  scanStart: (
    source: ScanSource,
    mode: ScanMode,
    githubPackIds: readonly GitHubPackId[] = [],
    sources: readonly ScanSourceItem[] = [],
    manualEnrich: readonly ManualEnrichEngine[] = [],
    resumeRunId = "",
  ) =>
    request<ScanStatusResponse>("/scan/start", {
      method: "POST",
      body: {
        source,
        // Multi-select list; backend prefers this over single `source` when non-empty.
        sources: sources.length > 0 ? [...sources] : undefined,
        mode,
        github_pack_ids: githubPackIds,
        // Custom hunt: reverse-lookup stored hostnames on FOFA/Shodan.
        manual_enrich: manualEnrich.length > 0 ? [...manualEnrich] : undefined,
        resume_run_id: resumeRunId || undefined,
      },
    }),
  scanStop: () => request<ScanStatusResponse>("/scan/stop", { method: "POST" }),
  scanStatus: (signal?: AbortSignal) => request<ScanStatusResponse>("/scan/status", { signal }),
  scanLogs: (since = 0) => request<ScanLogsResponse>(`/scan/logs?since=${since}`),

  // CVE
  getCve: () => request<CveResponse>("/cve"),
  cveSync: () => request<CveSyncResponse>("/cve/sync", { method: "POST" }),
  cveAdd: (body: CveAddRequest) =>
    request<CveAddResponse>("/cve/add", { method: "POST", body }),

  // Honeypot site cache
  getHoneypots: (params?: { q?: string; source?: string; limit?: number; offset?: number }) => {
    const sp = new URLSearchParams()
    if (params?.q) sp.set("q", params.q)
    if (params?.source) sp.set("source", params.source)
    if (params?.limit != null) sp.set("limit", String(params.limit))
    if (params?.offset != null) sp.set("offset", String(params.offset))
    const qs = sp.toString()
    return request<HoneypotListResponse>(`/honeypot${qs ? `?${qs}` : ""}`)
  },
  createHoneypot: (body: HoneypotCreateRequest) =>
    request<HoneypotSite>("/honeypot", { method: "POST", body }),
  updateHoneypot: (body: HoneypotUpdateRequest) =>
    request<HoneypotSite>("/honeypot", { method: "PATCH", body }),
  deleteHoneypot: (hostKey: string) =>
    request<{ ok: boolean; host_key: string }>(
      `/honeypot?host_key=${encodeURIComponent(hostKey)}`,
      { method: "DELETE" },
    ),
  bulkDeleteHoneypots: (hostKeys: string[]) =>
    request<{ deleted: number }>("/honeypot/bulk-delete", {
      method: "POST",
      body: { host_keys: hostKeys },
    }),

  // Manual scan targets (relay / gateway URLs for source=manual)
  getManualTargets: (params?: { enabled_only?: boolean; limit?: number; offset?: number }) => {
    const sp = new URLSearchParams()
    if (params?.enabled_only) sp.set("enabled_only", "true")
    if (params?.limit != null) sp.set("limit", String(params.limit))
    if (params?.offset != null) sp.set("offset", String(params.offset))
    const qs = sp.toString()
    return request<ManualTargetListResponse>(`/manual-targets${qs ? `?${qs}` : ""}`)
  },
  saveManualTargets: (body: ManualTargetBulkRequest) =>
    request<ManualTargetBulkResponse>("/manual-targets", { method: "POST", body }),
  deleteManualTarget: (url: string) =>
    request<{ deleted: number }>(
      `/manual-targets?url=${encodeURIComponent(url)}`,
      { method: "DELETE" },
    ),
  bulkDeleteManualTargets: (urls: string[]) =>
    request<{ deleted: number }>("/manual-targets/bulk-delete", {
      method: "POST",
      body: { urls },
    }),

  // Settings
  getSettings: () => request<SettingsView>("/settings"),
  updateSettings: (body: SettingsUpdate) =>
    request<SettingsUpdateResponse>("/settings", { method: "PUT", body }),
  checkFofa: () => request<FofaCheckResponse>("/settings/check/fofa", { method: "POST" }),
  checkShodan: () => request<ShodanCheckResponse>("/settings/check/shodan", { method: "POST" }),
  checkGithub: () => request<GithubCheckResponse>("/settings/check/github", { method: "POST" }),

  // System
  systemRestart: () => request<{ restarting: boolean }>("/system/restart", { method: "POST" }),
}

export type ApiClient = typeof api
