import { useCallback, useEffect, useMemo, useRef, useState } from "react"
import { Link, useParams } from "react-router-dom"
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { ArrowLeft, FileText, Loader2, RotateCcw } from "lucide-react"
import { toast } from "sonner"
import {
  api,
  type ChatResponse,
  type ExportFormat,
  type KeyRecord,
  type ResultKind,
} from "@/lib/api"
import { ChatTestDialog } from "@/components/chat-test-dialog"
import { KeyListToolbar, useKeyListView } from "@/components/key-list-filters"
import { BulkBar, CenterState, IndexedKeyRow, KeyPagination, KeyTableHeader } from "@/components/key-table"
import { useKeyTableSizing } from "@/components/key-table-columns"
import { extractKeyFields, formatBalance } from "@/components/key-record"
import { Button } from "@/components/ui/button"
import { RunLogDialog } from "@/components/run-log-dialog"
import { cn, copyToClipboard } from "@/lib/utils"

type Revealed = { apikey: string; apiurl: string }
type RowBusy = { models?: boolean; balance?: boolean; chat?: boolean }
type BalanceInfo = { balance?: string; tier?: string }

const KINDS: ResultKind[] = ["valid", "suspicious", "candidates"]

function rowKeyOf(kind: ResultKind, index: number): string {
  return `${kind}:${index}`
}

function runIdToLabel(runId: string): string {
  const m = /^run_(\d{4})_(\d{2})_(\d{2})_(\d{2})-(\d{2})-(\d{2})$/.exec(runId)
  if (!m) return runId
  const [, y, mo, d, h, mi] = m
  return `${y}-${mo}-${d} ${h}:${mi}`
}

function isoToLabel(iso: string): string {
  const parsed = new Date(iso)
  if (Number.isNaN(parsed.getTime())) return ""
  const pad = (n: number) => String(n).padStart(2, "0")
  return `${parsed.getFullYear()}-${pad(parsed.getMonth() + 1)}-${pad(parsed.getDate())} ${pad(parsed.getHours())}:${pad(parsed.getMinutes())}`
}

export default function RunResultsPage() {
  const { runId } = useParams<{ runId: string }>()
  const queryClient = useQueryClient()
  const [kind, setKind] = useState<ResultKind>("valid")
  const [selected, setSelected] = useState<Set<number>>(new Set())
  const [revealed, setRevealed] = useState<Record<string, Revealed>>({})
  const [models, setModels] = useState<Record<string, string[]>>({})
  const [balances, setBalances] = useState<Record<string, BalanceInfo>>({})
  const [expanded, setExpanded] = useState<Set<string>>(new Set())
  const [busy, setBusy] = useState<Record<string, RowBusy>>({})
  const [exporting, setExporting] = useState(false)
  const [chatIndex, setChatIndex] = useState<number | null>(null)
  const [chatResult, setChatResult] = useState<ChatResponse | null>(null)
  const [logOpen, setLogOpen] = useState(false)
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(50)
  /** Local flag so the button stays busy between POST and first poll. */
  const [retryStarting, setRetryStarting] = useState(false)
  /**
   * Only toast when a retry finishes during *this page session*.
   * Backend keeps the last job as state=finished forever, so toasting on any
   * finished snapshot would re-fire every time the user re-enters the page.
   * Armed when the user starts a retry, or when we observe state=running.
   */
  const toastOnRetryFinishRef = useRef(false)

  const actionWidth = 280
  const { table, columnSizeVars, sizingContainerRef } = useKeyTableSizing(actionWidth)

  const validQuery = useQuery({
    queryKey: ["run", runId, "valid"],
    queryFn: () => api.getRunResults(runId!, "valid"),
    enabled: Boolean(runId),
  })
  const suspiciousQuery = useQuery({
    queryKey: ["run", runId, "suspicious"],
    queryFn: () => api.getRunResults(runId!, "suspicious"),
    enabled: Boolean(runId),
  })
  const candidatesQuery = useQuery({
    queryKey: ["run", runId, "candidates"],
    queryFn: () => api.getRunCandidates(runId!),
    enabled: Boolean(runId),
  })
  const runsQuery = useQuery({ queryKey: ["runs"], queryFn: api.getRuns })
  const logQuery = useQuery({
    queryKey: ["run", runId, "log"],
    queryFn: () => api.getRunLog(runId!),
    enabled: Boolean(runId) && logOpen,
  })
  const gptFailedQuery = useQuery({
    queryKey: ["run", runId, "gpt-failed"],
    queryFn: () => api.getGptFailed(runId!),
    enabled: Boolean(runId),
    refetchInterval: (q) => {
      const state = q.state.data?.retry?.state
      return state === "running" ? 2000 : false
    },
  })

  const activeQuery =
    kind === "valid" ? validQuery : kind === "suspicious" ? suspiciousQuery : candidatesQuery
  const records = useMemo<KeyRecord[]>(() => activeQuery.data?.results ?? [], [activeQuery.data])
  const validCount = validQuery.data?.results.length ?? 0
  const suspiciousCount = suspiciousQuery.data?.results.length ?? 0
  const candidatesCount = candidatesQuery.data?.results.length ?? 0

  const summary = useMemo(
    () => runsQuery.data?.days.flatMap((day) => day.runs).find((run) => run.run_id === runId),
    [runsQuery.data, runId],
  )

  const subtitle = useMemo(() => {
    if (!runId) return ""
    const time = (summary?.started_at && isoToLabel(summary.started_at)) || runIdToLabel(runId)
    const parts = [time]
    if (summary?.sources.length) parts.push(summary.sources.join(","))
    if (summary && summary.raw_hits > 0) parts.push(`命中 ${summary.raw_hits}`)
    return parts.join(" · ")
  }, [runId, summary])

  const balanceOverrides = useMemo(() => {
    const out: Record<number, string | undefined> = {}
    for (let i = 0; i < records.length; i++) {
      const b = balances[rowKeyOf(kind, i)]?.balance
      if (b) out[i] = b
    }
    return out
  }, [records.length, balances, kind])

  const listView = useKeyListView(records, balanceOverrides)
  const { rows } = listView
  const totalPages = Math.max(1, Math.ceil(rows.length / pageSize))
  const currentPage = Math.min(page, totalPages)
  const pageRows = useMemo(
    () => rows.slice((currentPage - 1) * pageSize, currentPage * pageSize),
    [rows, currentPage, pageSize],
  )

  const stateRef = useRef({ records, kind, revealed, models, rows: pageRows })
  stateRef.current = { records, kind, revealed, models, rows: pageRows }

  // Destructure the STABLE `mutateAsync` refs (the mutation objects themselves
  // change identity every render); depending on these keeps the row callbacks
  // stable so the memoized `IndexedKeyRow`s don't all re-render on any change.
  const { mutateAsync: revealAsync } = useMutation({
    mutationFn: (vars: { kind: ResultKind; index: number }) =>
      api.keyReveal({ run_id: runId!, kind: vars.kind, index: vars.index }),
  })
  const { mutateAsync: modelsAsync } = useMutation({ mutationFn: api.keyModels })
  const { mutateAsync: balanceAsync } = useMutation({ mutationFn: api.keyBalance })
  const { mutateAsync: chatAsync } = useMutation({ mutationFn: api.keyChat })

  const setRowBusy = useCallback((key: string, patch: RowBusy) => {
    setBusy((prev) => ({ ...prev, [key]: { ...prev[key], ...patch } }))
  }, [])

  const ensureRevealed = useCallback(
    async (index: number): Promise<Revealed> => {
      const { records: recs, kind: activeKind, revealed: cache } = stateRef.current
      const key = rowKeyOf(activeKind, index)
      const cached = cache[key]
      if (cached) return cached
      const fields = extractKeyFields(recs[index])
      const res = await revealAsync({ kind: activeKind, index })
      const value: Revealed = { apikey: res.apikey, apiurl: res.apiurl || fields.apiurl || "" }
      setRevealed((prev) => ({ ...prev, [key]: value }))
      return value
    },
    [revealAsync],
  )

  const errorMessage = (err: unknown, fallback: string) =>
    err instanceof Error ? err.message : fallback

  const handleReveal = useCallback(
    async (index: number) => {
      try {
        await ensureRevealed(index)
      } catch (err) {
        toast.error("显示密钥失败", { description: errorMessage(err, "无法读取明文密钥") })
      }
    },
    [ensureRevealed],
  )

  const handleCopy = useCallback(
    async (index: number) => {
      try {
        const { apikey } = await ensureRevealed(index)
        await copyToClipboard(apikey)
        toast.success("已复制密钥到剪贴板")
      } catch (err) {
        toast.error("复制失败", { description: errorMessage(err, "剪贴板不可用") })
      }
    },
    [ensureRevealed],
  )

  const loadModels = useCallback(
    async (index: number) => {
      const key = rowKeyOf(stateRef.current.kind, index)
      if (stateRef.current.records[index] === undefined) return
      setRowBusy(key, { models: true })
      try {
        const rec = stateRef.current.records[index]
        const { apikey, apiurl } = await ensureRevealed(index)
        const res = await modelsAsync({
          apikey,
          apiurl,
          result_id: typeof rec?.result_id === "number" ? rec.result_id : undefined,
        })
        setModels((prev) => ({ ...prev, [key]: res.models }))
        setExpanded((prev) => new Set(prev).add(key))
        if (res.key_state === "expired") {
          setSelected((prev) => {
            const next = new Set(prev)
            next.delete(index)
            return next
          })
          await Promise.all([
            queryClient.invalidateQueries({ queryKey: ["run", runId, stateRef.current.kind] }),
            queryClient.invalidateQueries({ queryKey: ["keys"] }),
            queryClient.invalidateQueries({ queryKey: ["high-value"] }),
            queryClient.invalidateQueries({ queryKey: ["runs"] }),
          ])
          toast.error("密钥已过期", { description: "Provider 返回认证失败，已自动移至不可用。" })
        } else if (res.models.length === 0) {
          toast.warning("未获取到模型", {
            description: res.key_state === "rate_limited" ? "Provider 当前限流，密钥状态未变。" : res.error,
          })
        }
      } catch (err) {
        setModels((prev) => ({ ...prev, [key]: [] }))
        toast.error("加载模型失败", { description: errorMessage(err, "无法获取模型列表") })
      } finally {
        setRowBusy(key, { models: false })
      }
    },
    [ensureRevealed, modelsAsync, queryClient, runId, setRowBusy],
  )

  const handleBalance = useCallback(
    async (index: number) => {
      const key = rowKeyOf(stateRef.current.kind, index)
      const rec = stateRef.current.records[index]
      setRowBusy(key, { balance: true })
      try {
        const { apikey, apiurl } = await ensureRevealed(index)
        const resultId = typeof rec?.result_id === "number" ? rec.result_id : undefined
        const res = await balanceAsync({
          apikey,
          apiurl,
          result_id: resultId,
        })
        if (res.key_state === "expired") {
          setSelected((prev) => {
            const next = new Set(prev)
            next.delete(index)
            return next
          })
          await Promise.all([
            queryClient.invalidateQueries({ queryKey: ["run", runId, stateRef.current.kind] }),
            queryClient.invalidateQueries({ queryKey: ["keys"] }),
            queryClient.invalidateQueries({ queryKey: ["high-value"] }),
            queryClient.invalidateQueries({ queryKey: ["runs"] }),
          ])
          toast.error("密钥已过期", { description: "余额接口返回认证失败，已自动移至不可用。" })
          return
        }
        const balanceLabel = formatBalance(res.balance_usd)
        const tierLabel = res.tier?.trim() || undefined
        setBalances((prev) => ({
          ...prev,
          [key]: { balance: balanceLabel, tier: tierLabel },
        }))
        if (runId && resultId != null) {
          queryClient.setQueryData<{ kind: ResultKind; results: KeyRecord[] }>(
            ["run", runId, stateRef.current.kind],
            (old) => {
              if (!old) return old
              return {
                ...old,
                results: old.results.map((r, i) =>
                  i === index || r.result_id === resultId
                    ? {
                        ...r,
                        balance: res.balance_usd || "",
                        tier: res.tier || r.tier,
                        gateway: res.gateway || r.gateway,
                        provider_evidence:
                          (res.detail as KeyRecord["provider_evidence"]) ?? r.provider_evidence,
                      }
                    : r,
                ),
              }
            },
          )
        }
        const detailParts = [
          res.gateway || "gateway",
          balanceLabel || "N/A",
          tierLabel,
          res.persisted ? "已落库" : undefined,
        ].filter(Boolean)
        toast.success("余额已更新", { description: detailParts.join(" · ") })
      } catch (err) {
        toast.error("查询余额失败", { description: errorMessage(err, "无法获取余额") })
      } finally {
        setRowBusy(key, { balance: false })
      }
    },
    [ensureRevealed, balanceAsync, setRowBusy, queryClient, runId],
  )

  const handleExpandedChange = useCallback(
    (index: number, isExpanded: boolean) => {
      const key = rowKeyOf(stateRef.current.kind, index)
      setExpanded((prev) => {
        const next = new Set(prev)
        if (isExpanded) next.add(key)
        else next.delete(key)
        return next
      })
    },
    [],
  )

  const handleSelectedChange = useCallback((index: number, checked: boolean) => {
    setSelected((prev) => {
      const next = new Set(prev)
      if (checked) next.add(index)
      else next.delete(index)
      return next
    })
  }, [])

  const handleToggleAll = useCallback((checked: boolean) => {
    const visible = stateRef.current.rows.map((r) => r.originalIndex)
    setSelected((prev) => {
      const next = new Set(prev)
      for (const i of visible) {
        if (checked) next.add(i)
        else next.delete(i)
      }
      return next
    })
  }, [])

  const openChat = useCallback(
    (index: number) => {
      setChatResult(null)
      setChatIndex(index)
      const key = rowKeyOf(stateRef.current.kind, index)
      if (stateRef.current.models[key] === undefined) void loadModels(index)
    },
    [loadModels],
  )

  const handleSendChat = useCallback(
    async (model: string) => {
      if (chatIndex === null) return
      const key = rowKeyOf(stateRef.current.kind, chatIndex)
      setRowBusy(key, { chat: true })
      try {
        const { apikey, apiurl } = await ensureRevealed(chatIndex)
        const res = await chatAsync({ apikey, apiurl, model })
        setChatResult(res)
        if (res.success) {
          toast.success(res.consumes_credit ? "对话成功（已消耗额度）" : "对话成功")
        } else {
          toast.error("对话失败", { description: res.error || `HTTP ${res.status_code ?? "?"}` })
        }
      } catch (err) {
        toast.error("对话请求失败", { description: errorMessage(err, "无法完成对话测试") })
      } finally {
        setRowBusy(key, { chat: false })
      }
    },
    [chatIndex, ensureRevealed, chatAsync, setRowBusy],
  )

  const switchKind = useCallback((next: ResultKind) => {
    setKind(next)
    setSelected(new Set())
    setPage(1)
  }, [])

  const gptFailed = gptFailedQuery.data
  const retryState = gptFailed?.retry?.state
  const retryRunning = retryState === "running" || retryStarting
  const failedHits = gptFailed?.failed_hits ?? 0
  const failedFiles = gptFailed?.failed_files ?? 0
  const showRetry = failedHits > 0 || retryRunning || retryState === "finished" || retryState === "error"

  // When a retry we are watching finishes, toast once and refresh lists.
  // Never toast for a stale finished/error snapshot from a previous visit.
  useEffect(() => {
    if (!runId || !gptFailed) return
    const job = gptFailed.retry
    if (job.run_id && job.run_id !== runId) return

    if (job.state === "running") {
      toastOnRetryFinishRef.current = true
      return
    }

    if (!toastOnRetryFinishRef.current) return
    if (job.state !== "finished" && job.state !== "error") return

    toastOnRetryFinishRef.current = false
    setRetryStarting(false)

    if (job.state === "error") {
      toast.error("重试 AI 失败批次出错", { description: job.error || "未知错误" })
      void queryClient.invalidateQueries({ queryKey: ["run", runId, "gpt-failed"] })
      return
    }
    const report = job.report
    if (!report) return
    const appended = report.valid_appended + report.suspicious_appended
    if (appended > 0) {
      toast.success("重试完成，结果已追加到数据库", {
        description:
          report.message ||
          `新增可用 ${report.valid_appended} · 疑似 ${report.suspicious_appended}`,
      })
      void queryClient.invalidateQueries({ queryKey: ["run", runId] })
      void queryClient.invalidateQueries({ queryKey: ["runs"] })
    } else {
      toast.message("重试完成", { description: report.message || "未新增可用密钥" })
    }
    void queryClient.invalidateQueries({ queryKey: ["run", runId, "gpt-failed"] })
  }, [gptFailed, runId, queryClient])

  // Switching runs must not inherit the previous run's "watch for toast" arm.
  useEffect(() => {
    toastOnRetryFinishRef.current = false
    setRetryStarting(false)
  }, [runId])

  const handleRetryGptFailed = useCallback(async () => {
    if (!runId || retryRunning) return
    setRetryStarting(true)
    toastOnRetryFinishRef.current = true
    try {
      await api.retryGptFailed(runId)
      toast.message("已开始重试 AI 失败批次", {
        description: `将处理 ${failedHits} 条失败命中，恢复结果追加写入数据库`,
      })
      await queryClient.invalidateQueries({ queryKey: ["run", runId, "gpt-failed"] })
    } catch (err) {
      setRetryStarting(false)
      toastOnRetryFinishRef.current = false
      toast.error("无法启动重试", { description: errorMessage(err, "请稍后重试") })
    }
  }, [runId, retryRunning, failedHits, queryClient])

  const runExport = useCallback(
    async (format: ExportFormat) => {
      if (!runId) return
      setExporting(true)
      const { records: recs, kind: activeKind } = stateRef.current
      const indices = [...selected]
      try {
        if (indices.length > 0) {
          // Export by index — the server reads the plaintext keys straight from
          // the run file, so they never round-trip through the browser.
          await api.export({ dataset: "selected", format, run_id: runId, kind: activeKind, indices })
          toast.success(`已导出 ${indices.length} 个所选密钥`)
        } else {
          await api.export({ dataset: "run", format, run_id: runId, kind: activeKind })
          toast.success(`已导出全部 ${recs.length} 个密钥`)
        }
      } catch (err) {
        toast.error("导出失败", { description: errorMessage(err, "无法生成导出文件") })
      } finally {
        setExporting(false)
      }
    },
    [runId, selected],
  )

  const visibleIndices = useMemo(() => pageRows.map((r) => r.originalIndex), [pageRows])
  const allChecked =
    visibleIndices.length > 0 && visibleIndices.every((i) => selected.has(i))

  const chatFields =
    chatIndex !== null && records[chatIndex] ? extractKeyFields(records[chatIndex]) : null

  let body: React.ReactNode
  if (activeQuery.isLoading) {
    body = (
      <CenterState>
        <Loader2 className="mr-2 size-4 animate-spin" />
        加载密钥中…
      </CenterState>
    )
  } else if (activeQuery.isError) {
    body = <CenterState className="text-danger">{errorMessage(activeQuery.error, "加载失败")}</CenterState>
  } else if (records.length === 0) {
    body = <CenterState>该分类暂无密钥。</CenterState>
  } else if (rows.length === 0) {
    body = <CenterState>无匹配结果，试试调整搜索或筛选条件。</CenterState>
  } else {
    body = (
      <div>
        {pageRows.map(({ fields, status, originalIndex }) => {
          const key = rowKeyOf(kind, originalIndex)
          const reveal = revealed[key]
          const balanceInfo = balances[key]
          return (
            <IndexedKeyRow
              key={key}
              index={originalIndex}
              maskedKey={fields.maskedKey}
              revealedKey={reveal?.apikey}
              apiurl={reveal?.apiurl ?? fields.apiurl}
              host={fields.host}
              provider={fields.provider}
              balance={balanceInfo?.balance ?? fields.balance}
              tier={balanceInfo?.tier ?? fields.tier}
              credentialKind={fields.credentialKind}
              validationState={fields.validationState}
              scope={fields.scope}
              tierEvidence={balanceInfo ? undefined : fields.tierEvidence}
              createdAt={fields.createdAt}
              evidence={fields.evidence}
              status={status}
              models={models[key]}
              modelsLoading={busy[key]?.models}
              selected={selected.has(originalIndex)}
              expanded={expanded.has(key)}
              busy={busy[key]}
              actionWidth={actionWidth}
              onSelectedChange={handleSelectedChange}
              onExpandedChange={handleExpandedChange}
              onReveal={handleReveal}
              onCopy={handleCopy}
              onLoadModels={kind === "candidates" ? undefined : loadModels}
              onBalance={kind === "candidates" ? undefined : handleBalance}
              onChat={kind === "candidates" ? undefined : openChat}
            />
          )
        })}
      </div>
    )
  }

  return (
    <div className="flex h-full min-h-0 flex-col">
      <div className="flex flex-col gap-3 border-b border-border-primary px-4 py-4 sm:gap-4 sm:px-6 md:px-8 md:py-[18px]">
        <div className="flex items-start gap-3 sm:items-center">
          <Link
            to="/history"
            className="inline-flex min-h-11 shrink-0 items-center gap-1.5 rounded-sm border border-border-primary bg-surface-raised px-2.5 py-1.5 font-sans text-[13px] text-text-secondary transition-colors hover:text-text-primary sm:min-h-0"
          >
            <ArrowLeft className="size-3.5" />
            返回历史
          </Link>
          <div className="flex min-w-0 flex-col gap-0.5">
            <h1 className="truncate font-mono text-lg font-semibold text-text-primary">{runId}</h1>
            <p className="truncate font-mono text-xs text-text-muted">{subtitle}</p>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          {KINDS.map((tabKind) => {
            const isActive = kind === tabKind
            const count =
              tabKind === "valid" ? validCount : tabKind === "suspicious" ? suspiciousCount : candidatesCount
            const label =
              tabKind === "valid" ? "可用密钥" : tabKind === "suspicious" ? "疑似" : "候选密钥"
            return (
              <button
                key={tabKind}
                type="button"
                onClick={() => switchKind(tabKind)}
                aria-pressed={isActive}
                className={cn(
                  "inline-flex items-center gap-2 rounded-sm border px-3.5 py-2 font-sans text-[13px] transition-colors",
                  isActive
                    ? "border-accent bg-accent-dim font-semibold text-accent"
                    : "border-border-primary bg-surface-raised text-text-secondary hover:text-text-primary",
                )}
              >
                {label}
                <span
                  className={cn(
                    "inline-flex min-w-5 justify-center rounded-full px-1.5 py-px font-mono text-[11px]",
                    isActive ? "bg-accent text-accent-text" : "bg-surface-overlay text-text-secondary",
                  )}
                >
                  {count}
                </span>
              </button>
            )
          })}
          {summary ? (
            <Button type="button" variant="outline" size="sm" onClick={() => setLogOpen(true)}>
              <FileText className="size-3.5" />
              运行日志
            </Button>
          ) : null}

          {showRetry ? (
            <div className="flex w-full flex-wrap items-center gap-2 sm:ml-auto sm:w-auto">
              {failedHits > 0 || retryRunning ? (
                <span className="font-mono text-[11px] text-warning">
                  AI 失败 {failedHits} 条
                  {failedFiles > 0 ? ` · ${failedFiles} 文件` : ""}
                  {retryRunning ? " · 重试中…" : ""}
                </span>
              ) : null}
              <Button
                type="button"
                variant="outline"
                size="sm"
                disabled={retryRunning || failedHits === 0}
                onClick={() => void handleRetryGptFailed()}
                title="重试本 run 中 GPT 分析失败的批次；恢复结果追加写入数据库"
              >
                {retryRunning ? (
                  <Loader2 className="size-3.5 animate-spin" />
                ) : (
                  <RotateCcw className="size-3.5" />
                )}
                {retryRunning ? "重试中…" : "重试 AI 失败"}
              </Button>
            </div>
          ) : null}
        </div>
      </div>

      <KeyListToolbar
        search={listView.search}
        onSearchChange={(value) => { listView.setSearch(value); setPage(1); setSelected(new Set()) }}
        provider={listView.provider}
        onProviderChange={(value) => { listView.setProvider(value); setPage(1); setSelected(new Set()) }}
        providers={listView.providers}
        balanceSort={listView.balanceSort}
        onBalanceSortChange={(value) => { listView.setBalanceSort(value); setPage(1); setSelected(new Set()) }}
        filteredCount={listView.filteredCount}
        total={listView.total}
        hasActiveFilters={listView.hasActiveFilters}
        onClear={() => { listView.clearFilters(); setPage(1); setSelected(new Set()) }}
      />

      <BulkBar
        selectedCount={visibleIndices.filter((index) => selected.has(index)).length}
        total={pageRows.length}
        allChecked={allChecked}
        onToggleAll={handleToggleAll}
        onExport={(format) => void runExport(format)}
        exporting={exporting}
      />

      {/* @container lets expanded KeyRow panels size to the scrollport (100cqw). */}
      <div ref={sizingContainerRef} className="@container min-h-0 flex-1 overflow-y-auto md:overflow-auto" style={columnSizeVars}>
        {/* Fill the viewport while preserving intrinsic width for horizontal overflow. */}
        <div className="w-full md:w-max md:min-w-full">
          <div className="sticky top-0 z-10">
            <KeyTableHeader table={table} actionWidth={actionWidth} />
          </div>
          {body}
        </div>
      </div>
      <KeyPagination
        page={currentPage}
        pageSize={pageSize}
        totalItems={rows.length}
        onPageChange={(nextPage) => { setPage(nextPage); setSelected(new Set()) }}
        onPageSizeChange={(nextPageSize) => { setPageSize(nextPageSize); setPage(1); setSelected(new Set()) }}
      />

      <ChatTestDialog
        open={chatIndex !== null}
        onOpenChange={(open) => setChatIndex(open ? chatIndex : null)}
        maskedKey={
          chatIndex !== null
            ? revealed[rowKeyOf(kind, chatIndex)]?.apikey ?? chatFields?.maskedKey ?? ""
            : ""
        }
        models={chatIndex !== null ? models[rowKeyOf(kind, chatIndex)] ?? [] : []}
        modelsLoading={chatIndex !== null ? busy[rowKeyOf(kind, chatIndex)]?.models : false}
        pending={chatIndex !== null ? busy[rowKeyOf(kind, chatIndex)]?.chat : false}
        result={chatResult}
        onSend={handleSendChat}
      />
      <RunLogDialog
        runId={runId ?? ""}
        open={logOpen}
        onOpenChange={setLogOpen}
        log={logQuery.data}
        loading={logQuery.isLoading}
        error={logQuery.error}
      />

    </div>
  )
}
