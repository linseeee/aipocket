import { useMemo, useState } from "react"
import { useNavigate } from "react-router-dom"
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { Clock3, FileText, Inbox, Loader2, Plus, Search, Trash2 } from "lucide-react"
import { toast } from "sonner"
import { api, type RunDay, type RunSummary } from "@/lib/api"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { RunLogDialog } from "@/components/run-log-dialog"
import { cn } from "@/lib/utils"

const WEEKDAYS = ["周日", "周一", "周二", "周三", "周四", "周五", "周六"]

function formatDay(day: string): string {
  const date = new Date(`${day}T00:00:00`)
  if (Number.isNaN(date.getTime())) return day
  return `${day} · ${WEEKDAYS[date.getDay()]}`
}

function formatTime(iso: string): string {
  const date = new Date(iso)
  if (Number.isNaN(date.getTime())) return "--:--"
  const pad = (value: number) => String(value).padStart(2, "0")
  return `${pad(date.getHours())}:${pad(date.getMinutes())}`
}

const SOURCE_DOT: Record<string, string> = {
  fofa: "bg-info",
  shodan: "bg-warning",
  github: "bg-success",
}

function SourceBadge({ source }: Readonly<{ source: string }>) {
  const dot = SOURCE_DOT[source] ?? "bg-text-muted"
  return (
    <span className="inline-flex items-center gap-1.5 rounded-sm bg-surface-overlay px-2 py-[3px] font-mono text-[11px] text-text-secondary">
      <span className={cn("size-1.5 shrink-0 rounded-full", dot)} />
      {source}
    </span>
  )
}

function Stat({
  value,
  label,
  className,
}: Readonly<{ value: number; label: string; className: string }>) {
  return (
    <div className="flex min-w-[58px] flex-col items-end gap-0.5 max-sm:items-start">
      <span className={cn("font-mono text-lg font-semibold tabular-nums", className)}>{value}</span>
      <span className="font-mono text-[11px] text-text-muted">{label}</span>
    </div>
  )
}

function RunRow({
  run,
  onDelete,
  onLog,
  deleting,
}: Readonly<{
  run: RunSummary
  onDelete: (run: RunSummary) => void
  onLog: (run: RunSummary) => void
  deleting: boolean
}>) {
  const navigate = useNavigate()
  return (
    <div className="group flex flex-col gap-3 rounded-md border border-border-primary bg-surface-raised p-4 transition-colors hover:bg-surface-overlay sm:flex-row sm:items-center sm:gap-[18px] sm:px-[18px] [content-visibility:auto] [contain-intrinsic-size:auto_112px]">
      <button
        type="button"
        onClick={() => navigate(`/runs/${run.run_id}`)}
        className="flex min-w-0 flex-1 flex-col gap-3 text-left focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring/50 sm:flex-row sm:items-center sm:gap-[18px]"
      >
        <div className="flex min-w-0 flex-1 flex-col gap-1.5 sm:w-[300px] sm:shrink-0 sm:flex-none lg:w-[340px]">
          <div className="flex items-center gap-2.5">
            <Clock3 className="size-3.5 text-text-muted" />
            <span className="font-mono text-[15px] font-semibold text-text-primary">{formatTime(run.started_at)}</span>
          </div>
          <span className="truncate font-mono text-[11px] text-text-muted">{run.run_id}</span>
        </div>
        <div className="flex flex-wrap gap-1.5 sm:w-[150px] sm:shrink-0">
          {run.sources.length > 0 ? run.sources.map((source) => <SourceBadge key={source} source={source} />) : <span className="font-mono text-[11px] text-text-muted">—</span>}
        </div>
        <div className="grid w-full grid-cols-3 gap-3 sm:flex sm:flex-1 sm:items-center sm:justify-end sm:gap-4 lg:gap-7">
          <Stat value={run.raw_hits} label="原始命中" className="text-text-secondary" />
          <Stat value={run.unique_targets} label="唯一目标" className="text-text-secondary" />
          <Stat value={run.candidates} label="候选密钥" className="text-text-secondary" />
          <Stat value={run.final_verified} label="最终可用" className="text-success" />
          <Stat value={run.suspicious_count} label="可疑" className="text-info" />
          <Stat value={run.high_value_final} label="高价值" className="text-warning" />
        </div>
      </button>
      <div className="flex shrink-0 items-center justify-end gap-1 self-stretch border-t border-border-subtle pt-3 sm:self-auto sm:border-l sm:border-t-0 sm:pl-3 sm:pt-0">
        <Button
          variant="ghost"
          size="sm"
          className="text-text-secondary hover:text-text-primary"
          onClick={() => onLog(run)}
          aria-label={`查看 ${run.run_id} 日志`}
        >
          <FileText />
          日志
        </Button>
        {run.deletable ? (
          <Button
            variant="ghost"
            size="sm"
            className="text-text-muted hover:bg-danger-dim hover:text-danger"
            disabled={deleting}
            onClick={() => onDelete(run)}
            aria-label={`删除 ${run.run_id}`}
          >
            {deleting ? <Loader2 className="animate-spin" /> : <Trash2 />}
            删除
          </Button>
        ) : null}
      </div>
    </div>
  )
}

function StateMessage({ children }: Readonly<{ children: React.ReactNode }>) {
  return <div className="flex flex-col items-center gap-3 py-24 text-center">{children}</div>
}

function HistoryContent({
  isPending,
  isError,
  error,
  days,
  hasSearch,
  onScan,
  onLog,
  onDelete,
  deletingRunId,
}: Readonly<{
  isPending: boolean
  isError: boolean
  error: unknown
  days: RunDay[]
  hasSearch: boolean
  onScan: () => void
  onDelete: (run: RunSummary) => void
  onLog: (run: RunSummary) => void
  deletingRunId: string
}>) {
  if (isPending) {
    return (
      <div className="flex items-center justify-center gap-2 py-24 text-text-muted">
        <Loader2 className="size-4 animate-spin" />
        <span className="font-mono text-sm">加载扫描记录…</span>
      </div>
    )
  }

  if (isError) {
    return (
      <StateMessage>
        <span className="text-sm text-danger">加载失败</span>
        <span className="font-mono text-xs text-text-muted">
          {error instanceof Error ? error.message : "无法获取扫描记录"}
        </span>
      </StateMessage>
    )
  }

  if (days.length === 0) {
    return (
      <StateMessage>
        <Inbox className="size-8 text-text-muted" />
        <span className="text-sm text-text-secondary">
          {hasSearch ? "没有匹配的扫描记录" : "尚无扫描记录"}
        </span>
        {hasSearch ? null : (
          <Button variant="outline" size="sm" onClick={onScan}>
            <Plus />
            开始首次扫描
          </Button>
        )}
      </StateMessage>
    )
  }

  return (
    <div className="flex flex-col gap-7">
      {days.map((day) => (
        <section key={day.day} className="flex flex-col gap-3">
          <div className="flex items-center gap-2.5">
            <span className="font-mono text-[13px] font-semibold text-text-secondary">
              {formatDay(day.day)}
            </span>
            <span className="h-px flex-1 bg-border-subtle" />
          </div>
          <div className="flex flex-col gap-3">
            {day.runs.map((run) => (
              <RunRow
                key={run.run_id}
                run={run}
                onDelete={onDelete}
                onLog={onLog}
                deleting={deletingRunId === run.run_id}
              />
            ))}
          </div>
        </section>
      ))}
    </div>
  )
}

export default function HistoryPage() {
  const navigate = useNavigate()
  const queryClient = useQueryClient()
  const [deletingRunId, setDeletingRunId] = useState("")
  const [logRun, setLogRun] = useState<RunSummary | null>(null)
  const logQuery = useQuery({
    queryKey: ["run", logRun?.run_id, "log"],
    queryFn: () => api.getRunLog(logRun!.run_id),
    enabled: logRun !== null,
  })
  const deleteMutation = useMutation({
    mutationFn: api.deleteRun,
    onSuccess: async () => {
      toast.success("空扫描已删除")
      await queryClient.invalidateQueries({ queryKey: ["runs"] })
    },
    onError: (error) => toast.error(error instanceof Error ? error.message : "删除失败"),
    onSettled: () => setDeletingRunId(""),
  })

  const deleteEmptyRun = (run: RunSummary) => {
    const confirmed = window.confirm(
      `删除 ${run.run_id}？将级联删除该 run 的日志、候选和 HTTP ledger。`,
    )
    if (!confirmed) return
    setDeletingRunId(run.run_id)
    deleteMutation.mutate(run.run_id)
  }
  const [query, setQuery] = useState("")
  const { data, isPending, isError, error } = useQuery({
    queryKey: ["runs"],
    queryFn: () => api.getRuns(),
  })

  const needle = query.trim().toLowerCase()
  const { days, totalRuns } = useMemo(() => {
    const filtered = (data?.days ?? [])
      .map((day) => ({
        ...day,
        runs:
          needle.length === 0
            ? day.runs
            : day.runs.filter((run) => run.run_id.toLowerCase().includes(needle)),
      }))
      .filter((day) => day.runs.length > 0)
    return { days: filtered, totalRuns: filtered.reduce((sum, day) => sum + day.runs.length, 0) }
  }, [data, needle])

  return (
    <div className="flex h-full min-h-0 flex-col">
      <header className="flex flex-col gap-3 border-b border-border-primary px-4 py-4 sm:flex-row sm:items-center sm:gap-4 sm:px-6 md:px-8 md:py-5">
        <div className="flex flex-1 flex-col gap-0.5">
          <h1 className="text-xl font-semibold tracking-[-0.3px] text-text-primary">扫描历史</h1>
          <p className="font-mono text-xs text-text-muted">共 {totalRuns} 次扫描 · 按日期分组</p>
        </div>

        <div className="relative flex w-full items-center sm:w-auto">
          <Search className="pointer-events-none absolute left-3 size-[15px] text-text-muted" />
          <Input
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            placeholder="搜索 run / host…"
            className="w-full border-border-primary bg-surface-raised pl-9 text-[13px] dark:bg-surface-raised sm:w-[260px]"
          />
        </div>

        <Button className="min-h-11 sm:min-h-9" onClick={() => navigate("/scan")}>
          <Plus />
          执行扫描
        </Button>
      </header>

      <div className="flex-1 overflow-y-auto px-4 py-4 sm:px-6 md:px-8 md:py-6">
        <HistoryContent
          isPending={isPending}
          isError={isError}
          error={error}
          days={days}
          hasSearch={needle.length > 0}
          onScan={() => navigate("/scan")}
          onDelete={deleteEmptyRun}
          onLog={setLogRun}
          deletingRunId={deletingRunId}
        />
      </div>
      <RunLogDialog
        runId={logRun?.run_id ?? ""}
        open={logRun !== null}
        onOpenChange={(open) => {
          if (!open) setLogRun(null)
        }}
        log={logQuery.data}
        loading={logQuery.isLoading}
        error={logQuery.error}
      />
    </div>
  )
}
