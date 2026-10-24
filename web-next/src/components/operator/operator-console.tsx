"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { useT } from "@/lib/i18n";
import {
  activeTask,
  operatorApi,
  operatorKey,
  operatorUnavailable,
  type Citation,
  type OperatorProposal,
  type OperatorTask,
  type ProposalAction,
} from "@/lib/operator-api";

const copy = {
  en: {
    targets: "Targets",
    udp: "UDP ports",
    intent: "Scan purpose",
    defaults: "Server default",
    policy: "Policy",
    scope: "Approved scope",
    effect: "Effect",
    network: "Network probes",
    details: "Technical details",
    yes: "Yes",
    no: "No",
    rateDiscovery: "Discovery rate ceiling (packets/s)",
    ratePorts: "Port rate ceiling (packets/s)",
    hostConcurrency: "Concurrent host ceiling",
    hostRate: "Per-host rate ceiling",
    avoidPorts: "Excluded ports",
    safeOnly: "Safe profile only",
    asynchronous: "Stopping is asynchronous",
    findingState: "Finding state",
    scopeApproval: "Scope approved",
    verifyMethod: "Verification method",
    compare: "Compare published runs",
    previous: "Previous run ID",
    current: "Current run ID",
    removal:
      "A missing observation is not proof that a vulnerability was fixed. Coverage and freshness still require review.",
    unavailable: "Operator is disabled or unavailable on this installation.",
    failed:
      "The request could not be completed. Recheck your session, permissions and service status.",
    loading: "Loading operator…",
    retry: "Refresh server state",
    tenant: "Tenant",
    actor: "Actor",
    runtime: "Runtime readiness has not been checked.",
    quality: "Model quality has not been accepted. Review every proposal and its evidence.",
    local: "Local provider configured; offline operation has not been verified.",
    hosted:
      "External inference is configured. Authorized task data may be sent to the configured provider.",
    history: "Personal sessions",
    newSession: "New session",
    chooseSession: "Select a session",
    noSessions: "No sessions yet.",
    analysis: "Analyze a published run",
    run: "Run ID",
    summary: "Summarize counts",
    categorize: "Analyze findings",
    submit: "Queue analysis",
    tasks: "Tasks and answers",
    noTasks: "No tasks in this session.",
    cancel: "Request cancellation",
    cancelling: "Cancellation requested; waiting for worker confirmation.",
    openSource: "Open authorized source",
    source: "Source evidence",
    preparation: "Prepare an action",
    action: "Action",
    start: "Start scan",
    stop: "Cancel scan",
    verify: "Verify finding",
    ranges: "IP ranges (one per line)",
    domains: "Domains (one per line)",
    ports: "TCP ports",
    mode: "Profile",
    group: "Sensor group (optional)",
    job: "Job ID",
    finding: "Finding ID",
    prepare: "Preview action",
    preview: "Review the exact plan",
    expiry: "Expires",
    hash: "Plan digest",
    impact: "Expected effect and constraints",
    acknowledge: "I reviewed this tenant, actor, targets, profile, limits and side effects.",
    confirm: "Confirm this plan",
    confirmPending:
      "Confirmation sent. Refresh the server state to reconcile an uncertain response before taking another action.",
    stale:
      "This plan expired or is no longer awaiting confirmation. Prepare a new preview when required.",
    remediation: "Find a vendor-backed fix",
    device: "Endpoint device ID",
    lookup: "Find fixes",
    noFixes: "No confirmed fix cards are available; this is not evidence of safety.",
    installed: "Installed",
    target: "Vendor target",
    unknown: "unknown",
    context: "Distribution / release / architecture",
    command: "Suggested command for review only",
    limited: "The result is truncated. Narrow the selection before acting.",
    noWorker:
      "Task submission is disabled. Start the configured operator worker before queuing analysis.",
    safety:
      "Actions require a server-validated plan. This console cannot install patches or close findings.",
    pending: "Request in progress…",
    busy: "A task is queued or running. Its state is restored from the server; reconnecting does not submit it again.",
  },
  ru: {
    targets: "Цели",
    udp: "UDP-порты",
    intent: "Назначение скана",
    defaults: "По умолчанию на сервере",
    policy: "Политика",
    scope: "Утверждённый scope",
    effect: "Эффект",
    network: "Сетевые проверки",
    details: "Технические подробности",
    yes: "Да",
    no: "Нет",
    rateDiscovery: "Лимит discovery (пакетов/с)",
    ratePorts: "Лимит портов (пакетов/с)",
    hostConcurrency: "Лимит одновременных хостов",
    hostRate: "Лимит частоты на хост",
    avoidPorts: "Исключённые порты",
    safeOnly: "Только профиль safe",
    asynchronous: "Остановка асинхронна",
    findingState: "Состояние находки",
    scopeApproval: "Scope утверждён",
    verifyMethod: "Метод проверки",
    compare: "Сравнить опубликованные сканы",
    previous: "ID предыдущего скана",
    current: "ID текущего скана",
    removal:
      "Отсутствие наблюдения не доказывает исправление уязвимости. Проверьте покрытие и актуальность данных.",
    unavailable: "Оператор отключён или недоступен в этой установке.",
    failed: "Запрос не выполнен. Проверьте сессию, права и состояние сервиса.",
    loading: "Загрузка оператора…",
    retry: "Обновить состояние сервера",
    tenant: "Тенант",
    actor: "Пользователь",
    runtime: "Готовность runtime не проверена.",
    quality: "Качество модели не принято. Проверяйте каждое предложение и его источники.",
    local: "Настроен локальный провайдер; офлайн-работа ещё не подтверждена.",
    hosted:
      "Настроен внешний inference. Разрешённые данные задачи могут передаваться настроенному провайдеру.",
    history: "Личные сессии",
    newSession: "Новая сессия",
    chooseSession: "Выберите сессию",
    noSessions: "Сессий пока нет.",
    analysis: "Разбор опубликованного скана",
    run: "ID скана",
    summary: "Сводка счётчиков",
    categorize: "Анализ находок",
    submit: "Поставить анализ в очередь",
    tasks: "Задачи и ответы",
    noTasks: "В этой сессии пока нет задач.",
    cancel: "Запросить отмену",
    cancelling: "Отмена запрошена; ожидается подтверждение worker.",
    openSource: "Открыть разрешённый источник",
    source: "Доказательства источника",
    preparation: "Подготовить действие",
    action: "Действие",
    start: "Запуск скана",
    stop: "Отмена скана",
    verify: "Проверка исправления",
    ranges: "IP-диапазоны (по одному на строку)",
    domains: "Домены (по одному на строку)",
    ports: "TCP-порты",
    mode: "Профиль",
    group: "Группа сенсоров (необязательно)",
    job: "ID задания",
    finding: "ID находки",
    prepare: "Предпросмотр действия",
    preview: "Проверьте точный план",
    expiry: "Действует до",
    hash: "Хеш плана",
    impact: "Ожидаемый эффект и ограничения",
    acknowledge: "Я проверил тенант, пользователя, цели, профиль, ограничения и побочные эффекты.",
    confirm: "Подтвердить этот план",
    confirmPending:
      "Подтверждение отправлено. При неопределённом ответе обновите состояние сервера перед следующим действием.",
    stale:
      "План истёк или уже не ожидает подтверждения. При необходимости подготовьте новый предпросмотр.",
    remediation: "Найти исправление из advisory",
    device: "ID устройства endpoint",
    lookup: "Найти исправления",
    noFixes: "Подтверждённых карточек исправления нет; это не доказательство безопасности.",
    installed: "Установлено",
    target: "Версия из advisory",
    unknown: "неизвестно",
    context: "Дистрибутив / выпуск / архитектура",
    command: "Команда только для проверки пользователем",
    limited: "Результат усечён. Уточните выборку перед действием.",
    noWorker: "Постановка задач отключена. Перед анализом запустите настроенный worker оператора.",
    safety:
      "Действия требуют проверенного сервером плана. Консоль не устанавливает патчи и не закрывает находки.",
    pending: "Запрос выполняется…",
    busy: "Есть задача в очереди или в работе. Состояние восстанавливается с сервера; переподключение не отправляет её заново.",
  },
};

function remembered(key: string): string {
  try {
    return window.sessionStorage.getItem(key) ?? "";
  } catch {
    return "";
  }
}
function remember(key: string, value: string) {
  try {
    window.sessionStorage.setItem(key, value);
  } catch {
    /* storage is optional */
  }
}
const keyForRequest = () =>
  globalThis.crypto?.randomUUID?.() ?? `${Date.now()}-${Math.random().toString(36).slice(2)}`;

/** Text is deliberately rendered through React only: no Markdown renderer,
 * model URLs, external images, HTML, or automatic fetch of cited resources. */
export function OperatorConsole({
  tenant,
  actor,
  canOperate,
}: {
  tenant: string;
  actor: string;
  canOperate: boolean;
}) {
  const t = useT();
  const c = copy[t.locale];
  const language = t.locale;
  const client = useQueryClient();
  const prefix = useMemo(() => operatorKey(tenant, actor), [tenant, actor]);
  const storageKey = `operator-session:${JSON.stringify([tenant, actor])}`;
  const [session, setSession] = useState(() => remembered(storageKey));
  const [run, setRun] = useState("");
  const [tool, setTool] = useState("analyze_run");
  const [sourceRequest, setSourceRequest] = useState<{
    citation: Citation;
    device?: string;
  } | null>(null);
  const requestKey = useRef<{ body: string; key: string } | null>(null);
  useEffect(
    () => () => {
      // Aborted reads cannot populate the old cache after a tenant switch.
      void client.cancelQueries({ queryKey: prefix });
      client.removeQueries({ queryKey: prefix });
      for (const mutation of client.getMutationCache().findAll({ mutationKey: prefix })) {
        client.getMutationCache().remove(mutation);
      }
    },
    [client, prefix],
  );

  const status = useQuery({
    queryKey: [...prefix, "status"],
    queryFn: ({ signal }) => operatorApi.status(tenant, signal),
    retry: false,
  });
  const sessions = useQuery({
    queryKey: [...prefix, "sessions"],
    queryFn: ({ signal }) => operatorApi.sessions(tenant, signal),
    enabled: status.isSuccess,
    retry: false,
  });
  const detail = useQuery({
    queryKey: [...prefix, "session", session],
    queryFn: ({ signal }) => operatorApi.session(tenant, session, signal),
    enabled: status.isSuccess && Boolean(session),
    retry: false,
    refetchInterval: (query) => (query.state.data?.tasks?.some(activeTask) ? 2000 : false),
    refetchOnWindowFocus: true,
    refetchOnReconnect: true,
  });
  const create = useMutation({
    mutationKey: [...prefix, "create"],
    mutationFn: () => operatorApi.createSession(tenant),
    retry: false,
    onSuccess: (data) => {
      setSession(data.session_id);
      remember(storageKey, data.session_id);
      void client.invalidateQueries({ queryKey: [...prefix, "sessions"] });
    },
  });
  const submit = useMutation({
    mutationKey: [...prefix, "submit"],
    mutationFn: () => {
      const body = { tool, run_id: run.trim(), language };
      const identity = JSON.stringify([session, body]);
      if (requestKey.current?.body !== identity)
        requestKey.current = { body: identity, key: keyForRequest() };
      return operatorApi.submit(tenant, session, body, requestKey.current.key);
    },
    retry: false,
    onSuccess: () => {
      requestKey.current = null;
      void detail.refetch();
    },
  });
  const cancel = useMutation({
    mutationKey: [...prefix, "cancel"],
    mutationFn: (task: string) => operatorApi.cancel(tenant, task),
    retry: false,
    onSuccess: () => {
      void detail.refetch();
    },
  });
  const evidence = useQuery({
    queryKey: [...prefix, "source", sourceRequest],
    queryFn: ({ signal }) =>
      sourceRequest!.device
        ? operatorApi.remediationSource(
            tenant,
            sourceRequest!.device,
            sourceRequest!.citation,
            signal,
          )
        : operatorApi.evidence(tenant, sourceRequest!.citation, signal),
    enabled: Boolean(sourceRequest),
    retry: false,
    staleTime: 0,
  });
  const source = (citation: Citation, device?: string) => {
    setSourceRequest({ citation, device });
    // Clicking the same citation must recheck current authorization/freshness.
    if (sourceRequest?.citation === citation) void evidence.refetch();
  };

  if (status.isPending) return <p role="status">{c.loading}</p>;
  if (status.isError)
    return (
      <div role="status" className="rounded-lg border p-6">
        <p>{operatorUnavailable(status.error) ? c.unavailable : c.failed}</p>
        <Button
          variant="outline"
          onClick={() => {
            void status.refetch();
          }}
        >
          {c.retry}
        </Button>
      </div>
    );

  return (
    <div className="space-y-6">
      <Card>
        <CardContent className="space-y-2 pt-6 text-sm">
          <p>
            <strong>{c.tenant}:</strong> {tenant} · <strong>{c.actor}:</strong> {actor}
          </p>
          <p className="font-mono">
            {status.data.provider} / {status.data.model}
          </p>
          <p>{status.data.external_inference ? c.hosted : c.local}</p>
          <p>
            {c.runtime} <span className="font-mono">{status.data.runtime_status}</span>
          </p>
          <p className="text-amber-700 dark:text-amber-300">
            {c.quality} <span className="font-mono">{status.data.quality_status}</span>
          </p>
          <p>{c.safety}</p>
        </CardContent>
      </Card>
      <Card>
        <CardHeader>
          <CardTitle>{c.history}</CardTitle>
        </CardHeader>
        <CardContent className="flex flex-wrap items-center gap-3">
          <select
            aria-label={c.history}
            className="h-10 max-w-full rounded-md border bg-background px-3 text-sm"
            value={session}
            onChange={(event) => {
              setSession(event.target.value);
              remember(storageKey, event.target.value);
              setSourceRequest(null);
            }}
          >
            <option value="">{c.chooseSession}</option>
            {session && !sessions.data?.items.some((row) => row.session_id === session) && (
              <option value={session}>{session}</option>
            )}
            {sessions.data?.items.map((row) => (
              <option key={row.session_id} value={row.session_id}>
                {row.created_at} · {row.session_id}
              </option>
            ))}
          </select>
          <Button disabled={!canOperate || create.isPending} onClick={() => create.mutate()}>
            {c.newSession}
          </Button>
          <Button
            variant="outline"
            onClick={() => {
              void sessions.refetch();
              if (session) void detail.refetch();
            }}
          >
            {c.retry}
          </Button>
          {!sessions.data?.items.length && (
            <p className="text-sm text-muted-foreground">{c.noSessions}</p>
          )}
          {(sessions.isError || create.isError || detail.isError) && <p role="alert">{c.failed}</p>}
        </CardContent>
      </Card>
      {session && detail.data && (
        <>
          <Card>
            <CardHeader>
              <CardTitle>{c.analysis}</CardTitle>
            </CardHeader>
            <CardContent>
              <form
                className="flex flex-wrap items-end gap-3"
                onSubmit={(event) => {
                  event.preventDefault();
                  submit.mutate();
                }}
              >
                <label className="space-y-2 text-sm">
                  {c.run}
                  <Input
                    required
                    maxLength={128}
                    pattern="[A-Za-z0-9][A-Za-z0-9_-]*"
                    value={run}
                    onChange={(event) => setRun(event.target.value)}
                  />
                </label>
                <label className="space-y-2 text-sm">
                  {c.analysis}
                  <select
                    className="block h-10 rounded-md border bg-background px-3"
                    value={tool}
                    onChange={(event) => setTool(event.target.value)}
                  >
                    <option value="summarize_run">{c.summary}</option>
                    <option value="analyze_run">{c.categorize}</option>
                  </select>
                </label>
                <Button
                  disabled={
                    !canOperate ||
                    !status.data.task_submission_enabled ||
                    submit.isPending ||
                    !run.trim()
                  }
                >
                  {c.submit}
                </Button>
              </form>
              {!status.data.task_submission_enabled && (
                <p className="mt-3 text-sm text-muted-foreground">{c.noWorker}</p>
              )}
              {submit.isPending && <p role="status">{c.pending}</p>}
              {submit.isError && <p role="alert">{c.failed}</p>}
            </CardContent>
          </Card>
          <Card>
            <CardHeader>
              <CardTitle>{c.tasks}</CardTitle>
            </CardHeader>
            <CardContent className="space-y-4" aria-live="polite">
              {!detail.data.tasks?.length && (
                <p className="text-sm text-muted-foreground">{c.noTasks}</p>
              )}
              {detail.data.tasks?.some(activeTask) && (
                <p className="text-sm text-muted-foreground">{c.busy}</p>
              )}
              {detail.data.tasks?.map((task) => (
                <Task
                  key={task.task_id}
                  task={task}
                  c={c}
                  canOperate={canOperate}
                  cancelling={cancel.isPending}
                  onCancel={() => cancel.mutate(task.task_id)}
                  onSource={source}
                />
              ))}
              {cancel.isError && <p role="alert">{c.failed}</p>}
            </CardContent>
          </Card>
          {canOperate && (
            <ActionPanel
              key={session}
              tenant={tenant}
              actor={actor}
              session={session}
              canOperate={canOperate}
              c={c}
              history={detail.data.proposals ?? []}
            />
          )}
        </>
      )}
      <ComparePanel tenant={tenant} actor={actor} language={language} c={c} />
      <RemediationPanel tenant={tenant} actor={actor} language={language} c={c} onSource={source} />
      {sourceRequest && (
        <Card>
          <CardHeader>
            <CardTitle>{c.source}</CardTitle>
          </CardHeader>
          <CardContent>
            {evidence.isPending && <p role="status">{c.loading}</p>}
            {evidence.isError && <p role="alert">{c.failed}</p>}
            {evidence.data && (
              <pre className="max-h-96 overflow-auto whitespace-pre-wrap break-all rounded bg-muted p-4 text-xs">
                {JSON.stringify(evidence.data, null, 2)}
              </pre>
            )}
          </CardContent>
        </Card>
      )}
    </div>
  );
}

type Copy = typeof copy.en;

function ComparePanel({
  tenant,
  actor,
  language,
  c,
}: {
  tenant: string;
  actor: string;
  language: "ru" | "en";
  c: Copy;
}) {
  const [previous, setPrevious] = useState("");
  const [current, setCurrent] = useState("");
  const [selection, setSelection] = useState<{ previous: string; current: string } | null>(null);
  const comparison = useQuery({
    queryKey: [...operatorKey(tenant, actor), "compare", selection, language],
    queryFn: ({ signal }) =>
      operatorApi.compare(tenant, selection!.previous, selection!.current, language, signal),
    enabled: Boolean(selection),
    retry: false,
  });
  return (
    <Card>
      <CardHeader>
        <CardTitle>{c.compare}</CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        <form
          className="flex flex-wrap items-end gap-3"
          onSubmit={(event) => {
            event.preventDefault();
            if (selection?.previous === previous.trim() && selection.current === current.trim())
              void comparison.refetch();
            else setSelection({ previous: previous.trim(), current: current.trim() });
          }}
        >
          <label className="space-y-2 text-sm">
            {c.previous}
            <Input
              required
              maxLength={128}
              pattern="[A-Za-z0-9][A-Za-z0-9_-]*"
              value={previous}
              onChange={(event) => setPrevious(event.target.value)}
            />
          </label>
          <label className="space-y-2 text-sm">
            {c.current}
            <Input
              required
              maxLength={128}
              pattern="[A-Za-z0-9][A-Za-z0-9_-]*"
              value={current}
              onChange={(event) => setCurrent(event.target.value)}
            />
          </label>
          <Button disabled={!previous.trim() || !current.trim() || comparison.isFetching}>
            {c.compare}
          </Button>
        </form>
        {selection && comparison.isPending && <p role="status">{c.loading}</p>}
        {comparison.isError && <p role="alert">{c.failed}</p>}
        {comparison.data && (
          <div className="space-y-2 text-sm">
            <p role="status">
              {comparison.data.status} · {comparison.data.quality_status}
            </p>
            <p>{comparison.data.summary}</p>
            <p className="text-muted-foreground">{comparison.data.reason}</p>
            <dl className="grid grid-cols-2 gap-2 md:grid-cols-4">
              {Object.entries(comparison.data.counts).map(([key, value]) => (
                <div key={key} className="rounded border p-3">
                  <dt className="text-xs text-muted-foreground">{key}</dt>
                  <dd className="font-mono text-lg">{value}</dd>
                </div>
              ))}
            </dl>
            {comparison.data.diff_source && (
              <p className="break-all font-mono text-xs">
                {comparison.data.diff_source.artifact} · {comparison.data.diff_source.source_hash}
              </p>
            )}
            <p className="text-amber-700 dark:text-amber-300">{c.removal}</p>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
function Task({
  task,
  c,
  canOperate,
  cancelling,
  onCancel,
  onSource,
}: {
  task: OperatorTask;
  c: Copy;
  canOperate: boolean;
  cancelling: boolean;
  onCancel: () => void;
  onSource: (citation: Citation) => void;
}) {
  const answer = task.result?.analysis ?? task.result?.answer?.answer;
  return (
    <article className="space-y-3 rounded-lg border p-4">
      <p className="text-sm font-semibold">
        {task.kind} · {task.run_id} · <span role="status">{task.status}</span>
      </p>
      {task.cancel_requested && <p className="text-sm">{c.cancelling}</p>}
      {task.error && (
        <p role="alert" className="text-sm">
          {task.error}
        </p>
      )}
      {answer && (
        <>
          <p className="text-sm font-medium">
            {answer.status} · {task.result?.quality_status}
          </p>
          <p className="whitespace-pre-wrap text-sm">{answer.summary}</p>
          <p className="text-sm text-muted-foreground">{answer.reason}</p>
          {answer.recommendations?.map((item) => (
            <div key={item.source_id} className="rounded bg-muted p-3 text-sm">
              <p>
                {item.source_id}: {item.category} · {item.proposed_priority}
              </p>
              <ul className="list-inside list-disc">
                {item.next_steps.map((step) => (
                  <li key={step}>{step}</li>
                ))}
              </ul>
            </div>
          ))}
          {answer.citations?.map((citation) => (
            <Button
              key={citation.source_id}
              size="sm"
              variant="outline"
              onClick={() => onSource(citation)}
            >
              {c.openSource}: {citation.source_id} · {citation.status}
            </Button>
          ))}
        </>
      )}
      {activeTask(task) && (
        <Button
          size="sm"
          variant="outline"
          disabled={!canOperate || cancelling || task.cancel_requested}
          onClick={onCancel}
        >
          {c.cancel}
        </Button>
      )}
    </article>
  );
}

function ActionPanel({
  tenant,
  actor,
  session,
  canOperate,
  c,
  history,
}: {
  tenant: string;
  actor: string;
  session: string;
  canOperate: boolean;
  c: Copy;
  history: OperatorProposal[];
}) {
  const proposalStorage = `operator-proposal:${JSON.stringify([tenant, actor, session])}`;
  const [proposalId, setProposalId] = useState(() => remembered(proposalStorage));
  const [action, setAction] = useState<ProposalAction>("start_scan");
  const [ranges, setRanges] = useState("");
  const [domains, setDomains] = useState("");
  const [ports, setPorts] = useState("80,443");
  const [mode, setMode] = useState("balanced");
  const [group, setGroup] = useState("");
  const [resource, setResource] = useState("");
  const [acknowledged, acknowledge] = useState("");
  const [confirmSent, setConfirmSent] = useState(false);
  const [now, setNow] = useState(Date.now());
  const proposal = useQuery({
    queryKey: [...operatorKey(tenant, actor), "proposal", proposalId],
    queryFn: ({ signal }) => operatorApi.proposal(tenant, proposalId, signal),
    enabled: Boolean(proposalId),
    retry: false,
    refetchOnReconnect: true,
  });
  useEffect(() => {
    const timer = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(timer);
  }, []);
  const prepare = useMutation({
    mutationKey: [...operatorKey(tenant, actor), "prepare"],
    mutationFn: () => {
      const args =
        action === "start_scan"
          ? {
              ...(ranges.trim() ? { ranges: ranges.trim() } : {}),
              ...(domains.trim() ? { domains: domains.trim() } : {}),
              ports,
              mode,
              ...(group.trim() ? { agent_group: group.trim() } : {}),
            }
          : action === "cancel_scan"
            ? { job_id: resource.trim() }
            : { vuln_id: resource.trim() };
      return operatorApi.prepare(tenant, session, action, args);
    },
    retry: false,
    onSuccess: (data) => {
      setProposalId(data.proposal_id);
      remember(proposalStorage, data.proposal_id);
      acknowledge("");
      setConfirmSent(false);
    },
  });
  const confirm = useMutation({
    mutationKey: [...operatorKey(tenant, actor), "confirm"],
    mutationFn: (data: OperatorProposal) =>
      operatorApi.confirm(tenant, data.proposal_id, data.arguments_sha256),
    retry: false,
    onSettled: () => {
      void proposal.refetch();
    },
  });
  const data = proposal.data;
  const valid =
    data?.tenant_id === tenant &&
    data.session_id === session &&
    data.status === "preview" &&
    Date.parse(data.expires_at) > now;
  return (
    <Card>
      <CardHeader>
        <CardTitle>{c.preparation}</CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        {history.length > 0 && (
          <label className="block space-y-2 text-sm">
            {c.preview}
            <select
              aria-label={c.preview}
              className="block h-10 max-w-full rounded-md border bg-background px-3"
              value={proposalId}
              onChange={(event) => {
                setProposalId(event.target.value);
                remember(proposalStorage, event.target.value);
                acknowledge("");
                setConfirmSent(false);
              }}
            >
              <option value="">—</option>
              {history.map((item) => (
                <option value={item.proposal_id} key={item.proposal_id}>
                  {item.action} · {item.status} · {item.proposal_id}
                </option>
              ))}
            </select>
          </label>
        )}
        <form
          className="grid gap-3 md:grid-cols-2"
          onSubmit={(event) => {
            event.preventDefault();
            prepare.mutate();
          }}
        >
          <label className="space-y-2 text-sm">
            {c.action}
            <select
              className="block h-10 w-full rounded-md border bg-background px-3"
              value={action}
              onChange={(event) => {
                setAction(event.target.value as ProposalAction);
                setResource("");
              }}
            >
              <option value="start_scan">{c.start}</option>
              <option value="cancel_scan">{c.stop}</option>
              <option value="verify_finding">{c.verify}</option>
            </select>
          </label>
          {action === "start_scan" ? (
            <>
              <label className="space-y-2 text-sm">
                {c.ranges}
                <textarea
                  className="block min-h-20 w-full rounded-md border bg-background p-3"
                  value={ranges}
                  maxLength={16384}
                  onChange={(event) => setRanges(event.target.value)}
                />
              </label>
              <label className="space-y-2 text-sm">
                {c.domains}
                <textarea
                  className="block min-h-20 w-full rounded-md border bg-background p-3"
                  value={domains}
                  maxLength={16384}
                  onChange={(event) => setDomains(event.target.value)}
                />
              </label>
              <label className="space-y-2 text-sm">
                {c.ports}
                <Input
                  value={ports}
                  maxLength={512}
                  onChange={(event) => setPorts(event.target.value)}
                />
              </label>
              <label className="space-y-2 text-sm">
                {c.mode}
                <select
                  className="block h-10 w-full rounded-md border bg-background px-3"
                  value={mode}
                  onChange={(event) => setMode(event.target.value)}
                >
                  <option value="safe">safe</option>
                  <option value="balanced">balanced</option>
                  <option value="fast">fast</option>
                  <option value="test">test</option>
                </select>
              </label>
              <label className="space-y-2 text-sm">
                {c.group}
                <Input
                  value={group}
                  maxLength={63}
                  onChange={(event) => setGroup(event.target.value)}
                />
              </label>
            </>
          ) : (
            <label className="space-y-2 text-sm">
              {action === "cancel_scan" ? c.job : c.finding}
              <Input
                required
                value={resource}
                maxLength={256}
                onChange={(event) => setResource(event.target.value)}
              />
            </label>
          )}
          <Button
            disabled={
              !canOperate ||
              prepare.isPending ||
              (action === "start_scan" && !ranges.trim() && !domains.trim())
            }
          >
            {c.prepare}
          </Button>
        </form>
        {(prepare.isError || proposal.isError || confirm.isError) && <p role="alert">{c.failed}</p>}
        {data && (
          <section className="space-y-3 rounded-lg border p-4" aria-label={c.preview}>
            <h3 className="font-semibold">{c.preview}</h3>
            <p className="text-sm">
              {c.tenant}: {data.tenant_id} · {c.actor}: {data.username ?? actor} · {data.action} ·{" "}
              {data.status}
            </p>
            <PlanArguments proposal={data} c={c} />
            <p className="break-all text-xs">
              {c.hash}: {data.arguments_sha256}
            </p>
            <p className="text-sm">
              {c.expiry}: {data.expires_at}
            </p>
            <PlanImpact proposal={data} c={c} />
            {valid ? (
              <>
                <label className="flex items-start gap-2 text-sm">
                  <input
                    type="checkbox"
                    checked={acknowledged === data.arguments_sha256}
                    onChange={(event) =>
                      acknowledge(event.target.checked ? data.arguments_sha256 : "")
                    }
                  />
                  {c.acknowledge}
                </label>
                <Button
                  disabled={
                    !canOperate ||
                    acknowledged !== data.arguments_sha256 ||
                    confirmSent ||
                    confirm.isPending
                  }
                  onClick={() => {
                    setConfirmSent(true);
                    confirm.mutate(data);
                  }}
                >
                  {c.confirm}
                </Button>
              </>
            ) : (
              <p className="text-sm">{c.stale}</p>
            )}
            {confirmSent && (
              <p role="status" className="text-sm">
                {c.confirmPending}
              </p>
            )}
            <Button
              variant="outline"
              size="sm"
              onClick={() => {
                void proposal.refetch();
              }}
            >
              {c.retry}
            </Button>
            {data.execution && (
              <pre className="overflow-auto whitespace-pre-wrap break-all rounded bg-muted p-3 text-xs">
                {JSON.stringify(data.execution, null, 2)}
              </pre>
            )}
          </section>
        )}
      </CardContent>
    </Card>
  );
}

function PlanRows({ rows, c }: { rows: [string, unknown][]; c: Copy }) {
  const value = (item: unknown): string =>
    item == null || item === ""
      ? c.defaults
      : typeof item === "boolean"
        ? item
          ? c.yes
          : c.no
        : Array.isArray(item)
          ? item.map(value).join(", ") || "—"
          : String(item);
  return (
    <dl className="grid gap-3 rounded-md bg-muted/40 p-3 text-sm sm:grid-cols-2">
      {rows.map(([label, item]) => (
        <div key={label}>
          <dt className="text-xs text-muted-foreground">{label}</dt>
          <dd className="whitespace-pre-wrap break-all font-medium">{value(item)}</dd>
        </div>
      ))}
    </dl>
  );
}

function PlanArguments({ proposal, c }: { proposal: OperatorProposal; c: Copy }) {
  const labels: Record<string, string> = {
    ranges: c.targets,
    domains: c.domains,
    mode: c.mode,
    intent: c.intent,
    ports: c.ports,
    ports_udp: c.udp,
    agent_group: c.group,
    job_id: c.job,
    vuln_id: c.finding,
  };
  return (
    <PlanRows
      c={c}
      rows={Object.entries(proposal.arguments).map(([key, item]) => [labels[key] ?? key, item])}
    />
  );
}

function PlanImpact({ proposal, c }: { proposal: OperatorProposal; c: Copy }) {
  const impact =
    proposal.impact && typeof proposal.impact === "object"
      ? (proposal.impact as Record<string, unknown>)
      : {};
  const policy =
    impact.policy && typeof impact.policy === "object"
      ? (impact.policy as Record<string, unknown>)
      : {};
  const scope =
    impact.approved_scope && typeof impact.approved_scope === "object"
      ? (impact.approved_scope as Record<string, unknown>)
      : {};
  const rows: [string, unknown][] = [
    [
      c.effect,
      proposal.action === "start_scan"
        ? c.start
        : proposal.action === "cancel_scan"
          ? c.stop
          : c.verify,
    ],
  ];
  if ("network_access" in impact) rows.push([c.network, impact.network_access]);
  if ("ports" in impact) rows.push([c.ports, impact.ports]);
  if (Array.isArray(impact.targets)) rows.push([c.targets, impact.targets]);
  else if (impact.targets && typeof impact.targets === "object") {
    const targets = impact.targets as Record<string, unknown>;
    if (targets.ranges) rows.push([c.targets, targets.ranges]);
    if (targets.domains) rows.push([c.domains, targets.domains]);
  }
  if ("agent_group" in impact) rows.push([c.group, impact.agent_group]);
  if ("ports_udp" in impact)
    rows.push([c.udp, impact.ports_udp === "server_default" ? null : impact.ports_udp]);
  if ("stopping_is_asynchronous" in impact)
    rows.push([c.asynchronous, impact.stopping_is_asynchronous]);
  if ("finding_state" in impact) rows.push([c.findingState, impact.finding_state]);
  if ("approved" in scope) rows.push([c.scopeApproval, scope.approved]);
  if (impact.policy === null) rows.push([c.policy, null]);
  const policyLabels: Record<string, string> = {
    profile: c.policy,
    safe_only: c.safeOnly,
    max_discover_rate: c.rateDiscovery,
    max_port_rate: c.ratePorts,
    max_host_concurrency: c.hostConcurrency,
    per_host_rate: c.hostRate,
    avoid_ports: c.avoidPorts,
  };
  for (const [key, label] of Object.entries(policyLabels))
    if (key in policy) rows.push([label, policy[key]]);
  const entries = Array.isArray(scope.entries)
    ? (scope.entries as { effect: string; kind: string; value: string }[])
    : [];
  return (
    <div className="space-y-2">
      <h4 className="text-sm font-semibold">{c.impact}</h4>
      <PlanRows rows={rows} c={c} />
      {entries.length > 0 && (
        <div className="rounded border p-3 text-sm">
          <p className="font-medium">{c.scope}</p>
          <ul className="list-inside list-disc">
            {entries.map((entry, index) => (
              <li key={index}>
                {entry.effect} · {entry.kind} · {entry.value}
              </li>
            ))}
          </ul>
        </div>
      )}
      <details className="text-xs text-muted-foreground">
        <summary className="cursor-pointer">{c.details}</summary>
        <pre className="mt-2 overflow-auto whitespace-pre-wrap break-all">
          {JSON.stringify(proposal.impact, null, 2)}
        </pre>
      </details>
    </div>
  );
}

function RemediationPanel({
  tenant,
  actor,
  language,
  c,
  onSource,
}: {
  tenant: string;
  actor: string;
  language: "ru" | "en";
  c: Copy;
  onSource: (citation: Citation, device?: string) => void;
}) {
  const [device, setDevice] = useState("");
  const [selected, select] = useState("");
  const result = useQuery({
    queryKey: [...operatorKey(tenant, actor), "remediation", selected, language],
    queryFn: ({ signal }) => operatorApi.remediation(tenant, selected, language, signal),
    enabled: Boolean(selected),
    retry: false,
  });
  return (
    <Card>
      <CardHeader>
        <CardTitle>{c.remediation}</CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        <form
          className="flex flex-wrap items-end gap-3"
          onSubmit={(event) => {
            event.preventDefault();
            if (device.trim() === selected) void result.refetch();
            else select(device.trim());
          }}
        >
          <label className="space-y-2 text-sm">
            {c.device}
            <Input
              required
              maxLength={256}
              value={device}
              onChange={(event) => setDevice(event.target.value)}
            />
          </label>
          <Button disabled={!device.trim() || result.isFetching}>{c.lookup}</Button>
        </form>
        {selected && result.isPending && <p role="status">{c.loading}</p>}
        {result.isError && <p role="alert">{c.failed}</p>}
        {result.data && (
          <>
            <p role="status" className="text-sm">
              {result.data.state} · {result.data.quality_status} · {result.data.reason}
            </p>
            {result.data.truncated && <p>{c.limited}</p>}
            {!result.data.items.length && (
              <p className="text-sm text-muted-foreground">{c.noFixes}</p>
            )}
            {result.data.items.map((item, index) => (
              <article
                key={`${item.package}:${index}`}
                className="space-y-2 rounded-lg border p-4 text-sm"
              >
                <h3 className="font-semibold">
                  {item.package} · {item.status}
                </h3>
                <p>
                  {c.installed}: {item.installed_version} · {c.target}:{" "}
                  {item.target_version ?? c.unknown}
                </p>
                <p>
                  {c.context}:{" "}
                  {[item.distro, item.distro_release, item.architecture]
                    .filter(Boolean)
                    .join(" / ") || c.unknown}
                </p>
                <p>{item.cve_ids.join(", ")}</p>
                <p className="text-muted-foreground">
                  {c.verifyMethod}: {item.verification.method}
                </p>
                {item.upgrade_command && (
                  <>
                    <p>{c.command}</p>
                    <pre className="whitespace-pre-wrap break-all rounded bg-muted p-3">
                      {item.upgrade_command}
                    </pre>
                  </>
                )}
                <ul className="list-inside list-disc text-muted-foreground">
                  {item.limitations.map((limit, index) => (
                    <li key={index}>{limit}</li>
                  ))}
                </ul>
                {item.sources.map((citation) => (
                  <div key={citation.source_id} className="space-y-1">
                    <p className="text-xs text-muted-foreground">
                      {[citation.provider, citation.feed_date, citation.observed_at]
                        .filter(Boolean)
                        .join(" · ")}
                    </p>
                    <Button
                      size="sm"
                      variant="outline"
                      key={citation.source_id}
                      onClick={() => onSource(citation, selected)}
                    >
                      {c.openSource}: {citation.advisory_id ?? citation.source_id} ·{" "}
                      {citation.status}
                    </Button>
                  </div>
                ))}
              </article>
            ))}
          </>
        )}
      </CardContent>
    </Card>
  );
}
