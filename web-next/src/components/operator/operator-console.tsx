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
  type OperatorPlan,
  type PlannerRequest,
  type PlannerScan,
} from "@/lib/operator-api";

const copy = {
  en: {
    runtimeReady: "Model integrity was verified at startup and runtime health is available.",
    runtimeUnavailable: "Runtime is unavailable. Check its health before requesting model work.",
    modelDigest: "Model SHA-256",
    contextBudget: "Context tokens",
    parallelBudget: "Parallel inference",
    runtimeVerifiedAt: "Verified at",
    trackJob: "Track scan job",
    planner: "Ask the operator",
    request: "Your request",
    planRequest: "Propose the next step",
    boundContext: "Selected context (optional)",
    selectedRun: "Selected run ID",
    selectedPrevious: "Selected previous run ID",
    selectedDevice: "Selected endpoint device ID",
    selectedJob: "Selected job ID",
    selectedFinding: "Selected finding ID",
    includeScan: "Include explicit scan targets",
    proposalOnly:
      "This selects a proposed operation and executes nothing. Scan actions still require a separate preview and confirmation.",
    adopt: "Use these parameters",
    adopted:
      "Parameters copied into the form below. Review them and explicitly request the next step.",
    noEffect: "No action has been executed.",
    effectUnexpected:
      "Unexpected execution state. Refresh and review the server result before proceeding.",
    unsupportedPlan: "The request is unsupported or lacks sufficient selected context.",
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
    remediationScope: "Remediation context",
    endpointScope: "Endpoint inventory",
    findingScope: "Network finding",
    findingId: "Network finding ID",
    configuration: "Configuration hardening",
    directive: "Configuration directive for manual review",
    operatorRunbook: "Operator runbook · manual review required",
    vendorFacts:
      "Vendor facts cover package applicability and fixed versions only. These operational steps are Shapoclyack guidance and require administrator approval.",
    preconditions: "Preconditions",
    backup: "Backup",
    restart: "Restart",
    rollback: "Rollback",
    manualApproval: "Manual approval required",
    workaround: "Vendor workaround",
    noWorkaround: "Unsupported: no reviewed vendor workaround source.",
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
    runtimeReady: "Целостность модели проверена при запуске; runtime доступен.",
    runtimeUnavailable: "Runtime недоступен. Проверьте его состояние перед задачами модели.",
    modelDigest: "SHA-256 модели",
    contextBudget: "Токенов контекста",
    parallelBudget: "Параллельных inference",
    runtimeVerifiedAt: "Проверено",
    trackJob: "Открыть задание скана",
    planner: "Запрос оператору",
    request: "Ваш запрос",
    planRequest: "Предложить следующий шаг",
    boundContext: "Выбранный контекст (необязательно)",
    selectedRun: "ID выбранного скана",
    selectedPrevious: "ID выбранного предыдущего скана",
    selectedDevice: "ID выбранного endpoint-устройства",
    selectedJob: "ID выбранного задания",
    selectedFinding: "ID выбранной находки",
    includeScan: "Добавить явные цели скана",
    proposalOnly:
      "Оператор только предлагает операцию. Для действий со сканами остаются отдельные предпросмотр и подтверждение.",
    adopt: "Использовать параметры",
    adopted: "Параметры скопированы в форму ниже. Проверьте их и явно запросите следующий шаг.",
    noEffect: "Действия ещё не выполнялись.",
    effectUnexpected:
      "Неожиданное состояние исполнения. Обновите и проверьте результат сервера перед продолжением.",
    unsupportedPlan: "Запрос не поддерживается или выбранного контекста недостаточно.",
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
    remediationScope: "Контекст исправления",
    endpointScope: "Инвентаризация endpoint",
    findingScope: "Сетевая находка",
    findingId: "ID сетевой находки",
    configuration: "Усиление конфигурации",
    directive: "Директива конфигурации для ручной проверки",
    operatorRunbook: "Инструкция оператора · требуется ручная проверка",
    vendorFacts:
      "Факты поставщика относятся только к применимости пакета и исправленным версиям. Эти операционные шаги — инструкция Shapoclyack, требующая одобрения администратора.",
    preconditions: "Предусловия",
    backup: "Резервная копия",
    restart: "Перезапуск",
    rollback: "Откат",
    manualApproval: "Требуется ручное одобрение",
    workaround: "Обходное решение поставщика",
    noWorkaround: "Не поддерживается: нет проверенного источника обходного решения поставщика.",
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

type AdoptedPlan = { nonce: string; sessionId: string; plan: OperatorPlan };
const selectableTools = [
  "summarize_run",
  "analyze_run",
  "compare_runs",
  "find_remediation",
  "prepare_scan",
  "cancel_scan",
  "verify_finding",
];

function useActiveMount() {
  const active = useRef(true);
  useEffect(() => {
    active.current = true;
    return () => {
      active.current = false;
    };
  }, []);
  return active;
}

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
  const active = useActiveMount();
  const prefix = useMemo(() => operatorKey(tenant, actor), [tenant, actor]);
  const storageKey = `operator-session:${JSON.stringify([tenant, actor])}`;
  const [session, setSession] = useState(() => remembered(storageKey));
  const [run, setRun] = useState("");
  const [tool, setTool] = useState("analyze_run");
  const [adopted, setAdopted] = useState<AdoptedPlan | null>(null);
  const draft = adopted?.sessionId === session ? adopted : undefined;
  const adopt = (plan: OperatorPlan) => {
    if (
      !canOperate ||
      plan.effect_executed !== false ||
      plan.status !== "proposal" ||
      !selectableTools.includes(plan.tool)
    )
      return;
    setAdopted({ nonce: keyForRequest(), sessionId: session, plan });
    if (plan.tool === "summarize_run" || plan.tool === "analyze_run") {
      setRun(typeof plan.arguments.run_id === "string" ? plan.arguments.run_id : "");
      setTool(plan.tool);
    }
  };
  const [sourceRequest, setSourceRequest] = useState<{
    citation: Citation;
    device?: string;
    finding?: string;
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
      if (!active.current) return;
      setSession(data.session_id);
      setAdopted(null);
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
      if (!active.current) return;
      requestKey.current = null;
      void detail.refetch();
    },
  });
  const cancel = useMutation({
    mutationKey: [...prefix, "cancel"],
    mutationFn: (task: string) => operatorApi.cancel(tenant, task),
    retry: false,
    onSuccess: () => {
      if (!active.current) return;
      void detail.refetch();
    },
  });
  const evidence = useQuery({
    queryKey: [...prefix, "source", sourceRequest],
    queryFn: ({ signal }) =>
      sourceRequest!.finding
        ? operatorApi.findingRemediationSource(
            tenant,
            sourceRequest!.finding,
            sourceRequest!.citation,
            signal,
          )
        : sourceRequest!.device
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
  const source = (citation: Citation, device?: string, finding?: string) => {
    setSourceRequest({ citation, device, finding });
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
            {status.data.runtime_status === "ready"
              ? c.runtimeReady
              : status.data.runtime_status === "unavailable"
                ? c.runtimeUnavailable
                : c.runtime}{" "}
            <span className="font-mono">{status.data.runtime_status}</span>
          </p>
          {status.data.runtime_status === "ready" && (
            <div className="flex flex-wrap gap-x-5 gap-y-1 text-xs text-muted-foreground">
              {typeof status.data.model_sha256 === "string" &&
                /^[a-f0-9]{64}$/.test(status.data.model_sha256) && (
                  <span title={status.data.model_sha256}>
                    {c.modelDigest}: {status.data.model_sha256.slice(0, 16)}…
                  </span>
                )}
              {status.data.context_tokens != null && (
                <span>
                  {c.contextBudget}: {status.data.context_tokens}
                </span>
              )}
              {status.data.parallel != null && (
                <span>
                  {c.parallelBudget}: {status.data.parallel}
                </span>
              )}
              {status.data.verified_at && (
                <span>
                  {c.runtimeVerifiedAt}: {status.data.verified_at}
                </span>
              )}
              {status.data.profile && <span>{status.data.profile}</span>}
            </div>
          )}
          {status.data.runtime_status === "unavailable" && (
            <Button
              size="sm"
              variant="outline"
              onClick={() => {
                void status.refetch();
              }}
            >
              {c.retry}
            </Button>
          )}
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
              setAdopted(null);
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
              void status.refetch();
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
          <PlannerPanel
            key={`planner:${session}`}
            tenant={tenant}
            actor={actor}
            session={session}
            runId={run}
            language={language}
            c={c}
            canOperate={
              canOperate &&
              status.data.task_submission_enabled &&
              status.data.runtime_status !== "unavailable"
            }
            onQueued={() => {
              void detail.refetch();
            }}
          />
          {draft && (
            <p role="status" className="rounded border border-primary/30 bg-primary/5 p-3 text-sm">
              {c.adopted}
            </p>
          )}
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
                    status.data.runtime_status === "unavailable" ||
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
                  onAdopt={adopt}
                />
              ))}
              {cancel.isError && <p role="alert">{c.failed}</p>}
            </CardContent>
          </Card>
          {canOperate && (
            <ActionPanel
              key={`actions:${session}`}
              tenant={tenant}
              actor={actor}
              session={session}
              canOperate={canOperate}
              c={c}
              history={detail.data.proposals ?? []}
              draft={draft}
            />
          )}
        </>
      )}
      <ComparePanel tenant={tenant} actor={actor} language={language} c={c} draft={draft} />
      <RemediationPanel
        tenant={tenant}
        actor={actor}
        language={language}
        c={c}
        onSource={source}
        draft={draft}
      />
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

function toolLabel(tool: string, c: Copy): string {
  const labels: Record<string, string> = {
    summarize_run: c.summary,
    analyze_run: c.categorize,
    compare_runs: c.compare,
    find_remediation: c.remediation,
    prepare_scan: c.start,
    cancel_scan: c.stop,
    verify_finding: c.verify,
    abstain: c.unsupportedPlan,
  };
  return labels[tool] ?? c.unsupportedPlan;
}

function PlannerPanel({
  tenant,
  actor,
  session,
  runId,
  language,
  c,
  canOperate,
  onQueued,
}: {
  tenant: string;
  actor: string;
  session: string;
  runId: string;
  language: "ru" | "en";
  c: Copy;
  canOperate: boolean;
  onQueued: () => void;
}) {
  const active = useActiveMount();
  const [request, setRequest] = useState("");
  const [context, setContext] = useState({
    run_id: runId,
    previous_run_id: "",
    device_id: "",
    job_id: "",
    vuln_id: "",
  });
  const [includeScan, setIncludeScan] = useState(false);
  const [scan, setScan] = useState<PlannerScan>({
    mode: "safe",
    ranges: "",
    domains: "",
    ports: "443",
    ports_udp: "",
    agent_group: "",
    intent: "",
  });
  const requestKey = useRef<{ body: string; key: string } | null>(null);
  useEffect(() => {
    setContext((previous) => ({ ...previous, run_id: runId }));
  }, [runId]);
  const mutation = useMutation({
    mutationKey: [...operatorKey(tenant, actor), "plan-request"],
    mutationFn: () => {
      const bound: PlannerRequest["context"] = Object.fromEntries(
        Object.entries(context)
          .map(([key, value]) => [key, value.trim()])
          .filter(([, value]) => value),
      );
      if (includeScan) {
        const { intent, agent_group, ...fields } = scan;
        bound.scan = {
          ...fields,
          ranges: scan.ranges?.trim(),
          domains: scan.domains?.trim(),
          ports: scan.ports.trim(),
          ...(intent?.trim() ? { intent: intent.trim() } : {}),
          ...(agent_group?.trim() ? { agent_group: agent_group.trim() } : {}),
        };
      }
      const body: PlannerRequest = { request: request.trim(), language, context: bound };
      const identity = JSON.stringify([session, body]);
      if (requestKey.current?.body !== identity)
        requestKey.current = { body: identity, key: keyForRequest() };
      return operatorApi.plan(tenant, session, body, requestKey.current.key);
    },
    retry: false,
    onSuccess: () => {
      if (active.current) onQueued();
    },
  });
  const fields = [
    ["run_id", c.selectedRun],
    ["previous_run_id", c.selectedPrevious],
    ["device_id", c.selectedDevice],
    ["job_id", c.selectedJob],
    ["vuln_id", c.selectedFinding],
  ] as const;
  return (
    <Card role="region" aria-label={c.planner}>
      <CardHeader>
        <CardTitle>{c.planner}</CardTitle>
      </CardHeader>
      <CardContent className="space-y-3">
        <p className="text-sm text-muted-foreground">{c.proposalOnly}</p>
        <form
          className="space-y-3"
          onSubmit={(event) => {
            event.preventDefault();
            mutation.mutate();
          }}
        >
          <label className="block space-y-2 text-sm">
            {c.request}
            <textarea
              className="block min-h-24 w-full rounded-md border bg-background p-3"
              required
              maxLength={1000}
              value={request}
              onChange={(event) => setRequest(event.target.value)}
            />
          </label>
          <details className="rounded border p-3 text-sm">
            <summary className="cursor-pointer font-medium">{c.boundContext}</summary>
            <div className="mt-3 grid gap-3 md:grid-cols-2">
              {fields.map(([key, label]) => (
                <label className="space-y-2" key={key}>
                  {label}
                  <Input
                    maxLength={256}
                    pattern="[A-Za-z0-9][A-Za-z0-9_.:-]*"
                    value={context[key]}
                    onChange={(event) =>
                      setContext((value) => ({ ...value, [key]: event.target.value }))
                    }
                  />
                </label>
              ))}
            </div>
            <label className="mt-4 flex items-center gap-2">
              <input
                type="checkbox"
                checked={includeScan}
                onChange={(event) => setIncludeScan(event.target.checked)}
              />
              {c.includeScan}
            </label>
            {includeScan && (
              <div className="mt-3 grid gap-3 md:grid-cols-2">
                <label className="space-y-2">
                  {c.ranges}
                  <textarea
                    className="block min-h-20 w-full rounded-md border bg-background p-3"
                    maxLength={8192}
                    value={scan.ranges}
                    onChange={(event) =>
                      setScan((value) => ({ ...value, ranges: event.target.value }))
                    }
                  />
                </label>
                <label className="space-y-2">
                  {c.domains}
                  <textarea
                    className="block min-h-20 w-full rounded-md border bg-background p-3"
                    maxLength={8192}
                    value={scan.domains}
                    onChange={(event) =>
                      setScan((value) => ({ ...value, domains: event.target.value }))
                    }
                  />
                </label>
                <label className="space-y-2">
                  {c.ports}
                  <Input
                    required
                    maxLength={2048}
                    value={scan.ports}
                    onChange={(event) =>
                      setScan((value) => ({ ...value, ports: event.target.value }))
                    }
                  />
                </label>
                <label className="space-y-2">
                  {c.mode}
                  <select
                    className="block h-10 w-full rounded border bg-background px-3"
                    value={scan.mode}
                    onChange={(event) =>
                      setScan((value) => ({
                        ...value,
                        mode: event.target.value as PlannerScan["mode"],
                      }))
                    }
                  >
                    {["safe", "balanced", "fast", "test"].map((mode) => (
                      <option key={mode} value={mode}>
                        {mode}
                      </option>
                    ))}
                  </select>
                </label>
                <label className="space-y-2">
                  {c.udp}
                  <Input
                    maxLength={2048}
                    value={scan.ports_udp}
                    onChange={(event) =>
                      setScan((value) => ({ ...value, ports_udp: event.target.value }))
                    }
                  />
                </label>
                <label className="space-y-2">
                  {c.intent}
                  <Input
                    maxLength={64}
                    value={scan.intent ?? ""}
                    onChange={(event) =>
                      setScan((value) => ({ ...value, intent: event.target.value }))
                    }
                  />
                </label>
                <label className="space-y-2">
                  {c.group}
                  <Input
                    maxLength={63}
                    value={scan.agent_group ?? ""}
                    onChange={(event) =>
                      setScan((value) => ({ ...value, agent_group: event.target.value }))
                    }
                  />
                </label>
              </div>
            )}
          </details>
          <Button
            disabled={
              !canOperate ||
              !request.trim() ||
              mutation.isPending ||
              (includeScan && !scan.ranges?.trim() && !scan.domains?.trim())
            }
          >
            {c.planRequest}
          </Button>
          {mutation.isPending && <p role="status">{c.pending}</p>}
          {mutation.isError && <p role="alert">{c.failed}</p>}
        </form>
      </CardContent>
    </Card>
  );
}

function ComparePanel({
  tenant,
  actor,
  language,
  c,
  draft,
}: {
  tenant: string;
  actor: string;
  language: "ru" | "en";
  c: Copy;
  draft?: AdoptedPlan;
}) {
  const [previous, setPrevious] = useState("");
  const [current, setCurrent] = useState("");
  const [selection, setSelection] = useState<{ previous: string; current: string } | null>(null);
  useEffect(() => {
    if (draft?.plan.tool !== "compare_runs") return;
    setPrevious(
      typeof draft.plan.arguments.previous_run_id === "string"
        ? draft.plan.arguments.previous_run_id
        : "",
    );
    setCurrent(
      typeof draft.plan.arguments.current_run_id === "string"
        ? draft.plan.arguments.current_run_id
        : "",
    );
    setSelection(null);
  }, [draft]);
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
  onAdopt,
}: {
  task: OperatorTask;
  c: Copy;
  canOperate: boolean;
  cancelling: boolean;
  onCancel: () => void;
  onSource: (citation: Citation) => void;
  onAdopt: (plan: OperatorPlan) => void;
}) {
  const answer = task.result?.analysis ?? task.result?.answer?.answer;
  const plan = task.result?.plan;
  return (
    <article className="space-y-3 rounded-lg border p-4">
      <p className="text-sm font-semibold">
        {task.kind === "plan_request" ? c.planner : `${task.kind} · ${task.run_id}`} ·{" "}
        <span role="status">{task.status}</span>
      </p>
      {task.cancel_requested && <p className="text-sm">{c.cancelling}</p>}
      {task.error && (
        <p role="alert" className="text-sm">
          {task.error}
        </p>
      )}
      {plan && (
        <div className="space-y-3 rounded border bg-muted/30 p-3 text-sm">
          <p className="font-semibold">
            {toolLabel(plan.tool, c)} · {plan.status} · {plan.quality_status}
          </p>
          <p>{plan.effect_executed === false ? c.noEffect : c.effectUnexpected}</p>
          {plan.tool === "abstain" ? (
            <p>{c.unsupportedPlan}</p>
          ) : (
            <ArgumentRows arguments={plan.arguments} c={c} />
          )}
          {canOperate &&
            plan.status === "proposal" &&
            plan.effect_executed === false &&
            selectableTools.includes(plan.tool) && (
              <Button variant="outline" size="sm" onClick={() => onAdopt(plan)}>
                {c.adopt}
              </Button>
            )}
        </div>
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
  draft,
}: {
  tenant: string;
  actor: string;
  session: string;
  canOperate: boolean;
  c: Copy;
  history: OperatorProposal[];
  draft?: AdoptedPlan;
}) {
  const proposalStorage = `operator-proposal:${JSON.stringify([tenant, actor, session])}`;
  const active = useActiveMount();
  const [proposalId, setProposalId] = useState(() => remembered(proposalStorage));
  const [action, setAction] = useState<ProposalAction>("start_scan");
  const [ranges, setRanges] = useState("");
  const [domains, setDomains] = useState("");
  const [ports, setPorts] = useState("80,443");
  const [udp, setUdp] = useState("");
  const [intent, setIntent] = useState("");
  const [mode, setMode] = useState("balanced");
  const [group, setGroup] = useState("");
  const [resource, setResource] = useState("");
  const [acknowledged, acknowledge] = useState("");
  const [confirmSent, setConfirmSent] = useState(false);
  const [now, setNow] = useState(Date.now());
  useEffect(() => {
    if (!draft || !["prepare_scan", "cancel_scan", "verify_finding"].includes(draft.plan.tool))
      return;
    const args = draft.plan.arguments;
    setAction(
      draft.plan.tool === "prepare_scan"
        ? "start_scan"
        : draft.plan.tool === "cancel_scan"
          ? "cancel_scan"
          : "verify_finding",
    );
    setRanges(typeof args.ranges === "string" ? args.ranges : "");
    setDomains(typeof args.domains === "string" ? args.domains : "");
    setPorts(typeof args.ports === "string" ? args.ports : "");
    setUdp(typeof args.ports_udp === "string" ? args.ports_udp : "");
    setIntent(typeof args.intent === "string" ? args.intent : "");
    setMode(typeof args.mode === "string" ? args.mode : "safe");
    setGroup(typeof args.agent_group === "string" ? args.agent_group : "");
    setResource(
      typeof args.job_id === "string"
        ? args.job_id
        : typeof args.vuln_id === "string"
          ? args.vuln_id
          : "",
    );
    setProposalId("");
    remember(proposalStorage, "");
    acknowledge("");
    setConfirmSent(false);
  }, [draft, proposalStorage]);
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
              ...(udp.trim() ? { ports_udp: udp.trim() } : {}),
              ...(intent.trim() ? { intent: intent.trim() } : {}),
              ...(group.trim() ? { agent_group: group.trim() } : {}),
            }
          : action === "cancel_scan"
            ? { job_id: resource.trim() }
            : { vuln_id: resource.trim() };
      return operatorApi.prepare(tenant, session, action, args);
    },
    retry: false,
    onSuccess: (data) => {
      if (!active.current) return;
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
      if (!active.current) return;
      void proposal.refetch();
    },
  });
  const data = proposal.data;
  const executionResult = data?.execution?.result;
  const resultJobId =
    executionResult &&
    typeof executionResult === "object" &&
    "job_id" in executionResult &&
    typeof executionResult.job_id === "string" &&
    /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,255}$/.test(executionResult.job_id)
      ? executionResult.job_id
      : null;
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
                {c.udp}
                <Input
                  maxLength={2048}
                  value={udp}
                  onChange={(event) => setUdp(event.target.value)}
                />
              </label>
              <label className="space-y-2 text-sm">
                {c.intent}
                <Input
                  maxLength={64}
                  value={intent}
                  onChange={(event) => setIntent(event.target.value)}
                />
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
              <div className="space-y-2 text-sm">
                <p>{data.execution.status}</p>
                {resultJobId && (
                  <a
                    className="inline-flex rounded border px-3 py-2 font-medium underline-offset-4 hover:underline"
                    href={`/scans?job=${encodeURIComponent(resultJobId)}`}
                  >
                    {c.trackJob}: {resultJobId}
                  </a>
                )}
                <details className="text-xs text-muted-foreground">
                  <summary className="cursor-pointer">{c.details}</summary>
                  <pre className="mt-2 overflow-auto whitespace-pre-wrap break-all">
                    {JSON.stringify(data.execution, null, 2)}
                  </pre>
                </details>
              </div>
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
  return <ArgumentRows arguments={proposal.arguments} c={c} />;
}

function ArgumentRows({ arguments: args, c }: { arguments: Record<string, unknown>; c: Copy }) {
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
    run_id: c.run,
    previous_run_id: c.previous,
    current_run_id: c.current,
    device_id: c.device,
  };
  return (
    <PlanRows c={c} rows={Object.entries(args).map(([key, item]) => [labels[key] ?? key, item])} />
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
  draft,
}: {
  tenant: string;
  actor: string;
  language: "ru" | "en";
  c: Copy;
  onSource: (citation: Citation, device?: string, finding?: string) => void;
  draft?: AdoptedPlan;
}) {
  const [device, setDevice] = useState("");
  const [scope, setScope] = useState<"device" | "finding">("device");
  const [selected, select] = useState("");
  useEffect(() => {
    if (draft?.plan.tool !== "find_remediation") return;
    const finding = typeof draft.plan.arguments.vuln_id === "string";
    setScope(finding ? "finding" : "device");
    setDevice(
      finding
        ? (draft.plan.arguments.vuln_id as string)
        : typeof draft.plan.arguments.device_id === "string"
          ? draft.plan.arguments.device_id
          : "",
    );
    select("");
  }, [draft]);
  const result = useQuery({
    queryKey: [...operatorKey(tenant, actor), "remediation", scope, selected, language],
    queryFn: ({ signal }) =>
      scope === "finding"
        ? operatorApi.findingRemediation(tenant, selected, language, signal)
        : operatorApi.remediation(tenant, selected, language, signal),
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
            {c.remediationScope}
            <select
              className="block rounded border bg-background p-2"
              value={scope}
              onChange={(event) => {
                setScope(event.target.value as "device" | "finding");
                setDevice("");
                select("");
              }}
            >
              <option value="device">{c.endpointScope}</option>
              <option value="finding">{c.findingScope}</option>
            </select>
          </label>
          <label className="space-y-2 text-sm">
            {scope === "finding" ? c.findingId : c.device}
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
                  {item.kind === "configuration_hardening" ? c.configuration : item.package} ·{" "}
                  {item.status}
                </h3>
                {item.kind === "configuration_hardening" ? (
                  <>
                    <p>{[item.product, item.applicability].filter(Boolean).join(" · ")}</p>
                    {item.summary && <p>{item.summary}</p>}
                    {item.directive && (
                      <>
                        <p>{c.directive}</p>
                        <pre className="whitespace-pre-wrap break-all rounded bg-muted p-3">
                          {item.directive}
                        </pre>
                      </>
                    )}
                    {item.preconditions?.map((condition, index) => (
                      <p key={index}>{condition}</p>
                    ))}
                  </>
                ) : (
                  <>
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
                  </>
                )}
                {item.cve_ids.length > 0 && <p>{item.cve_ids.join(", ")}</p>}
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
                {item.kind === "package_upgrade" &&
                  item.plan?.origin === "shapoclyack_operator_runbook" && (
                    <section
                      aria-label={c.operatorRunbook}
                      className="space-y-3 rounded border bg-muted/30 p-3"
                    >
                      <h4 className="font-semibold">{c.operatorRunbook}</h4>
                      <p className="text-muted-foreground">{c.vendorFacts}</p>
                      <details>
                        <summary className="cursor-pointer font-medium">{c.preconditions}</summary>
                        <ul className="mt-2 list-inside list-disc space-y-1">
                          {item.plan.preconditions[language].map((text, index) => (
                            <li key={index}>{text}</li>
                          ))}
                        </ul>
                      </details>
                      <dl className="grid gap-3 md:grid-cols-3">
                        {(["backup", "restart", "rollback"] as const).map((step) => (
                          <div key={step}>
                            <dt className="font-medium">
                              {c[step]} ·{" "}
                              {item.plan![step].status === "unknown"
                                ? c.unknown
                                : item.plan![step].status === "manual_approval_required"
                                  ? c.manualApproval
                                  : item.plan![step].status}
                            </dt>
                            <dd className="mt-1 text-muted-foreground">
                              {item.plan![step][language]}
                            </dd>
                          </div>
                        ))}
                      </dl>
                      <p>
                        <strong>{c.verifyMethod}:</strong> {item.plan.verification[language]}
                      </p>
                      <p>
                        <strong>{c.workaround}:</strong>{" "}
                        {item.plan.vendor_workaround.status === "unsupported"
                          ? c.noWorkaround
                          : item.plan.vendor_workaround.status}
                      </p>
                      <details className="text-xs text-muted-foreground">
                        <summary className="cursor-pointer">{c.details}</summary>
                        <p>{item.plan.runbook_id}</p>
                        <p className="break-all">runbook SHA-256: {item.plan.runbook_sha256}</p>
                        <p className="break-all">plan SHA-256: {item.plan.plan_sha256}</p>
                      </details>
                    </section>
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
                      onClick={() =>
                        onSource(
                          citation,
                          scope === "device" ? selected : undefined,
                          scope === "finding" ? selected : undefined,
                        )
                      }
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
