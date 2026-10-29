"use client";

import { useEffect, useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { useT } from "@/lib/i18n";
import {
  operatorSettingsApi,
  type EndpointSettings,
  type ConnectionResult,
} from "@/lib/operator-settings-api";

export function OperatorSettings({ actor }: { actor: string }) {
  const t = useT();
  const text = (en: string, ru: string) => (t.locale === "ru" ? ru : en);
  const cache = useQueryClient();
  const snapshot = useQuery({
    queryKey: ["operator-settings", actor],
    queryFn: operatorSettingsApi.get,
    retry: false,
  });
  const [draft, setDraft] = useState<EndpointSettings | null>(null);
  const [key, setKey] = useState("");
  const [clearKey, setClearKey] = useState(false);
  const [completion, setCompletion] = useState(false);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  const [result, setResult] = useState<ConnectionResult | null>(null);
  useEffect(() => {
    if (snapshot.data) {
      const values = snapshot.data.effective ?? snapshot.data.deployment;
      setDraft({
        provider: values.provider,
        base_url: values.base_url,
        model: values.model,
        allow_external: values.allow_external,
        timeout_seconds: values.timeout_seconds,
        max_output_tokens: values.max_output_tokens,
      });
      setKey("");
      setClearKey(false);
      setResult(null);
    }
  }, [snapshot.data]);

  async function run(action: "save" | "reset" | "discover" | "test") {
    if (!draft) return;
    setBusy(true);
    setMessage("");
    setResult(null);
    const body = { ...draft, api_key: clearKey ? "" : key || undefined };
    try {
      if (action === "test" || action === "discover") {
        setResult(await operatorSettingsApi.test(body, action === "test" && completion));
      } else {
        if (action === "reset") await operatorSettingsApi.reset();
        else await operatorSettingsApi.save(body);
        setKey("");
        setClearKey(false);
        await snapshot.refetch();
        await cache.invalidateQueries({ queryKey: ["local-operator"] });
        setMessage(text("Settings saved.", "Настройки сохранены."));
      }
    } catch {
      setMessage(
        text(
          "Request failed. Check endpoint, credentials, permissions and deployment limits.",
          "Запрос не выполнен. Проверьте адрес, ключ, права и ограничения развёртывания.",
        ),
      );
    } finally {
      setBusy(false);
    }
  }
  if (snapshot.isPending)
    return (
      <p role="status">{text("Loading connection settings…", "Загрузка настроек подключения…")}</p>
    );
  if (snapshot.isError || !draft)
    return (
      <p role="alert">
        {text("Connection settings unavailable.", "Настройки подключения недоступны.")}{" "}
        <Button onClick={() => void snapshot.refetch()}>{text("Retry", "Повторить")}</Button>
      </p>
    );

  return (
    <details className="rounded-lg border bg-card p-6">
      <summary className="cursor-pointer font-semibold">
        {text("AI connection settings (installation-wide)", "Подключение ИИ (вся установка)")}
      </summary>
      <form
        className="mt-4 space-y-4"
        onSubmit={(e) => {
          e.preventDefault();
          void run("save");
        }}
      >
        <p className="text-sm">
          {text(
            "Applies to the next worker task. Enablement and worker activation are managed by the deployment.",
            "Применяется к следующей задаче воркера. Включение ИИ и воркера задаётся при развёртывании.",
          )}
        </p>
        <p className="text-sm">
          {text(
            "Local: private IP literals only. Cloud: public HTTPS, API key and explicit consent; deployment must also permit external inference.",
            "Локально: только частные IP-адреса. Облако: публичный HTTPS, ключ API и явное согласие; развёртывание также должно разрешать внешние запросы.",
          )}
        </p>
        {snapshot.data?.error && <p role="alert">{snapshot.data.error}</p>}
        <fieldset disabled={busy} className="grid gap-4 sm:grid-cols-2">
          <label>
            {text("Provider", "Провайдер")}
            <select
              className="block h-10 w-full rounded-md border bg-background px-3"
              value={draft.provider}
              onChange={(e) => {
                setDraft({
                  ...draft,
                  provider: e.target.value as EndpointSettings["provider"],
                  base_url: "",
                  allow_external: false,
                });
                setKey("");
                setResult(null);
              }}
            >
              <option value="local">Local / LAN</option>
              <option value="openrouter">OpenRouter</option>
              <option value="omnirouter">OmniRouter</option>
              <option value="openai_compatible">OpenAI-compatible cloud</option>
            </select>
          </label>
          <label>
            {text("API base URL", "Базовый URL API")}
            <Input
              value={draft.base_url}
              maxLength={2048}
              placeholder={
                draft.provider === "local"
                  ? "http://192.168.1.50:8080/v1"
                  : "https://llm.example.com/v1"
              }
              onChange={(e) => {
                setDraft({ ...draft, base_url: e.target.value });
                setResult(null);
              }}
            />
          </label>
          <label>
            {text("Model", "Модель")}
            <Input
              required
              maxLength={256}
              list="operator-discovered-models"
              value={draft.model}
              onChange={(e) => setDraft({ ...draft, model: e.target.value })}
            />
            <datalist id="operator-discovered-models">
              {result?.models.map((model) => (
                <option key={model.id} value={model.id} />
              ))}
            </datalist>
          </label>
          <label>
            {text(
              "API key (blank keeps current key for the same endpoint)",
              "Ключ API (пустое поле сохраняет ключ для прежнего адреса)",
            )}
            <Input
              type="password"
              autoComplete="new-password"
              maxLength={4096}
              disabled={clearKey}
              value={key}
              onChange={(e) => setKey(e.target.value)}
            />
          </label>
          <label>
            <input
              type="checkbox"
              checked={clearKey}
              onChange={(e) => {
                setClearKey(e.target.checked);
                setKey("");
              }}
            />{" "}
            {text("Clear API key", "Удалить ключ API")}
          </label>
          <label>
            <input
              type="checkbox"
              disabled={!snapshot.data?.external_permitted || draft.provider === "local"}
              checked={draft.allow_external}
              onChange={(e) => setDraft({ ...draft, allow_external: e.target.checked })}
            />{" "}
            {text(
              "Allow sending task data to this cloud provider",
              "Разрешить отправку данных задач этому облачному провайдеру",
            )}
          </label>
          <label>
            {text("Timeout (seconds)", "Тайм-аут (секунды)")}
            <Input
              type="number"
              required
              min={0.1}
              max={120}
              step="any"
              value={draft.timeout_seconds}
              onChange={(e) => setDraft({ ...draft, timeout_seconds: Number(e.target.value) })}
            />
          </label>
          <label>
            {text("Maximum output tokens", "Максимум токенов ответа")}
            <Input
              type="number"
              required
              min={1}
              max={8192}
              value={draft.max_output_tokens}
              onChange={(e) => setDraft({ ...draft, max_output_tokens: Number(e.target.value) })}
            />
          </label>
          <label className="sm:col-span-2">
            <input
              type="checkbox"
              checked={completion}
              onChange={(e) => setCompletion(e.target.checked)}
            />{" "}
            {text(
              "Include a small completion in the test (cloud providers may charge)",
              "Добавить короткую генерацию в проверку (облако может списать оплату)",
            )}
          </label>
          <div className="flex flex-wrap gap-2 sm:col-span-2">
            <Button type="submit">{text("Save connection", "Сохранить подключение")}</Button>
            <Button type="button" variant="outline" onClick={() => void run("discover")}>
              {text("Discover models", "Найти модели")}
            </Button>
            <Button type="button" variant="outline" onClick={() => void run("test")}>
              {text("Test connection", "Проверить подключение")}
            </Button>
            <Button type="button" variant="outline" onClick={() => void run("reset")}>
              {text("Restore deployment settings", "Восстановить настройки развёртывания")}
            </Button>
          </div>
        </fieldset>
        {message && <p role="status">{message}</p>}
        {result && (
          <div role="status" className="text-sm">
            <p>
              {result.ok
                ? text("Connection check passed.", "Подключение проверено.")
                : result.error}
            </p>
            <p>
              {text("Completion", "Генерация")}: {result.completion}
            </p>
            <p>
              {text("Discovered models", "Найденные модели")}:{" "}
              {result.models.map((m) => m.id).join(", ") || "—"}
            </p>
          </div>
        )}
      </form>
    </details>
  );
}
