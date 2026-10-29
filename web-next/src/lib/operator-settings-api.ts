import { api } from "@/lib/api";

export type EndpointSettings = {
  provider: "local" | "openrouter" | "omnirouter" | "openai_compatible";
  base_url: string;
  model: string;
  allow_external: boolean;
  timeout_seconds: number;
  max_output_tokens: number;
  api_key?: string;
};
export type SettingsSnapshot = {
  enabled: boolean;
  worker_enabled: boolean;
  external_permitted: boolean;
  effective: (EndpointSettings & { api_key_set: boolean }) | null;
  deployment: EndpointSettings;
  override: Partial<EndpointSettings> | null;
  valid: boolean;
  error: string | null;
};
export type ConnectionResult = {
  ok: boolean;
  error: string | null;
  completion: string;
  models: { id: string; context_tokens: number | null }[];
};
// Installation scope: never accept an endpoint/key in tenant inference requests.
export const operatorSettingsApi = {
  get: async () => (await api.get<SettingsSnapshot>("/operator/settings")).data,
  save: async (body: EndpointSettings) =>
    (await api.put<SettingsSnapshot>("/operator/settings", body)).data,
  reset: async () => {
    await api.delete("/operator/settings");
  },
  test: async (body: EndpointSettings, completion = false) =>
    (await api.post<ConnectionResult>("/operator/settings/test", { ...body, completion })).data,
};
