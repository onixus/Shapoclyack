import axios from "axios";

const TOKEN_KEY = "octo_man_access_token";

export function getAccessToken(): string | null {
  if (typeof window === "undefined") return null;
  return window.localStorage.getItem(TOKEN_KEY);
}

export function setAccessToken(token: string | null) {
  if (typeof window === "undefined") return;
  if (!token) {
    window.localStorage.removeItem(TOKEN_KEY);
    return;
  }
  window.localStorage.setItem(TOKEN_KEY, token);
}

export const api = axios.create({
  baseURL: process.env.NEXT_PUBLIC_API_BASE_URL || "/api",
  headers: {
    "Content-Type": "application/json",
  },
});

api.interceptors.request.use((config) => {
  const token = getAccessToken();
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error?.response?.status === 401 && typeof window !== "undefined") {
      setAccessToken(null);
    }
    return Promise.reject(error);
  },
);

export type Tenant = {
  id: string;
  name: string;
  status: "active" | "paused" | "provisioning";
  agentCount: number;
  assetCount: number;
  createdAt: string;
};

export type AssetRow = {
  id: string;
  host: string;
  tenant: string;
  openPorts: number;
  criticality: "critical" | "high" | "medium" | "low" | "info";
  lastScanned: string;
  diff?: { kind: "port" | "cve"; label: string };
};
