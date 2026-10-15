import { api } from "@/lib/api";

export type ViewPage = "assets" | "vulnerabilities";
export type ViewState = {
  version: 1;
  search: string;
  sort: string | null;
  order: "asc" | "desc";
  filters: Record<string, string | boolean>;
};
export type SavedView = {
  view_id: string;
  name: string;
  page: ViewPage;
  state: ViewState;
  compatible: boolean;
};

export async function fetchViews(page: ViewPage, tenant: string, signal?: AbortSignal) {
  return (
    await api.get<SavedView[]>("/saved-views", { params: { page, tenant_id: tenant }, signal })
  ).data;
}
export async function createView(page: ViewPage, name: string, state: ViewState, tenant: string) {
  return (
    await api.post<SavedView>(
      "/saved-views",
      { page, name, state },
      { params: { tenant_id: tenant } },
    )
  ).data;
}
export async function renameView(id: string, name: string, tenant: string) {
  return (
    await api.patch<SavedView>(
      `/saved-views/${encodeURIComponent(id)}`,
      { name },
      { params: { tenant_id: tenant } },
    )
  ).data;
}
export async function deleteView(id: string, tenant: string) {
  await api.delete(`/saved-views/${encodeURIComponent(id)}`, { params: { tenant_id: tenant } });
}
