import { render, screen } from "@testing-library/react";
import { it, expect, vi } from "vitest";
import { useAppearanceStore } from "@/lib/appearance";
import RunsPage from "./page";
vi.mock("next/navigation", () => ({ useSearchParams: () => new URLSearchParams() }));
vi.mock("@/hooks/use-runs", () => ({
  useRuns: () => ({
    data: {
      items: [
        {
          run_id: "run-proof",
          profile: "balanced",
          unconfirmed_findings: 2,
          potential_vulnerabilities: 2,
          has_diff: true,
          has_summary: true,
        },
      ],
      total: 1,
    },
    isLoading: false,
  }),
}));
it("shows Russian run profiles and artifacts with the original profile collapsed", () => {
  useAppearanceStore.setState({ locale: "ru" });
  render(<RunsPage />);
  expect(screen.getByText("Сбалансированный")).toBeVisible();
  expect(screen.getByText("Изменения")).toBeVisible();
  expect(screen.getByText("Отчёт PDF")).toBeVisible();
  expect(screen.getByText("Не подтверждено: 2")).toBeVisible();
  const details = screen.getByText("Технические данные").closest("details")!;
  expect(details).not.toHaveAttribute("open");
  expect(details).toHaveTextContent("balanced");
  expect(screen.getByRole("link", { name: "run-proof" })).toHaveAttribute(
    "href",
    "/runs/view?runId=run-proof",
  );
});
