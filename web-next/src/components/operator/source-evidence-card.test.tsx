import { render, screen } from "@testing-library/react";
import coverage from "./description-coverage.json";
import { describe, it, expect } from "vitest";
import { SourceEvidenceCard, russianObservationDescription } from "./source-evidence-card";
const data = {
  source_id: "source1",
  status: "partial",
  context: { host: "192.0.2.8", port: 22, severity: "unknown" },
  source_display: {
    run_id: "20261028T162811Z-example",
    findings: [
      {
        title: "SSH banner observed",
        detail: "Observed SSH service, not proof of exploitation",
        source: "pulse",
        script_id: "ssh-banner",
      },
    ],
    match_count: 1,
  },
};
describe("source evidence card", () => {
  it("renders the host, port, actual observation and local original-run link", () => {
    const v = render(<SourceEvidenceCard data={data} language="ru" />);
    expect(screen.getByText("192.0.2.8")).toBeVisible();
    expect(screen.getByText("22")).toBeVisible();
    expect(screen.getByText("SSH banner observed")).toBeVisible();
    expect(screen.getByRole("link", { name: "Открыть исходный скан" })).toHaveAttribute(
      "href",
      "/runs/view?runId=20261028T162811Z-example",
    );
    expect(v.container.querySelector("pre")).toBeNull();
  });
  it("shows the reviewed Russian description and keeps the exact original collapsed", () => {
    const view = render(<SourceEvidenceCard data={data} language="ru" />);
    expect(
      screen.getByText(
        "Обнаружен SSH-сервис. Это наблюдение не доказывает эксплуатацию уязвимости.",
      ),
    ).toBeVisible();
    const original = screen.getByText("Observed SSH service, not proof of exploitation");
    expect(original.closest("details")).toBe(view.container.querySelector("details"));
    expect(original.closest("details")).not.toHaveAttribute("open");
  });
  it("preserves the trust limitations in the SSH-key translation", () => {
    const original =
      "Ed25519 host-key fingerprint from a signature-verified curve25519 key exchange. This proves key possession on this connection, not known-host trust, host identity or absence of weak algorithms.";
    const translated = russianObservationDescription(original);
    expect(translated).toContain("владел соответствующим закрытым ключом");
    expect(translated).toContain(
      "не подтверждает доверие к ключу, подлинность хоста или отсутствие слабых",
    );
  });
  it("does not invent a translation for an unrecognized or changed description", () => {
    expect(russianObservationDescription("Unrecognized detector says safe")).toContain(
      "Сканер зарегистрировал техническое наблюдение",
    );
  });
  it("keeps source prose inert and rejects an external run destination", () => {
    const v = render(
      <SourceEvidenceCard
        data={{
          ...data,
          source_display: {
            ...data.source_display,
            run_id: "https://evil.test",
            findings: [{ title: '<img src="https://evil.test" onerror="alert(1)">' }],
          },
        }}
        language="en"
      />,
    );
    expect(screen.getByText(/<img src=/)).toBeVisible();
    expect(v.container.querySelector("img")).toBeNull();
    expect(screen.queryByRole("link")).not.toBeInTheDocument();
  });
  it("does not invent a finding title and discloses ambiguous matches", () => {
    render(
      <SourceEvidenceCard
        data={{
          ...data,
          source_display: { ...data.source_display, match_count: 2, findings: [{}, {}] },
        }}
        language="en"
      />,
    );
    expect(screen.getByText(/matches multiple observations/)).toBeVisible();
    expect(screen.getAllByText("Finding title was not retained")).toHaveLength(2);
  });
});

describe("Russian description catalogue coverage", () => {
  it.each(coverage)("translates recorded/module description: $origin / $detail", ({ detail }) => {
    const translated = russianObservationDescription(detail);
    expect(translated).toMatch(/[А-Яа-яЁё]/);
    expect(translated).not.toBe(detail);
    expect(translated).not.toContain("Сканер зарегистрировал техническое наблюдение");
    expect(translated).not.toContain("нет проверенного");
  });
  it("handles dynamic SMB, administration ports and old OpenSSH banners without dropping limitations", () => {
    expect(
      russianObservationDescription(
        "Exposure only: VNC answers on port 5901. Network-level authentication, encryption and password policy were not checked.",
      ),
    ).toContain("на порту 5901");
    expect(
      russianObservationDescription(
        "The banner says OpenSSH 6.x, which predates 7.0 and is out of upstream support. Distributions backport fixes without changing this string, so it is a hint to check the package, not proof of exposure.",
      ),
    ).toContain("наличие уязвимости по баннеру не доказано");
  });
  it("gives a bounded factual explanation for a new external description without pretending to translate it", () => {
    const translated = russianObservationDescription(
      "New detector: definitely safe <script>alert(1)</script>",
    );
    expect(translated).toContain("Полное исходное описание сохранено");
    expect(translated).not.toContain("safe");
    expect(translated).not.toContain("<script>");
  });
});
