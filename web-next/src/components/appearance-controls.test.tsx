import { beforeEach, describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { AppearanceControls } from "@/components/appearance-controls";
import { useAppearanceStore } from "@/lib/appearance";

describe("AppearanceControls", () => {
  beforeEach(() => {
    useAppearanceStore.setState({
      theme: "dark",
      preference: "dark",
      locale: "en",
      hydrated: true,
    });
    document.documentElement.className = "dark";
    document.documentElement.lang = "en";
  });

  it("switches to Russian chrome and persists the locale", async () => {
    const user = userEvent.setup();
    render(<AppearanceControls />);
    await user.click(screen.getByRole("button", { name: "Language" }));
    await user.click(screen.getByText("Русский"));
    expect(useAppearanceStore.getState().locale).toBe("ru");
    expect(screen.getByRole("button", { name: "Язык" })).toBeInTheDocument();
  });

  it("selects the light theme from the menu", async () => {
    const user = userEvent.setup();
    render(<AppearanceControls />);
    await user.click(screen.getByRole("button", { name: "Theme" }));
    await user.click(screen.getByRole("menuitem", { name: "Light" }));
    expect(useAppearanceStore.getState().preference).toBe("light");
    expect(useAppearanceStore.getState().theme).toBe("light");
    expect(document.documentElement.classList.contains("light")).toBe(true);
    expect(document.documentElement.classList.contains("dark")).toBe(false);
    expect(document.documentElement.dataset.theme).toBe("light");
  });
});
