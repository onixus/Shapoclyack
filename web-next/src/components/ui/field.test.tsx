import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import { CheckboxOption, Field, FieldGrid, fieldHintId } from "@/components/ui/field";
import { Input } from "@/components/ui/input";

describe("Field", () => {
  it("labels the control and describes it with the hint", () => {
    render(
      <Field label="TCP ports" htmlFor="ports" optional="optional" hint="Comma-separated.">
        <Input id="ports" aria-describedby={fieldHintId("ports")} />
      </Field>,
    );
    const input = screen.getByLabelText("TCP ports");
    expect(input).toHaveAccessibleDescription("Comma-separated.");
    expect(screen.getByText("optional")).toBeInTheDocument();
  });

  it("keeps an empty hint row so neighbours stay aligned", () => {
    const { container } = render(
      <FieldGrid cols={2}>
        <Field label="With hint" htmlFor="a" hint="Something">
          <Input id="a" />
        </Field>
        <Field label="Without hint" htmlFor="b">
          <Input id="b" />
        </Field>
      </FieldGrid>,
    );
    expect(container.querySelector(`#${fieldHintId("b")}`)).toBeInTheDocument();
    expect(container.firstElementChild).toHaveClass("items-start");
  });

  it("drops the hint row in filter bars", () => {
    const { container } = render(
      <Field label="Severity" htmlFor="sev" reserveHint={false}>
        <Input id="sev" />
      </Field>,
    );
    expect(container.querySelector(`#${fieldHintId("sev")}`)).toBeNull();
  });
});

describe("CheckboxOption", () => {
  it("toggles from a click on its text", async () => {
    const onChange = vi.fn();
    render(
      <CheckboxOption
        label="Alert notifications"
        description="Send alerts."
        checked={false}
        onCheckedChange={onChange}
      />,
    );
    await userEvent.setup().click(screen.getByText("Alert notifications"));
    expect(onChange).toHaveBeenCalledWith(true);
  });
});
