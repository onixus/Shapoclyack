import { Card, Metric, Text } from "@tremor/react";

export function KpiCard({
  label,
  value,
  hint,
  decorationColor,
}: {
  label: string;
  value: string | number;
  hint?: string;
  decorationColor?: string;
}) {
  return (
    <Card decoration={decorationColor ? "top" : undefined} decorationColor={decorationColor}>
      <Text>{label}</Text>
      <Metric>{typeof value === "number" ? value.toLocaleString() : value}</Metric>
      {hint ? <Text className="mt-1 text-xs">{hint}</Text> : null}
    </Card>
  );
}
