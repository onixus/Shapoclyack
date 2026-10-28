import { type ClassValue, clsx } from "clsx";
import { extendTailwindMerge } from "tailwind-merge";

// tailwind-merge only knows Tailwind's own size names, so it would read the
// APEX type styles (`text-body-sm`, `text-h3`, ...) as text colours and drop
// them next to `text-muted-foreground`. Register them as font sizes.
const twMerge = extendTailwindMerge({
  extend: {
    classGroups: {
      "font-size": [{ text: ["body-sm", "h3", "caption", "overline"] }],
    },
  },
});

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}
