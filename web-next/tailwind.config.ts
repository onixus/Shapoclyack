import type { Config } from "tailwindcss";
import tailwindAnimate from "tailwindcss-animate";

/**
 * Tremor paints both its light and `dark:` classes. Point them at the same
 * APEX variables so a card follows the theme instead of staying white.
 */
const tremorPalette = {
  brand: {
    faint: "var(--apex-accent-subtle)",
    muted: "hsl(var(--apex-accent) / 0.35)",
    subtle: "hsl(var(--apex-accent) / 0.6)",
    DEFAULT: "hsl(var(--apex-accent))",
    emphasis: "hsl(var(--apex-accent))",
    inverted: "hsl(var(--apex-on-accent))",
  },
  background: {
    muted: "hsl(var(--apex-sunken))",
    subtle: "hsl(var(--apex-surface-2))",
    DEFAULT: "hsl(var(--apex-surface-1))",
    emphasis: "hsl(var(--apex-text-secondary))",
  },
  border: {
    DEFAULT: "hsl(var(--apex-border-subtle))",
  },
  ring: {
    DEFAULT: "hsl(var(--apex-border-subtle))",
  },
  content: {
    subtle: "hsl(var(--apex-text-muted))",
    DEFAULT: "hsl(var(--apex-text-secondary))",
    emphasis: "hsl(var(--apex-text-primary))",
    strong: "hsl(var(--apex-text-primary))",
    inverted: "hsl(var(--apex-canvas))",
  },
};

const config: Config = {
  darkMode: ["class"],
  content: [
    "./src/pages/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/components/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/app/**/*.{js,ts,jsx,tsx,mdx}",
    "./node_modules/@tremor/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    transparent: "transparent",
    current: "currentColor",
    extend: {
      colors: {
        border: "hsl(var(--border))",
        input: "hsl(var(--input))",
        ring: "hsl(var(--ring))",
        control: "hsl(var(--control))",
        warning: "hsl(var(--warning))",
        success: "hsl(var(--success))",
        // APEX Design System names (values live in globals.css).
        canvas: "hsl(var(--apex-canvas))",
        sunken: "hsl(var(--apex-sunken))",
        surface: {
          1: "hsl(var(--apex-surface-1))",
          2: "hsl(var(--apex-surface-2))",
          3: "hsl(var(--apex-surface-3))",
        },
        "border-subtle": "hsl(var(--apex-border-subtle))",
        "border-strong": "hsl(var(--apex-border-strong))",
        text: {
          primary: "hsl(var(--apex-text-primary))",
          secondary: "hsl(var(--apex-text-secondary))",
          muted: "hsl(var(--apex-text-muted))",
          disabled: "hsl(var(--apex-text-disabled))",
        },
        danger: {
          DEFAULT: "hsl(var(--apex-danger))",
          subtle: "var(--apex-danger-subtle)",
        },
        info: {
          DEFAULT: "hsl(var(--apex-info))",
          subtle: "var(--apex-info-subtle)",
        },
        "success-subtle": "var(--apex-success-subtle)",
        "warning-subtle": "var(--apex-warning-subtle)",
        "accent-subtle": "var(--apex-accent-subtle)",
        sev: {
          critical: "hsl(var(--sev-critical))",
          high: "hsl(var(--sev-high))",
          medium: "hsl(var(--sev-medium))",
          low: "hsl(var(--sev-low))",
          info: "hsl(var(--sev-info))",
        },
        background: "hsl(var(--background))",
        foreground: "hsl(var(--foreground))",
        primary: {
          DEFAULT: "hsl(var(--primary))",
          foreground: "hsl(var(--primary-foreground))",
        },
        secondary: {
          DEFAULT: "hsl(var(--secondary))",
          foreground: "hsl(var(--secondary-foreground))",
        },
        destructive: {
          DEFAULT: "hsl(var(--destructive))",
          foreground: "hsl(var(--destructive-foreground))",
        },
        muted: {
          DEFAULT: "hsl(var(--muted))",
          foreground: "hsl(var(--muted-foreground))",
        },
        accent: {
          DEFAULT: "hsl(var(--accent))",
          foreground: "hsl(var(--accent-foreground))",
        },
        popover: {
          DEFAULT: "hsl(var(--popover))",
          foreground: "hsl(var(--popover-foreground))",
        },
        card: {
          DEFAULT: "hsl(var(--card))",
          foreground: "hsl(var(--card-foreground))",
        },
        // Flat names: Tremor appends a shade only for Tailwind base colours.
        viz1: "var(--viz-1)",
        viz2: "var(--viz-2)",
        viz3: "var(--viz-3)",
        viz4: "var(--viz-4)",
        viz5: "var(--viz-5)",
        viz6: "var(--viz-6)",
        viz7: "var(--viz-7)",
        viz8: "var(--viz-8)",
        sevinfo: "hsl(var(--sev-info))",
        sevlow: "hsl(var(--sev-low))",
        sevmedium: "hsl(var(--sev-medium))",
        sevhigh: "hsl(var(--sev-high))",
        sevcritical: "hsl(var(--sev-critical))",
        tremor: tremorPalette,
        "dark-tremor": tremorPalette,
      },
      borderRadius: {
        lg: "var(--radius)",
        md: "calc(var(--radius) - 4px)",
        sm: "calc(var(--radius) - 6px)",
        "tremor-small": "0.375rem",
        "tremor-default": "0.5rem",
        "tremor-full": "9999px",
      },
      boxShadow: {
        // Depth is the 1px ring. A tremor drop shadow reads as a second theme.
        "tremor-input": "none",
        "tremor-card": "none",
        "tremor-dropdown": "none",
        "dark-tremor-input": "none",
        "dark-tremor-card": "none",
        "dark-tremor-dropdown": "none",
      },
      fontFamily: {
        sans: ["var(--font-inter)", "ui-sans-serif", "system-ui", "sans-serif"],
        mono: ["var(--font-jetbrains)", "ui-monospace", "monospace"],
      },
      fontSize: {
        "tremor-label": ["0.75rem", { lineHeight: "1rem" }],
        "tremor-default": ["0.875rem", { lineHeight: "1.25rem" }],
        "tremor-title": ["1.125rem", { lineHeight: "1.75rem" }],
        "tremor-metric": ["1.875rem", { lineHeight: "2.25rem" }],
        // APEX type scale: body-sm for field labels and dense tables.
        "body-sm": ["0.8125rem", { lineHeight: "1.125rem" }],
        h3: ["0.9375rem", { lineHeight: "1.375rem", fontWeight: "600" }],
        caption: ["0.75rem", { lineHeight: "1rem", fontWeight: "500" }],
        overline: ["0.6875rem", { lineHeight: "1rem", fontWeight: "600", letterSpacing: "0.08em" }],
      },
    },
  },
  safelist: [
    {
      pattern:
        /^(?:bg|text|border|stroke|fill|ring)-(?:viz[1-8]|sevinfo|sevlow|sevmedium|sevhigh|sevcritical)$/,
      variants: ["hover", "dark", "data-[selected]"],
    },
  ],
  plugins: [tailwindAnimate],
};

export default config;
