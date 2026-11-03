// Small shadcn-style primitives (Tailwind + clsx/tailwind-merge).
import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";
import type { ButtonHTMLAttributes, HTMLAttributes, ReactNode } from "react";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

type Variant = "default" | "danger" | "ghost" | "outline";

const variants: Record<Variant, string> = {
  default: "bg-accent text-bg hover:bg-accent/85",
  danger: "bg-bad text-bg hover:bg-bad/85",
  ghost: "bg-transparent text-fg hover:bg-panel-2",
  outline: "border border-line bg-panel-2 text-fg hover:border-accent",
};

export function Button({
  variant = "default",
  className,
  ...props
}: ButtonHTMLAttributes<HTMLButtonElement> & { variant?: Variant }) {
  return (
    <button
      className={cn(
        "inline-flex items-center justify-center gap-2 rounded-lg px-3 py-2 text-[15px] font-semibold",
        "transition-colors disabled:cursor-not-allowed disabled:opacity-40",
        variants[variant],
        className,
      )}
      {...props}
    />
  );
}

export function Card({ className, ...props }: HTMLAttributes<HTMLDivElement>) {
  return <div className={cn("rounded-xl border border-line bg-panel", className)} {...props} />;
}

export function CardHeader({ title, right }: { title: ReactNode; right?: ReactNode }) {
  return (
    <div className="flex items-center justify-between border-b border-line px-4 py-3">
      <h2 className="text-[15px] font-bold uppercase tracking-wider text-muted">{title}</h2>
      {right}
    </div>
  );
}

type Tone = "ok" | "warn" | "bad" | "muted" | "accent";

const tones: Record<Tone, string> = {
  ok: "bg-ok/15 text-ok border-ok/40",
  warn: "bg-warn/15 text-warn border-warn/40",
  bad: "bg-bad/15 text-bad border-bad/40",
  muted: "bg-panel-2 text-muted border-line",
  accent: "bg-accent/15 text-accent border-accent/40",
};

export function Badge({
  tone = "muted",
  className,
  children,
  title,
}: {
  tone?: Tone;
  className?: string;
  children: ReactNode;
  title?: string;
}) {
  return (
    <span
      title={title}
      className={cn(
        "inline-flex items-center gap-1.5 rounded-full border px-2.5 py-0.5 text-[13px] font-semibold",
        tones[tone],
        className,
      )}
    >
      {children}
    </span>
  );
}
