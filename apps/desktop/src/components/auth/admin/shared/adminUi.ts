import { useI18n } from "vue-i18n";
import { translateBackendError } from "@/i18n/backend-errors";

export const selectClass = "h-8 w-full rounded-md border border-input bg-transparent px-2 text-sm dark:bg-input/30 focus-visible:outline-none focus-visible:ring-3 focus-visible:ring-ring/50 disabled:opacity-50";
export const fieldLabelClass = "space-y-1.5 text-xs font-medium text-muted-foreground";
export const checkboxClass = "h-4 w-4 rounded border-input accent-primary";

export function useAdminText() {
  const { t, locale } = useI18n();

  function errorText(e: unknown): string {
    const code = e instanceof Error ? e.message : String(e);
    return translateBackendError(t, code) || t("users.actionFailed");
  }

  function dateTime(value: number | null | undefined, empty = ""): string {
    if (!value) return empty;
    return new Date(value).toLocaleString(String(locale.value), { dateStyle: "medium", timeStyle: "short" });
  }

  function date(value: number | null | undefined, empty = ""): string {
    if (!value) return empty;
    return new Date(value).toLocaleDateString(String(locale.value), { dateStyle: "medium" });
  }

  function relative(value: number | null | undefined, empty = ""): string {
    if (!value) return empty;
    const seconds = Math.round((value - Date.now()) / 1000);
    const units: [Intl.RelativeTimeFormatUnit, number][] = [
      ["year", 31536000],
      ["month", 2592000],
      ["day", 86400],
      ["hour", 3600],
      ["minute", 60],
    ];
    const format = new Intl.RelativeTimeFormat(String(locale.value), { numeric: "auto" });
    for (const [unit, size] of units) {
      if (Math.abs(seconds) >= size) return format.format(Math.round(seconds / size), unit);
    }
    return format.format(0, "minute");
  }

  return { errorText, dateTime, date, relative };
}

export function dateInputValue(millis: number | null | undefined): string {
  if (!millis) return "";
  const value = new Date(millis);
  const pad = (part: number) => String(part).padStart(2, "0");
  return `${value.getFullYear()}-${pad(value.getMonth() + 1)}-${pad(value.getDate())}`;
}
