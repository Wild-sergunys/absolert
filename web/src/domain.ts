export type Severity = "high" | "medium" | "low";
export type NetworkEvent = {
  id: string;
  time: string;
  title: string;
  severity: Severity;
  source: string;
  target: string;
  sid: number;
  ports: number[];
  matches: number;
  count: number;
  seconds: number;
};
export type Signature = {
  id: string;
  sid: number | null;
  title: string;
  service: string;
  enabled: boolean;
  draft: boolean;
  text: string;
};
export type EventFilters = {
  query: string;
  severity: Severity | "all";
  review: "all" | "new" | "reviewed";
};

export const severityLabels: Record<Severity, string> = {
  high: "Высокая",
  medium: "Средняя",
  low: "Низкая",
};
export const number = (n: number) => new Intl.NumberFormat("ru-RU").format(n);

export function filterEvents(
  events: NetworkEvent[],
  filters: EventFilters,
  reviewed: Set<string>,
) {
  const q = filters.query.trim().toLocaleLowerCase("ru");
  return events.filter(
    (event) =>
      (filters.severity === "all" || event.severity === filters.severity) &&
      (filters.review === "all" ||
        reviewed.has(event.id) === (filters.review === "reviewed")) &&
      `${event.title} ${event.source} ${event.target} ${event.sid} ${event.id}`
        .toLocaleLowerCase("ru")
        .includes(q),
  );
}

// Проверяется только форма черновика; синтаксис и исполнение проверит Go-движок.
export function validateDraft(title: string, text: string): string | null {
  if (!title.trim()) return "Укажите название сигнатуры";
  if (title.trim().length > 120)
    return "Название должно быть не длиннее 120 символов";
  if (!text.trim()) return "Добавьте текст правила";
  if (new TextEncoder().encode(text).length > 65536)
    return "Размер черновика не должен превышать 64 КиБ";
  return null;
}

// График агрегирован по минутам, а события содержат ещё и секунды.
export function findMinuteIndex(
  time: string,
  points: readonly { minute: string }[],
): number {
  return points.findIndex((point) => point.minute === time.slice(0, 5));
}
