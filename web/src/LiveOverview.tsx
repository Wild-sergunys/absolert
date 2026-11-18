import { useEffect, useState } from "react";
import { Activity, ArrowRight } from "lucide-react";

type Mode = "live" | "pcap";
type Alert = {
  id: number;
  time: string;
  mode: Mode;
  source: string;
  destination: string;
  sid: number;
  revision: number;
  message: string;
  flags: string;
  threshold: "both" | "limit";
  count: number;
  limit: number;
  seconds: number;
};
type Snapshot = {
  alerts: Alert[];
  fresh: boolean;
  updated_at: string;
  status: {
    running: boolean;
    result?: "complete" | "failed";
    mode: Mode;
    read: number;
    tcp: number;
    alerts: number;
    dropped: number;
  } | null;
};

const clock = new Intl.DateTimeFormat("ru-RU", { timeStyle: "medium" });
const dateTime = new Intl.DateTimeFormat("ru-RU", {
  dateStyle: "short",
  timeStyle: "medium",
});
const modeLabel = (mode: Mode) =>
  mode === "pcap" ? "Запись PCAP" : "Живой захват";

function statusLabel(snapshot: Snapshot | null, failed: boolean) {
  if (failed) return "API недоступен";
  if (!snapshot) return "Подключение к API";
  const status = snapshot.status;
  if (!status) return "Ожидание сенсора";
  if (!status.running) {
    if (status.result === "complete") return "Запись обработана";
    if (status.result === "failed") {
      return status.mode === "pcap"
        ? "Ошибка чтения PCAP"
        : "Захват завершился с ошибкой";
    }
    return status.mode === "pcap"
      ? "Чтение PCAP остановлено"
      : "Сенсор остановлен";
  }
  if (!snapshot.fresh) return "Сенсор не отвечает";
  return status.mode === "pcap"
    ? "Читается запись PCAP"
    : "Сенсор захватывает пакеты";
}

export default function LiveOverview() {
  const [snapshot, setSnapshot] = useState<Snapshot | null>(null);
  const [failed, setFailed] = useState(false);
  const [selectedId, setSelectedId] = useState<number | null>(null);
  useEffect(() => {
    const controller = new AbortController();
    let timer = 0;
    async function refresh() {
      try {
        const response = await fetch("/api/monitor", {
          signal: AbortSignal.any([
            controller.signal,
            AbortSignal.timeout(2500),
          ]),
        });
        if (!response.ok) throw new Error("API недоступен");
        const next: Snapshot = await response.json();
        if (!controller.signal.aborted) {
          setSnapshot(next);
          setFailed(false);
        }
      } catch {
        if (!controller.signal.aborted) setFailed(true);
      } finally {
        if (!controller.signal.aborted)
          timer = window.setTimeout(refresh, 1000);
      }
    }
    void refresh();
    return () => {
      controller.abort();
      window.clearTimeout(timer);
    };
  }, []);

  const alerts = snapshot?.alerts ?? [];
  const selected = alerts.find(({ id }) => selectedId === id) ?? alerts[0];
  const status = snapshot?.status;
  return (
    <>
      <div className="page-heading overview-heading">
        <h1>Мониторинг сети</h1>
      </div>
      <section
        className="stream-status live-status"
        aria-label="Состояние потока"
      >
        <div className="stream-state">
          <Activity />
          <div>
            <strong role="status">{statusLabel(snapshot, failed)}</strong>
            <span>
              {status && snapshot
                ? `Последний отчёт · ${clock.format(new Date(snapshot.updated_at))}`
                : "Отчётов о захвате пока нет"}
            </span>
          </div>
        </div>
        <dl className="stream-counters">
          <div>
            <dt>Пакеты</dt>
            <dd>{status?.read ?? "—"}</dd>
          </div>
          <div>
            <dt>TCP</dt>
            <dd>{status?.tcp ?? "—"}</dd>
          </div>
          <div>
            <dt>Алерты</dt>
            <dd>{status?.alerts ?? "—"}</dd>
          </div>
          <div>
            <dt>Не доставлено</dt>
            <dd>{status?.dropped ?? "—"}</dd>
          </div>
        </dl>
      </section>
      <div className="overview-columns live-columns">
        <section className="panel event-panel">
          <div className="panel-toolbar">
            <h2>
              Алерты сенсора <span className="count">{alerts.length}</span>
            </h2>
          </div>
          {alerts.length ? (
            <div
              className="table-scroll"
              role="region"
              aria-label="Алерты"
              tabIndex={0}
            >
              <table className="events-table">
                <thead>
                  <tr>
                    <th>Время</th>
                    <th>Сигнатура</th>
                    <th>Источник → цель</th>
                  </tr>
                </thead>
                <tbody>
                  {alerts.map((alert) => (
                    <tr
                      key={alert.id}
                      className={
                        selected?.id === alert.id ? "selected-event" : ""
                      }
                    >
                      <td className="mono time-cell">
                        <time dateTime={alert.time}>
                          {clock.format(new Date(alert.time))}
                        </time>
                      </td>
                      <td>
                        <button
                          className="row-title"
                          onClick={() => setSelectedId(alert.id)}
                          aria-pressed={selected?.id === alert.id}
                        >
                          <span>
                            {alert.message}
                            <small>
                              SID {alert.sid} · {modeLabel(alert.mode)}
                            </small>
                          </span>
                        </button>
                      </td>
                      <td className="mono endpoints-cell">
                        {alert.source}
                        <span>
                          <ArrowRight />
                          {alert.destination}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <div className="empty-state">
              <h3>Пока нет алертов</h3>
            </div>
          )}
          <div className="table-footer">Последние 100 алертов в памяти API</div>
        </section>
        <aside className="panel event-context" aria-label="Выбранный алерт">
          {selected ? (
            <>
              <span className="eyebrow">{modeLabel(selected.mode)}</span>
              <time className="mono context-time" dateTime={selected.time}>
                {dateTime.format(new Date(selected.time))}
              </time>
              <h2>{selected.message}</h2>
              <dl className="context-addresses">
                <div>
                  <dt>Источник</dt>
                  <dd className="mono">{selected.source}</dd>
                </div>
                <div>
                  <dt>Назначение</dt>
                  <dd className="mono">{selected.destination}</dd>
                </div>
              </dl>
              <section className="detection-trace">
                <h3>Почему сработало</h3>
                <dl className="facts">
                  <div>
                    <dt>TCP-флаги</dt>
                    <dd className="mono">{selected.flags}</dd>
                  </div>
                  <div>
                    <dt>Совпадения по IP источника</dt>
                    <dd className="mono">
                      {selected.count} за {selected.seconds} с
                    </dd>
                  </div>
                  <div>
                    <dt>
                      {selected.threshold === "limit"
                        ? "Лимит алертов"
                        : "Порог"}
                    </dt>
                    <dd className="mono">{selected.limit}</dd>
                  </div>
                  <div>
                    <dt>Сигнатура</dt>
                    <dd className="mono">
                      {selected.sid}:{selected.revision}
                    </dd>
                  </div>
                </dl>
              </section>
            </>
          ) : (
            <div className="empty-state">
              <p>Разбор появится после первого алерта</p>
            </div>
          )}
        </aside>
      </div>
    </>
  );
}
