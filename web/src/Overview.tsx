import { useState } from "react";
import {
  ArrowDownToLine,
  ArrowRight,
  ChevronDown,
  ChevronRight,
  Search,
  SlidersHorizontal,
  Unplug,
} from "lucide-react";
import { filterEvents, findMinuteIndex } from "./domain.ts";
import type { EventFilters, NetworkEvent } from "./domain.ts";
import { events, traffic } from "./fixtures.ts";
import { DetectionTrace, PortStrip, SeverityBadge } from "./components.tsx";
import TrafficChart from "./TrafficChart.tsx";

export default function Overview({
  reviewed,
  onEvent,
  notify,
}: {
  reviewed: Set<string>;
  onEvent: (event: NetworkEvent) => void;
  notify: (message: string) => void;
}) {
  const [period, setPeriod] = useState<15 | 60>(15);
  const [filters, setFilters] = useState<EventFilters>({
    query: "",
    severity: "all",
    review: "new",
  });
  const filtered = filterEvents(events, filters, reviewed);
  const [selectedId, setSelectedId] = useState(events[0].id);
  const selected =
    filtered.find((item) => item.id === selectedId) ?? filtered[0] ?? null;
  function selectEvent(item: NetworkEvent) {
    setSelectedId(item.id);
    if (findMinuteIndex(item.time, traffic.slice(-period)) < 0) setPeriod(60);
  }
  function openEvent(item: NetworkEvent) {
    selectEvent(item);
    onEvent(item);
  }

  function exportEvents() {
    const file = new Blob(
      [
        JSON.stringify(
          {
            mode: "demonstration",
            events: filtered.map((event) => ({
              ...event,
              reviewed: reviewed.has(event.id),
            })),
          },
          null,
          2,
        ),
      ],
      { type: "application/json" },
    );
    const url = URL.createObjectURL(file);
    const link = document.createElement("a");
    link.href = url;
    link.download = "absolert-demo-events.json";
    link.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
    notify(`Экспортировано событий: ${filtered.length}`);
  }
  return (
    <>
      <div className="page-heading overview-heading">
        <h1>Мониторинг сети</h1>
        <span className="monitor-mode">Пассивный режим</span>
      </div>
      <section className="stream-status" aria-label="Состояние потока">
        <div className="stream-state">
          <Unplug />
          <div>
            <strong>Сенсор не подключён</strong>
            <span>На экране — учебные данные</span>
          </div>
        </div>
        <dl className="stream-counters">
          <div>
            <dt>Пакетов / с</dt>
            <dd>—</dd>
          </div>
          <div>
            <dt>Обновлено</dt>
            <dd>—</dd>
          </div>
        </dl>
        <div className="work-queue">
          <strong>{events.length - reviewed.size}</strong>
          <span>
            Требуют разбора<small>из учебного набора</small>
          </span>
        </div>
      </section>
      <div className="overview-columns">
        <section className="panel activity-panel">
          <div className="panel-heading">
            <h2>Трафик и события</h2>
            <div className="segmented" aria-label="Период графика">
              {([15, 60] as const).map((value) => (
                <button
                  key={value}
                  className={period === value ? "selected" : ""}
                  aria-pressed={period === value}
                  onClick={() => setPeriod(value)}
                >
                  {value === 60 ? "1 час" : "15 мин"}
                </button>
              ))}
            </div>
          </div>
          <TrafficChart
            period={period}
            events={filtered}
            selected={selected}
            onSelect={selectEvent}
          />
          {selected &&
            findMinuteIndex(selected.time, traffic.slice(-period)) < 0 && (
              <div className="chart-outside">
                Выбранное событие вне периода
                <button className="text-button" onClick={() => setPeriod(60)}>
                  Показать на графике
                  <ArrowRight />
                </button>
              </div>
            )}
        </section>
        <section className="panel event-panel">
          <div className="panel-toolbar">
            <h2>
              Лента событий <span className="count">{filtered.length}</span>
            </h2>
            <button className="button secondary small" onClick={exportEvents}>
              <ArrowDownToLine />
              Экспорт JSON
            </button>
          </div>
          <div className="event-filters">
            <div className="tabs" aria-label="Статус разбора">
              {(
                [
                  { id: "all", text: "Все события", count: events.length },
                  {
                    id: "new",
                    text: "Новые",
                    count: events.length - reviewed.size,
                  },
                  { id: "reviewed", text: "Разобранные", count: reviewed.size },
                ] as const
              ).map((tab) => (
                <button
                  key={tab.id}
                  className={filters.review === tab.id ? "active" : ""}
                  aria-pressed={filters.review === tab.id}
                  onClick={() => setFilters({ ...filters, review: tab.id })}
                >
                  {tab.text}
                  <span>{tab.count}</span>
                </button>
              ))}
            </div>
            <div className="filter-inputs">
              <label className="search">
                <Search />
                <input
                  aria-label="Поиск событий"
                  placeholder="Адрес, событие или SID"
                  value={filters.query}
                  onChange={(e) =>
                    setFilters({ ...filters, query: e.target.value })
                  }
                />
              </label>
              <label className="select-control">
                <SlidersHorizontal />
                <select
                  aria-label="Важность события"
                  value={filters.severity}
                  onChange={(e) =>
                    setFilters({
                      ...filters,
                      severity: e.target.value as EventFilters["severity"],
                    })
                  }
                >
                  <option value="all">Любая важность</option>
                  <option value="high">Высокая</option>
                  <option value="medium">Средняя</option>
                  <option value="low">Низкая</option>
                </select>
                <ChevronDown />
              </label>
            </div>
          </div>
          <div
            className="table-scroll"
            role="region"
            aria-label="События"
            tabIndex={0}
          >
            <table className="events-table">
              <thead>
                <tr>
                  <th>Время</th>
                  <th>Событие</th>
                  <th>Источник → цель</th>
                  <th>Важность</th>
                  <th>
                    <span className="sr-only">Разобрать</span>
                  </th>
                </tr>
              </thead>
              <tbody>
                {filtered.map((item) => (
                  <tr
                    key={item.id}
                    className={`${reviewed.has(item.id) ? "reviewed" : ""} ${selected?.id === item.id ? "selected-event" : ""}`}
                  >
                    <td className="mono time-cell">
                      {item.time}
                      <span>
                        {reviewed.has(item.id) ? "Разобрано" : "Новое"}
                      </span>
                    </td>
                    <td>
                      <button
                        className="row-title"
                        aria-pressed={selected?.id === item.id}
                        onClick={() => selectEvent(item)}
                      >
                        <span className={`event-mark ${item.severity}`} />
                        <span>
                          {item.title}
                          <small className="mono">
                            SID {item.sid} · {item.matches} совпадений
                          </small>
                        </span>
                      </button>
                    </td>
                    <td className="mono endpoints-cell">
                      {item.source}
                      <span>
                        <ArrowRight />
                        {item.target}
                      </span>
                    </td>
                    <td>
                      <SeverityBadge value={item.severity} />
                    </td>
                    <td>
                      <button
                        className="icon-button"
                        aria-label={`Разобрать ${item.id}`}
                        onClick={() => openEvent(item)}
                      >
                        <ChevronRight />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {filtered.length === 0 && (
            <div className="empty-state">
              <Search />
              <h3>Событий по этим условиям нет</h3>
              <p>Измените поиск или важность события</p>
              <button
                className="button secondary"
                onClick={() =>
                  setFilters({ query: "", severity: "all", review: "all" })
                }
              >
                Сбросить фильтры
              </button>
            </div>
          )}
          <div className="table-footer">
            <span>
              Показано {filtered.length} из {events.length}
            </span>
            <span>Адреса из диапазонов для документации</span>
          </div>
        </section>
        <aside className="panel event-context" aria-label="Выбранное событие">
          {selected ? (
            <>
              <div className="context-heading">
                <span className="eyebrow">Выбранное событие</span>
                <SeverityBadge value={selected.severity} />
              </div>
              <span className="mono context-time">
                {selected.id} · {selected.time}
              </span>
              <h2>{selected.title}</h2>
              <dl className="context-addresses">
                <div>
                  <dt>Источник</dt>
                  <dd className="mono">{selected.source}</dd>
                </div>
                <div>
                  <dt>Назначение</dt>
                  <dd className="mono">{selected.target}</dd>
                </div>
              </dl>
              <PortStrip ports={selected.ports} />
              <DetectionTrace event={selected} />
              <button
                className="button primary"
                onClick={() => openEvent(selected)}
              >
                Открыть разбор
                <ArrowRight />
              </button>
            </>
          ) : (
            <div className="empty-state">
              <Search />
              <h3>Событие не выбрано</h3>
              <p>Измените фильтры, чтобы увидеть события</p>
            </div>
          )}
        </aside>
      </div>
    </>
  );
}
