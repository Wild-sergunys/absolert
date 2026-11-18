import { useEffect, useId, useRef } from "react";
import type { ReactNode } from "react";
import {
  ArrowDownLeft,
  ArrowUpRight,
  Check,
  ChevronRight,
  X,
} from "lucide-react";
import { severityLabels } from "./domain.ts";
import type { NetworkEvent, Severity } from "./domain.ts";

export function SeverityBadge({ value }: { value: Severity }) {
  return (
    <span className={`severity ${value}`}>
      <span />
      {severityLabels[value]}
    </span>
  );
}

export function Modal({
  title,
  children,
  onClose,
  sheet = false,
}: {
  title: string;
  children: ReactNode;
  onClose: () => void;
  sheet?: boolean;
}) {
  const ref = useRef<HTMLDialogElement>(null);
  const titleId = useId();
  useEffect(() => {
    const dialog = ref.current!;
    dialog.showModal();
    return () => dialog.close();
  }, []);
  return (
    <dialog
      ref={ref}
      className={sheet ? "modal sheet" : "modal"}
      aria-labelledby={titleId}
      onCancel={onClose}
      onClick={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div className="modal-inner">
        <header className="modal-header">
          <h2 id={titleId}>{title}</h2>
          <button
            className="icon-button"
            onClick={onClose}
            aria-label="Закрыть"
          >
            <X />
          </button>
        </header>
        {children}
      </div>
    </dialog>
  );
}

// Сводка использует только поля выбранного события, без имитации исполнения правила.
export function DetectionTrace({ event }: { event: NetworkEvent }) {
  return (
    <section className="detection-trace">
      <h3>Почему сработало</h3>
      <ol>
        <li>
          <Check />
          <div>
            <span>Признак пакета</span>
            <strong className="mono">TCP · SYN</strong>
          </div>
        </li>
        <li>
          <Check />
          <div>
            <span>Порог совпадений</span>
            <strong className="mono">
              {event.matches} / {event.count}
              <small>{event.seconds} с</small>
            </strong>
          </div>
        </li>
        <li>
          <Check />
          <div>
            <span>Сигнатура</span>
            <strong className="mono">SID {event.sid}</strong>
          </div>
        </li>
      </ol>
    </section>
  );
}

export function PortStrip({ ports }: { ports: number[] }) {
  const range = ports.some((port) => port >= 5800 && port <= 5820)
    ? Array.from({ length: 21 }, (_, i) => 5800 + i)
    : ports;
  return (
    <div className="port-map">
      <div
        role="img"
        aria-label={`Наблюдались попытки к TCP-портам: ${ports.join(", ")}`}
      >
        <div className="port-cells">
          {range.map((port) => (
            <span
              key={port}
              className={`port-cell ${ports.includes(port) ? "hit" : ""}`}
              title={`TCP ${port}: ${ports.includes(port) ? "есть попытка" : "нет наблюдений"}`}
            />
          ))}
        </div>
        <div className="port-map-labels">
          <span className="mono">{range[0]}</span>
          <span>
            {range.length > 1 ? "Порты назначения" : "Порт назначения"}
          </span>
          {range.length > 1 && <span className="mono">{range.at(-1)}</span>}
        </div>
      </div>
      <details className="port-breakdown">
        <summary>Наблюдаемые порты · {ports.length}</summary>
        <p className="mono">{ports.join(", ")}</p>
      </details>
    </div>
  );
}

export function EventDetails({
  event,
  reviewed,
  onReview,
  onClose,
  onRule,
}: {
  event: NetworkEvent;
  reviewed: boolean;
  onReview: () => void;
  onClose: () => void;
  onRule: () => void;
}) {
  return (
    <Modal title="Разбор события" onClose={onClose} sheet>
      <div className="sheet-body">
        <div className="detail-meta">
          <span className="mono">
            {event.id} · {event.time}
          </span>
          <SeverityBadge value={event.severity} />
        </div>
        <h3 className="detail-title">{event.title}</h3>
        <p className="muted">
          Совпадение лабораторной сигнатуры в демонстрационном сеансе
        </p>
        <div className="endpoint-diagram">
          <div>
            <ArrowDownLeft />
            <span>Источник</span>
            <strong className="mono">{event.source}</strong>
          </div>
          <ChevronRight />
          <div>
            <ArrowUpRight />
            <span>Назначение</span>
            <strong className="mono">{event.target}</strong>
          </div>
        </div>
        <DetectionTrace event={event} />
        <section className="detail-section">
          <h4>Что обнаружено</h4>
          <p>
            За окно {event.seconds} с зафиксировано {event.matches} совпадений
            SYN при пороге {event.count}. Это признак подозрительной активности,
            а не подтверждение успешного вторжения.
          </p>
          <PortStrip ports={event.ports} />
          <p className="caption">
            Заполненная ячейка — попытка подключения. Успешность соединения
            здесь не определяется.
          </p>
        </section>
        <section className="detail-section">
          <h4>Условия срабатывания</h4>
          <dl className="facts">
            <div>
              <dt>Флаги</dt>
              <dd className="mono">SYN · ECN игнорируется</dd>
            </div>
            <div>
              <dt>Группировка</dt>
              <dd>По адресу источника</dd>
            </div>
            <div>
              <dt>Сигнатура</dt>
              <dd>
                <button className="text-button mono" onClick={onRule}>
                  SID {event.sid}
                  <ChevronRight />
                </button>
              </dd>
            </div>
          </dl>
        </section>
        <div className="quiet-note">
          Детали взяты из демонстрационного набора. Сборка TCP-потоков и
          рекомендации ещё не подключены.
        </div>
      </div>
      <footer className="sheet-footer">
        <button
          className={reviewed ? "button secondary" : "button primary"}
          onClick={onReview}
        >
          <Check />
          {reviewed ? "Вернуть в новые" : "Отметить разобранным"}
        </button>
        <span className="caption">Сохраняется до обновления страницы</span>
      </footer>
    </Modal>
  );
}
