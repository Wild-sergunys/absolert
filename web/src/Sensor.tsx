import { Activity, Check, EthernetPort, Layers3, X } from "lucide-react";
import { number } from "./domain.ts";
import { traffic } from "./fixtures.ts";

export default function Sensor() {
  const total = traffic.reduce((sum, point) => sum + point.packets, 0);
  return (
    <>
      <div className="page-heading">
        <div>
          <p className="eyebrow">Точка наблюдения</p>
          <h1>Сенсор</h1>
          <p className="page-description">
            Состояние захвата и границы видимости
          </p>
        </div>
        <span className="disconnected">
          <span />
          Учебные данные
        </span>
      </div>
      <div className="sensor-layout">
        <section className="panel sensor-overview">
          <div className="sensor-illustration" aria-hidden="true">
            <div className="wire wire-left" />
            <div className="device">
              <EthernetPort />
              <span>sensor-01</span>
            </div>
            <div className="wire wire-right" />
            <span className="wire-dot" />
          </div>
          <h2>Захват трафика</h2>
          <p>
            Сенсор запускается из терминала. Состояние захвата и алерты доступны
            на странице мониторинга.
          </p>
          <a className="button secondary" href="/monitor">
            <Activity />
            Открыть мониторинг
          </a>
        </section>
        <section className="panel configuration-panel">
          <div className="panel-heading">
            <h2>Параметры демосеанса</h2>
            <EthernetPort />
          </div>
          <dl className="facts">
            <div>
              <dt>Сенсор</dt>
              <dd className="mono">sensor-01</dd>
            </div>
            <div>
              <dt>Интерфейс</dt>
              <dd className="mono">eth-lab</dd>
            </div>
            <div>
              <dt>Режим</dt>
              <dd>Пассивный</dd>
            </div>
            <div>
              <dt>Протоколы</dt>
              <dd className="mono">Ethernet / IPv4 / TCP</dd>
            </div>
            <div>
              <dt>Источник</dt>
              <dd>Учебный набор</dd>
            </div>
            <div>
              <dt>Сеанс</dt>
              <dd className="mono">13:00–14:00</dd>
            </div>
          </dl>
        </section>
      </div>
      <section className="panel sensor-counters">
        <div className="panel-heading">
          <div>
            <h2>Счётчики обработки</h2>
            <p>Фиксированные значения демонстрационного сеанса</p>
          </div>
          <Layers3 />
        </div>
        <div className="counter-grid">
          <div>
            <span>Прочитано</span>
            <strong>{number(total + 186)}</strong>
          </div>
          <div>
            <span>IPv4 / TCP</span>
            <strong>{number(total)}</strong>
          </div>
          <div>
            <span>Неподдерживаемые</span>
            <strong>186</strong>
          </div>
          <div>
            <span>Повреждённые</span>
            <strong>0</strong>
          </div>
          <div>
            <span>Усечённые</span>
            <strong>0</strong>
          </div>
        </div>
      </section>
      <section className="boundaries">
        <h2>Что видно сенсору</h2>
        <div>
          <p>
            <Check />
            Ethernet, IPv4 и TCP-флаги
          </p>
          <p>
            <Check />
            Адреса и порты соединений
          </p>
          <p>
            <X />
            Содержимое TLS и HTTP/2
          </p>
          <p>
            <X />
            Сборка TCP-потоков
          </p>
        </div>
      </section>
    </>
  );
}
