import { useState } from "react";
import type { KeyboardEvent, PointerEvent } from "react";
import { findMinuteIndex, number } from "./domain.ts";
import type { NetworkEvent } from "./domain.ts";
import { traffic } from "./fixtures.ts";

const width = 1000;
const height = 144;
const inset = 8;

export default function TrafficChart({
  period,
  events,
  selected,
  onSelect,
}: {
  period: 15 | 60;
  events: NetworkEvent[];
  selected: NetworkEvent | null;
  onSelect: (event: NetworkEvent) => void;
}) {
  const data = traffic.slice(-period);
  const [hovered, setHovered] = useState<number | null>(null);
  const selectedIndex = selected ? findMinuteIndex(selected.time, data) : -1;
  const cursor =
    hovered === null ? selectedIndex : Math.min(hovered, data.length - 1);
  const current = data[cursor];
  const ceiling =
    Math.ceil(Math.max(...data.map((point) => point.packets)) / 500) * 500;
  const x = (index: number) =>
    inset + (index / (data.length - 1)) * (width - inset * 2);
  const y = (packets: number) =>
    height - inset - (packets / ceiling) * (height - inset * 2);
  const line = data
    .map(
      (point, index) => `${index ? "L" : "M"} ${x(index)} ${y(point.packets)}`,
    )
    .join(" ");

  function inspectPointer(event: PointerEvent<SVGSVGElement>) {
    const bounds = event.currentTarget.getBoundingClientRect();
    const position = (event.clientX - bounds.left) / bounds.width;
    const index = Math.round(
      ((position * width - inset) / (width - inset * 2)) * (data.length - 1),
    );
    setHovered(Math.max(0, Math.min(data.length - 1, index)));
  }
  function inspectKey(event: KeyboardEvent<SVGSVGElement>) {
    if (event.target !== event.currentTarget) return;
    if (event.key !== "ArrowLeft" && event.key !== "ArrowRight") return;
    event.preventDefault();
    const next = Math.max(0, cursor) + (event.key === "ArrowRight" ? 1 : -1);
    setHovered(Math.max(0, Math.min(data.length - 1, next)));
  }

  return (
    <div className="traffic-chart">
      <div className="chart-plot">
        <div className="chart-y-labels" aria-hidden="true">
          <span>{number(ceiling)}</span>
          <span>{number(ceiling / 2)}</span>
          <span>0</span>
        </div>
        <svg
          viewBox={`0 0 ${width} ${height}`}
          preserveAspectRatio="none"
          tabIndex={0}
          role="group"
          aria-label={`Трафик за ${period} минут. Стрелки влево и вправо выбирают минуту. Маркеры обозначают события.`}
          onPointerMove={inspectPointer}
          onPointerLeave={() => setHovered(null)}
          onKeyDown={inspectKey}
          onBlur={() => setHovered(null)}
        >
          {[0, ceiling / 2, ceiling].map((value) => (
            <line
              key={value}
              x1={inset}
              x2={width - inset}
              y1={y(value)}
              y2={y(value)}
              className="chart-grid"
              vectorEffect="non-scaling-stroke"
            />
          ))}
          <path
            d={`${line} L ${width - inset} ${height - inset} L ${inset} ${height - inset} Z`}
            className="chart-area"
          />
          <path
            d={line}
            className="chart-line"
            vectorEffect="non-scaling-stroke"
          />
          {cursor >= 0 && (
            <g aria-hidden="true">
              <line
                x1={x(cursor)}
                x2={x(cursor)}
                y1={inset}
                y2={height - inset}
                className="chart-cursor"
                vectorEffect="non-scaling-stroke"
              />
              <circle
                cx={x(cursor)}
                cy={y(data[cursor].packets)}
                r="4"
                className="chart-cursor-dot"
                vectorEffect="non-scaling-stroke"
              />
            </g>
          )}
          {events.map((event) => {
            const index = findMinuteIndex(event.time, data);
            if (index < 0) return null;
            return (
              <g
                key={event.id}
                role="button"
                tabIndex={0}
                aria-label={`Выбрать событие ${event.id} в ${event.time}`}
                aria-pressed={selected?.id === event.id}
                className={`chart-marker ${selected?.id === event.id ? "selected" : ""}`}
                onClick={() => onSelect(event)}
                onKeyDown={(e) => {
                  if (e.key === "Enter" || e.key === " ") {
                    e.preventDefault();
                    onSelect(event);
                  }
                }}
              >
                <title>
                  {event.time} · {event.title}
                </title>
                <line
                  x1={x(index)}
                  x2={x(index)}
                  y1={y(data[index].packets)}
                  y2={height - inset}
                  vectorEffect="non-scaling-stroke"
                />
                <circle
                  cx={x(index)}
                  cy={y(data[index].packets)}
                  r="5"
                  vectorEffect="non-scaling-stroke"
                />
                <rect
                  x={x(index) - 14}
                  y={y(data[index].packets) - 14}
                  width="28"
                  height="28"
                  fill="transparent"
                  stroke="none"
                />
              </g>
            );
          })}
        </svg>
        <div className="chart-x-labels mono">
          {[0, Math.floor((data.length - 1) / 2), data.length - 1].map(
            (index) => (
              <span key={index}>{data[index].minute}</span>
            ),
          )}
        </div>
      </div>
      <div className="chart-bottom">
        <div className="chart-legend">
          <span className="legend-mark traffic" />
          Трафик, пак./мин
          <span className="legend-mark incident" />
          События
        </div>
        <span className="mono chart-value" aria-live="polite">
          {current
            ? `${current.minute} · ${number(current.packets)} пак.`
            : "Наведите на график или используйте ← →"}
        </span>
      </div>
    </div>
  );
}
