import { useEffect, useState } from "react";
import {
  Activity,
  ArrowRight,
  Check,
  ChevronRight,
  CircleHelp,
  Cpu,
  FileCode2,
  FlaskConical,
  Menu,
  Network,
  RotateCcw,
  Shield,
  X,
} from "lucide-react";
import type { LucideIcon } from "lucide-react";
import { EventDetails, Modal } from "./components.tsx";
import type { NetworkEvent } from "./domain.ts";
import { events, signatures } from "./fixtures.ts";
import Signatures from "./Signatures.tsx";
import Overview from "./Overview.tsx";
import Sensor from "./Sensor.tsx";
import LiveOverview from "./LiveOverview.tsx";

type Page = "overview" | "signatures" | "sensor";
const monitoring = location.pathname === "/monitor";
const pages: { id: Page; label: string; icon: LucideIcon }[] = [
  { id: "overview", label: "Мониторинг", icon: Activity },
  { id: "signatures", label: "Сигнатуры", icon: FileCode2 },
  { id: "sensor", label: "Сенсор", icon: Cpu },
];
const navigation = monitoring ? pages.slice(0, 1) : pages;

function currentPage(): Page {
  if (monitoring) return "overview";
  const hash = location.hash.slice(1);
  return pages.find((page) => page.id === hash)?.id ?? "overview";
}

export default function App() {
  const [page, setPage] = useState<Page>(currentPage);
  const [mobileNav, setMobileNav] = useState(false);
  const [rules, setRules] = useState(signatures);
  const [reviewed, setReviewed] = useState(
    new Set(["EV-001", "EV-002", "EV-003"]),
  );
  const [event, setEvent] = useState<NetworkEvent | null>(null);
  const [selectedRule, setSelectedRule] = useState<string | null>(null);
  const [about, setAbout] = useState(false);
  const [resetting, setResetting] = useState(false);
  const [toast, setToast] = useState("");
  const pageTitle = pages.find(({ id }) => id === page)?.label;
  useEffect(() => {
    const onHash = () => {
      setPage(currentPage());
      setMobileNav(false);
      setEvent(null);
    };
    window.addEventListener("hashchange", onHash);
    return () => window.removeEventListener("hashchange", onHash);
  }, []);
  useEffect(() => {
    if (!mobileNav) return;
    const close = (e: KeyboardEvent) => {
      if (e.key === "Escape") setMobileNav(false);
    };
    window.addEventListener("keydown", close);
    return () => window.removeEventListener("keydown", close);
  }, [mobileNav]);
  useEffect(() => {
    if (!toast) return;
    const timer = setTimeout(() => setToast(""), 4500);
    return () => clearTimeout(timer);
  }, [toast]);
  useEffect(() => {
    document.title = `${pageTitle} — Absolert`;
  }, [pageTitle]);
  const navigate = (target: Page) => {
    location.hash = target;
    setPage(target);
    setMobileNav(false);
  };
  return (
    <div className="app-shell">
      <a
        className="skip-link"
        href="#main-content"
        onClick={(e) => {
          e.preventDefault();
          document.getElementById("main-content")?.focus();
        }}
      >
        К содержимому
      </a>
      {mobileNav && (
        <button
          className="nav-backdrop"
          aria-label="Закрыть навигацию"
          onClick={() => setMobileNav(false)}
        />
      )}
      <aside
        id="primary-sidebar"
        className={`sidebar ${mobileNav ? "open" : ""}`}
      >
        <a
          href="#overview"
          className="brand"
          aria-label="Absolert — мониторинг сети"
          onClick={() => setMobileNav(false)}
        >
          <img src="/absolert-mark.png" alt="" width={36} height={36} />
          <span>
            absolert<span className="brand-period">.</span>
          </span>
        </a>
        <div className="workspace-label">
          <span className="workspace-icon">
            <Network />
          </span>
          <div>
            Лаборатория<span>Сетевой периметр</span>
          </div>
        </div>
        <div className="nav-section-title">Наблюдение</div>
        <nav aria-label="Основная навигация">
          {navigation.map(({ id, label, icon: Icon }) => (
            <a
              key={id}
              href={`#${id}`}
              className={`nav-item ${page === id ? "active" : ""}`}
              aria-current={page === id ? "page" : undefined}
              onClick={() => setMobileNav(false)}
            >
              <Icon />
              <span>{label}</span>
              {!monitoring && id === "overview" && (
                <span className="nav-count">
                  {events.length - reviewed.size}
                </span>
              )}
            </a>
          ))}
        </nav>
        <div className="sidebar-bottom">
          {monitoring ? (
            <a href="/" className="nav-item">
              <FlaskConical />
              <span>Учебный режим</span>
            </a>
          ) : (
            <button className="nav-item" onClick={() => setAbout(true)}>
              <CircleHelp />
              <span>О демонстрации</span>
            </button>
          )}
          <div className="session-label">
            <Shield />
            <span>Пассивный режим</span>
          </div>
        </div>
      </aside>
      <div className="workspace">
        <header className="topbar">
          <div className="breadcrumbs">
            <button
              className="icon-button mobile-menu"
              onClick={() => setMobileNav(!mobileNav)}
              aria-expanded={mobileNav}
              aria-controls="primary-sidebar"
              aria-label="Открыть навигацию"
            >
              <Menu />
            </button>
            <span>Лаборатория</span>
            <ChevronRight />
            <strong>{pageTitle}</strong>
          </div>
          {!monitoring && (
            <div className="topbar-actions">
              <button className="demo-label" onClick={() => setAbout(true)}>
                <FlaskConical />
                Учебный режим
              </button>
              <button
                className="icon-button"
                title="Сбросить демонстрацию"
                aria-label="Сбросить демонстрацию"
                onClick={() => setResetting(true)}
              >
                <RotateCcw />
              </button>
            </div>
          )}
        </header>
        <main id="main-content" className="page" tabIndex={-1}>
          {monitoring && <LiveOverview />}
          {!monitoring && page === "overview" && (
            <Overview
              reviewed={reviewed}
              onEvent={setEvent}
              notify={setToast}
            />
          )}
          {page === "signatures" && (
            <Signatures
              rules={rules}
              setRules={setRules}
              notify={setToast}
              selectedRule={selectedRule}
              clearSelectedRule={() => setSelectedRule(null)}
            />
          )}
          {page === "sensor" && <Sensor />}
          <footer className="page-footer">
            <span>
              Absolert<span className="footer-dot">/</span>Пассивная система
              обнаружения вторжений
            </span>
            <span className="mono">IPv4 / TCP</span>
          </footer>
        </main>
      </div>
      {event && (
        <EventDetails
          event={event}
          reviewed={reviewed.has(event.id)}
          onClose={() => setEvent(null)}
          onReview={() => {
            setReviewed((old) => {
              const next = new Set(old);
              if (next.has(event.id)) next.delete(event.id);
              else next.add(event.id);
              return next;
            });
            setToast(
              reviewed.has(event.id)
                ? "Событие возвращено в новые"
                : "Событие отмечено разобранным",
            );
          }}
          onRule={() => {
            setSelectedRule(
              rules.find((rule) => rule.sid === event.sid)?.id ?? null,
            );
            setEvent(null);
            navigate("signatures");
          }}
        />
      )}
      {about && (
        <Modal title="Лаборатория Absolert" onClose={() => setAbout(false)}>
          <div className="about-body">
            <div className="about-symbol">
              <Shield />
            </div>
            <h3>Учебный режим</h3>
            <p>
              Здесь можно разобрать алерт и изменить сигнатуру на учебных
              данных.
            </p>
            <div className="quiet-note">
              <a href="/monitor">Мониторинг</a> показывает данные сенсора.
            </div>
            <p className="caption">
              Изменения хранятся до обновления страницы. История учебных событий
              фиксирована.
            </p>
            <p className="caption">
              При работе над дизайном использован{" "}
              <a
                href="https://heydamir.design/unslop"
                target="_blank"
                rel="noreferrer"
              >
                unslop by Damir Sokolovsky
              </a>
              , CC BY 4.0.
            </p>
            <button className="button primary" onClick={() => setAbout(false)}>
              Вернуться к работе
              <ArrowRight />
            </button>
          </div>
        </Modal>
      )}
      {resetting && (
        <Modal
          title="Начать демонстрацию заново?"
          onClose={() => setResetting(false)}
        >
          <div className="about-body">
            <p>
              Черновики и отметки разбора будут удалены из текущего демосеанса.
              Исходный набор сигнатур восстановится.
            </p>
            <div className="form-footer">
              <button
                className="button secondary"
                onClick={() => setResetting(false)}
              >
                Отмена
              </button>
              <button
                className="button primary"
                onClick={() => {
                  setRules(signatures);
                  setReviewed(new Set(["EV-001", "EV-002", "EV-003"]));
                  setSelectedRule(null);
                  setResetting(false);
                  navigate("overview");
                  setToast("Исходный демосеанс восстановлен");
                }}
              >
                Сбросить демосеанс
              </button>
            </div>
          </div>
        </Modal>
      )}
      {toast && (
        <div className="toast" role="status">
          <Check />
          <span>{toast}</span>
          <button
            className="icon-button"
            aria-label="Скрыть уведомление"
            onClick={() => setToast("")}
          >
            <X />
          </button>
        </div>
      )}
    </div>
  );
}
