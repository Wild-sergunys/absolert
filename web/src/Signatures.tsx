import { useState } from "react";
import {
  Check,
  ChevronRight,
  Code2,
  FilePlus2,
  Plus,
  Search,
  ShieldCheck,
} from "lucide-react";
import { Modal } from "./components.tsx";
import { validateDraft } from "./domain.ts";
import type { Signature } from "./domain.ts";
import { draftTemplate } from "./fixtures.ts";

export default function Signatures({
  rules,
  setRules,
  notify,
  selectedRule,
  clearSelectedRule,
}: {
  rules: Signature[];
  setRules: (rules: Signature[]) => void;
  notify: (text: string) => void;
  selectedRule: string | null;
  clearSelectedRule: () => void;
}) {
  const [query, setQuery] = useState("");
  const [adding, setAdding] = useState(false);
  const [localSelection, setLocalSelection] = useState<string | null>(null);
  const [title, setTitle] = useState("");
  const [text, setText] = useState("");
  const [error, setError] = useState<string | null>(null);
  const selected = rules.find(
    (rule) => rule.id === (selectedRule ?? localSelection),
  );
  const filtered = rules.filter((rule) =>
    `${rule.title} ${rule.sid ?? ""} ${rule.service}`
      .toLocaleLowerCase("ru")
      .includes(query.toLocaleLowerCase("ru")),
  );
  const closeDetails = () => {
    setLocalSelection(null);
    clearSelectedRule();
  };
  function addDraft(e: React.SubmitEvent<HTMLFormElement>) {
    e.preventDefault();
    const issue = validateDraft(title, text);
    if (issue) {
      setError(issue);
      return;
    }
    setRules([
      ...rules,
      {
        id: crypto.randomUUID(),
        sid: null,
        title: title.trim(),
        service: "Ожидает проверки движком",
        enabled: false,
        draft: true,
        text: text.trim(),
      },
    ]);
    setAdding(false);
    setTitle("");
    setText("");
    setError(null);
    notify("Черновик сохранён. Проверка движком ещё не выполнялась");
  }
  return (
    <>
      <div className="page-heading">
        <div>
          <p className="eyebrow">База обнаружения</p>
          <h1>Сигнатуры</h1>
          <p className="page-description">
            Условия, по которым система выделяет подозрительный трафик
          </p>
        </div>
        <button
          className="button primary"
          onClick={() => {
            setAdding(true);
            setError(null);
          }}
        >
          <Plus />
          Добавить сигнатуру
        </button>
      </div>
      <div className="summary-line">
        <span>
          <strong>{rules.length}</strong> в наборе
        </span>
        <span>
          <strong>{rules.filter((r) => r.enabled).length}</strong> включены в
          демо
        </span>
        <span>
          <strong>{rules.filter((r) => r.draft).length}</strong> черновиков
        </span>
      </div>
      <section className="panel rules-panel">
        <div className="panel-toolbar">
          <h2>
            Лабораторный набор <span className="count">{rules.length}</span>
          </h2>
          <label className="search">
            <Search />
            <input
              aria-label="Поиск сигнатур"
              placeholder="Название или SID"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
            />
          </label>
        </div>
        <div className="table-scroll">
          <table className="rules-table">
            <thead>
              <tr>
                <th>Сигнатура</th>
                <th>Идентификатор</th>
                <th>Назначение</th>
                <th>Состояние</th>
                <th>
                  <span className="sr-only">Просмотр</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((rule) => (
                <tr key={rule.id}>
                  <td>
                    <button
                      className="row-title"
                      onClick={() => setLocalSelection(rule.id)}
                    >
                      <span className="rule-icon">
                        <Code2 />
                      </span>
                      <span>
                        {rule.title}
                        <small>
                          {rule.draft
                            ? "Пользовательский черновик"
                            : "Демонстрационное правило"}
                        </small>
                      </span>
                    </button>
                  </td>
                  <td className="mono muted">{rule.sid ?? "—"}</td>
                  <td className="muted">{rule.service}</td>
                  <td>
                    {rule.draft ? (
                      <span className="draft-label">Не проверена</span>
                    ) : (
                      <button
                        role="switch"
                        aria-checked={rule.enabled}
                        aria-label={`Сигнатура ${rule.title}`}
                        className={`switch ${rule.enabled ? "on" : ""}`}
                        onClick={() => {
                          setRules(
                            rules.map((r) =>
                              r.id === rule.id
                                ? { ...r, enabled: !r.enabled }
                                : r,
                            ),
                          );
                          notify(
                            rule.enabled
                              ? "Сигнатура выключена в демонаборе"
                              : "Сигнатура включена в демонаборе",
                          );
                        }}
                      >
                        <span />
                      </button>
                    )}
                  </td>
                  <td>
                    <button
                      className="icon-button"
                      aria-label={`Открыть ${rule.title}`}
                      onClick={() => setLocalSelection(rule.id)}
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
            <h3>Совпадений нет</h3>
            <p>Попробуйте другое название или идентификатор</p>
            <button className="button secondary" onClick={() => setQuery("")}>
              Сбросить поиск
            </button>
          </div>
        )}
        <div className="panel-footnote">
          <ShieldCheck />
          <span>
            Переключатели меняют только демонабор. Исторические события остаются
            в журнале.
          </span>
        </div>
      </section>
      <div className="explanation-row">
        <FilePlus2 />
        <div>
          <h3>Сначала проверка, затем включение</h3>
          <p>
            Новое правило сохраняется черновиком. Перед использованием сенсор
            должен проверить все условия и поддерживаемые ключевые слова.
          </p>
        </div>
      </div>
      {selected && (
        <Modal title="Сигнатура" onClose={closeDetails} sheet>
          <div className="sheet-body">
            <p className="eyebrow">
              {selected.sid
                ? `SID ${selected.sid} · rev 1`
                : "Черновик · SID ещё не извлечён"}
            </p>
            <h3 className="detail-title">{selected.title}</h3>
            <div className="detail-section">
              <h4>Текст правила</h4>
              <pre className="rule-source">{selected.text}</pre>
            </div>
            <div className="quiet-note">
              {selected.draft
                ? "Черновик не прошёл проверку движком. Включение недоступно."
                : "Это лабораторный пример для интерфейса. Настоящий движок к демонабору не подключён."}
            </div>
          </div>
          <footer className="sheet-footer">
            <button className="button secondary" onClick={closeDetails}>
              Закрыть
            </button>
          </footer>
        </Modal>
      )}
      {adding && (
        <Modal title="Добавить сигнатуру" onClose={() => setAdding(false)}>
          <form onSubmit={addDraft} className="draft-form">
            <p className="muted">
              Сохраните правило как черновик. Оно не попадёт в активный набор до
              проверки движком.
            </p>
            <label className="field">
              Название
              <input
                autoFocus
                value={title}
                maxLength={121}
                onChange={(e) => setTitle(e.target.value)}
                placeholder="Например, серия SYN к VNC"
              />
            </label>
            <label className="field">
              Правило Suricata
              <textarea
                value={text}
                onChange={(e) => setText(e.target.value)}
                rows={7}
                spellCheck={false}
                placeholder="alert tcp …"
              />
            </label>
            <button
              type="button"
              className="text-button"
              onClick={() => {
                setText(draftTemplate);
                if (!title) setTitle("Лабораторная активность VNC");
              }}
            >
              <Code2 />
              Вставить лабораторный пример
            </button>
            {error && (
              <p className="form-error" role="alert">
                {error}
              </p>
            )}
            <div className="quiet-note">
              Форма проверяет заполненность и размер полей. Синтаксис правил
              проверяется при загрузке файла сенсором.
            </div>
            <footer className="form-footer">
              <button
                type="button"
                className="button secondary"
                onClick={() => setAdding(false)}
              >
                Отмена
              </button>
              <button className="button primary" type="submit">
                <Check />
                Сохранить черновик
              </button>
            </footer>
          </form>
        </Modal>
      )}
    </>
  );
}
