import test from "node:test";
import assert from "node:assert/strict";
import { filterEvents, findMinuteIndex, validateDraft } from "./domain.ts";
import { events } from "./fixtures.ts";

test("search combines address, severity and review filters", () => {
  const reviewed = new Set([events[0].id]);
  assert.equal(
    filterEvents(
      events,
      { query: events[0].source, severity: "all", review: "reviewed" },
      reviewed,
    ).length,
    1,
  );
  assert.equal(
    filterEvents(
      events,
      { query: "no-such-address", severity: "all", review: "all" },
      reviewed,
    ).length,
    0,
  );
  assert.ok(
    filterEvents(
      events,
      { query: "", severity: "high", review: "new" },
      reviewed,
    ).every((e) => e.severity === "high" && !reviewed.has(e.id)),
  );
});

test("draft validation checks form bounds without claiming Suricata compatibility", () => {
  assert.ok(validateDraft("", "alert tcp any any -> any any ()"));
  assert.ok(validateDraft("test", ""));
  assert.ok(validateDraft("x".repeat(121), "test"));
  assert.ok(validateDraft("test", "x".repeat(65537)));
  assert.ok(validateDraft("test", "я".repeat(32769)));
  assert.equal(
    validateDraft("Лабораторная сигнатура", "text awaiting engine validation"),
    null,
  );
});

test("chart maps event seconds to its minute without pretending out-of-period events are visible", () => {
  const minutes = [{ minute: "13:58" }, { minute: "13:59" }];
  assert.equal(findMinuteIndex("13:58:42", minutes), 0);
  assert.equal(findMinuteIndex("13:59:00", minutes), 1);
  assert.equal(findMinuteIndex("13:18:36", minutes), -1);
  assert.equal(findMinuteIndex("13:58:42", []), -1);
});
