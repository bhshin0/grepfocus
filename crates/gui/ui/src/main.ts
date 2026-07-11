import { invoke } from "@tauri-apps/api/core";

type AppMatcher =
  | { kind: "exe_path"; path: string }
  | { kind: "basename"; name: string }
  | { kind: "cmdline"; contains: string };

/// Mirrors core's `LockMode` (snake_case on the wire). How taking a break on
/// this block is locked down; every mode but "normal" is premium, enforced by
/// the daemon when the block is SAVED.
type LockMode = "normal" | "password_breaks" | "challenge_breaks";

interface Block {
  id: number;
  name: string;
  domains: string[];
  apps: AppMatcher[];
  allowance_secs_per_day: number;
  lock: LockMode;
}

interface AllowanceLedger {
  block_id: number;
  day: number;
  used_secs: number;
}

type Originator = { kind: "manual" } | { kind: "schedule"; schedule_id: number };

interface ActiveBlock {
  block: Block;
  started_at_unix: number;
  ends_at_unix: number;
  originator: Originator;
  break_until_unix: number | null;
  /// The lock mode SNAPSHOTTED at activation — not `block.lock`, which is the
  /// (editable) saved config. This is the one the daemon enforces, so it is
  /// the one the break UI must branch on.
  lock: LockMode;
}

interface Status {
  active: ActiveBlock[];
  now_unix: number;
  password_set: boolean;
  unlocked: boolean;
  allowance_used: AllowanceLedger[];
  license_present: boolean;
  license_valid: boolean;
  license_kind: string | null;
  license_email: string | null;
  license_expires_at: number | null;
  licensed_features: string[];
}

interface Schedule {
  id: number;
  name: string;
  block_id: number;
  days: number; // bitmask
  start_minute: number;
  duration_minutes: number;
  enabled: boolean;
}

// ─── Tab switching ─────────────────────────────────────────────────────────

const tabs = document.querySelectorAll<HTMLButtonElement>("nav button");
tabs.forEach((btn) => {
  btn.addEventListener("click", () => {
    const target = btn.dataset.tab!;
    tabs.forEach((b) => b.classList.toggle("active", b === btn));
    document.querySelectorAll<HTMLElement>("section.tab").forEach((s) => {
      s.classList.toggle("active", s.id === target);
    });
    if (target === "new") refreshLockWarning();
    if (target === "list") refreshList();
    if (target === "status") refreshStatus();
    if (target === "schedules") refreshSchedules();
    if (target === "settings") refreshSettings();
    if (target === "license") refreshLicense();
  });
});

// ─── New block form ────────────────────────────────────────────────────────

function parseAppLines(raw: string): AppMatcher[] {
  return raw
    .split("\n")
    .map((s) => s.trim())
    .filter(Boolean)
    .map((line): AppMatcher =>
      line.startsWith("/") ? { kind: "exe_path", path: line } : { kind: "basename", name: line },
    );
}

const newForm = document.querySelector<HTMLFormElement>("#new-block-form")!;
const newMsg = document.querySelector<HTMLParagraphElement>("#new-block-msg")!;
const lockSelect = newForm.querySelector<HTMLSelectElement>('select[name="lock"]')!;
const lockWarn = document.querySelector<HTMLParagraphElement>("#lock-warn")!;

/// Non-blocking warning for "password-locked breaks with no settings password":
/// a lock with no key. The daemon accepts the SAVE (it only refuses the BREAK
/// later, with "password-locked breaks need a settings password"), so this is
/// deliberately advice, not validation — it never blocks submission.
///
/// The premium gate itself is NOT duplicated here: the daemon is the authority
/// on what a license permits, and its refusal renders in #new-block-msg.
async function refreshLockWarning() {
  if (lockSelect.value !== "password_breaks") {
    lockWarn.hidden = true;
    return;
  }
  try {
    const s = await invoke<Status>("get_status");
    lockWarn.hidden = s.password_set;
    lockWarn.textContent =
      "No settings password is set — set one in Settings first, or this lock has no key and every break on this block will simply be refused.";
  } catch {
    // Status unreadable: say nothing rather than warn on a guess.
    lockWarn.hidden = true;
  }
}
lockSelect.addEventListener("change", refreshLockWarning);

newForm.addEventListener("submit", async (ev) => {
  ev.preventDefault();
  newMsg.classList.remove("error");
  newMsg.textContent = "";
  const fd = new FormData(newForm);
  const block = {
    id: 0,
    name: String(fd.get("name") ?? "").trim(),
    domains: String(fd.get("domains") ?? "")
      .split("\n")
      .map((s) => s.trim())
      .filter(Boolean),
    apps: parseAppLines(String(fd.get("apps") ?? "")),
    allowance_secs_per_day: Math.max(0, Math.floor(Number(fd.get("allowance_minutes") ?? 0))) * 60,
    lock: String(fd.get("lock") ?? "normal") as LockMode,
  };
  if (!block.name) {
    newMsg.classList.add("error");
    newMsg.textContent = "name is required";
    return;
  }
  if (!(await ensureUnlocked())) return;
  try {
    const id = await invoke<number>("add_block", { block });
    newMsg.textContent = `saved (id ${id})`;
    newForm.reset();
    refreshLockWarning();
  } catch (e) {
    newMsg.classList.add("error");
    newMsg.textContent = String(e);
  }
});

// ─── Block list ────────────────────────────────────────────────────────────

const listEl = document.querySelector<HTMLUListElement>("#block-list")!;
const listMsg = document.querySelector<HTMLParagraphElement>("#list-msg")!;

async function refreshList() {
  listMsg.classList.remove("error");
  listMsg.textContent = "";
  listEl.innerHTML = "";
  try {
    const blocks = await invoke<Block[]>("list_blocks");
    if (blocks.length === 0) {
      listEl.appendChild(emptyLi('No saved blocks yet. Create one in "New block".'));
      return;
    }
    for (const b of blocks) listEl.appendChild(renderBlockCard(b));
  } catch (e) {
    listMsg.classList.add("error");
    listMsg.textContent = String(e);
  }
}

/// Lock-mode suffix for a block's one-line summary. Shown whenever the mode is
/// premium, allowance or not: it is part of the saved config, and a block with
/// a lock but no allowance (breaks disabled outright) is worth seeing as-is
/// rather than silently hiding one half of it.
const LOCK_NOTE: Record<LockMode, string> = {
  normal: "",
  password_breaks: " · password-locked breaks",
  challenge_breaks: " · challenge-locked breaks",
};

function renderBlockCard(b: Block): HTMLLIElement {
  const li = document.createElement("li");
  li.className = "block-card";
  li.innerHTML = `
    <h3></h3>
    <div class="meta"></div>
    <div class="row">
      <input type="number" class="duration" min="1" value="30" /> min
      <button class="start-btn">Start</button>
      <button class="delete-btn">Delete</button>
    </div>
  `;
  li.querySelector("h3")!.textContent = b.name;
  const apps = b.apps.map((a) => {
    if (a.kind === "exe_path") return a.path;
    if (a.kind === "basename") return a.name;
    return `cmdline:${a.contains}`;
  });
  const allowanceNote =
    b.allowance_secs_per_day > 0 ? ` · break allowance ${Math.floor(b.allowance_secs_per_day / 60)} min/day` : "";
  li.querySelector(".meta")!.textContent =
    `${b.domains.length} domain(s), ${b.apps.length} app(s)${allowanceNote}${LOCK_NOTE[b.lock]} — ${[...b.domains, ...apps].join(", ") || "(empty)"}`;
  const dur = li.querySelector<HTMLInputElement>(".duration")!;
  li.querySelector<HTMLButtonElement>(".start-btn")!.addEventListener("click", async () => {
    const minutes = Math.max(1, parseInt(dur.value, 10) || 30);
    listMsg.classList.remove("error");
    try {
      await invoke("start_block", { id: b.id, durationSecs: minutes * 60 });
      listMsg.textContent = `started for ${minutes} minute(s)`;
      refreshStatus();
    } catch (e) {
      listMsg.classList.add("error");
      listMsg.textContent = String(e);
    }
  });
  li.querySelector<HTMLButtonElement>(".delete-btn")!.addEventListener("click", async () => {
    listMsg.classList.remove("error");
    if (!(await ensureUnlocked())) return;
    try {
      await invoke("delete_block", { id: b.id });
      refreshList();
    } catch (e) {
      listMsg.classList.add("error");
      listMsg.textContent = String(e);
    }
  });
  return li;
}

// ─── Status (now a list of active blocks) ──────────────────────────────────

const statusEl = document.querySelector<HTMLDivElement>("#status-content")!;
let activeServerSkew = 0; // server now - client now, in seconds
let countdownTimer: number | null = null;
let breakRequestInFlight = false;

/// True while re-rendering the status list would yank the DOM out from under
/// the user: a take-break request is in flight (a re-render would produce a
/// fresh, enabled button mid-request), a break dialog is open, or they are
/// typing in a status input.
///
/// The dialog checks are what make the locked break flows survive the 5s poll.
/// Both flows suspend on a modal — the unlock dialog for `password_breaks`, the
/// challenge dialog for `challenge_breaks` — and both hold a closure over the
/// break row's button and error span. A poll landing mid-dialog would rebuild
/// the row, detaching those elements: the request would still be sent, but its
/// outcome would be written into an orphaned DOM node and the user would see
/// nothing happen. So while either dialog is open, the list holds still.
function statusInteractionBusy(): boolean {
  if (breakRequestInFlight) return true;
  if (unlockDialog.open || challengeDialog.open) return true;
  const el = document.activeElement;
  return el instanceof HTMLInputElement && statusEl.contains(el);
}

async function refreshStatus() {
  try {
    const s = await invoke<Status>("get_status");
    activeServerSkew = s.now_unix - Math.floor(Date.now() / 1000);
    if (s.active.length === 0) {
      statusEl.innerHTML = `<p class="empty">No active block. Pick one from "Block list" to start, or set up a schedule.</p>`;
      stopCountdownTimer();
      return;
    }
    // Countdowns keep ticking off the existing DOM; the next idle poll
    // re-renders with fresh data.
    if (!statusInteractionBusy()) {
      renderActive(s);
    }
    if (countdownTimer == null) {
      countdownTimer = window.setInterval(tickCountdowns, 1000);
    }
  } catch (e) {
    statusEl.innerHTML = "";
    const p = document.createElement("p");
    p.className = "msg error";
    p.textContent = String(e);
    statusEl.appendChild(p);
    stopCountdownTimer();
  }
}

function stopCountdownTimer() {
  if (countdownTimer != null) {
    clearInterval(countdownTimer);
    countdownTimer = null;
  }
}

function fmtRemaining(secs: number): string {
  const s = Math.max(0, Math.floor(secs));
  const h = Math.floor(s / 3600);
  const m = Math.floor((s % 3600) / 60);
  const r = s % 60;
  return [h, m, r].map((n) => String(n).padStart(2, "0")).join(":");
}

function renderActive(s: Status) {
  statusEl.innerHTML = "";
  const usedByBlock = new Map<number, number>();
  for (const l of s.allowance_used) usedByBlock.set(l.block_id, l.used_secs);
  const nowSec = s.now_unix;

  for (const a of s.active) {
    const div = document.createElement("div");
    div.className = "active-banner";
    div.dataset.endsAt = String(a.ends_at_unix);
    const origin =
      a.originator.kind === "schedule"
        ? ` <span class="origin">(scheduled)</span>`
        : "";
    div.innerHTML = `
      <h3>Blocking: <span class="name"></span>${origin}</h3>
      <div class="countdown">--:--:--</div>
      <div class="meta-line">${a.block.domains.length} domain(s), ${a.block.apps.length} app(s)</div>
    `;
    div.querySelector<HTMLSpanElement>(".name")!.textContent = a.block.name;

    const allowance = a.block.allowance_secs_per_day;
    if (allowance > 0) {
      const onBreak = a.break_until_unix != null && a.break_until_unix > nowSec;
      if (onBreak) {
        const ob = document.createElement("div");
        ob.className = "on-break";
        ob.dataset.breakUntil = String(a.break_until_unix);
        ob.textContent = "On break — resumes in --:--:--";
        div.appendChild(ob);
      } else {
        const used = usedByBlock.get(a.block.id) ?? 0;
        const remainingMin = Math.floor((allowance - used) / 60);
        const row = document.createElement("div");
        row.className = "break-row";
        const defMin = Math.min(5, Math.max(1, remainingMin));
        row.innerHTML = `
          <input type="number" class="break-min" min="1" value="${defMin}" /> min
          <button class="break-btn">Take a break</button>
          <span class="break-left"></span>
        `;
        const btn = row.querySelector<HTMLButtonElement>(".break-btn")!;
        const input = row.querySelector<HTMLInputElement>(".break-min")!;
        const left = row.querySelector<HTMLSpanElement>(".break-left")!;

        // Branch on the ACTIVE record's lock snapshot (`a.lock`), never on
        // `a.block.lock`: the snapshot is what the daemon's break_gate
        // enforces, and a mid-block edit must not soften a running block.
        if (a.lock !== "normal") {
          const badge = document.createElement("span");
          badge.className = "break-lock";
          badge.textContent =
            a.lock === "password_breaks" ? "password required" : "challenge required";
          // Before the button, so the cost of the break is visible before it
          // is clicked rather than sprung on the user afterwards.
          row.insertBefore(badge, btn);
          if (a.lock === "challenge_breaks") {
            btn.textContent = "Take a break…"; // ellipsis: a dialog follows
          }
        }

        if (remainingMin <= 0) {
          btn.disabled = true;
          input.disabled = true;
          left.textContent = "no allowance left today";
        } else {
          left.textContent = `${remainingMin} min left today`;
        }
        btn.addEventListener("click", async () => {
          const minutes = Math.max(1, parseInt(input.value, 10) || 1);
          const secs = minutes * 60;

          // Challenge-locked: the whole exchange happens in the dialog, which
          // sends its own take_break with the typed response.
          if (a.lock === "challenge_breaks") {
            void openChallengeDialog(a.block.id, secs);
            return;
          }

          btn.disabled = true;
          // Held across the unlock dialog too, so the poll cannot rebuild this
          // row while the user is typing their password into it.
          breakRequestInFlight = true;
          let ok = false;
          try {
            // Password-locked: the daemon requires an ACTIVE unlock window and
            // answers MSG_SETTINGS_LOCKED without one, so open the existing
            // settings-unlock dialog first. Cancelling aborts silently — the
            // user changed their mind, that is not an error.
            if (a.lock === "password_breaks" && !(await ensureUnlocked())) {
              btn.disabled = false;
              return;
            }
            await invoke("take_break", { blockId: a.block.id, secs });
            ok = true;
          } catch (e) {
            // Includes the daemon's own refusals — e.g. password-locked breaks
            // on a block with no settings password set. Its verdict, verbatim.
            left.textContent = String(e);
            btn.disabled = false;
          } finally {
            breakRequestInFlight = false;
          }
          if (ok) refreshStatus();
        });
        div.appendChild(row);
      }
    }

    statusEl.appendChild(div);
  }
  const note = document.createElement("p");
  note.className = "note";
  note.textContent =
    "Active blocks cannot be cancelled. They end automatically when their timer or schedule window closes.";
  statusEl.appendChild(note);
  tickCountdowns();
}

function tickCountdowns() {
  const nowSec = Math.floor(Date.now() / 1000) + activeServerSkew;
  const banners = statusEl.querySelectorAll<HTMLDivElement>(".active-banner");
  let allDone = banners.length > 0;
  banners.forEach((div) => {
    const endsAt = Number(div.dataset.endsAt);
    const remaining = endsAt - nowSec;
    if (remaining > 0) allDone = false;
    div.querySelector(".countdown")!.textContent = fmtRemaining(remaining);
  });

  // Break countdowns: when one elapses, refresh so the controls return.
  statusEl.querySelectorAll<HTMLDivElement>(".on-break").forEach((ob) => {
    const until = Number(ob.dataset.breakUntil);
    const rem = until - nowSec;
    if (rem > 0) {
      ob.textContent = `On break — resumes in ${fmtRemaining(rem)}`;
    } else {
      ob.textContent = "Break ending…";
      setTimeout(refreshStatus, 500);
    }
  });

  if (allDone) setTimeout(refreshStatus, 500);
}

// ─── Challenge-locked breaks ───────────────────────────────────────────────

const challengeDialog = document.querySelector<HTMLDialogElement>("#challenge-dialog")!;
const challengeForm = document.querySelector<HTMLFormElement>("#challenge-form")!;
const challengeTextEl = document.querySelector<HTMLDivElement>("#challenge-text")!;
const challengeInput = document.querySelector<HTMLInputElement>("#challenge-input")!;
const challengeSubmit = document.querySelector<HTMLButtonElement>("#challenge-submit")!;
const challengeNew = document.querySelector<HTMLButtonElement>("#challenge-new")!;
const challengeCancel = document.querySelector<HTMLButtonElement>("#challenge-cancel")!;
const challengeMsg = document.querySelector<HTMLParagraphElement>("#challenge-msg")!;

/// The break the open dialog is negotiating. `null` when it is closed.
let challengeCtx: { blockId: number; secs: number } | null = null;
/// Length of the challenge currently displayed; 0 when none is loaded. Used
/// ONLY to gate the Confirm button (see the input listener).
let challengeLen = 0;

/// The friction IS the typing. Copy-paste would hand it straight back, so the
/// challenge text is unselectable (`user-select: none`, see style.css) and
/// paste/drop into the response field is refused here.
///
/// Honest about what this is: friction, not security. A determined user can
/// still read the challenge off the socket and script the reply — the same way
/// they could just stop the daemon as root. Defeating a user who is actively
/// engineering their way around their own commitment device is not the threat
/// model; the akrasia of the moment is.
for (const evName of ["paste", "drop"] as const) {
  challengeInput.addEventListener(evName, (ev) => ev.preventDefault());
}

/// Fetch a fresh challenge from the daemon and display it. Each call replaces
/// any previous one: the daemon only ever honours the most recently issued
/// string, so the UI must never show a stale one.
async function loadChallenge() {
  if (!challengeCtx) return;
  challengeSubmit.disabled = true;
  challengeLen = 0;
  challengeInput.value = "";
  challengeTextEl.textContent = "";
  challengeMsg.classList.remove("error");
  challengeMsg.textContent = "requesting a challenge…";
  try {
    const text = await invoke<string>("get_break_challenge", { blockId: challengeCtx.blockId });
    challengeTextEl.textContent = text;
    challengeLen = text.length;
    challengeMsg.textContent = "";
    challengeInput.focus();
  } catch (e) {
    challengeMsg.classList.add("error");
    challengeMsg.textContent = String(e);
  }
}

async function openChallengeDialog(blockId: number, secs: number) {
  challengeCtx = { blockId, secs };
  challengeMsg.classList.remove("error");
  challengeMsg.textContent = "";
  challengeDialog.showModal();
  await loadChallenge();
}

function closeChallengeDialog() {
  if (challengeDialog.open) challengeDialog.close();
  challengeCtx = null;
  challengeLen = 0;
  challengeInput.value = "";
  challengeTextEl.textContent = "";
}

/// Length-only feedback: enough to catch a half-typed response, while the
/// VERDICT stays with the daemon. It issued the string and it verifies it —
/// checking correctness here would put the answer in the (spoofable) frontend
/// and teach the user to trust a check that is not the one being enforced.
challengeInput.addEventListener("input", () => {
  challengeSubmit.disabled = challengeLen === 0 || challengeInput.value.trim().length !== challengeLen;
});

challengeForm.addEventListener("submit", async (ev) => {
  ev.preventDefault();
  if (!challengeCtx) return;
  const { blockId, secs } = challengeCtx;
  challengeMsg.classList.remove("error");
  challengeMsg.textContent = "";
  challengeSubmit.disabled = true;
  breakRequestInFlight = true;
  let ok = false;
  try {
    await invoke("take_break", { blockId, secs, challenge: challengeInput.value });
    ok = true;
  } catch (e) {
    // A mismatch lands here. The daemon does NOT retire a challenge it
    // rejected — only a matched one is consumed — so the displayed string is
    // still live and retyping it is a valid retry. "New challenge" is there
    // for the user who would rather start over.
    challengeMsg.classList.add("error");
    challengeMsg.textContent = String(e);
    challengeSubmit.disabled = false;
  } finally {
    breakRequestInFlight = false;
  }
  if (ok) {
    closeChallengeDialog();
    refreshStatus();
  }
});

challengeNew.addEventListener("click", () => void loadChallenge());
challengeCancel.addEventListener("click", closeChallengeDialog);
// Esc-dismissal → cancel, same as the unlock dialog.
challengeDialog.addEventListener("cancel", (ev) => {
  ev.preventDefault();
  closeChallengeDialog();
});

// ─── Schedules ─────────────────────────────────────────────────────────────

const DAY_LABEL = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];

const schedListEl = document.querySelector<HTMLUListElement>("#schedule-list")!;
const schedForm = document.querySelector<HTMLFormElement>("#schedule-form")!;
const schedMsg = document.querySelector<HTMLParagraphElement>("#schedule-msg")!;
const schedDetails = document.querySelector<HTMLDetailsElement>("#schedule-form-details")!;
const schedCancel = document.querySelector<HTMLButtonElement>("#schedule-cancel")!;
const schedBlockSelect = schedForm.querySelector<HTMLSelectElement>('select[name="block_id"]')!;

async function refreshSchedules() {
  schedMsg.classList.remove("error");
  schedMsg.textContent = "";
  schedListEl.innerHTML = "";
  try {
    const [schedules, blocks] = await Promise.all([
      invoke<Schedule[]>("list_schedules"),
      invoke<Block[]>("list_blocks"),
    ]);
    // Populate block <select>
    schedBlockSelect.innerHTML = "";
    if (blocks.length === 0) {
      const opt = document.createElement("option");
      opt.disabled = true;
      opt.textContent = "(create a block first)";
      schedBlockSelect.appendChild(opt);
    }
    for (const b of blocks) {
      const opt = document.createElement("option");
      opt.value = String(b.id);
      opt.textContent = b.name;
      schedBlockSelect.appendChild(opt);
    }
    if (schedules.length === 0) {
      schedListEl.appendChild(emptyLi("No schedules yet. Add one below."));
      return;
    }
    const blockNames = new Map(blocks.map((b) => [b.id, b.name] as const));
    for (const s of schedules) {
      schedListEl.appendChild(renderScheduleCard(s, blockNames.get(s.block_id) ?? `#${s.block_id}`));
    }
  } catch (e) {
    schedMsg.classList.add("error");
    schedMsg.textContent = String(e);
  }
}

function renderScheduleCard(s: Schedule, blockName: string): HTMLLIElement {
  const li = document.createElement("li");
  li.className = `block-card${s.enabled ? "" : " disabled"}`;
  const days: string[] = [];
  for (let d = 0; d < 7; d++) {
    if (s.days & (1 << d)) days.push(DAY_LABEL[d]);
  }
  const start = `${String(Math.floor(s.start_minute / 60)).padStart(2, "0")}:${String(s.start_minute % 60).padStart(2, "0")}`;
  const endMin = s.start_minute + s.duration_minutes;
  const end = `${String(Math.floor(endMin / 60) % 24).padStart(2, "0")}:${String(endMin % 60).padStart(2, "0")}`;
  li.innerHTML = `
    <h3></h3>
    <div class="meta"></div>
    <div class="row">
      <button class="edit-btn">Edit</button>
      <button class="toggle-btn"></button>
      <button class="delete-btn">Delete</button>
    </div>
  `;
  li.querySelector("h3")!.textContent = s.name + (s.enabled ? "" : "  (disabled)");
  li.querySelector(".meta")!.textContent = `${blockName} · ${days.join(", ") || "no days"} · ${start}–${end}`;
  const toggle = li.querySelector<HTMLButtonElement>(".toggle-btn")!;
  toggle.textContent = s.enabled ? "Disable" : "Enable";
  toggle.addEventListener("click", async () => {
    if (!(await ensureUnlocked())) return;
    try {
      await invoke("update_schedule", { schedule: { ...s, enabled: !s.enabled } });
      refreshSchedules();
    } catch (e) {
      schedMsg.classList.add("error");
      schedMsg.textContent = String(e);
    }
  });
  li.querySelector<HTMLButtonElement>(".edit-btn")!.addEventListener("click", () => {
    loadIntoForm(s);
  });
  li.querySelector<HTMLButtonElement>(".delete-btn")!.addEventListener("click", async () => {
    if (!(await ensureUnlocked())) return;
    try {
      await invoke("delete_schedule", { id: s.id });
      refreshSchedules();
    } catch (e) {
      schedMsg.classList.add("error");
      schedMsg.textContent = String(e);
    }
  });
  return li;
}

function loadIntoForm(s: Schedule) {
  schedDetails.open = true;
  (schedForm.querySelector('input[name="id"]') as HTMLInputElement).value = String(s.id);
  (schedForm.querySelector('input[name="name"]') as HTMLInputElement).value = s.name;
  schedBlockSelect.value = String(s.block_id);
  schedForm.querySelectorAll<HTMLInputElement>('input[name="day"]').forEach((cb) => {
    cb.checked = (s.days & (1 << Number(cb.value))) !== 0;
  });
  (schedForm.querySelector('input[name="start_time"]') as HTMLInputElement).value =
    `${String(Math.floor(s.start_minute / 60)).padStart(2, "0")}:${String(s.start_minute % 60).padStart(2, "0")}`;
  (schedForm.querySelector('input[name="duration_hours"]') as HTMLInputElement).value = String(
    Math.round((s.duration_minutes / 60) * 100) / 100,
  );
  (schedForm.querySelector('input[name="enabled"]') as HTMLInputElement).checked = s.enabled;
}

function resetForm() {
  schedForm.reset();
  (schedForm.querySelector('input[name="id"]') as HTMLInputElement).value = "";
  schedDetails.open = false;
  schedMsg.classList.remove("error");
  schedMsg.textContent = "";
}

schedCancel.addEventListener("click", resetForm);

schedForm.addEventListener("submit", async (ev) => {
  ev.preventDefault();
  schedMsg.classList.remove("error");
  schedMsg.textContent = "";
  const fd = new FormData(schedForm);
  const idRaw = String(fd.get("id") ?? "");
  const id = idRaw === "" ? 0 : Number(idRaw);
  let days = 0;
  schedForm.querySelectorAll<HTMLInputElement>('input[name="day"]:checked').forEach((cb) => {
    days |= 1 << Number(cb.value);
  });
  const time = String(fd.get("start_time") ?? "00:00");
  const [hh, mm] = time.split(":").map((n) => parseInt(n, 10));
  const start_minute = (hh || 0) * 60 + (mm || 0);
  const duration_minutes = Math.round(Number(fd.get("duration_hours") ?? 0) * 60);
  const block_id = Number(schedBlockSelect.value);
  const enabled = (schedForm.querySelector('input[name="enabled"]') as HTMLInputElement).checked;
  const name = String(fd.get("name") ?? "").trim();

  const schedule: Schedule = {
    id,
    name,
    block_id,
    days,
    start_minute,
    duration_minutes,
    enabled,
  };
  if (!(await ensureUnlocked())) return;
  try {
    if (id === 0) {
      await invoke("add_schedule", { schedule });
    } else {
      await invoke("update_schedule", { schedule });
    }
    resetForm();
    refreshSchedules();
  } catch (e) {
    schedMsg.classList.add("error");
    schedMsg.textContent = String(e);
  }
});

// ─── Settings: password lock ────────────────────────────────────────────────

const lockStateEl = document.querySelector<HTMLDivElement>("#lock-state")!;
const pwForm = document.querySelector<HTMLFormElement>("#password-form")!;
const pwMsg = document.querySelector<HTMLParagraphElement>("#password-msg")!;
const oldPwLabel = document.querySelector<HTMLLabelElement>("#old-pw-label")!;
const pwSubmit = document.querySelector<HTMLButtonElement>("#password-submit")!;
const pwClear = document.querySelector<HTMLButtonElement>("#password-clear")!;

const unlockDialog = document.querySelector<HTMLDialogElement>("#unlock-dialog")!;
const unlockForm = document.querySelector<HTMLFormElement>("#unlock-form")!;
const unlockMsg = document.querySelector<HTMLParagraphElement>("#unlock-msg")!;
const unlockCancel = document.querySelector<HTMLButtonElement>("#unlock-cancel")!;

let unlockResolver: ((ok: boolean) => void) | null = null;
let unlockPromise: Promise<boolean> | null = null;

/// Resolve once the user unlocks (true) or cancels (false). Concurrent gated
/// actions share the single in-flight prompt instead of each opening its own
/// and clobbering the previous resolver (which would leak that promise).
function promptUnlock(): Promise<boolean> {
  if (unlockPromise) return unlockPromise;
  unlockPromise = new Promise((resolve) => {
    unlockResolver = resolve;
    (unlockForm.querySelector('input[name="password"]') as HTMLInputElement).value = "";
    unlockMsg.classList.remove("error");
    unlockMsg.textContent = "";
    unlockDialog.showModal();
  });
  return unlockPromise;
}

function finishUnlock(ok: boolean) {
  if (unlockDialog.open) unlockDialog.close();
  const r = unlockResolver;
  unlockResolver = null;
  unlockPromise = null;
  r?.(ok);
}

unlockForm.addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const pw = (unlockForm.querySelector('input[name="password"]') as HTMLInputElement).value;
  unlockMsg.classList.remove("error");
  try {
    await invoke("unlock", { password: pw });
    finishUnlock(true);
  } catch (e) {
    unlockMsg.classList.add("error");
    unlockMsg.textContent = String(e);
  }
});
unlockCancel.addEventListener("click", () => finishUnlock(false));
// Dialog dismissed via Esc → treat as cancel.
unlockDialog.addEventListener("cancel", (ev) => {
  ev.preventDefault();
  finishUnlock(false);
});

/// Ensure configuration changes are permitted; prompts for the password when a
/// password is set and no unlock window is active. Returns false if the user
/// cancels (caller should abort the action).
async function ensureUnlocked(): Promise<boolean> {
  try {
    const s = await invoke<Status>("get_status");
    if (!s.password_set || s.unlocked) return true;
  } catch {
    // If status can't be read, let the action proceed and surface its own error.
    return true;
  }
  return await promptUnlock();
}

async function refreshSettings() {
  pwMsg.classList.remove("error");
  pwMsg.textContent = "";
  pwForm.reset();
  try {
    const s = await invoke<Status>("get_status");
    if (!s.password_set) {
      lockStateEl.textContent = "No settings password is set. Configuration can be changed freely.";
      lockStateEl.className = "lock-state";
      oldPwLabel.hidden = true;
      pwClear.hidden = true;
      pwSubmit.textContent = "Set password";
    } else {
      lockStateEl.textContent = s.unlocked
        ? "Password is set. Settings are currently unlocked."
        : "Password is set. Settings are locked.";
      lockStateEl.className = `lock-state${s.unlocked ? " unlocked" : " locked"}`;
      oldPwLabel.hidden = false;
      pwClear.hidden = false;
      pwSubmit.textContent = "Change password";
    }
  } catch (e) {
    lockStateEl.textContent = String(e);
    lockStateEl.className = "lock-state locked";
  }
}

pwForm.addEventListener("submit", async (ev) => {
  ev.preventDefault();
  pwMsg.classList.remove("error");
  pwMsg.textContent = "";
  const fd = new FormData(pwForm);
  const old = String(fd.get("old") ?? "");
  const next = String(fd.get("new") ?? "");
  const confirm = String(fd.get("confirm") ?? "");
  if (!next) {
    pwMsg.classList.add("error");
    pwMsg.textContent = "new password cannot be empty";
    return;
  }
  if (next !== confirm) {
    pwMsg.classList.add("error");
    pwMsg.textContent = "passwords do not match";
    return;
  }
  try {
    await invoke("set_password", { old: old || null, new: next });
    pwMsg.textContent = "password updated";
    refreshSettings();
  } catch (e) {
    pwMsg.classList.add("error");
    pwMsg.textContent = String(e);
  }
});

pwClear.addEventListener("click", async () => {
  pwMsg.classList.remove("error");
  pwMsg.textContent = "";
  const fd = new FormData(pwForm);
  const old = String(fd.get("old") ?? "");
  if (!old) {
    pwMsg.classList.add("error");
    pwMsg.textContent = "enter your current password to remove it";
    return;
  }
  try {
    await invoke("set_password", { old, new: null });
    pwMsg.textContent = "password removed";
    refreshSettings();
  } catch (e) {
    pwMsg.classList.add("error");
    pwMsg.textContent = String(e);
  }
});

// ─── License ────────────────────────────────────────────────────────────────

const licenseStateEl = document.querySelector<HTMLDivElement>("#license-state")!;
const licenseForm = document.querySelector<HTMLFormElement>("#license-form")!;
const licenseMsg = document.querySelector<HTMLParagraphElement>("#license-msg")!;
const licenseRemove = document.querySelector<HTMLButtonElement>("#license-remove")!;
const licenseTokenInput = licenseForm.querySelector<HTMLTextAreaElement>('textarea[name="token"]')!;

/// Human labels for the feature keys in license tokens (core's
/// `license::features`). Unknown keys render as-is so newer licenses stay
/// legible in older builds.
const FEATURE_LABEL: Record<string, string> = {
  app_blocking: "App blocking",
  schedules: "Recurring schedules",
  tamper_protection: "Tamper protection",
  unlimited_blocks: "Unlimited blocks",
  lock_modes: "Lock modes",
  usage_stats: "Usage statistics",
  pomodoro: "Pomodoro timer",
};

function featureList(heading: string, keys: string[]): HTMLElement {
  const wrap = document.createElement("div");
  const label = document.createElement("div");
  label.className = "feature-heading";
  label.textContent = heading;
  wrap.appendChild(label);
  const ul = document.createElement("ul");
  ul.className = "feature-list";
  for (const k of keys) {
    const li = document.createElement("li");
    li.textContent = FEATURE_LABEL[k] ?? k;
    ul.appendChild(li);
  }
  wrap.appendChild(ul);
  return wrap;
}

function fmtDate(unixSecs: number): string {
  return new Date(unixSecs * 1000).toLocaleDateString();
}

function renderLicenseState(s: Status) {
  licenseStateEl.innerHTML = "";
  const line = document.createElement("div");

  if (!s.license_present) {
    licenseStateEl.className = "lock-state";
    line.textContent = "Free tier — no license installed.";
    licenseStateEl.appendChild(line);
    licenseStateEl.appendChild(featureList("A license unlocks:", Object.keys(FEATURE_LABEL)));
    return;
  }

  if (s.license_valid) {
    licenseStateEl.className = "lock-state unlocked";
    if (s.license_kind === "trial") {
      line.textContent =
        s.license_expires_at != null ? `Trial — expires ${fmtDate(s.license_expires_at)}` : "Trial";
    } else {
      line.textContent = `Premium (${s.license_kind ?? "unknown kind"})`;
    }
    licenseStateEl.appendChild(line);
    if (s.license_email) {
      const email = document.createElement("div");
      email.textContent = `Licensed to ${s.license_email}`;
      licenseStateEl.appendChild(email);
    }
    if (s.licensed_features.length > 0) {
      licenseStateEl.appendChild(featureList("Unlocked features:", s.licensed_features));
    }
    return;
  }

  // A token is stored but no longer verifies.
  licenseStateEl.className = "lock-state locked";
  const nowSec = Math.floor(Date.now() / 1000);
  if (s.license_expires_at != null && s.license_expires_at < nowSec) {
    line.textContent = `Trial expired ${fmtDate(s.license_expires_at)}. The app has returned to the free tier — saved config is untouched.`;
  } else {
    line.textContent = "A license is stored but failed verification.";
  }
  licenseStateEl.appendChild(line);
}

async function refreshLicense() {
  try {
    const s = await invoke<Status>("get_status");
    renderLicenseState(s);
    licenseRemove.hidden = !s.license_present;
  } catch (e) {
    licenseStateEl.textContent = String(e);
    licenseStateEl.className = "lock-state locked";
  }
}

licenseForm.addEventListener("submit", async (ev) => {
  ev.preventDefault();
  licenseMsg.classList.remove("error");
  licenseMsg.textContent = "";
  const token = licenseTokenInput.value.trim();
  if (!token) {
    licenseMsg.classList.add("error");
    licenseMsg.textContent = "paste a license key first";
    return;
  }
  if (!(await ensureUnlocked())) return;
  try {
    await invoke("set_license", { token });
    licenseMsg.textContent = "license activated";
    licenseTokenInput.value = "";
    refreshLicense();
    refreshStatus();
  } catch (e) {
    licenseMsg.classList.add("error");
    licenseMsg.textContent = String(e);
  }
});

licenseRemove.addEventListener("click", async () => {
  licenseMsg.classList.remove("error");
  licenseMsg.textContent = "";
  if (!(await ensureUnlocked())) return;
  try {
    await invoke("set_license", { token: null });
    licenseMsg.textContent = "license removed";
    refreshLicense();
    refreshStatus();
  } catch (e) {
    licenseMsg.classList.add("error");
    licenseMsg.textContent = String(e);
  }
});

// ─── Shared helpers ────────────────────────────────────────────────────────

function emptyLi(text: string): HTMLLIElement {
  const li = document.createElement("li");
  li.className = "empty";
  li.textContent = text;
  return li;
}

// ─── Boot ──────────────────────────────────────────────────────────────────

refreshStatus();
window.setInterval(refreshStatus, 5000);
