import { invoke } from "@tauri-apps/api/core";

type AppMatcher =
  | { kind: "exe_path"; path: string }
  | { kind: "basename"; name: string }
  | { kind: "cmdline"; contains: string };

interface Block {
  id: number;
  name: string;
  domains: string[];
  apps: AppMatcher[];
  allowance_secs_per_day: number;
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
}

interface Status {
  active: ActiveBlock[];
  now_unix: number;
  password_set: boolean;
  unlocked: boolean;
  allowance_used: AllowanceLedger[];
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
    if (target === "list") refreshList();
    if (target === "status") refreshStatus();
    if (target === "schedules") refreshSchedules();
    if (target === "settings") refreshSettings();
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
    `${b.domains.length} domain(s), ${b.apps.length} app(s)${allowanceNote} — ${[...b.domains, ...apps].join(", ") || "(empty)"}`;
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
/// fresh, enabled button mid-request) or they are typing in a status input.
function statusInteractionBusy(): boolean {
  if (breakRequestInFlight) return true;
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
    p.textContent = `Failed to reach daemon: ${e}`;
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
        if (remainingMin <= 0) {
          btn.disabled = true;
          input.disabled = true;
          left.textContent = "no allowance left today";
        } else {
          left.textContent = `${remainingMin} min left today`;
        }
        btn.addEventListener("click", async () => {
          const minutes = Math.max(1, parseInt(input.value, 10) || 1);
          btn.disabled = true;
          breakRequestInFlight = true;
          let ok = false;
          try {
            await invoke("take_break", { blockId: a.block.id, secs: minutes * 60 });
            ok = true;
          } catch (e) {
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

/// Resolve once the user unlocks (true) or cancels (false).
function promptUnlock(): Promise<boolean> {
  return new Promise((resolve) => {
    unlockResolver = resolve;
    (unlockForm.querySelector('input[name="password"]') as HTMLInputElement).value = "";
    unlockMsg.classList.remove("error");
    unlockMsg.textContent = "";
    unlockDialog.showModal();
  });
}

function finishUnlock(ok: boolean) {
  if (unlockDialog.open) unlockDialog.close();
  const r = unlockResolver;
  unlockResolver = null;
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
    lockStateEl.textContent = `Failed to reach daemon: ${e}`;
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
