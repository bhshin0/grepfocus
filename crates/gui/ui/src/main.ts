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
}

type Originator = { kind: "manual" } | { kind: "schedule"; schedule_id: number };

interface ActiveBlock {
  block: Block;
  started_at_unix: number;
  ends_at_unix: number;
  originator: Originator;
}

interface Status {
  active: ActiveBlock[];
  now_unix: number;
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
  };
  if (!block.name) {
    newMsg.classList.add("error");
    newMsg.textContent = "name is required";
    return;
  }
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
  li.querySelector(".meta")!.textContent =
    `${b.domains.length} domain(s), ${b.apps.length} app(s) — ${[...b.domains, ...apps].join(", ") || "(empty)"}`;
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

async function refreshStatus() {
  try {
    const s = await invoke<Status>("get_status");
    activeServerSkew = s.now_unix - Math.floor(Date.now() / 1000);
    if (s.active.length === 0) {
      statusEl.innerHTML = `<p class="empty">No active block. Pick one from "Block list" to start, or set up a schedule.</p>`;
      stopCountdownTimer();
      return;
    }
    renderActive(s.active);
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

function renderActive(active: ActiveBlock[]) {
  statusEl.innerHTML = "";
  for (const a of active) {
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
