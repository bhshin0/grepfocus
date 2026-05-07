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

interface ActiveBlock {
  block: Block;
  started_at_unix: number;
  ends_at_unix: number;
}

interface Status {
  active: ActiveBlock | null;
  now_unix: number;
}

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
  });
});

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

const listEl = document.querySelector<HTMLUListElement>("#block-list")!;
const listMsg = document.querySelector<HTMLParagraphElement>("#list-msg")!;

async function refreshList() {
  listMsg.classList.remove("error");
  listMsg.textContent = "";
  listEl.innerHTML = "";
  try {
    const blocks = await invoke<Block[]>("list_blocks");
    if (blocks.length === 0) {
      const empty = document.createElement("li");
      empty.className = "empty";
      empty.textContent = "No saved blocks yet. Create one in “New block”.";
      listEl.appendChild(empty);
      return;
    }
    for (const b of blocks) listEl.appendChild(renderBlock(b));
  } catch (e) {
    listMsg.classList.add("error");
    listMsg.textContent = String(e);
  }
}

function renderBlock(b: Block): HTMLLIElement {
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

const statusEl = document.querySelector<HTMLDivElement>("#status-content")!;

function fmtRemaining(secs: number): string {
  const s = Math.max(0, Math.floor(secs));
  const h = Math.floor(s / 3600);
  const m = Math.floor((s % 3600) / 60);
  const r = s % 60;
  return [h, m, r].map((n) => String(n).padStart(2, "0")).join(":");
}

let activeEnds: number | null = null;
let activeServerSkew = 0; // server now - client now, in seconds
let countdownTimer: number | null = null;

async function refreshStatus() {
  try {
    const s = await invoke<Status>("get_status");
    if (s.active) {
      activeEnds = s.active.ends_at_unix;
      activeServerSkew = s.now_unix - Math.floor(Date.now() / 1000);
      renderActive(s.active);
      if (countdownTimer == null) {
        countdownTimer = window.setInterval(tickCountdown, 1000);
      }
    } else {
      activeEnds = null;
      if (countdownTimer != null) {
        clearInterval(countdownTimer);
        countdownTimer = null;
      }
      statusEl.innerHTML = `<p class="empty">No active block. Pick one from “Block list” to start.</p>`;
    }
  } catch (e) {
    statusEl.innerHTML = "";
    const p = document.createElement("p");
    p.className = "msg error";
    p.textContent = `Failed to reach daemon: ${e}`;
    statusEl.appendChild(p);
  }
}

function renderActive(a: ActiveBlock) {
  statusEl.innerHTML = `
    <div class="active-banner">
      <h3 id="active-name"></h3>
      <div class="countdown" id="active-countdown">--:--:--</div>
      <div class="note">Active blocks cannot be cancelled. They will end automatically.</div>
    </div>
    <p class="meta" id="active-meta"></p>
  `;
  statusEl.querySelector("#active-name")!.textContent = `Blocking: ${a.block.name}`;
  statusEl.querySelector("#active-meta")!.textContent =
    `${a.block.domains.length} domain(s), ${a.block.apps.length} app(s)`;
  tickCountdown();
}

function tickCountdown() {
  if (activeEnds == null) return;
  const nowSec = Math.floor(Date.now() / 1000) + activeServerSkew;
  const remaining = activeEnds - nowSec;
  const el = document.querySelector<HTMLDivElement>("#active-countdown");
  if (el) el.textContent = fmtRemaining(remaining);
  if (remaining <= 0) {
    setTimeout(refreshStatus, 500);
  }
}

refreshStatus();
window.setInterval(refreshStatus, 5000);
