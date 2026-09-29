const state = {
  apiBase: localStorage.getItem("secuvueApiBase") || "",
  systems: [],
  events: [],
  overview: null
};

const qs = (selector) => document.querySelector(selector);
const qsa = (selector) => [...document.querySelectorAll(selector)];

function normalizeBase(value) {
  return String(value || "").trim().replace(/\/+$/, "");
}

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>"']/g, (char) => ({
    "&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#039;"
  }[char]));
}

function formatDate(value) {
  if (!value) return "-";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? String(value) : date.toLocaleString("ko-KR");
}

function statusText(status) {
  return ({healthy:"정상",warning:"경고",critical:"위험",offline:"오프라인"})[status] || "대기";
}

function severityBadge(level) {
  return `<span class="severity ${escapeHtml(level)}">${escapeHtml(level)}</span>`;
}

async function api(path, options = {}) {
  if (!state.apiBase) throw new Error("Backend API URL이 설정되지 않았습니다.");
  const response = await fetch(`${state.apiBase}${path}`, {
    headers: {"Accept":"application/json", ...(options.headers || {})},
    ...options
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(data.error || `HTTP ${response.status}`);
  return data;
}

function updateApiStatus(kind, title, detail) {
  const dot = qs("#apiDot");
  dot.className = kind === "online" ? "online" : kind === "error" ? "error" : "";
  qs("#apiState").textContent = title;
  qs("#apiSmall").textContent = detail;
}

async function testApi(base = state.apiBase) {
  const clean = normalizeBase(base);
  if (!clean) throw new Error("API URL을 입력해주세요.");
  const response = await fetch(`${clean}/health`, {headers:{"Accept":"application/json"}});
  if (!response.ok) throw new Error(`API 응답 오류: HTTP ${response.status}`);
  const data = await response.json();
  if (!data.ok) throw new Error("API health check 실패");
  return data;
}

function renderOverview(data) {
  qs("#totalSystems").textContent = data.total || 0;
  qs("#healthySystems").textContent = data.healthy || 0;
  qs("#alertSystems").textContent = (data.warning || 0) + (data.critical || 0);
  qs("#offlineSystems").textContent = data.offline || 0;
  qs("#infoEvents").textContent = data.event_counts?.info || 0;
  qs("#warningEvents").textContent = data.event_counts?.warning || 0;
  qs("#criticalEvents").textContent = data.event_counts?.critical || 0;
}

function miniSystem(system) {
  return `<div class="mini-system">
    <div class="mini-head">
      <div>
        <h3>${escapeHtml(system.name || system.hostname || system.agent_id)}</h3>
        <div class="meta">${escapeHtml(system.ip || "-")} · ${escapeHtml(system.os_name || "Unknown OS")}</div>
      </div>
      <span class="status-pill ${escapeHtml(system.status)}">${statusText(system.status)}</span>
    </div>
    <div class="metrics">
      <div class="metric"><span>CPU</span><strong>${Number(system.cpu || 0).toFixed(1)}%</strong></div>
      <div class="metric"><span>RAM</span><strong>${Number(system.memory || 0).toFixed(1)}%</strong></div>
      <div class="metric"><span>Disk</span><strong>${Number(system.disk || 0).toFixed(1)}%</strong></div>
    </div>
  </div>`;
}

function renderSystems() {
  const dashboard = qs("#dashboardSystems");
  const grid = qs("#systemsGrid");
  qs("#systemCount").textContent = `${state.systems.length} systems`;

  if (!state.systems.length) {
    dashboard.className = "system-list empty-box";
    dashboard.textContent = "등록된 Agent가 없습니다.";
    grid.className = "systems-grid empty-box";
    grid.textContent = "등록된 Agent가 없습니다.";
    return;
  }

  dashboard.className = "system-list";
  dashboard.innerHTML = state.systems.slice(0, 6).map(miniSystem).join("");

  grid.className = "systems-grid";
  grid.innerHTML = state.systems.map((system) => {
    const services = Object.entries(system.services || {}).map(([name, value]) => {
      const status = typeof value === "object" ? value.state : value;
      return `<span class="service-tag ${status === "active" ? "active" : ""}">${escapeHtml(name)}: ${escapeHtml(status)}</span>`;
    }).join("");

    return `<article class="system-card">
      <div class="system-head">
        <div>
          <h3>${escapeHtml(system.name || system.hostname || system.agent_id)}</h3>
          <div class="meta">
            ${escapeHtml(system.ip || "-")}<br>
            ${escapeHtml(system.os_name || "Unknown OS")}<br>
            Last seen: ${escapeHtml(formatDate(system.last_seen))}
          </div>
        </div>
        <span class="status-pill ${escapeHtml(system.status)}">${statusText(system.status)}</span>
      </div>
      <div class="metrics">
        <div class="metric"><span>CPU</span><strong>${Number(system.cpu || 0).toFixed(1)}%</strong></div>
        <div class="metric"><span>RAM</span><strong>${Number(system.memory || 0).toFixed(1)}%</strong></div>
        <div class="metric"><span>Disk</span><strong>${Number(system.disk || 0).toFixed(1)}%</strong></div>
      </div>
      <div class="service-tags">${services || '<span class="service-tag">서비스 데이터 없음</span>'}</div>
    </article>`;
  }).join("");
}

function eventRows(events, full) {
  if (!events.length) {
    return `<tr><td colspan="${full ? 6 : 5}" class="empty-cell">이벤트가 없습니다.</td></tr>`;
  }
  return events.map((event) => `<tr>
    <td>${escapeHtml(formatDate(event.occurred_at))}</td>
    <td>${escapeHtml(event.system_name || event.agent_id || "-")}</td>
    ${full ? `<td>${escapeHtml(event.ip || "-")}</td>` : ""}
    <td>${escapeHtml(event.type || "-")}</td>
    <td title="${escapeHtml(event.message || "")}">${escapeHtml(event.message || "")}</td>
    <td>${severityBadge(event.severity || "info")}</td>
  </tr>`).join("");
}

function renderEvents() {
  qs("#recentEvents").innerHTML = eventRows(state.events.slice(0, 8), false);
  const filter = qs("#severityFilter").value;
  const filtered = filter === "all" ? state.events : state.events.filter((e) => e.severity === filter);
  qs("#allEvents").innerHTML = eventRows(filtered, true);
}

async function loadData() {
  if (!state.apiBase) {
    qs("#connectionNotice").classList.remove("hidden");
    updateApiStatus("idle", "API 미설정", "Backend URL을 연결하세요");
    return;
  }

  try {
    const [overview, systems, events] = await Promise.all([
      api("/api/overview"),
      api("/api/systems"),
      api("/api/events?limit=200")
    ]);

    state.overview = overview;
    state.systems = systems;
    state.events = events;

    renderOverview(overview);
    renderSystems();
    renderEvents();

    qs("#connectionNotice").classList.add("hidden");
    qs("#lastUpdated").textContent = `Updated ${new Date().toLocaleTimeString("ko-KR")}`;
    updateApiStatus("online", "API 연결됨", new URL(state.apiBase).host);
  } catch (error) {
    qs("#connectionNotice").classList.remove("hidden");
    qs("#connectionNotice strong").textContent = "Backend API에 연결할 수 없습니다.";
    qs("#connectionNotice span").textContent = error.message;
    updateApiStatus("error", "API 연결 실패", error.message.slice(0, 36));
  }
}

function openSettings() {
  qs("#apiUrlInput").value = state.apiBase;
  qs("#settingsError").classList.add("hidden");
  qs("#settingsModal").classList.remove("hidden");
}

function closeSettings() {
  qs("#settingsModal").classList.add("hidden");
}

qs("#settingsBtn").addEventListener("click", openSettings);
qs("#noticeSettings").addEventListener("click", openSettings);
qs("#closeSettings").addEventListener("click", closeSettings);

qs("#settingsForm").addEventListener("submit", async (event) => {
  event.preventDefault();
  const input = normalizeBase(qs("#apiUrlInput").value);
  const errorBox = qs("#settingsError");
  const submitButton = event.submitter;
  errorBox.classList.add("hidden");
  submitButton.disabled = true;
  submitButton.textContent = "연결 확인 중...";

  try {
    await testApi(input);
    state.apiBase = input;
    localStorage.setItem("secuvueApiBase", input);
    closeSettings();
    await loadData();
  } catch (error) {
    errorBox.textContent = error.message;
    errorBox.classList.remove("hidden");
  } finally {
    submitButton.disabled = false;
    submitButton.textContent = "연결 테스트 후 저장";
  }
});

qs("#clearApiBtn").addEventListener("click", () => {
  localStorage.removeItem("secuvueApiBase");
  state.apiBase = "";
  state.systems = [];
  state.events = [];
  closeSettings();
  location.reload();
});

qs("#refreshBtn").addEventListener("click", loadData);
qs("#severityFilter").addEventListener("change", renderEvents);

qsa(".nav-item").forEach((button) => {
  button.addEventListener("click", () => switchPage(button.dataset.page));
});
qsa("[data-go]").forEach((button) => {
  button.addEventListener("click", () => switchPage(button.dataset.go));
});

function switchPage(page) {
  qsa(".page").forEach((el) => el.classList.remove("active"));
  qsa(".nav-item").forEach((el) => el.classList.remove("active"));
  qs(`#${page}Page`).classList.add("active");
  qs(`.nav-item[data-page="${page}"]`).classList.add("active");
  qs("#pageTitle").textContent = ({
    dashboard:"Security Monitoring Dashboard",
    systems:"Systems",
    events:"Security Events"
  })[page];
}

const apiFromQuery = new URLSearchParams(location.search).get("api");
if (apiFromQuery) {
  state.apiBase = normalizeBase(apiFromQuery);
  localStorage.setItem("secuvueApiBase", state.apiBase);
}

loadData();
setInterval(loadData, 15000);
