import { browserName, fillTab, getToken, native, pairingCode, request } from "./common.js";

const app = document.getElementById("app");
let tab;

const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);

function render(html) {
  app.innerHTML = html;
}

function message(title, text, buttonLabel, onClick) {
  render(`<div class="state"><h2>${title}</h2><p>${text}</p>${buttonLabel ? `<button id="act" class="accent">${buttonLabel}</button>` : ""}</div>`);
  if (buttonLabel) document.getElementById("act").onclick = onClick;
}

const FILL_RESULT = {
  host_changed: "La page a changé de site, remplissage annulé.",
  username_only: "Identifiant rempli. Passe à l'étape suivante puis rouvre CoffreFort pour le mot de passe.",
  no_fields: "Aucun champ de connexion trouvé sur cette page.",
};

async function init() {
  [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  const st = await request("status");

  if (st.error === "no_host") {
    return message("Installation incomplète",
      "Le lien avec CoffreFort n'est pas installé. Lance <b>Installer extension.bat</b> dans le dossier CoffreFort, puis redémarre le navigateur.");
  }
  if (st.error === "not_running") {
    return message("CoffreFort est fermé", "Ouvre l'application pour accéder à tes identifiants.", "Ouvrir CoffreFort", launch);
  }
  if (st.error) return message("Erreur", esc(st.message || st.error));
  const installed = chrome.runtime.getManifest().version;
  if (st.extension_version && st.extension_version !== installed) return updateExtension(st.extension_version, installed);
  if (!st.unlocked) {
    request("focus");
    return message("Coffre verrouillé",
      "Déverrouille CoffreFort (la fenêtre vient de passer au premier plan), puis réessaie.",
      "Réessayer", init);
  }
  if (!st.paired) return showPair();
  return showEntries();
}

// Une extension chargée en mode développeur ne se met pas à jour seule :
// runtime.reload() relit les fichiers du dossier. Une seule tentative par version,
// pour ne pas boucler si le navigateur a chargé un autre dossier.
async function updateExtension(expected, installed) {
  const { reloadedFor } = await chrome.storage.local.get("reloadedFor");
  if (reloadedFor !== expected) {
    await chrome.storage.local.set({ reloadedFor: expected });
    message("Mise à jour de l'extension…", `Version ${esc(installed)} → ${esc(expected)}. Rouvre l'extension dans un instant.`);
    setTimeout(() => chrome.runtime.reload(), 900);
    return;
  }
  message("Mise à jour de l'extension",
    `La version ${esc(expected)} est disponible (installée : ${esc(installed)}). Sur la page des extensions, clique sur ↻ sous CoffreFort.`,
    "Ouvrir la page des extensions",
    () => chrome.tabs.create({ url: "chrome://extensions/?id=" + chrome.runtime.id }));
}

async function launch() {
  await native({ type: "launch" });
  message("Ouverture…", "Lancement de CoffreFort.");
  for (let i = 0; i < 20; i++) {
    await new Promise((r) => setTimeout(r, 500));
    const st = await request("status");
    if (st.ok) return init();
  }
  message("CoffreFort ne répond pas", "Ouvre-le manuellement depuis le raccourci du bureau.");
}

async function showPair() {
  const code = await pairingCode(await getToken());
  render(`<div class="state">
    <h2>Associer ce navigateur</h2>
    <p>Une seule fois : CoffreFort doit autoriser cette extension.</p>
    <div class="code">${code}</div>
    <p class="muted">Clique sur « Associer », vérifie que CoffreFort affiche le même code et accepte. Rouvre ensuite l'extension.</p>
    <button id="pair" class="accent">Associer</button></div>`);
  document.getElementById("pair").onclick = async () => {
    document.getElementById("pair").disabled = true;
    const res = await request("pair", { name: browserName() });
    if (res.ok) return init();
    message("Association refusée", res.error === "busy" ? "Une demande est déjà en attente dans CoffreFort." : "Réessaie si c'était une erreur.");
  };
}

async function showEntries() {
  const res = await request("list", { url: tab?.url || "" });
  if (res.error === "bad_url") return message("Page non compatible", "CoffreFort fonctionne sur les sites web (http/https).");
  if (res.error) return message("Erreur", esc(res.error));

  const host = res.host;
  const insecure = tab.url.startsWith("http://");
  const items = res.entries.map((e) => `
    <button class="entry" data-id="${esc(e.id)}">
      <span class="site">${esc(e.site)}</span>
      <span class="user">${esc(e.username || "(sans identifiant)")}</span>
    </button>`).join("");

  render(`
    <div class="host">${esc(host)}</div>
    ${insecure ? `<div class="warn">⚠ Connexion non chiffrée (http)</div>` : ""}
    <div class="list">${items || `<p class="muted">Aucun identifiant enregistré pour ce site.</p>`}</div>
    <details ${res.entries.length ? "" : "open"}>
      <summary>＋ Nouveau compte sur ce site</summary>
      <input id="newUser" placeholder="Identifiant ou e-mail" autocomplete="off">
      <div class="row">
        <label>Longueur <select id="newLen"><option>20</option><option selected>24</option><option>32</option></select></label>
        <button id="create" class="accent">Générer et remplir</button>
      </div>
      <p class="muted">Un mot de passe fort est créé, enregistré dans CoffreFort et rempli dans la page.</p>
    </details>
    <div id="status" class="muted"></div>`);

  const status = document.getElementById("status");
  document.querySelectorAll(".entry").forEach((btn) => {
    btn.onclick = async () => {
      const f = await request("fill", { url: tab.url, id: btn.dataset.id });
      if (!f.ok) return (status.textContent = "Refusé : " + f.error);
      const result = await fillTab(tab.id, f.host, f.username, f.password, "login");
      if (result === "ok") return window.close();
      status.textContent = FILL_RESULT[result] || result;
    };
  });
  document.getElementById("create").onclick = async () => {
    const username = document.getElementById("newUser").value.trim();
    const length = Number(document.getElementById("newLen").value);
    const f = await request("create", { url: tab.url, username, length });
    if (!f.ok) return (status.textContent = "Erreur : " + f.error);
    const result = await fillTab(tab.id, f.host, f.username, f.password, "new");
    status.textContent = "✔ Enregistré dans CoffreFort. " + (result === "ok" ? "" : FILL_RESULT[result] || "");
    if (result === "ok") setTimeout(() => window.close(), 1200);
  };
}

init();
