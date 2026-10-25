// Code partagé entre la popup et le service worker.
export const NATIVE_HOST = "com.coffrefort.host";

export function native(msg) {
  return new Promise((resolve) => {
    chrome.runtime.sendNativeMessage(NATIVE_HOST, msg, (resp) => {
      if (chrome.runtime.lastError) {
        resolve({ error: "no_host", message: chrome.runtime.lastError.message });
      } else {
        resolve(resp || { error: "empty" });
      }
    });
  });
}

const hex = (bytes) => [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");

// Jeton propre à cette installation de l'extension ; CoffreFort n'en garde que l'empreinte.
export async function getToken() {
  let { token } = await chrome.storage.local.get("token");
  if (!token) {
    token = hex(crypto.getRandomValues(new Uint8Array(32)));
    await chrome.storage.local.set({ token });
  }
  return token;
}

// Même calcul que bridge.pairing_code côté Python.
export async function pairingCode(token) {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(token)));
  const n = parseInt(hex(digest).slice(0, 8), 16) % 1000000;
  const s = String(n).padStart(6, "0");
  return `${s.slice(0, 3)} ${s.slice(3)}`;
}

export async function request(type, extra = {}) {
  return native({ type, token: await getToken(), ...extra });
}

export function browserName() {
  const brands = (navigator.userAgentData?.brands || []).map((b) => b.brand);
  if (navigator.brave) return "Brave";
  if (brands.some((b) => /Opera GX/i.test(b)) || /OPRGX/.test(navigator.userAgent)) return "Opera GX";
  if (brands.some((b) => /Opera/i.test(b)) || /OPR\//.test(navigator.userAgent)) return "Opera";
  if (brands.some((b) => /Edge/i.test(b))) return "Edge";
  return "Chrome";
}

export async function fillTab(tabId, host, username, email, password, mode) {
  const [res] = await chrome.scripting.executeScript({
    target: { tabId },
    func: fillPage,
    args: [host, username || "", email || "", password, mode],
  });
  return res?.result;
}

// Exécutée DANS la page. Refuse de remplir si le site a changé entre-temps.
function fillPage(expectedHost, username, email, password, mode) {
  const host = location.hostname.toLowerCase().replace(/^www\./, "");
  if (host !== expectedHost && !host.endsWith("." + expectedHost)) return "host_changed";

  const visible = (el) => {
    const r = el.getBoundingClientRect();
    const s = getComputedStyle(el);
    return r.width > 0 && r.height > 0 && s.visibility !== "hidden" && s.display !== "none" && !el.disabled && !el.readOnly;
  };
  const setValue = (el, value) => {
    const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value").set;
    el.focus();
    setter.call(el, value); // compatible React/Vue
    el.dispatchEvent(new Event("input", { bubbles: true }));
    el.dispatchEvent(new Event("change", { bubbles: true }));
  };
  const textLike = (i) => ["text", "email", "tel"].includes(i.type);
  // Ce que le champ annonce : nom, id, texte indicatif, libellé…
  // « user[email] » (Rails, Symfony…) : seule la partie entre crochets compte.
  const key = (s) => (s || "").replace(/^[\w-]+\[([\w-]+)\]$/, "$1");
  const hint = (i) => [key(i.name), key(i.id), i.placeholder, i.autocomplete, i.getAttribute("aria-label"),
    ...[...(i.labels || [])].map((l) => l.textContent)].join(" ").toLowerCase();
  const isEmail = (i) => i.type === "email" || /e-?mail|courriel/.test(hint(i));
  // Un champ type="email" n'est jamais un pseudo ; sinon « Username or email » compte pour les deux.
  const isUser = (i) => i.type !== "email" && /user|login|pseudo|nick|identifiant|handle|account/.test(hint(i));

  const inputs = [...document.querySelectorAll("input")].filter(visible);
  const pwFields = inputs.filter((i) => i.type === "password");
  // Une ancienne entrée peut avoir l'e-mail dans « Identifiant ».
  if (!email && username.includes("@")) [email, username] = [username, ""];

  // Formulaire avec pseudo ET e-mail séparés (inscriptions, certains sites comme gg.deals).
  const scope = pwFields[0]?.form ? inputs.filter((i) => i.form === pwFields[0].form) : inputs;
  const emailField = scope.find((i) => textLike(i) && isEmail(i) && !isUser(i));
  const userField = scope.find((i) => textLike(i) && isUser(i) && !isEmail(i));
  let filled = false;
  if (email && emailField) { setValue(emailField, email); filled = true; }
  if (username && userField) { setValue(userField, username); filled = true; }

  // Sinon : un seul champ « identifiant ou e-mail ».
  if (!filled) {
    const login = username || email;
    const byAutocomplete = inputs.find((i) => i.type !== "password" && /username|email/.test(i.autocomplete || ""));
    let field;
    if (pwFields.length) {
      const before = inputs.slice(0, inputs.indexOf(pwFields[0])).reverse();
      field = byAutocomplete || before.find(textLike);
    } else {
      field = byAutocomplete || inputs.find(textLike); // connexion en 2 étapes (Google, Microsoft…)
    }
    if (field && login) { setValue(field, login); filled = true; }
  }

  if (mode === "new") pwFields.forEach((f) => setValue(f, password)); // mot de passe + confirmation
  else if (pwFields[0]) setValue(pwFields[0], password);

  if (pwFields.length) return "ok";
  return filled ? "username_only" : "no_fields";
}
