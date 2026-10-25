import { fillTab, request } from "./common.js";

// Raccourci clavier (Ctrl+Maj+L par défaut) : remplit directement s'il n'y a
// qu'un compte pour le site, sinon ouvre la popup pour choisir.
chrome.commands.onCommand.addListener(async (command, tab) => {
  if (command !== "fill-login") return;
  tab = tab || (await chrome.tabs.query({ active: true, currentWindow: true }))[0];
  if (!tab?.url) return;

  const res = await request("list", { url: tab.url });
  if (res.ok && res.entries.length === 1) {
    const f = await request("fill", { url: tab.url, id: res.entries[0].id });
    if (f.ok) {
      await fillTab(tab.id, f.host, f.username, f.password, "login");
      return;
    }
  }
  try {
    await chrome.action.openPopup();
  } catch {
    chrome.action.setBadgeText({ text: "?", tabId: tab.id });
    setTimeout(() => chrome.action.setBadgeText({ text: "", tabId: tab.id }), 3000);
  }
});
