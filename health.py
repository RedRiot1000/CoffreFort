"""Santé du coffre : mots de passe faibles, réutilisés, anciens, et (en option) présents dans des fuites.

L'analyse se fait entièrement sur le PC. La vérification des fuites est optionnelle et utilise
Have I Been Pwned avec la « k-anonymité » : seuls les 5 premiers caractères de l'empreinte SHA-1
du mot de passe partent sur Internet ; le service renvoie toutes les empreintes qui commencent
pareil (des centaines) et la comparaison se fait ici. Ni le mot de passe ni son empreinte complète
ne quittent le PC.
"""

import hashlib
import re
import time
import urllib.request

from vault import estimate_entropy

OLD_DAYS = 365
MIN_LENGTH = 10
MIN_BITS = 60
HIBP_URL = "https://api.pwnedpasswords.com/range/"
TIMEOUT = 10

# Morceaux qu'on retrouve en tête des listes de mots de passe piratés.
COMMON = ("password", "motdepasse", "azerty", "qwerty", "123456", "654321", "111111", "000000", "abc123",
          "iloveyou", "jetaime", "soleil", "bonjour", "doudou", "chouchou", "loulou", "marseille", "football",
          "dragon", "monkey", "letmein", "welcome", "admin", "princess", "superman", "batman", "azertyuiop",
          "qwertyuiop", "nicolas", "camille", "0123", "1234", "2345", "abcd")

# Gravité : la première de la liste est la plus urgente.
KINDS = ("pwned", "reused", "weak", "old")
LABELS = {"pwned": "Dans une fuite", "reused": "Réutilisé", "weak": "Faible", "old": "Ancien"}


def password_age_days(entry: dict, now: float | None = None) -> float:
    changed = entry.get("pw_changed") or entry.get("created") or entry.get("modified") or 0
    return ((now or time.time()) - changed) / 86400 if changed else 0


def weakness(entry: dict) -> str | None:
    """Raison pour laquelle le mot de passe est faible, ou None."""
    pw = entry.get("password", "")
    low = pw.lower()
    if len(pw) < MIN_LENGTH:
        return f"seulement {len(pw)} caractères"
    word = next((w for w in COMMON if w in low), None)
    if word:
        return f"contient « {word} », très courant"
    site = re.sub(r"[^a-z0-9]", "", entry.get("site", "").lower())
    if len(site) >= 4 and site in re.sub(r"[^a-z0-9]", "", low):
        return "contient le nom du site"
    if re.search(r"(.)\1\1\1", pw):
        return "même caractère répété"
    if estimate_entropy(pw) < MIN_BITS:
        return "trop simple (peu de types de caractères)"
    return None


def _base(pw: str) -> str:
    """« Soleil2023! » et « Soleil2024? » → même base : réutilisation déguisée."""
    return re.sub(r"[\d\W_]+$", "", pw.lower())


def analyze(entries: list[dict], pwned: dict[str, int] | None = None, now: float | None = None) -> dict:
    """Problèmes par compte : {"issues": {id: [(type, détail), …]}, "counts": {type: n}, "score": 0-100}."""
    pwned = pwned or {}
    with_pw = [e for e in entries if e.get("password")]
    same, similar = {}, {}
    for e in with_pw:
        same.setdefault(e["password"], []).append(e)
        b = _base(e["password"])
        if len(b) >= 5:
            similar.setdefault(b, []).append(e)

    issues: dict[str, list] = {}
    for e in with_pw:
        found = []
        if pwned.get(e["id"]):
            found.append(("pwned", f"vu {pwned[e['id']]:,} fois dans des fuites".replace(",", " ")))
        twins = [o for o in same[e["password"]] if o is not e]
        near = [o for o in similar.get(_base(e["password"]), []) if o is not e and o not in twins]
        if twins:
            found.append(("reused", "même mot de passe que " + _names(twins)))
        elif near:
            found.append(("reused", "presque identique à " + _names(near)))
        why = weakness(e)
        if why:
            found.append(("weak", why))
        age = password_age_days(e, now)
        if age > OLD_DAYS:
            found.append(("old", f"pas changé depuis {int(age // 30)} mois"))
        if found:
            issues[e["id"]] = found

    counts = {k: sum(1 for f in issues.values() if any(t == k for t, _ in f)) for k in KINDS}
    # Chaque compte compte pour 1 ; une fuite ou une réutilisation pèse plus qu'un mot de passe ancien.
    weights = {"pwned": 1.0, "reused": 0.7, "weak": 0.6, "old": 0.25}
    penalty = sum(max(weights[t] for t, _ in f) for f in issues.values())
    score = 100 if not with_pw else round(100 * (1 - penalty / len(with_pw)))
    return {"issues": issues, "counts": counts, "score": max(0, score), "total": len(with_pw)}


def _names(others: list[dict]) -> str:
    names = [o["site"] + (f" ({o['username'] or o.get('email', '')})" if o.get("username") or o.get("email") else "")
             for o in others[:2]]
    more = len(others) - 2
    return ", ".join(names) + (f" et {more} autre{'s' if more > 1 else ''}" if more > 0 else "")


def _range(prefix: str) -> dict[str, int]:
    req = urllib.request.Request(HIBP_URL + prefix, headers={"User-Agent": "CoffreFort", "Add-Padding": "true"})
    with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
        text = r.read(4 * 1024 * 1024).decode("ascii", "replace")
    out = {}
    for line in text.splitlines():
        suffix, _, count = line.strip().partition(":")
        if count.isdigit() and int(count) > 0:  # le remplissage (Add-Padding) arrive avec un compte à 0
            out[suffix.upper()] = int(count)
    return out


def check_pwned(entries: list[dict], progress=None) -> dict[str, int]:
    """Nombre d'apparitions de chaque mot de passe dans des fuites connues (id du compte → nombre)."""
    by_prefix: dict[str, list] = {}
    for e in entries:
        if e.get("password"):
            h = hashlib.sha1(e["password"].encode("utf-8")).hexdigest().upper()
            by_prefix.setdefault(h[:5], []).append((h[5:], e["id"]))
    result = {}
    for i, (prefix, items) in enumerate(by_prefix.items()):
        found = _range(prefix)
        for suffix, eid in items:
            if found.get(suffix):
                result[eid] = found[suffix]
        if progress:
            progress(i + 1, len(by_prefix))
    return result
