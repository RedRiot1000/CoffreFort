"""Générateur de mots de passe personnalisable : caractères aléatoires, mots français ou code PIN.

Tout le hasard vient du module `secrets` (aléa cryptographique). `entropy()` donne l'aléa réel du
réglage choisi (en bits), pas une estimation sur le résultat : c'est ce qui mesure la solidité.
"""

import math
import secrets
import string

from mots_fr import WORDS

SYMBOLS = "!@#$%^&*()-_=+[]{};:,.<>/?~"
AMBIGUOUS = set("Il1O0o|`'\"")
POSITIONS = {"partout": "Mélangés partout", "debut": "Au début", "fin": "À la fin", "milieu": "Au milieu",
             "bords": "Au début et à la fin"}
WORD_POSITIONS = {"fin": "À la fin", "debut": "Au début", "milieu": "Au milieu", "mots": "Entre les mots",
                  "hasard": "N'importe où"}
CASES = {"initiale": "Initiale en majuscule", "min": "minuscules", "maj": "MAJUSCULES",
         "hasard": "Au hasard (par mot)", "une": "Une seule majuscule au hasard"}
SEPARATORS = {"-": "Tiret  -", ".": "Point  .", "_": "Souligné  _", " ": "Espace", "": "Aucun",
              "chiffre": "Un chiffre au hasard", "symbole": "Un symbole au hasard", "perso": "Personnalisé…"}

DEFAULTS = {
    "mode": "chars",
    # caractères
    "length": 20, "lower": True, "upper": True, "digits": True, "symbols": True, "symbol_set": SYMBOLS,
    "min_upper": 1, "min_lower": 1, "min_digits": 2, "min_symbols": 2, "digits_pos": "partout",
    "symbols_pos": "partout", "avoid_ambiguous": False, "exclude": "", "start_letter": False, "no_repeat": False,
    # mots
    "words": 5, "separator": "-", "separator_custom": "+", "case": "initiale", "word_digits": 2,
    "word_digits_pos": "fin", "word_symbols": 1, "word_symbols_pos": "fin", "min_word": 3, "max_word": 9,
    # code PIN
    "pin_length": 6,
}


def settings(saved: dict | None) -> dict:
    out = dict(DEFAULTS)
    for k, v in (saved or {}).items():
        if k in DEFAULTS and type(v) is type(DEFAULTS[k]):
            out[k] = v
    return out


def _pool(chars: str, opt: dict) -> str:
    bad = set(opt["exclude"]) | (AMBIGUOUS if opt["avoid_ambiguous"] else set())
    return "".join(dict.fromkeys(c for c in chars if c not in bad))


def _families(opt: dict) -> dict:
    fam = {}
    if opt["lower"]:
        fam["lower"] = _pool(string.ascii_lowercase, opt)
    if opt["upper"]:
        fam["upper"] = _pool(string.ascii_uppercase, opt)
    if opt["digits"]:
        fam["digits"] = _pool(string.digits, opt)
    if opt["symbols"]:
        fam["symbols"] = _pool(opt["symbol_set"], opt)
    return {k: v for k, v in fam.items() if v}


def _shuffle(items: list) -> None:
    for i in range(len(items) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        items[i], items[j] = items[j], items[i]


def _place(body: list, block: list, pos: str) -> list:
    """Insère un groupe de caractères au début / à la fin / au milieu / aux deux bords du reste."""
    if pos == "debut":
        return block + body
    if pos == "fin":
        return body + block
    if pos == "milieu":
        mid = len(body) // 2
        return body[:mid] + block + body[mid:]
    half = (len(block) + 1) // 2  # « bords »
    return block[:half] + body + block[half:]


def _chars(opt: dict) -> str:
    fam = _families(opt)
    if not fam:
        raise ValueError("Choisis au moins un type de caractères.")
    length = opt["length"]
    need = {k: max(opt.get("min_" + k, 0), 1) if k in fam else 0 for k in ("lower", "upper", "digits", "symbols")}
    grouped = {k: opt[k + "_pos"] for k in ("digits", "symbols") if k in fam and opt[k + "_pos"] != "partout"}
    if sum(need.values()) > length:
        raise ValueError("Longueur trop courte pour les minimums demandés.")
    if grouped and not set(fam) - set(grouped):
        raise ValueError("Il faut au moins un type de caractères « mélangés partout ».")

    # Familles regroupées : exactement leur minimum, à la place choisie. Le reste est mélangé partout.
    blocks = {k: [secrets.choice(fam[k]) for _ in range(need[k])] for k in grouped}
    free = {k: v for k, v in fam.items() if k not in grouped}
    body = [secrets.choice(free[k]) for k in free for _ in range(need[k])]
    alphabet = "".join(free.values())
    body += [secrets.choice(alphabet) for _ in range(length - len(body) - sum(map(len, blocks.values())))]
    for _ in range(200):
        _shuffle(body)
        if opt["start_letter"] and not (body and body[0].isalpha()) and any(c.isalpha() for c in body):
            continue
        if opt["no_repeat"] and any(a == b for a, b in zip(body, body[1:])):
            continue
        break
    chars = body
    for k, pos in grouped.items():
        chars = _place(chars, blocks[k], pos)
    return "".join(chars)


def _word_list(opt: dict) -> list[str]:
    lo, hi = min(opt["min_word"], opt["max_word"]), max(opt["min_word"], opt["max_word"])
    words = [w for w in WORDS if lo <= len(w) <= hi]
    if len(words) < 100:
        raise ValueError("Trop peu de mots avec ces longueurs : élargis la plage.")
    return words


def _case(word: str, mode: str) -> str:
    if mode == "initiale":
        return word.capitalize()
    if mode == "maj":
        return word.upper()
    if mode == "hasard":
        return word.upper() if secrets.randbelow(2) else word.capitalize() if secrets.randbelow(2) else word
    return word


def _words(opt: dict) -> str:
    words = _word_list(opt)
    picked = [_case(secrets.choice(words), opt["case"]) for _ in range(opt["words"])]
    if opt["case"] == "une":
        letters = [(i, j) for i, w in enumerate(picked) for j in range(len(w))]
        i, j = letters[secrets.randbelow(len(letters))]
        picked[i] = picked[i][:j] + picked[i][j].upper() + picked[i][j + 1:]
    sym = opt["symbol_set"] or SYMBOLS
    sep = opt["separator"]
    seps = [secrets.choice(string.digits) if sep == "chiffre" else secrets.choice(sym) if sep == "symbole"
            else opt["separator_custom"] if sep == "perso" else sep for _ in range(len(picked) - 1)]

    extras = [("digits", string.digits, opt["word_digits"], opt["word_digits_pos"]),
              ("symbols", sym, opt["word_symbols"], opt["word_symbols_pos"])]
    for _, alphabet, count, pos in extras:
        add = "".join(secrets.choice(alphabet) for _ in range(count))
        if not add:
            continue
        if pos == "debut":
            picked[0] = add + picked[0]
        elif pos == "fin":
            picked[-1] = picked[-1] + add
        elif pos == "milieu":
            picked[len(picked) // 2] = add + picked[len(picked) // 2]
        elif pos == "mots" and len(picked) > 1:
            for c in add:  # chaque caractère colle à la fin d'un mot au hasard (sauf le dernier)
                k = secrets.randbelow(len(picked) - 1)
                picked[k] += c
        else:  # n'importe où, y compris au milieu d'un mot
            for c in add:
                k = secrets.randbelow(len(picked))
                cut = secrets.randbelow(len(picked[k]) + 1)
                picked[k] = picked[k][:cut] + c + picked[k][cut:]
    out = picked[0]
    for s, w in zip(seps, picked[1:]):
        out += s + w
    return out


def generate(opt: dict) -> str:
    opt = settings(opt)
    if opt["mode"] == "words":
        return _words(opt)
    if opt["mode"] == "pin":
        return "".join(secrets.choice(string.digits) for _ in range(opt["pin_length"]))
    return _chars(opt)


def entropy(opt: dict) -> float:
    """Aléa du réglage, en bits (sous-estimé quand le calcul exact est compliqué)."""
    opt = settings(opt)
    if opt["mode"] == "pin":
        return opt["pin_length"] * math.log2(10)
    if opt["mode"] == "words":
        bits = opt["words"] * math.log2(len(_word_list(opt)))
        bits += {"hasard": opt["words"] * 1.5, "une": math.log2(opt["words"] * 6)}.get(opt["case"], 0)
        sym = len(opt["symbol_set"] or SYMBOLS)
        if opt["separator"] in ("chiffre", "symbole"):
            bits += (opt["words"] - 1) * math.log2(10 if opt["separator"] == "chiffre" else sym)
        bits += opt["word_digits"] * math.log2(10) + opt["word_symbols"] * math.log2(sym)
        return bits
    fam = _families(opt)
    if not fam:
        return 0.0
    grouped = {k for k in ("digits", "symbols") if k in fam and opt[k + "_pos"] != "partout"}
    free = "".join(v for k, v in fam.items() if k not in grouped)
    n_grouped = sum(max(opt["min_" + k], 1) for k in grouped)
    bits = (opt["length"] - n_grouped) * math.log2(max(len(free), 1))
    bits += sum(max(opt["min_" + k], 1) * math.log2(len(fam[k])) for k in grouped)
    if opt["start_letter"]:
        bits -= 1
    return max(bits, 0.0)


def crack_time(bits: float) -> str:
    """Temps moyen pour deviner, à 100 milliards d'essais par seconde (gros matériel spécialisé)."""
    seconds = 2 ** bits / 2 / 1e11
    for unit, size in (("milliards d'années", 3.15e16), ("millions d'années", 3.15e13), ("ans", 3.15e7),
                       ("jours", 86400), ("heures", 3600), ("minutes", 60)):
        if seconds >= size:
            n = seconds / size
            return ("plus de 1000 " + unit) if n >= 1000 and unit == "milliards d'années" else f"{n:,.0f} {unit}".replace(",", " ")
    return "moins d'une minute"
