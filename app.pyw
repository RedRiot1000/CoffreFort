"""CoffreFort — gestionnaire de mots de passe local et chiffré."""

import ctypes
import json
import os
import queue
import re
import subprocess
import sys
import threading
import time
import tkinter as tk
import webbrowser
from ctypes import wintypes
from tkinter import filedialog, messagebox, ttk

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import backup  # noqa: E402
import autotype  # noqa: E402
import bridge  # noqa: E402
import updater  # noqa: E402
import winsec  # noqa: E402
from vault import Vault, VaultError, WrongPassword, estimate_entropy, generate_password, strength_label  # noqa: E402

VAULT_PATH = os.path.join(os.environ.get("LOCALAPPDATA", os.path.expanduser("~")), "CoffreFort", "coffre.vault")
AUTO_LOCK_SECONDS = 5 * 60
HELLO_MAX_HOURS = 12
CLIPBOARD_CLEAR_SECONDS = 20
MIN_MASTER_LENGTH = 12
PROGRAM_FILES = ("app.pyw", "vault.py", "bridge.py", "backup.py", "updater.py", "autotype.py", "winsec.py")
UPDATE_CHECK_MS = 3000
UPDATE_SETTLE_SECONDS = 5
ONLINE_CHECK_MS = 6 * 3600 * 1000


def program_fingerprint():
    """Empreinte (date + taille) des fichiers du programme, pour repérer une mise à jour."""
    out = []
    for name in PROGRAM_FILES:
        try:
            st = os.stat(os.path.join(HERE, name))
            out.append((name, st.st_mtime_ns, st.st_size))
        except FileNotFoundError:
            out.append((name, None, None))
    return tuple(out)


def program_compiles():
    """Vérifie que la nouvelle version est complète avant de redémarrer dessus."""
    try:
        for name in PROGRAM_FILES:
            path = os.path.join(HERE, name)
            with open(path, encoding="utf-8") as f:
                compile(f.read(), path, "exec")
        return True
    except (OSError, SyntaxError, ValueError):
        return False

BG = "#1e1f24"
PANEL = "#2a2c33"
FG = "#e8e8ea"
MUTED = "#9a9ca5"
ACCENT = "#4f8cff"


# ---------------------------------------------------------------- presse-papiers
class SecureClipboard:
    """Copie via l'API Windows en marquant le contenu comme exclu de l'historique
    (Win+V) et de la synchro cloud, puis l'efface automatiquement."""

    def __init__(self):
        self.ok = sys.platform == "win32"
        self._seq = None
        if not self.ok:
            return
        u, k = ctypes.WinDLL("user32"), ctypes.WinDLL("kernel32")
        u.OpenClipboard.argtypes = [wintypes.HWND]
        u.OpenClipboard.restype = wintypes.BOOL
        u.SetClipboardData.argtypes = [wintypes.UINT, wintypes.HANDLE]
        u.SetClipboardData.restype = wintypes.HANDLE
        u.RegisterClipboardFormatW.argtypes = [wintypes.LPCWSTR]
        u.RegisterClipboardFormatW.restype = wintypes.UINT
        u.GetClipboardSequenceNumber.restype = wintypes.DWORD
        k.GlobalAlloc.argtypes = [wintypes.UINT, ctypes.c_size_t]
        k.GlobalAlloc.restype = wintypes.HANDLE
        k.GlobalLock.argtypes = [wintypes.HANDLE]
        k.GlobalLock.restype = ctypes.c_void_p
        k.GlobalUnlock.argtypes = [wintypes.HANDLE]
        k.GlobalFree.argtypes = [wintypes.HANDLE]
        self.u, self.k = u, k

    def _open(self):
        for _ in range(10):
            if self.u.OpenClipboard(None):
                return True
            time.sleep(0.02)
        return False

    def _put(self, fmt, data: bytes):
        h = self.k.GlobalAlloc(0x0002, len(data))  # GMEM_MOVEABLE
        p = self.k.GlobalLock(h)
        ctypes.memmove(p, data, len(data))
        self.k.GlobalUnlock(h)
        if not self.u.SetClipboardData(fmt, h):
            self.k.GlobalFree(h)

    def copy(self, root: tk.Tk, text: str):
        if not self.ok or not self._open():
            root.clipboard_clear()
            root.clipboard_append(text)
            return
        try:
            self.u.EmptyClipboard()
            self._put(13, (text + "\0").encode("utf-16-le"))  # CF_UNICODETEXT
            zero = (0).to_bytes(4, "little")
            for name in ("ExcludeClipboardContentFromMonitorProcessing",
                         "CanIncludeInClipboardHistory", "CanUploadToCloudClipboard"):
                self._put(self.u.RegisterClipboardFormatW(name), zero)
        finally:
            self.u.CloseClipboard()
        self._seq = self.u.GetClipboardSequenceNumber()

    def clear_if_ours(self):
        """N'efface que si le presse-papiers contient encore notre copie."""
        if not self.ok or self._seq is None:
            return
        if self.u.GetClipboardSequenceNumber() == self._seq and self._open():
            try:
                self.u.EmptyClipboard()
            finally:
                self.u.CloseClipboard()
        self._seq = None


# ---------------------------------------------------------------- widgets utiles
class StrengthBar(ttk.Frame):
    def __init__(self, parent):
        super().__init__(parent, style="Panel.TFrame")
        self.canvas = tk.Canvas(self, height=6, bg=PANEL, highlightthickness=0)
        self.canvas.pack(fill="x", side="top")
        self.label = ttk.Label(self, text="", style="Muted.TLabel")
        self.label.pack(anchor="w", side="top")

    def update_for(self, password: str):
        bits = estimate_entropy(password) if password else 0
        text, color = strength_label(bits)
        self.canvas.delete("all")
        width = max(self.canvas.winfo_width(), 200)
        self.canvas.create_rectangle(0, 0, width * min(bits, 128) / 128, 6, fill=color, width=0)
        self.label.config(text=f"{text} · ~{int(bits)} bits" if password else "")


class GeneratorPanel(ttk.Frame):
    def __init__(self, parent, on_use=None, on_copy=None):
        super().__init__(parent, style="Panel.TFrame", padding=16)
        self.on_use, self.on_copy = on_use, on_copy
        self.length = tk.IntVar(value=24)
        self.opts = {k: tk.BooleanVar(value=True) for k in ("lower", "upper", "digits", "symbols")}
        self.ambig = tk.BooleanVar(value=False)
        self.result = tk.StringVar()

        out = ttk.Entry(self, textvariable=self.result, font=("Consolas", 13), width=40)
        out.pack(fill="x")
        self.strength = StrengthBar(self)
        self.strength.pack(fill="x", pady=(6, 10))

        row = ttk.Frame(self, style="Panel.TFrame")
        row.pack(fill="x")
        ttk.Label(row, text="Longueur", style="Panel.TLabel").pack(side="left")
        self.len_label = ttk.Label(row, text="24", width=3, style="Panel.TLabel")
        self.len_label.pack(side="right")
        ttk.Scale(row, from_=8, to=64, variable=self.length, command=self._on_len).pack(
            side="left", fill="x", expand=True, padx=10)

        labels = {"lower": "Minuscules (a-z)", "upper": "Majuscules (A-Z)",
                  "digits": "Chiffres (0-9)", "symbols": "Symboles (!@#…)"}
        grid = ttk.Frame(self, style="Panel.TFrame")
        grid.pack(fill="x", pady=8)
        for i, (k, lbl) in enumerate(labels.items()):
            ttk.Checkbutton(grid, text=lbl, variable=self.opts[k], command=self.generate).grid(
                row=i // 2, column=i % 2, sticky="w", padx=(0, 20), pady=2)
        ttk.Checkbutton(grid, text="Éviter les caractères ambigus (l, 1, O, 0…)", variable=self.ambig,
                        command=self.generate).grid(row=2, column=0, columnspan=2, sticky="w", pady=2)

        btns = ttk.Frame(self, style="Panel.TFrame")
        btns.pack(fill="x", pady=(6, 0))
        ttk.Button(btns, text="↻ Régénérer", command=self.generate).pack(side="left")
        if on_copy:
            ttk.Button(btns, text="Copier", command=lambda: on_copy(self.result.get())).pack(side="left", padx=6)
        if on_use:
            ttk.Button(btns, text="Utiliser ce mot de passe", style="Accent.TButton",
                       command=lambda: on_use(self.result.get())).pack(side="right")
        self.result.trace_add("write", lambda *_: self.strength.update_for(self.result.get()))
        self.after(50, self.generate)

    def _on_len(self, _=None):
        n = int(float(self.length.get()))
        self.length.set(n)
        self.len_label.config(text=str(n))
        self.generate()

    def generate(self):
        try:
            self.result.set(generate_password(
                self.length.get(), avoid_ambiguous=self.ambig.get(), **{k: v.get() for k, v in self.opts.items()}))
        except ValueError as e:
            self.result.set("")
            self.strength.label.config(text=str(e))


# ---------------------------------------------------------------- mise à jour en ligne
LAST_UPDATE_ERROR = None


def startup_update_quiet():
    global LAST_UPDATE_ERROR
    try:
        version = updater.update_now()
        LAST_UPDATE_ERROR = None
        return version
    except Exception as ex:  # noqa: BLE001 - hors ligne, GitHub indisponible, signature refusée : on garde la version actuelle
        LAST_UPDATE_ERROR = str(ex) or type(ex).__name__
        return None


def startup_update():
    """Au lancement d'une copie partagée : installe la dernière version publiée, s'il y en a une."""
    if not updater.enabled():
        return False
    result = {}
    worker = threading.Thread(target=lambda: result.update(version=startup_update_quiet()), daemon=True)
    worker.start()
    worker.join(1.0)
    if worker.is_alive():  # réseau lent : petite fenêtre pour ne pas sembler planté
        splash = tk.Tk()
        splash.overrideredirect(True)
        splash.configure(bg=BG)
        tk.Label(splash, text="CoffreFort — recherche de mise à jour…", bg=BG, fg=FG,
                 font=("Segoe UI", 11), padx=28, pady=18).pack()
        splash.update_idletasks()
        splash.geometry(f"+{(splash.winfo_screenwidth() - splash.winfo_width()) // 2}"
                        f"+{(splash.winfo_screenheight() - splash.winfo_height()) // 2}")
        deadline = time.time() + 60

        def poll():
            if worker.is_alive() and time.time() < deadline:
                splash.after(100, poll)
            else:
                splash.destroy()
        poll()
        splash.mainloop()
    return bool(result.get("version"))


# ---------------------------------------------------------------- application
class App(tk.Tk):
    def __init__(self):
        super().__init__()
        version = updater.current_version()
        self.title(f"CoffreFort  (version {version})" if version else "CoffreFort")
        self.geometry("980x600")
        self.minsize(980, 520)
        self.configure(bg=BG)
        self._setup_style()

        self.vault = Vault(VAULT_PATH)
        self.settings = backup.load_settings()
        self._backup_error = None
        self.vault.on_saved = self._auto_backup
        self.clip = SecureClipboard()
        self._clip_job = None
        self.failed_attempts = 0
        self.locked_until = 0.0
        self.last_activity = time.time()
        self.dialogs: list[tk.Toplevel] = []
        self.current = None
        self._pair_dialog = None

        self.bridge = bridge.BridgeServer()
        try:
            self.bridge.start()
        except OSError:
            self.bridge = None  # extension indisponible, l'app reste utilisable
        self.after(100, self._bridge_tick)

        self._pending_target = None
        self.hotkey = autotype.HotkeyListener()
        if not self.hotkey.start():
            self.hotkey = None  # raccourci pris par une autre appli : le reste fonctionne
        else:
            self.after(100, self._autotype_tick)

        for seq in ("<Any-KeyPress>", "<Any-ButtonPress>", "<Motion>"):
            self.bind_all(seq, self._touch, add="+")
        self.protocol("WM_DELETE_WINDOW", self._quit)
        self.after(5000, self._auto_lock_tick)
        self._master_at = 0.0  # dernier déverrouillage par mot de passe maître (ou clé de secours)
        self._via_hello = False
        self._hello_state = None
        self._check_hello()
        self._last_session_tick = time.time()
        self.after(2000, self._session_tick)

        self.body = ttk.Frame(self, style="TFrame")
        self.body.pack(fill="both", expand=True)

        self._fingerprint = program_fingerprint()
        self._pending_fp, self._pending_since = None, 0.0
        self.update_ready = False
        self.banner = tk.Frame(self, bg="#2e5bd8")
        tk.Label(self.banner, text="🔄  Une mise à jour de CoffreFort est installée.", bg="#2e5bd8", fg="white",
                 font=("Segoe UI Semibold", 10)).pack(side="left", padx=12, pady=6)
        ttk.Button(self.banner, text="Redémarrer maintenant", command=self.restart).pack(side="right", padx=8, pady=4)
        self.after(UPDATE_CHECK_MS, self._update_tick)
        if updater.enabled():
            self.after(ONLINE_CHECK_MS, self._online_check)

        self.show_login()

    # ---------- style ----------
    def _setup_style(self):
        s = ttk.Style(self)
        s.theme_use("clam")
        s.configure(".", background=BG, foreground=FG, fieldbackground=PANEL, font=("Segoe UI", 10),
                    bordercolor="#3a3c44", lightcolor=PANEL, darkcolor=PANEL, insertcolor=FG)
        s.configure("TFrame", background=BG)
        s.configure("Panel.TFrame", background=PANEL)
        s.configure("TLabel", background=BG, foreground=FG)
        s.configure("Panel.TLabel", background=PANEL, foreground=FG)
        s.configure("Muted.TLabel", background=PANEL, foreground=MUTED, font=("Segoe UI", 9))
        s.configure("Title.TLabel", background=BG, foreground=FG, font=("Segoe UI Semibold", 20))
        s.configure("Sub.TLabel", background=BG, foreground=MUTED)
        s.configure("Value.TLabel", background=PANEL, foreground=FG, font=("Segoe UI", 11))
        s.configure("Mono.TLabel", background=PANEL, foreground=FG, font=("Consolas", 12))
        s.configure("Warn.TLabel", background=PANEL, foreground="#f0ad4e")
        s.configure("Code.TLabel", background=PANEL, foreground="#ffd166", font=("Consolas", 26, "bold"))
        s.configure("TMenubutton", background="#3a3c44", foreground=FG, padding=(10, 5), borderwidth=0)
        s.map("TMenubutton", background=[("active", "#4a4c55")])
        s.configure("Error.TLabel", background=BG, foreground="#ff6b6b")
        s.configure("TButton", background="#3a3c44", foreground=FG, padding=(10, 5), borderwidth=0)
        s.map("TButton", background=[("active", "#4a4c55"), ("disabled", "#2e3036")],
              foreground=[("disabled", MUTED)])
        s.configure("Accent.TButton", background=ACCENT, foreground="white")
        s.map("Accent.TButton", background=[("active", "#3b78ee"), ("disabled", "#2e3a55")])
        s.configure("Danger.TButton", background="#7a2e2e", foreground="white")
        s.map("Danger.TButton", background=[("active", "#963838")])
        s.configure("TEntry", padding=6)
        s.configure("TCheckbutton", background=PANEL, foreground=FG)
        s.map("TCheckbutton", background=[("active", PANEL)])
        s.configure("Horizontal.TScale", background=PANEL, troughcolor="#3a3c44")
        s.configure("Treeview", background=PANEL, fieldbackground=PANEL, foreground=FG, rowheight=30,
                    borderwidth=0)
        s.configure("Treeview.Heading", background="#33353d", foreground=MUTED, borderwidth=0)
        s.map("Treeview", background=[("selected", ACCENT)], foreground=[("selected", "white")])

    def _clear_body(self):
        for w in self.body.winfo_children():
            w.destroy()

    # ---------- écran de connexion / création ----------
    def show_login(self):
        self._clear_body()
        creating = not self.vault.exists
        box = ttk.Frame(self.body, style="TFrame")
        box.place(relx=0.5, rely=0.45, anchor="center")

        ttk.Label(box, text="🔒  CoffreFort", style="Title.TLabel").pack(pady=(0, 4))
        ttk.Label(box, text="Créer ton mot de passe maître" if creating else "Entre ton mot de passe maître",
                  style="Sub.TLabel").pack(pady=(0, 16))

        pw = tk.StringVar()
        pw2 = tk.StringVar()
        e1 = ttk.Entry(box, textvariable=pw, show="•", width=38, font=("Segoe UI", 12))
        e1.pack(pady=4)
        e1.focus_set()
        e2 = None
        if creating:
            e2 = ttk.Entry(box, textvariable=pw2, show="•", width=38, font=("Segoe UI", 12))
            e2.pack(pady=4)
            holder = ttk.Frame(box, style="Panel.TFrame", padding=(8, 6))
            holder.pack(fill="x", pady=4)
            bar = StrengthBar(holder)
            bar.pack(fill="x")
            pw.trace_add("write", lambda *_: bar.update_for(pw.get()))
            ttk.Label(box, text=f"Au moins {MIN_MASTER_LENGTH} caractères. Astuce : une phrase de 4-5 mots\n"
                                "que toi seul connais. S'il est perdu, le coffre est IRRÉCUPÉRABLE.",
                      style="Sub.TLabel", justify="center").pack(pady=6)

        msg = ttk.Label(box, text="", style="Error.TLabel")
        msg.pack(pady=4)
        btn = ttk.Button(box, text="Créer le coffre" if creating else "Déverrouiller", style="Accent.TButton")
        btn.pack(pady=6, ipadx=20)
        if not creating and self.vault.suspended:
            hello_btn = ttk.Button(box, text="🖐  Déverrouiller avec Windows Hello")
            hello_btn.config(command=lambda: self._hello_unlock(hello_btn, msg))
            hello_btn.pack(pady=(2, 6), ipadx=10)

        def submit(_=None):
            if str(btn["state"]) == "disabled":
                return
            password = pw.get()
            if creating:
                if len(password) < MIN_MASTER_LENGTH:
                    msg.config(text=f"Trop court (minimum {MIN_MASTER_LENGTH} caractères).")
                    return
                if password != pw2.get():
                    msg.config(text="Les deux mots de passe ne correspondent pas.")
                    return
                if estimate_entropy(password) < 60 and not messagebox.askyesno(
                        "Mot de passe faible", "Ce mot de passe maître est faible. Continuer quand même ?"):
                    return
            pw.set("")
            pw2.set("")
            if creating:
                def done(recovery):
                    self.show_main()
                    self.show_recovery_key(recovery, first=True)
                self._attempt(btn, msg, lambda: self.vault.create(password), done, "Création…")
            else:
                self._attempt(btn, msg, lambda: self.vault.unlock(password), lambda _: self.show_main())

        btn.config(command=submit)
        e1.bind("<Return>", submit)
        if e2:
            e2.bind("<Return>", submit)
        if creating:
            restore = ttk.Label(box, text="Restaurer une sauvegarde…", style="Sub.TLabel", cursor="hand2",
                                font=("Segoe UI", 9, "underline"))
            restore.pack(pady=(10, 0))
            restore.bind("<Button-1>", lambda _: self.restore_backup())
        else:
            forgot = ttk.Label(box, text="Mot de passe oublié ?", style="Sub.TLabel", cursor="hand2",
                               font=("Segoe UI", 9, "underline"))
            forgot.pack(pady=(10, 0))
            forgot.bind("<Button-1>", lambda _: self.show_recovery_login())

    def _attempt(self, btn, msg, fn, on_success, busy_text="Déchiffrement…"):
        """Lance fn (Argon2, ~0,5 s) hors du thread de l'interface, avec délai
        croissant après plusieurs échecs."""
        wait = self.locked_until - time.time()
        if wait > 0:
            msg.config(text=f"Trop d'essais. Réessaie dans {int(wait) + 1} s.", style="Error.TLabel")
            return
        btn.config(state="disabled")
        msg.config(text=busy_text, style="Sub.TLabel")
        result = {}

        def work():
            try:
                result["value"] = fn()
            except Exception as ex:  # noqa: BLE001
                result["err"] = ex

        def poll():
            if t.is_alive():
                self.after(50, poll)
                return
            err = result.get("err")
            if err is None:
                self.failed_attempts = 0
                on_success(result.get("value"))
                return
            btn.config(state="normal")
            msg.config(style="Error.TLabel")
            if isinstance(err, WrongPassword):
                self.failed_attempts += 1
                if self.failed_attempts >= 3:
                    delay = min(2 ** (self.failed_attempts - 2), 300)
                    self.locked_until = time.time() + delay
                    msg.config(text=f"Incorrect. Attente de {delay} s.")
                else:
                    msg.config(text="Incorrect.")
            else:
                msg.config(text=f"Erreur : {err}")

        t = threading.Thread(target=work, daemon=True)
        t.start()
        poll()

    # ---------- récupération par clé de secours ----------
    def show_recovery_login(self):
        self._clear_body()
        box = ttk.Frame(self.body, style="TFrame")
        box.place(relx=0.5, rely=0.45, anchor="center")
        ttk.Label(box, text="🛟  Clé de secours", style="Title.TLabel").pack(pady=(0, 4))
        ttk.Label(box, text="Entre la clé de secours notée à la création du coffre\n"
                            "(format XXXXX-XXXXX-XXXXX-XXXXX-XXXXX-XXXXX).",
                  style="Sub.TLabel", justify="center").pack(pady=(0, 16))
        key = tk.StringVar()
        e = ttk.Entry(box, textvariable=key, width=40, font=("Consolas", 13), justify="center")
        e.pack(pady=4)
        e.focus_set()
        msg = ttk.Label(box, text="", style="Error.TLabel")
        msg.pack(pady=4)
        btn = ttk.Button(box, text="Ouvrir le coffre", style="Accent.TButton")
        btn.pack(pady=6, ipadx=20)

        def submit(_=None):
            if str(btn["state"]) == "disabled":
                return
            k = key.get()
            key.set("")
            self._attempt(btn, msg, lambda: self.vault.unlock_with_recovery(k),
                          lambda _: self.show_new_master())

        btn.config(command=submit)
        e.bind("<Return>", submit)
        back = ttk.Label(box, text="← Retour", style="Sub.TLabel", cursor="hand2")
        back.pack(pady=(10, 0))
        back.bind("<Button-1>", lambda _: self.show_login())

    def show_new_master(self):
        """Après ouverture par clé de secours : choisir un nouveau mot de passe maître."""
        self._clear_body()
        box = ttk.Frame(self.body, style="TFrame")
        box.place(relx=0.5, rely=0.45, anchor="center")
        ttk.Label(box, text="Nouveau mot de passe maître", style="Title.TLabel").pack(pady=(0, 4))
        ttk.Label(box, text="Coffre ouvert avec la clé de secours. Choisis un nouveau mot de passe maître.\n"
                            "Ta clé de secours reste valable.", style="Sub.TLabel", justify="center").pack(pady=(0, 16))
        pw, pw2 = tk.StringVar(), tk.StringVar()
        e1 = ttk.Entry(box, textvariable=pw, show="•", width=38, font=("Segoe UI", 12))
        e1.pack(pady=4)
        e1.focus_set()
        ttk.Entry(box, textvariable=pw2, show="•", width=38, font=("Segoe UI", 12)).pack(pady=4)
        holder = ttk.Frame(box, style="Panel.TFrame", padding=(8, 6))
        holder.pack(fill="x", pady=4)
        bar = StrengthBar(holder)
        bar.pack(fill="x")
        pw.trace_add("write", lambda *_: bar.update_for(pw.get()))
        msg = ttk.Label(box, text="", style="Error.TLabel")
        msg.pack(pady=4)

        def submit(_=None):
            if len(pw.get()) < MIN_MASTER_LENGTH:
                msg.config(text=f"Trop court (minimum {MIN_MASTER_LENGTH} caractères).")
                return
            if pw.get() != pw2.get():
                msg.config(text="Les deux mots de passe ne correspondent pas.")
                return
            if self._busy(lambda: self.vault.set_password(pw.get()) or True):
                pw.set("")
                pw2.set("")
                self.show_main()
                self.set_status("Nouveau mot de passe maître enregistré.")

        ttk.Button(box, text="Enregistrer", style="Accent.TButton", command=submit).pack(pady=6, ipadx=20)
        e1.bind("<Return>", submit)

    def show_recovery_key(self, recovery, first=False):
        d = self._dialog("Clé de secours")
        d.protocol("WM_DELETE_WINDOW", lambda: None)  # fermeture seulement après confirmation
        f = ttk.Frame(d, style="Panel.TFrame", padding=22)
        f.pack(fill="both", expand=True)
        ttk.Label(f, text="🛟  Ta clé de secours", style="Panel.TLabel",
                  font=("Segoe UI Semibold", 15)).pack(anchor="w")
        intro = ("Ton coffre est créé. " if first else "Nouvelle clé générée : l'ancienne ne fonctionne PLUS. ")
        ttk.Label(f, text=intro + "Si tu oublies ton mot de passe maître, cette clé\n"
                                  "est le SEUL moyen de rouvrir ton coffre.",
                  style="Panel.TLabel", justify="left").pack(anchor="w", pady=(6, 12))
        key_box = tk.Entry(f, font=("Consolas", 16, "bold"), justify="center", width=38, relief="flat",
                           readonlybackground=BG, fg="#ffd166", bd=10)
        key_box.insert(0, recovery)
        key_box.config(state="readonly")
        key_box.pack(fill="x")
        ttk.Label(f, text="✍  Recopie-la sur papier et range-la en lieu sûr (pas dans ce PC, pas en photo\n"
                          "dans ton téléphone). Elle ne sera plus jamais affichée.\n"
                          "⚠  Quiconque a cette clé ET ton fichier de coffre peut l'ouvrir.",
                  style="Muted.TLabel", justify="left").pack(anchor="w", pady=12)
        ok = tk.BooleanVar(value=False)
        close = ttk.Button(f, text="Fermer", style="Accent.TButton", state="disabled", command=d.destroy)
        ttk.Checkbutton(f, text="J'ai bien noté ma clé de secours", variable=ok,
                        command=lambda: close.config(state="normal" if ok.get() else "disabled")).pack(anchor="w")
        close.pack(anchor="e", pady=(10, 0))

    def regenerate_recovery(self):
        if not messagebox.askyesno(
                "Nouvelle clé de secours",
                "Générer une nouvelle clé de secours ?\n\nL'ancienne (celle sur papier) ne fonctionnera plus.\n"
                "Utile si tu l'as perdue ou si quelqu'un a pu la voir."):
            return
        recovery = self._busy(self.vault.new_recovery_key)
        if recovery:
            self.show_recovery_key(recovery)

    # ---------- écran principal ----------
    def show_main(self):
        if not self._via_hello:
            self._master_at = time.time()
        self._via_hello = False
        self._clear_body()
        self.current = None

        top = ttk.Frame(self.body, style="TFrame", padding=(12, 10))
        top.pack(fill="x")
        self.search_var = tk.StringVar()
        search = ttk.Entry(top, textvariable=self.search_var, width=34)
        search.pack(side="left")
        search.insert(0, "")
        search.focus_set()
        self.search_var.trace_add("write", lambda *_: self.refresh_list())
        ttk.Label(top, text="  🔍 Rechercher", style="Sub.TLabel").pack(side="left")
        ttk.Button(top, text="🔒 Verrouiller", command=self.lock).pack(side="right")
        settings = ttk.Menubutton(top, text="⚙ Réglages")
        menu = tk.Menu(settings, tearoff=False, bg=PANEL, fg=FG, activebackground=ACCENT, activeforeground="white",
                       relief="flat", font=("Segoe UI", 10))
        menu.add_command(label="Mot de passe maître…", command=self.change_master)
        menu.add_command(label="Clé de secours…", command=self.regenerate_recovery)
        menu.add_command(label="Extensions navigateur…", command=self.manage_extensions)
        menu.add_command(label="Sauvegarde automatique…", command=self.backup_dialog)
        menu.add_command(label="Verrouillage et Windows Hello…", command=self.lock_dialog)
        if updater.enabled():
            menu.add_command(label="Mises à jour…", command=self.update_dialog)
        settings["menu"] = menu
        settings.pack(side="right", padx=6)
        ttk.Button(top, text="🎲 Générateur", command=self.open_generator).pack(side="right")
        ttk.Button(top, text="＋ Ajouter", style="Accent.TButton", command=self.add_entry).pack(side="right", padx=6)

        main = ttk.Frame(self.body, style="TFrame", padding=(12, 0, 12, 12))
        main.pack(fill="both", expand=True)
        main.columnconfigure(0, weight=3)
        main.columnconfigure(1, weight=2)
        main.rowconfigure(0, weight=1)

        self.tree = ttk.Treeview(main, columns=("site", "user"), show="headings", selectmode="browse")
        self.tree.heading("site", text="Site / Appli")
        self.tree.heading("user", text="Identifiant")
        self.tree.column("site", width=240)
        self.tree.column("user", width=240)
        self.tree.grid(row=0, column=0, sticky="nsew")
        self.tree.bind("<<TreeviewSelect>>", lambda _: self.show_details())
        # Choix fait par l'utilisateur (clic ou flèches), pas une sélection automatique.
        self.tree.bind("<ButtonRelease-1>", self._arm, add="+")
        self.tree.bind("<KeyRelease>", self._arm, add="+")
        self.tree.bind("<Double-1>", lambda _: self.copy_field("password"))

        self.details = ttk.Frame(main, style="Panel.TFrame", padding=18)
        self.details.grid(row=0, column=1, sticky="nsew", padx=(12, 0))

        self.status = ttk.Label(self.body, text="", style="Sub.TLabel", padding=(12, 0, 12, 8))
        self.status.pack(fill="x", side="bottom")
        self._auto_backup()
        self.refresh_list()
        self.show_details()
        pending, self._pending_target = self._pending_target, None
        if pending and time.time() - pending[1] < 120:  # Ctrl+Alt+L appuyé pendant que le coffre était verrouillé
            self.after(300, lambda: self._autotype_request(pending[0]))

    def refresh_list(self, select_id=None):
        self.tree.delete(*self.tree.get_children())
        for e in self.vault.search(self.search_var.get()):
            self.tree.insert("", "end", iid=e["id"], values=(e["site"], e["username"] or e.get("email", "")))
        if select_id and self.tree.exists(select_id):
            self.tree.selection_set(select_id)
            self.tree.see(select_id)
        n = len(self.vault.entries)
        cloud = "⚠ sauvegarde cloud en échec" if self._backup_error else (
            "☁ sauvegarde auto activée" if self.settings.get("backup_dir") else "sauvegarde auto désactivée")
        self.set_status(f"{n} entrée{'s' if n > 1 else ''} · {cloud} · coffre : {self.vault.path}")

    def set_status(self, text):
        if hasattr(self, "status") and self.status.winfo_exists():
            self.status.config(text=text)

    def _selected(self):
        sel = self.tree.selection()
        if not sel:
            return None
        return next((e for e in self.vault.entries if e["id"] == sel[0]), None)

    def _arm(self, _=None):
        self._selected_at = time.time()

    def show_details(self):
        for w in self.details.winfo_children():
            w.destroy()
        e = self._selected()
        self.current = e
        if e is None:
            ttk.Label(self.details, text="Sélectionne une entrée,\nou clique sur « ＋ Ajouter ».",
                      style="Muted.TLabel", justify="center").pack(expand=True)
            return

        ttk.Label(self.details, text=e["site"], style="Panel.TLabel",
                  font=("Segoe UI Semibold", 16)).pack(anchor="w", pady=(0, 12))

        def field(label, value, key=None, secret=False):
            ttk.Label(self.details, text=label, style="Muted.TLabel").pack(anchor="w")
            row = ttk.Frame(self.details, style="Panel.TFrame")
            row.pack(fill="x", pady=(0, 10))
            shown = tk.BooleanVar(value=not secret)
            lbl = ttk.Label(row, text=value if not secret else "•" * 12,
                            style="Mono.TLabel" if secret else "Value.TLabel", wraplength=260)
            lbl.pack(side="left", fill="x", expand=True)
            if key:
                ttk.Button(row, text="Copier", command=lambda: self.copy_field(key)).pack(side="right")
            if secret:
                def toggle():
                    shown.set(not shown.get())
                    lbl.config(text=value if shown.get() else "•" * 12)
                    eye.config(text="Masquer" if shown.get() else "Afficher")
                eye = ttk.Button(row, text="Afficher", command=toggle)
                eye.pack(side="right", padx=4)

        field("Identifiant", e["username"] or "—", "username" if e["username"] else None)
        if e.get("email"):
            field("E-mail", e["email"], "email")
        if e.get("apps"):
            ttk.Label(self.details, text=f"Applis Windows ({autotype.HOTKEY_LABEL})", style="Muted.TLabel").pack(anchor="w")
            for app_exe in e["apps"]:
                row = ttk.Frame(self.details, style="Panel.TFrame")
                row.pack(fill="x", pady=(0, 2))
                ttk.Label(row, text=app_exe, style="Value.TLabel").pack(side="left")
                ttk.Button(row, text="Retirer", command=lambda x=app_exe: self._set_app(e, x, False)).pack(side="right")
            ttk.Frame(self.details, style="Panel.TFrame", height=8).pack()
        field("Mot de passe", e["password"], "password", secret=True)
        bits = estimate_entropy(e["password"])
        text, _ = strength_label(bits)
        ttk.Label(self.details, text=f"Robustesse : {text} (~{int(bits)} bits)", style="Muted.TLabel").pack(
            anchor="w", pady=(0, 6))
        reused = sum(1 for o in self.vault.entries if o["password"] == e["password"]) - 1
        if reused > 0:
            ttk.Label(self.details, text=f"⚠ Mot de passe réutilisé sur {reused} autre(s) entrée(s)",
                      style="Warn.TLabel").pack(anchor="w", pady=(0, 6))
        if e["url"]:
            ttk.Label(self.details, text="Adresse", style="Muted.TLabel").pack(anchor="w")
            row = ttk.Frame(self.details, style="Panel.TFrame")
            row.pack(fill="x", pady=(0, 10))
            ttk.Label(row, text=e["url"], style="Value.TLabel", wraplength=260).pack(side="left", fill="x",
                                                                                      expand=True)
            url = e["url"] if "://" in e["url"] else "https://" + e["url"]
            ttk.Button(row, text="Ouvrir", command=lambda: webbrowser.open(url)).pack(side="right")
        if e["notes"]:
            ttk.Label(self.details, text="Notes", style="Muted.TLabel").pack(anchor="w")
            ttk.Label(self.details, text=e["notes"], style="Value.TLabel", wraplength=320,
                      justify="left").pack(anchor="w", pady=(0, 10))

        btns = ttk.Frame(self.details, style="Panel.TFrame")
        btns.pack(side="bottom", fill="x")
        ttk.Button(btns, text="Modifier", command=self.edit_entry).pack(side="left")
        ttk.Button(btns, text="⌨ Remplir l'appli", command=lambda: self.fill_open_app(e)).pack(side="left", padx=6)
        ttk.Button(btns, text="Supprimer", style="Danger.TButton", command=self.delete_entry).pack(side="right")
        modified = time.strftime("%d/%m/%Y %H:%M", time.localtime(e["modified"]))
        ttk.Label(self.details, text=f"Modifié le {modified}", style="Muted.TLabel").pack(side="bottom", anchor="w",
                                                                                         pady=6)

    # ---------- presse-papiers ----------
    def copy_text(self, text, what="Mot de passe"):
        if not text:
            return
        self.clip.copy(self, text)
        if self._clip_job:
            self.after_cancel(self._clip_job)
        self._clip_job = self.after(CLIPBOARD_CLEAR_SECONDS * 1000, self._clear_clipboard)
        self.set_status(f"{what} copié — effacé du presse-papiers dans {CLIPBOARD_CLEAR_SECONDS} s.")

    def copy_field(self, key):
        e = self._selected()
        if e:
            self.copy_text(e.get(key, ""), {"password": "Mot de passe", "email": "E-mail"}.get(key, "Identifiant"))

    def _clear_clipboard(self):
        self._clip_job = None
        self.clip.clear_if_ours()
        self.set_status("Presse-papiers effacé.")

    # ---------- dialogues ----------
    def _dialog(self, title):
        d = tk.Toplevel(self)
        d.title(title)
        d.configure(bg=PANEL)
        d.transient(self)
        d.resizable(False, False)
        self.dialogs.append(d)
        d.bind("<Destroy>", lambda ev: ev.widget is d and d in self.dialogs and self.dialogs.remove(d))
        d.after(10, d.grab_set)
        return d

    def _busy(self, fn):
        """Les sauvegardes passent par Argon2 (~1 s) : curseur d'attente pendant ce temps."""
        self.config(cursor="watch")
        self.update_idletasks()
        try:
            return fn()
        except VaultError as ex:
            messagebox.showerror("Erreur", str(ex))
        finally:
            self.config(cursor="")

    def open_generator(self):
        d = self._dialog("Générateur de mots de passe")
        GeneratorPanel(d, on_copy=lambda p: self.copy_text(p)).pack(fill="both", expand=True)

    def entry_form(self, entry=None):
        d = self._dialog("Modifier l'entrée" if entry else "Nouvelle entrée")
        f = ttk.Frame(d, style="Panel.TFrame", padding=18)
        f.pack(fill="both", expand=True)
        vars_ = {k: tk.StringVar(value=(entry or {}).get(k, "")) for k in ("site", "username", "email", "password", "url")}

        def label(text):
            ttk.Label(f, text=text, style="Muted.TLabel").pack(anchor="w", pady=(6, 2))

        label("Site / Appli *")
        site_e = ttk.Entry(f, textvariable=vars_["site"], width=48)
        site_e.pack(fill="x")
        site_e.focus_set()
        label("Identifiant / pseudo")
        ttk.Entry(f, textvariable=vars_["username"]).pack(fill="x")
        label("E-mail (si le site demande aussi un e-mail)")
        ttk.Entry(f, textvariable=vars_["email"]).pack(fill="x")
        label("Mot de passe *")
        row = ttk.Frame(f, style="Panel.TFrame")
        row.pack(fill="x")
        pw_e = ttk.Entry(row, textvariable=vars_["password"], show="•", font=("Consolas", 11))
        pw_e.pack(side="left", fill="x", expand=True)

        def toggle():
            pw_e.config(show="" if pw_e.cget("show") else "•")
        ttk.Button(row, text="👁", width=3, command=toggle).pack(side="left", padx=4)

        gen_holder = ttk.Frame(f, style="Panel.TFrame")

        def use(p):
            vars_["password"].set(p)
            gen_holder.pack_forget()
        ttk.Button(row, text="🎲 Générer", command=lambda: gen_holder.pack(fill="x", after=bar)).pack(side="left")
        bar = StrengthBar(f)
        bar.pack(fill="x", pady=(4, 0))
        vars_["password"].trace_add("write", lambda *_: bar.update_for(vars_["password"].get()))
        f.after(50, lambda: bar.update_for(vars_["password"].get()))
        GeneratorPanel(gen_holder, on_use=use).pack(fill="x", pady=6)
        if not entry:
            gen_holder.pack(fill="x", after=bar)

        label("Adresse (URL)")
        ttk.Entry(f, textvariable=vars_["url"]).pack(fill="x")
        label(f"Applis Windows, remplies avec {autotype.HOTKEY_LABEL} (ex. steamwebhelper.exe)")
        apps_var = tk.StringVar(value=", ".join((entry or {}).get("apps", [])))
        ttk.Entry(f, textvariable=apps_var).pack(fill="x")
        label("Notes")
        notes = tk.Text(f, height=4, width=48, bg=BG, fg=FG, insertbackground=FG, relief="flat",
                        font=("Segoe UI", 10), wrap="word")
        notes.pack(fill="x")
        notes.insert("1.0", (entry or {}).get("notes", ""))

        def save(_=None):
            data = {k: v.get().strip() for k, v in vars_.items()}
            data["password"] = vars_["password"].get()  # pas de strip sur un mot de passe
            data["notes"] = notes.get("1.0", "end").strip()
            data["apps"] = [a.strip().lower() for a in apps_var.get().replace(";", ",").split(",") if a.strip()]
            if not data["site"] or not data["password"]:
                messagebox.showwarning("Champs manquants", "Le site et le mot de passe sont obligatoires.", parent=d)
                return
            if entry:
                saved = self._busy(lambda: self.vault.update(entry["id"], **data))
            else:
                saved = self._busy(lambda: self.vault.add(**data))
            if saved:
                d.destroy()
                self.refresh_list(select_id=saved["id"])
                self.show_details()

        btns = ttk.Frame(f, style="Panel.TFrame")
        btns.pack(fill="x", pady=(14, 0))
        ttk.Button(btns, text="Annuler", command=d.destroy).pack(side="right")
        ttk.Button(btns, text="Enregistrer", style="Accent.TButton", command=save).pack(side="right", padx=6)
        d.bind("<Control-s>", save)

    def add_entry(self):
        self.entry_form()

    def edit_entry(self):
        e = self._selected()
        if e:
            self.entry_form(e)

    def delete_entry(self):
        e = self._selected()
        if e and messagebox.askyesno("Supprimer", f"Supprimer définitivement « {e['site']} » ?"):
            self._busy(lambda: self.vault.delete(e["id"]))
            self.refresh_list()
            self.show_details()

    def change_master(self):
        d = self._dialog("Changer le mot de passe maître")
        f = ttk.Frame(d, style="Panel.TFrame", padding=18)
        f.pack(fill="both", expand=True)
        old, new, new2 = tk.StringVar(), tk.StringVar(), tk.StringVar()
        for text, var in (("Mot de passe actuel", old), ("Nouveau mot de passe", new), ("Confirmer", new2)):
            ttk.Label(f, text=text, style="Muted.TLabel").pack(anchor="w", pady=(6, 2))
            ttk.Entry(f, textvariable=var, show="•", width=40).pack(fill="x")
        bar = StrengthBar(f)
        bar.pack(fill="x", pady=6)
        new.trace_add("write", lambda *_: bar.update_for(new.get()))

        def go():
            if len(new.get()) < MIN_MASTER_LENGTH:
                messagebox.showwarning("Trop court", f"Minimum {MIN_MASTER_LENGTH} caractères.", parent=d)
                return
            if new.get() != new2.get():
                messagebox.showwarning("Erreur", "Les nouveaux mots de passe ne correspondent pas.", parent=d)
                return
            if self._busy(lambda: self.vault.change_password(old.get(), new.get()) or True):
                d.destroy()
                messagebox.showinfo("OK", "Mot de passe maître changé.")
        ttk.Button(f, text="Changer", style="Accent.TButton", command=go).pack(anchor="e", pady=(10, 0))

    # ---------- verrouillage : Windows (Win+L, veille) et Windows Hello ----------
    def _session_tick(self):
        now = time.time()
        slept = now - self._last_session_tick > 30  # le minuteur a « sauté » : le PC était en veille
        self._last_session_tick = now
        if self.vault.unlocked and self.settings.get("lock_on_session", True):
            try:
                locked = winsec.session_locked()
            except OSError:
                locked = False
            if slept or locked:
                self.lock()
        self.after(2000, self._session_tick)

    def _check_hello(self):
        threading.Thread(target=lambda: setattr(self, "_hello_state", winsec.hello_availability()),
                         daemon=True).start()

    def _hello_allowed(self):
        return (self.settings.get("hello", False) and self._hello_state == "Available"
                and time.time() - self._master_at < HELLO_MAX_HOURS * 3600)

    def _hello_unlock(self, btn, msg):
        btn.config(state="disabled")
        msg.config(text="Identifie-toi dans la fenêtre Windows Hello…", style="Sub.TLabel")
        result = {}
        worker = threading.Thread(target=lambda: result.update(r=winsec.hello_verify("Déverrouiller CoffreFort")),
                                  daemon=True)
        worker.start()

        def poll():
            if worker.is_alive():
                self.after(150, poll)
                return
            r = result.get("r")
            if r == "Verified" and self.vault.suspended:
                try:
                    self.vault.resume()
                except (VaultError, OSError) as ex:
                    self.vault.forget_suspended()
                    self.show_login()
                    messagebox.showerror("Windows Hello", f"{ex}\nEntre ton mot de passe maître.")
                    return
                self._via_hello = True
                self.show_main()
                return
            if not btn.winfo_exists():
                return
            btn.config(state="normal")
            msg.config(style="Error.TLabel", text={
                "Canceled": "", "DeviceNotPresent": "Lecteur Windows Hello introuvable.",
                "NotConfiguredForUser": "Windows Hello n'est pas configuré sur ce PC.",
                "DisabledByPolicy": "Windows Hello est désactivé sur ce PC.",
                "RetriesExhausted": "Trop d'essais : entre ton mot de passe maître.",
            }.get(r, "Windows Hello n'a pas abouti : entre ton mot de passe maître."))
        poll()

    def lock_dialog(self):
        d = self._dialog("Verrouillage")
        f = ttk.Frame(d, style="Panel.TFrame", padding=20)
        f.pack(fill="both", expand=True)
        ttk.Label(f, text="🔒  Verrouillage", style="Panel.TLabel", font=("Segoe UI Semibold", 15)).pack(anchor="w")
        on_session = tk.BooleanVar(value=self.settings.get("lock_on_session", True))
        hello = tk.BooleanVar(value=self.settings.get("hello", False))
        ttk.Checkbutton(f, text="Verrouiller CoffreFort quand je verrouille Windows (Win+L) ou que le PC se met en veille",
                        variable=on_session).pack(anchor="w", pady=(12, 0))
        ttk.Label(f, text=f"CoffreFort se verrouille aussi après {AUTO_LOCK_SECONDS // 60} minutes sans activité.",
                  style="Muted.TLabel").pack(anchor="w", padx=(22, 0))
        available = self._hello_state == "Available"
        cb = ttk.Checkbutton(f, text="Déverrouiller avec Windows Hello (code PIN, empreinte, visage)", variable=hello)
        cb.pack(anchor="w", pady=(14, 0))
        if not available:
            cb.state(["disabled"])
            hello.set(False)
        ttk.Label(f, text=("Le mot de passe maître reste demandé à chaque démarrage de CoffreFort et au moins toutes les "
                           f"{HELLO_MAX_HOURS} heures. Entre-temps, la clé du coffre reste en mémoire, chiffrée par "
                           "Windows pour CoffreFort seul." if available else
                           "Windows Hello n'est pas configuré sur ce PC (Paramètres → Comptes → Options de connexion)."),
                  style="Muted.TLabel", wraplength=470, justify="left").pack(anchor="w", padx=(22, 0))

        def save():
            self.settings["lock_on_session"] = on_session.get()
            self.settings["hello"] = hello.get()
            backup.save_settings(self.settings)
            d.destroy()
            self.set_status("Réglages de verrouillage enregistrés.")
        btns = ttk.Frame(f, style="Panel.TFrame")
        btns.pack(fill="x", pady=(16, 0))
        ttk.Button(btns, text="Annuler", command=d.destroy).pack(side="right")
        ttk.Button(btns, text="Enregistrer", style="Accent.TButton", command=save).pack(side="right", padx=6)

    # ---------- saisie automatique dans les applis Windows ----------
    BROWSERS = ("chrome.exe", "brave.exe", "opera.exe", "msedge.exe", "firefox.exe", "vivaldi.exe")
    SELECTION_TTL = 120  # s : un compte choisi dans CoffreFort reste « armé » pour Ctrl+Alt+L

    def _autotype_tick(self):
        try:
            while True:
                self._autotype_request(self.hotkey.events.get_nowait())
        except queue.Empty:
            pass
        self.after(100, self._autotype_tick)

    def _apps_of(self, e):
        return [a.lower() for a in e.get("apps", [])]

    def _armed_entry(self):
        """Compte sélectionné récemment dans la liste de CoffreFort, s'il y en a un."""
        e = self._selected() if hasattr(self, "tree") and self.tree.winfo_exists() else None
        if e and time.time() - getattr(self, "_selected_at", 0) < self.SELECTION_TTL:
            return e
        return None

    def _guesses(self, target):
        """Comptes non associés qui ressemblent à l'appli (nom du programme ou titre de la fenêtre)."""
        stem = os.path.splitext(target["exe"])[0].replace("webhelper", "").replace("launcher", "").strip()
        words = {w for w in re.split(r"[^a-z0-9]+", f"{stem} {target['title'].lower()}") if len(w) >= 3}
        out = []
        for e in self.vault.entries:
            hay = f"{e['site']} {e['url']}".lower()
            if any(w in hay for w in words):
                out.append(e)
        return out

    def _autotype_request(self, target):
        if not self.vault.unlocked:
            self._pending_target = (target, time.time())
            self._bring_to_front()
            return
        self.last_activity = time.time()
        if target["pid"] == os.getpid():
            # Ctrl+Alt+L dans CoffreFort : remplir l'appli ouverte qui correspond au compte sélectionné.
            return self.fill_open_app()
        if not target["exe"]:
            return
        matches = [e for e in self.vault.entries if target["exe"] in self._apps_of(e)]
        armed = self._armed_entry()
        if armed:
            self._selected_at = 0  # une seule fois
            # Compte choisi juste avant dans CoffreFort (plusieurs comptes Steam…) : direct s'il va avec
            # cette appli ; sinon on demande, ce compte en tête, pour ne rien taper au mauvais endroit.
            if armed in matches or (not matches and armed in self._guesses(target)):
                return self._autotype(target, armed, remember=not matches)
            return self._autotype_picker(target, matches, preferred=armed)
        if len(matches) == 1:
            return self._autotype(target, matches[0])
        self._autotype_picker(target, matches)

    def _window_for(self, entry):
        """Fenêtre ouverte (la plus en avant) qui correspond au compte."""
        apps = self._apps_of(entry)
        site = entry["site"].lower().strip()

        def match(w):
            if w["pid"] == os.getpid():
                return False
            if w["exe"] in apps:
                return True
            # Pas encore associé : titre de fenêtre contenant le nom du site (hors navigateurs : extension).
            return not apps and len(site) >= 3 and site in w["title"].lower() and w["exe"] not in self.BROWSERS
        wins = autotype.find_windows(match)
        return wins[0] if wins else None

    def fill_open_app(self, entry=None):
        entry = entry or self._selected()
        if not entry:
            self.set_status(f"Sélectionne d'abord un compte, puis {autotype.HOTKEY_LABEL}.")
            return
        target = self._window_for(entry)
        if not target:
            messagebox.showinfo(
                "Remplir une appli",
                f"Aucune fenêtre ouverte ne correspond à « {entry['site']} ».\n\n"
                f"Ouvre la page de connexion de l'appli, clique dans le champ identifiant, puis appuie sur "
                f"{autotype.HOTKEY_LABEL} dans l'appli : ce compte sera proposé en premier.")
            self._selected_at = time.time()
            return
        self._autotype(target, entry, remember=not self._apps_of(entry))

    def _autotype(self, target, entry, password_only=False, remember=False):
        login = entry["username"] or entry.get("email", "")
        if login and not password_only:
            steps = [autotype.SELECT_ALL, login, autotype.TAB, autotype.SELECT_ALL, entry["password"]]
        else:
            steps = [autotype.SELECT_ALL, entry["password"]]
        result = autotype.type_into(target["hwnd"], steps)
        messages = {
            "ok": f"« {entry['site']} » rempli dans {target['exe']}.",
            "focus_lost": "Saisie interrompue : une autre fenêtre est passée au premier plan.",
            "blocked": f"Windows bloque la saisie dans {target['exe']} (appli lancée en administrateur ?).",
            "modifiers": "Saisie annulée : relâche Ctrl et Alt puis recommence.",
            "no_window": "La fenêtre de l'appli a été fermée.",
        }
        self.set_status(messages.get(result, result))
        if result != "ok":
            self._bring_to_front()
            messagebox.showwarning("Remplissage", messages.get(result, result))
        elif remember and target["exe"] and target["exe"] not in self._apps_of(entry):
            self.after(50, lambda: self._set_app(entry, target["exe"], True))  # après la frappe (~1 s)

    def _autotype_picker(self, target, matches, preferred=None):
        if getattr(self, "_picker", None) is not None and self._picker.winfo_exists():
            self._picker.destroy()
        d = tk.Toplevel(self)
        self._picker = d
        self.dialogs.append(d)
        d.bind("<Destroy>", lambda ev: ev.widget is d and d in self.dialogs and self.dialogs.remove(d))
        d.title("CoffreFort — remplir une appli")
        d.configure(bg=PANEL)
        d.resizable(False, False)
        d.attributes("-topmost", True)
        f = ttk.Frame(d, style="Panel.TFrame", padding=16)
        f.pack(fill="both", expand=True)
        exe = target["exe"]
        ttk.Label(f, text=f"Remplir dans « {target['title'] or exe} »", style="Panel.TLabel",
                  font=("Segoe UI Semibold", 13), wraplength=440).pack(anchor="w")
        ttk.Label(f, text=f"Programme : {exe}", style="Muted.TLabel").pack(anchor="w", pady=(0, 8))
        query = tk.StringVar()
        search = ttk.Entry(f, textvariable=query, width=54)
        search.pack(fill="x")
        show_all = tk.BooleanVar(value=False)
        lst = tk.Listbox(f, height=7, bg=BG, fg=FG, selectbackground=ACCENT, relief="flat", activestyle="none",
                         font=("Segoe UI", 10), highlightthickness=0, exportselection=False)
        lst.pack(fill="both", expand=True, pady=(6, 2))
        hint = ttk.Label(f, style="Muted.TLabel", wraplength=440, justify="left")
        hint.pack(anchor="w")
        notes = ttk.Label(f, style="Value.TLabel", wraplength=440, justify="left")
        notes.pack(anchor="w", pady=(6, 4))
        ttk.Checkbutton(f, text="Afficher tous mes comptes", variable=show_all,
                        command=lambda: refresh()).pack(anchor="w")
        remember = tk.BooleanVar(value=not matches)
        ttk.Checkbutton(f, text=f"Associer ce compte à {exe} (proposé directement la prochaine fois)",
                        variable=remember).pack(anchor="w")
        ttk.Label(f, text="Clique d'abord dans le champ identifiant de l'appli. Entrée = remplir.",
                  style="Muted.TLabel").pack(anchor="w", pady=(4, 8))
        shown = []
        guesses = [] if matches else self._guesses(target)

        def refresh(*_):
            q = query.get().strip()
            if q:
                items = self.vault.search(q)  # la recherche porte sur tous les comptes
                hint.config(text="Résultats de la recherche dans tous tes comptes.")
            elif show_all.get():
                items = self.vault.search("")
                hint.config(text="Tous tes comptes.")
            elif matches:
                items = sorted(matches, key=lambda e: e["site"].lower())
                hint.config(text=f"★ Comptes associés à {exe}. Tape pour chercher un autre compte.")
            elif guesses:
                items = guesses
                hint.config(text="Comptes qui semblent correspondre. Tape pour chercher un autre compte.")
            else:
                items = self.vault.search("")
                hint.config(text="Aucun compte associé à cette appli : choisis-le une fois, il sera retenu.")
            if preferred and not q:
                items = [preferred] + [e for e in items if e["id"] != preferred["id"]]
            shown[:] = items
            lst.delete(0, "end")
            for e in items:
                login = e["username"] or e.get("email", "")
                star = "★ " if exe in self._apps_of(e) else "   "
                lst.insert("end", star + e["site"] + (f"  —  {login}" if login else ""))
            if items:
                lst.selection_set(0)
            on_select()

        def current():
            sel = lst.curselection()
            return shown[sel[0]] if sel else None

        def on_select(_=None):
            e = current()
            linked = bool(e) and exe in self._apps_of(e)
            notes.config(text=("📝 " + e["notes"]) if e and e.get("notes") else "")
            forget_btn.config(state="normal" if linked else "disabled")
            remember.set(bool(e) and not linked and not matches)

        def go(password_only=False):
            e = current()
            if not e:
                return
            d.destroy()
            self._autotype(target, e, password_only, remember=remember.get())

        def forget():
            e = current()
            if e and messagebox.askyesno("Retirer l'association",
                                         f"Ne plus proposer « {e['site']} » pour {exe} ?", parent=d):
                self._set_app(e, exe, False)
                if e in matches:
                    matches.remove(e)
                refresh()

        def move(delta):
            sel = lst.curselection()
            i = min(max((sel[0] if sel else 0) + delta, 0), lst.size() - 1)
            lst.selection_clear(0, "end")
            lst.selection_set(i)
            lst.see(i)
            on_select()
            return "break"
        search.bind("<Down>", lambda _: move(1))
        search.bind("<Up>", lambda _: move(-1))
        lst.bind("<<ListboxSelect>>", on_select)
        d.bind("<Return>", lambda _: go())
        d.bind("<Escape>", lambda _: d.destroy())
        lst.bind("<Double-1>", lambda _: go())
        btns = ttk.Frame(f, style="Panel.TFrame")
        btns.pack(fill="x")
        ttk.Button(btns, text="Remplir", style="Accent.TButton", command=go).pack(side="left")
        ttk.Button(btns, text="Mot de passe seul", command=lambda: go(True)).pack(side="left", padx=6)
        forget_btn = ttk.Button(btns, text="Retirer de cette appli", command=forget)
        forget_btn.pack(side="left")
        ttk.Button(btns, text="Annuler", command=d.destroy).pack(side="right")
        query.trace_add("write", refresh)
        refresh()
        d.update_idletasks()
        x, y = self.winfo_pointerxy()
        d.geometry(f"+{max(0, x - d.winfo_width() // 2)}+{max(0, y - 40)}")
        d.lift()
        d.focus_force()
        search.focus_set()

    def _set_app(self, entry, exe, linked):
        apps = [a for a in entry.get("apps", []) if a.lower() != exe.lower()] + ([exe] if linked else [])
        saved = self._busy(lambda: self.vault.update(entry["id"], apps=apps))
        if saved and hasattr(self, "tree") and self.tree.winfo_exists():
            self.refresh_list(select_id=entry["id"])
            self.show_details()
            self.set_status(f"« {entry['site']} » associé à {exe} ({autotype.HOTKEY_LABEL})." if linked
                            else f"« {entry['site']} » n'est plus associé à {exe}.")

    # ---------- mises à jour ----------
    def _update_tick(self):
        fp = program_fingerprint()
        if fp != self._fingerprint and not self.update_ready:
            if fp != self._pending_fp:
                # Fichiers en cours de modification : on attend qu'ils soient stables.
                self._pending_fp, self._pending_since = fp, time.time()
            elif time.time() - self._pending_since >= UPDATE_SETTLE_SECONDS and program_compiles():
                self.update_ready = True
                self.banner.pack(fill="x", side="top", before=self.body)
        # Coffre verrouillé et personne au clavier : on peut redémarrer sans rien perdre.
        if self.update_ready and not self.vault.unlocked and time.time() - self.last_activity > 10:
            if self.restart(auto=True):
                return
        self.after(UPDATE_CHECK_MS, self._update_tick)

    def _online_check(self):
        # Les fichiers téléchargés sont repérés par _update_tick (bandeau ou redémarrage auto).
        threading.Thread(target=startup_update_quiet, daemon=True).start()
        self.after(ONLINE_CHECK_MS, self._online_check)

    def restart(self, auto=False):
        if not program_compiles():
            if not auto:
                messagebox.showerror("Mise à jour", "La mise à jour semble incomplète, réessaie dans un instant.")
            return False
        if not auto and self.dialogs and not messagebox.askyesno(
                "Redémarrer", "Des fenêtres sont ouvertes : les modifications non enregistrées seront perdues.\n"
                              "Redémarrer quand même ?"):
            return False
        if self.bridge:
            self.bridge.close()
        if self.hotkey:
            self.hotkey.stop()
        self.clip.clear_if_ours()
        self.vault.lock()
        flags = subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP if sys.platform == "win32" else 0
        subprocess.Popen([sys.executable, os.path.join(HERE, "app.pyw"), "--restart"], cwd=HERE,
                         creationflags=flags, close_fds=True)
        self.destroy()
        return True

    def _expected_extension_version(self):
        try:
            with open(os.path.join(HERE, "extension", "manifest.json"), encoding="utf-8") as f:
                return json.load(f).get("version")
        except (OSError, ValueError):
            return None

    # ---------- sauvegarde cloud ----------
    def _auto_backup(self):
        folder = self.settings.get("backup_dir")
        if not folder or not self.vault.exists:
            return
        try:
            self.settings["last_backup"] = backup.run_backup(self.vault.path, folder)
            backup.save_settings(self.settings)
            self._backup_error = None
        except OSError as ex:
            self._backup_error = str(ex)
            # La création du coffre tourne dans un thread : on ne touche à l'interface que depuis le principal.
            if threading.current_thread() is threading.main_thread():
                self.set_status(f"⚠ Sauvegarde cloud échouée : {ex}")

    def update_dialog(self):
        d = self._dialog("Mises à jour")
        f = ttk.Frame(d, style="Panel.TFrame", padding=20)
        f.pack(fill="both", expand=True)
        ttk.Label(f, text="🔄  Mises à jour", style="Panel.TLabel", font=("Segoe UI Semibold", 15)).pack(anchor="w")
        ttk.Label(f, text="CoffreFort installe tout seul les nouvelles versions à chaque lancement,\n"
                          "après avoir vérifié leur signature. Tes mots de passe ne sont jamais envoyés.",
                  style="Panel.TLabel", justify="left").pack(anchor="w", pady=(6, 12))
        version_lbl = ttk.Label(f, style="Value.TLabel")
        version_lbl.pack(anchor="w")
        info = ttk.Label(f, style="Muted.TLabel", justify="left", wraplength=480)
        info.pack(anchor="w", pady=(4, 12))
        version_lbl.config(text=f"Version installée : {updater.current_version()}")
        if LAST_UPDATE_ERROR:
            info.config(text=f"⚠ Dernière vérification échouée : {LAST_UPDATE_ERROR}")
        btns = ttk.Frame(f, style="Panel.TFrame")
        btns.pack(fill="x")
        restart_btn = ttk.Button(btns, text="Redémarrer maintenant", style="Accent.TButton", command=self.restart)

        def check():
            check_btn.config(state="disabled")
            info.config(text="Recherche en cours…")
            worker = threading.Thread(target=lambda: result.update(version=startup_update_quiet()), daemon=True)
            result = {}
            worker.start()

            def poll():
                if worker.is_alive():
                    d.after(200, poll)
                    return
                if not d.winfo_exists():
                    return
                check_btn.config(state="normal")
                version_lbl.config(text=f"Version installée : {updater.current_version()}")
                if result.get("version"):
                    info.config(text=f"✔ Version {result['version']} installée. Redémarre CoffreFort pour l'utiliser.")
                    restart_btn.pack(side="left", padx=(8, 0))
                elif LAST_UPDATE_ERROR:
                    info.config(text=f"⚠ Vérification impossible : {LAST_UPDATE_ERROR}")
                else:
                    info.config(text="✔ CoffreFort est à jour.\n(Une version publiée il y a moins de 5 minutes peut ne pas être encore visible.)")
            poll()
        check_btn = ttk.Button(btns, text="Vérifier maintenant", command=check)
        check_btn.pack(side="left")
        ttk.Button(btns, text="Fermer", command=d.destroy).pack(side="right")

    def backup_dialog(self):
        d = self._dialog("Sauvegarde automatique")
        f = ttk.Frame(d, style="Panel.TFrame", padding=20)
        f.pack(fill="both", expand=True)
        ttk.Label(f, text="☁  Sauvegarde automatique", style="Panel.TLabel",
                  font=("Segoe UI Semibold", 15)).pack(anchor="w")
        ttk.Label(f, text="À chaque modification, le coffre (déjà chiffré) est copié dans ce dossier,\n"
                          "avec une version par jour sur 30 jours et le programme pour tout réinstaller.\n"
                          "Choisis un dossier synchronisé par MEGA pour l'avoir dans le cloud.",
                  style="Panel.TLabel", justify="left").pack(anchor="w", pady=(6, 12))
        folder_lbl = ttk.Label(f, style="Value.TLabel", wraplength=480)
        folder_lbl.pack(anchor="w")
        info = ttk.Label(f, style="Muted.TLabel", justify="left")
        info.pack(anchor="w", pady=(4, 12))

        def refresh():
            folder = self.settings.get("backup_dir")
            folder_lbl.config(text=folder or "Désactivée")
            last = self.settings.get("last_backup") or 0
            text = ("Dernière sauvegarde : " + time.strftime("%d/%m/%Y %H:%M:%S", time.localtime(last))) if last else \
                "Aucune sauvegarde pour l'instant."
            if self._backup_error:
                text += f"\n⚠ Dernière tentative échouée : {self._backup_error}"
            info.config(text=text)

        def choose():
            start = self.settings.get("backup_dir") or backup.suggest_folder() or os.path.expanduser("~")
            folder = filedialog.askdirectory(parent=d, initialdir=os.path.dirname(start) if not os.path.isdir(start) else start,
                                             title="Dossier de sauvegarde (synchronisé par MEGA)")
            if folder:
                self.settings["backup_dir"] = os.path.normpath(folder)
                backup.save_settings(self.settings)
                self._auto_backup()
                refresh()

        def disable():
            if messagebox.askyesno("Désactiver", "Désactiver la sauvegarde automatique ?", parent=d):
                self.settings["backup_dir"] = ""
                backup.save_settings(self.settings)
                refresh()

        def now():
            self._auto_backup()
            refresh()
            if not self._backup_error:
                messagebox.showinfo("Sauvegarde", "Sauvegarde effectuée.", parent=d)

        def open_folder():
            folder = self.settings.get("backup_dir")
            if folder and os.path.isdir(folder):
                os.startfile(folder)

        btns = ttk.Frame(f, style="Panel.TFrame")
        btns.pack(fill="x")
        ttk.Button(btns, text="Sauvegarder maintenant", style="Accent.TButton", command=now).pack(side="left")
        ttk.Button(btns, text="Changer de dossier…", command=choose).pack(side="left", padx=6)
        ttk.Button(btns, text="Ouvrir", command=open_folder).pack(side="left")
        ttk.Button(btns, text="Désactiver", command=disable).pack(side="right")
        refresh()

    def restore_backup(self):
        source = filedialog.askopenfilename(
            title="Choisir une sauvegarde de coffre", initialdir=self.settings.get("backup_dir") or os.path.expanduser("~"),
            filetypes=[("Coffre CoffreFort", "*.vault"), ("Tous les fichiers", "*.*")])
        if not source:
            return
        try:
            backup.restore_file(source, self.vault.path)
        except (OSError, ValueError) as ex:
            messagebox.showerror("Restauration impossible", str(ex))
            return
        messagebox.showinfo("Coffre restauré", "Sauvegarde restaurée. Ouvre-la avec ton mot de passe maître\n"
                                               "(ou « Mot de passe oublié ? » avec ta clé de secours).")
        self.show_login()

    # ---------- extension navigateur ----------
    def _bridge_tick(self):
        if self.bridge:
            try:
                while True:
                    req, box, done = self.bridge.requests.get_nowait()

                    def respond(reply, box=box, done=done):
                        box["reply"] = reply
                        done.set()
                    try:
                        reply = self._bridge_request(req, respond)
                    except Exception as ex:  # noqa: BLE001
                        reply = {"error": "internal", "message": str(ex)}
                    if reply is not None:
                        respond(reply)
            except queue.Empty:
                pass
        self.after(100, self._bridge_tick)

    def _bring_to_front(self):
        self.deiconify()
        self.lift()
        self.attributes("-topmost", True)
        self.after(300, lambda: self.attributes("-topmost", False))
        self.focus_force()

    def _is_paired(self, token):
        return isinstance(token, str) and any(p["hash"] == bridge.token_hash(token) for p in self.vault.paired)

    def _bridge_request(self, req, respond):
        """Renvoie la réponse, ou None si elle viendra plus tard via respond()."""
        kind = req.get("type")
        if kind == "focus":
            self._bring_to_front()
            return {"ok": True}
        if kind == "status":
            return {"ok": True, "unlocked": self.vault.unlocked,
                    "paired": self.vault.unlocked and self._is_paired(req.get("token")),
                    "extension_version": self._expected_extension_version(),
                    "extension_dir": os.path.join(HERE, "extension")}
        if not self.vault.unlocked:
            self._bring_to_front()
            return {"error": "locked"}
        if kind == "pair":
            return self._pair_request(req, respond)
        if not self._is_paired(req.get("token")):
            return {"error": "not_paired"}

        host = bridge.page_host(req.get("url"))
        if not host:
            return {"error": "bad_url"}
        matches = [e for e in self.vault.entries if bridge.entry_matches(e, host)]
        if kind == "list":
            return {"ok": True, "host": host,
                    "entries": [{"id": e["id"], "site": e["site"], "username": e["username"],
                                 "email": e.get("email", "")} for e in matches]}
        if kind == "fill":
            e = next((e for e in matches if e["id"] == req.get("id")), None)
            if e is None:
                return {"error": "no_match"}
            self.set_status(f"Identifiants « {e['site']} » envoyés au navigateur ({host}).")
            return {"ok": True, "host": host, "username": e["username"], "email": e.get("email", ""),
                    "password": e["password"]}
        if kind == "create":
            username = str(req.get("username", ""))[:200]
            email = str(req.get("email", ""))[:200]
            try:
                length = min(max(int(req.get("length", 24)), 12), 64)
            except (TypeError, ValueError):
                length = 24
            password = generate_password(length)
            entry = self.vault.add(site=host, username=username, email=email, password=password, url="https://" + host)
            if hasattr(self, "tree") and self.tree.winfo_exists():
                self.refresh_list(select_id=entry["id"])
                self.show_details()
            self.set_status(f"Nouveau compte enregistré depuis le navigateur : {host}")
            return {"ok": True, "host": host, "username": username, "email": email, "password": password}
        return {"error": "unknown"}

    def _pair_request(self, req, respond):
        token = req.get("token")
        if not isinstance(token, str) or len(token) < 32:
            return {"error": "bad_token"}
        if self._is_paired(token):
            return {"ok": True}
        if self._pair_dialog is not None:
            return {"error": "busy"}
        name = str(req.get("name", "Navigateur"))[:60]
        self._bring_to_front()
        d = self._dialog("Associer une extension")
        self._pair_dialog = d
        answered = {"done": False}

        def finish(accept):
            if answered["done"]:
                return
            answered["done"] = True
            if accept:
                self.vault.paired.append({"hash": bridge.token_hash(token), "name": name, "date": time.time()})
                self._busy(self.vault.save)
                self.set_status(f"Extension associée : {name}")
            respond({"ok": True} if accept else {"error": "denied"})
            if d.winfo_exists():
                d.destroy()

        def on_destroy(ev):
            if ev.widget is d:
                self._pair_dialog = None
                finish(False)

        d.bind("<Destroy>", on_destroy, add="+")
        d.protocol("WM_DELETE_WINDOW", lambda: finish(False))
        f = ttk.Frame(d, style="Panel.TFrame", padding=22)
        f.pack(fill="both", expand=True)
        ttk.Label(f, text="🧩  Associer une extension", style="Panel.TLabel",
                  font=("Segoe UI Semibold", 15)).pack(anchor="w")
        ttk.Label(f, text=f"L'extension CoffreFort de « {name} » demande l'accès à ton coffre.\n"
                          "Vérifie que ce code est bien affiché dans l'extension :",
                  style="Panel.TLabel", justify="left").pack(anchor="w", pady=(6, 10))
        ttk.Label(f, text=bridge.pairing_code(token), style="Code.TLabel").pack(pady=4)
        ttk.Label(f, text="Si tu n'as rien demandé, refuse.", style="Muted.TLabel").pack(anchor="w", pady=(10, 0))
        btns = ttk.Frame(f, style="Panel.TFrame")
        btns.pack(fill="x", pady=(14, 0))
        ttk.Button(btns, text="Associer", style="Accent.TButton", command=lambda: finish(True)).pack(side="right")
        ttk.Button(btns, text="Refuser", command=lambda: finish(False)).pack(side="right", padx=6)
        return None

    def manage_extensions(self):
        d = self._dialog("Extensions navigateur")
        f = ttk.Frame(d, style="Panel.TFrame", padding=20)
        f.pack(fill="both", expand=True)
        ttk.Label(f, text="🧩  Extensions associées", style="Panel.TLabel",
                  font=("Segoe UI Semibold", 15)).pack(anchor="w", pady=(0, 10))
        if not self.vault.paired:
            ttk.Label(f, text="Aucune extension associée.\n\n"
                              "Installation : lance « Installer extension.bat », puis charge le dossier\n"
                              "« extension » dans brave://extensions, opera://extensions ou chrome://extensions\n"
                              "(mode développeur → Charger l'extension non empaquetée).",
                      style="Panel.TLabel", justify="left").pack(anchor="w")
        for p in list(self.vault.paired):
            row = ttk.Frame(f, style="Panel.TFrame")
            row.pack(fill="x", pady=3)
            when = time.strftime("%d/%m/%Y", time.localtime(p["date"]))
            ttk.Label(row, text=f"{p['name']}  ·  associée le {when}", style="Panel.TLabel").pack(side="left")

            def revoke(p=p):
                if messagebox.askyesno("Révoquer", f"Retirer l'accès de « {p['name']} » ?", parent=d):
                    self.vault.paired.remove(p)
                    self._busy(self.vault.save)
                    d.destroy()
                    self.manage_extensions()
            ttk.Button(row, text="Révoquer", style="Danger.TButton", command=revoke).pack(side="right", padx=(20, 0))
        if self.bridge is None:
            ttk.Label(f, text="⚠ Le pont navigateur n'a pas pu démarrer.", style="Warn.TLabel").pack(anchor="w", pady=8)

    # ---------- verrouillage ----------
    def _touch(self, _=None):
        self.last_activity = time.time()

    def _auto_lock_tick(self):
        if self.vault.unlocked and time.time() - self.last_activity > AUTO_LOCK_SECONDS:
            self.lock()
        self.after(5000, self._auto_lock_tick)

    def lock(self):
        for d in list(self.dialogs):
            d.destroy()
        if self._clip_job:
            self.after_cancel(self._clip_job)
            self._clip_job = None
        self.clip.clear_if_ours()
        if self.vault.unlocked and self._hello_allowed():
            self.vault.suspend()  # Windows Hello pourra rouvrir sans le mot de passe maître
        else:
            self.vault.lock()
        self.current = None
        self.show_login()

    def _quit(self):
        if self.bridge:
            self.bridge.close()
        if self.hotkey:
            self.hotkey.stop()
        self.clip.clear_if_ours()
        self.vault.lock()
        self.destroy()


if __name__ == "__main__":
    if "--restart" in sys.argv:
        # Redémarrage après mise à jour : on attend que l'ancienne instance ait libéré la place.
        deadline = time.time() + 10
        while bridge.ping_existing() and time.time() < deadline:
            time.sleep(0.2)
    elif bridge.ping_existing():
        sys.exit(0)  # déjà ouvert : l'instance existante passe au premier plan
    elif startup_update():
        # Nouvelle version installée : on relance sur les nouveaux fichiers.
        subprocess.Popen([sys.executable, os.path.join(HERE, "app.pyw"), "--restart"], cwd=HERE)
        sys.exit(0)
    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(1)  # texte net sur écrans HiDPI
    except Exception:  # noqa: BLE001
        pass
    App().mainloop()
