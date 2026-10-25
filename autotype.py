"""Saisie automatique dans les applis Windows (Steam, Battle.net, Epic, Riot…).

Raccourci global Ctrl+Alt+L : CoffreFort note la fenêtre au premier plan, puis tape
l'identifiant, Tab et le mot de passe dans CETTE fenêtre uniquement. La frappe
s'arrête net si une autre fenêtre passe au premier plan entre-temps.
"""

import ctypes
import os
import queue
import threading
import time
from ctypes import wintypes

HOTKEY_LABEL = "Ctrl+Alt+L"
HOTKEY_ID = 0xC0F
MOD_ALT, MOD_CONTROL, MOD_NOREPEAT = 0x0001, 0x0002, 0x4000
VK_L = 0x4C
WM_HOTKEY, WM_QUIT = 0x0312, 0x0012
INPUT_KEYBOARD = 1
KEYEVENTF_KEYUP, KEYEVENTF_UNICODE = 0x0002, 0x0004
VK_TAB = 0x09
MODIFIER_KEYS = (0x10, 0x11, 0x12, 0x5B, 0x5C)  # Maj, Ctrl, Alt, Windows gauche/droite
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000

user32 = ctypes.WinDLL("user32", use_last_error=True)
kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)


class KEYBDINPUT(ctypes.Structure):
    _fields_ = [("wVk", wintypes.WORD), ("wScan", wintypes.WORD), ("dwFlags", wintypes.DWORD),
                ("time", wintypes.DWORD), ("dwExtraInfo", ctypes.c_size_t)]


class MOUSEINPUT(ctypes.Structure):  # seulement pour donner sa vraie taille à INPUT
    _fields_ = [("dx", wintypes.LONG), ("dy", wintypes.LONG), ("mouseData", wintypes.DWORD),
                ("dwFlags", wintypes.DWORD), ("time", wintypes.DWORD), ("dwExtraInfo", ctypes.c_size_t)]


class INPUT(ctypes.Structure):
    class _U(ctypes.Union):
        _fields_ = [("ki", KEYBDINPUT), ("mi", MOUSEINPUT)]
    _anonymous_ = ("u",)
    _fields_ = [("type", wintypes.DWORD), ("u", _U)]


user32.RegisterHotKey.argtypes = [wintypes.HWND, ctypes.c_int, wintypes.UINT, wintypes.UINT]
user32.UnregisterHotKey.argtypes = [wintypes.HWND, ctypes.c_int]
user32.GetMessageW.argtypes = [ctypes.POINTER(wintypes.MSG), wintypes.HWND, wintypes.UINT, wintypes.UINT]
user32.PostThreadMessageW.argtypes = [wintypes.DWORD, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]
user32.GetForegroundWindow.restype = wintypes.HWND
user32.SetForegroundWindow.argtypes = [wintypes.HWND]
user32.GetWindowTextW.argtypes = [wintypes.HWND, wintypes.LPWSTR, ctypes.c_int]
user32.GetWindowThreadProcessId.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.DWORD)]
user32.IsWindow.argtypes = [wintypes.HWND]
user32.SendInput.argtypes = [wintypes.UINT, ctypes.POINTER(INPUT), ctypes.c_int]
user32.GetAsyncKeyState.argtypes = [ctypes.c_int]
user32.GetAsyncKeyState.restype = ctypes.c_short
kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
kernel32.OpenProcess.restype = wintypes.HANDLE
kernel32.QueryFullProcessImageNameW.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR,
                                                ctypes.POINTER(wintypes.DWORD)]
kernel32.CloseHandle.argtypes = [wintypes.HANDLE]


def window_info(hwnd):
    """{hwnd, title, exe (ex. « steam.exe »), pid} d'une fenêtre."""
    buf = ctypes.create_unicode_buffer(512)
    user32.GetWindowTextW(hwnd, buf, 512)
    pid = wintypes.DWORD()
    user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
    exe = ""
    h = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid.value)
    if h:
        path = ctypes.create_unicode_buffer(1024)
        size = wintypes.DWORD(1024)
        if kernel32.QueryFullProcessImageNameW(h, 0, path, ctypes.byref(size)):
            exe = os.path.basename(path.value).lower()
        kernel32.CloseHandle(h)
    return {"hwnd": hwnd, "title": buf.value, "exe": exe, "pid": pid.value}


def foreground_info():
    hwnd = user32.GetForegroundWindow()
    return window_info(hwnd) if hwnd else None


class HotkeyListener:
    """Écoute le raccourci global dans un thread ; chaque appui dépose la fenêtre active dans `events`."""

    def __init__(self, vk=VK_L, mods=MOD_CONTROL | MOD_ALT):
        self.vk, self.mods = vk, mods
        self.events = queue.Queue()
        self._tid = None
        self._ready = threading.Event()
        self.ok = False

    def start(self) -> bool:
        threading.Thread(target=self._run, daemon=True).start()
        self._ready.wait(5)
        return self.ok

    def _run(self):
        self._tid = kernel32.GetCurrentThreadId()
        for _ in range(10):  # après un redémarrage, l'ancienne instance peut le tenir encore un instant
            self.ok = bool(user32.RegisterHotKey(None, HOTKEY_ID, self.mods | MOD_NOREPEAT, self.vk))
            if self.ok:
                break
            time.sleep(0.3)
        self._ready.set()
        if not self.ok:
            return  # raccourci déjà pris par une autre appli
        msg = wintypes.MSG()
        while user32.GetMessageW(ctypes.byref(msg), None, 0, 0) > 0:
            if msg.message == WM_HOTKEY and msg.wParam == HOTKEY_ID:
                info = foreground_info()  # tout de suite, avant que le focus ne bouge
                if info:
                    self.events.put(info)
        user32.UnregisterHotKey(None, HOTKEY_ID)

    def stop(self):
        if self._tid:
            user32.PostThreadMessageW(self._tid, WM_QUIT, 0, 0)


def _key(vk=0, scan=0, flags=0):
    i = INPUT(type=INPUT_KEYBOARD)
    i.ki = KEYBDINPUT(vk, scan, flags, 0, 0)
    return i


def _send(inputs):
    arr = (INPUT * len(inputs))(*inputs)
    return user32.SendInput(len(inputs), arr, ctypes.sizeof(INPUT)) == len(inputs)


def wait_modifiers_released(timeout=3.0):
    """Ctrl/Alt encore enfoncés transformeraient chaque lettre en raccourci."""
    end = time.time() + timeout
    while time.time() < end:
        if not any(user32.GetAsyncKeyState(vk) & 0x8000 for vk in MODIFIER_KEYS):
            return True
        time.sleep(0.02)
    return False


def focus(hwnd, timeout=1.0):
    if user32.GetForegroundWindow() == hwnd:
        return True
    user32.SetForegroundWindow(hwnd)
    end = time.time() + timeout
    while time.time() < end:
        if user32.GetForegroundWindow() == hwnd:
            time.sleep(0.15)  # le temps que l'appli rende le focus à son champ
            return True
        time.sleep(0.02)
    return False


def type_into(hwnd, steps, delay=0.008):
    """Tape `steps` (texte, ou "\\t" pour Tab) dans la fenêtre hwnd.
    Renvoie "ok", "no_window", "modifiers", "focus_lost" ou "blocked"."""
    if not user32.IsWindow(hwnd):
        return "no_window"
    if not wait_modifiers_released():
        return "modifiers"
    if not focus(hwnd):
        return "focus_lost"
    for step in steps:
        if step == "\t":
            units = None
        else:
            data = step.encode("utf-16-le")
            units = [int.from_bytes(data[i:i + 2], "little") for i in range(0, len(data), 2)]
        for unit in (units if units is not None else [None]):
            if user32.GetForegroundWindow() != hwnd:
                return "focus_lost"  # l'utilisateur a changé de fenêtre : on n'écrit pas ailleurs
            if unit is None:
                ok = _send([_key(vk=VK_TAB), _key(vk=VK_TAB, flags=KEYEVENTF_KEYUP)])
            else:
                ok = _send([_key(scan=unit, flags=KEYEVENTF_UNICODE),
                            _key(scan=unit, flags=KEYEVENTF_UNICODE | KEYEVENTF_KEYUP)])
            if not ok:
                return "blocked"  # appli lancée en administrateur : Windows bloque la frappe
            time.sleep(delay)
        if step == "\t":
            time.sleep(0.12)  # laisser le champ suivant prendre le focus
    return "ok"
