"""Fonctions Windows pour le verrouillage : session verrouillée, mémoire protégée, Windows Hello."""

import ctypes
import os
import subprocess
from ctypes import wintypes

user32 = ctypes.WinDLL("user32", use_last_error=True)
crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
user32.OpenInputDesktop.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
user32.OpenInputDesktop.restype = wintypes.HANDLE
user32.GetUserObjectInformationW.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD,
                                             ctypes.POINTER(wintypes.DWORD)]
user32.CloseDesktop.argtypes = [wintypes.HANDLE]
crypt32.CryptProtectMemory.argtypes = [ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD]
crypt32.CryptUnprotectMemory.argtypes = [ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD]

wtsapi32 = ctypes.WinDLL("wtsapi32", use_last_error=True)
wtsapi32.WTSQuerySessionInformationW.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.c_int,
                                                 ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(wintypes.DWORD)]
wtsapi32.WTSFreeMemory.argtypes = [ctypes.c_void_p]
WTS_CURRENT_SESSION = 0xFFFFFFFF
WTS_SESSION_INFO_EX = 25
WTS_SESSIONSTATE_LOCK = 0

DESKTOP_READOBJECTS = 0x0001
UOI_NAME = 2
CRYPTPROTECTMEMORY_SAME_PROCESS = 0
CREATE_NO_WINDOW = 0x08000000


def session_locked() -> bool:
    """Vrai quand l'écran de verrouillage Windows (Win+L) est affiché."""
    buf, size = ctypes.c_void_p(), wintypes.DWORD()
    if wtsapi32.WTSQuerySessionInformationW(None, WTS_CURRENT_SESSION, WTS_SESSION_INFO_EX,
                                            ctypes.byref(buf), ctypes.byref(size)):
        try:
            # WTSINFOEXW : Level, (alignement), SessionId, SessionState, SessionFlags (0 = verrouillée).
            return ctypes.c_long.from_address(buf.value + 16).value == WTS_SESSIONSTATE_LOCK
        finally:
            wtsapi32.WTSFreeMemory(buf)
    # Repli : le bureau sécurisé refuse l'accès (mais il s'affiche aussi pour les invites UAC).
    desk = user32.OpenInputDesktop(0, False, DESKTOP_READOBJECTS)
    if not desk:
        return True  # le bureau sécurisé (verrouillage, UAC) refuse l'accès
    try:
        buf = ctypes.create_unicode_buffer(256)
        needed = wintypes.DWORD()
        if not user32.GetUserObjectInformationW(desk, UOI_NAME, buf, ctypes.sizeof(buf), ctypes.byref(needed)):
            return False
        return buf.value.lower() != "default"
    finally:
        user32.CloseDesktop(desk)


def _memory(buf: bytearray, fn):
    if len(buf) % 16:
        raise ValueError("taille non multiple de 16")
    c = (ctypes.c_char * len(buf)).from_buffer(buf)
    if not fn(c, len(buf), CRYPTPROTECTMEMORY_SAME_PROCESS):
        raise OSError(ctypes.get_last_error(), "CryptProtectMemory")


def protect_memory(buf: bytearray):
    """Chiffre `buf` sur place : seul CE processus pourra le déchiffrer (clé gardée par Windows)."""
    _memory(buf, crypt32.CryptProtectMemory)


def unprotect_memory(buf: bytearray):
    _memory(buf, crypt32.CryptUnprotectMemory)


class _Blob(ctypes.Structure):
    _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]


crypt32.CryptProtectData.argtypes = [ctypes.POINTER(_Blob), wintypes.LPCWSTR, ctypes.POINTER(_Blob), ctypes.c_void_p,
                                     ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(_Blob)]
crypt32.CryptUnprotectData.argtypes = [ctypes.POINTER(_Blob), ctypes.c_void_p, ctypes.POINTER(_Blob), ctypes.c_void_p,
                                       ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(_Blob)]
kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
kernel32.LocalFree.argtypes = [ctypes.c_void_p]
CRYPTPROTECT_UI_FORBIDDEN = 0x1


def _dpapi(fn, data: bytes, *extra) -> bytes:
    buf = ctypes.create_string_buffer(data, len(data))
    src, out = _Blob(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char))), _Blob()
    if not fn(ctypes.byref(src), *extra, None, None, None, CRYPTPROTECT_UI_FORBIDDEN, ctypes.byref(out)):
        raise OSError(ctypes.get_last_error(), fn.__name__)
    try:
        return ctypes.string_at(out.pbData, out.cbData)
    finally:
        kernel32.LocalFree(out.pbData)


def protect_data(data: bytes) -> bytes:
    """Chiffre pour le stockage : seul ce compte Windows, sur ce PC, pourra le relire (DPAPI)."""
    return _dpapi(crypt32.CryptProtectData, data, "CoffreFort")


def unprotect_data(data: bytes) -> bytes:
    return _dpapi(crypt32.CryptUnprotectData, data, None)


# Windows Hello via WinRT (UserConsentVerifier), appelé par PowerShell : aucune bibliothèque à installer.
_HELLO_PS = r'''
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Runtime.WindowsRuntime
$asTask = [System.WindowsRuntimeSystemExtensions].GetMethods() | Where-Object {
  $_.Name -eq 'AsTask' -and $_.GetParameters().Count -eq 1 -and $_.GetParameters()[0].ParameterType.Name -eq 'IAsyncOperation`1' } | Select-Object -First 1
function Await($op, $type) { $t = $asTask.MakeGenericMethod($type).Invoke($null, @($op)); $t.Wait(-1) | Out-Null; $t.Result }
$V = [Windows.Security.Credentials.UI.UserConsentVerifier, Windows.Security.Credentials.UI, ContentType = WindowsRuntime]
$avail = Await ($V::CheckAvailabilityAsync()) ([Windows.Security.Credentials.UI.UserConsentVerifierAvailability])
if ("$avail" -ne 'Available' -or $env:CF_MODE -eq 'check') { Write-Output "RESULT:$avail"; exit }
$r = Await ($V::RequestVerificationAsync($env:CF_MESSAGE)) ([Windows.Security.Credentials.UI.UserConsentVerificationResult])
Write-Output "RESULT:$r"
'''


def _hello(mode, message="", timeout=120):
    env = dict(os.environ, CF_MODE=mode, CF_MESSAGE=message)
    try:
        out = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
                              "-Command", _HELLO_PS], capture_output=True, text=True, timeout=timeout, env=env,
                             creationflags=CREATE_NO_WINDOW).stdout
    except (OSError, subprocess.TimeoutExpired):
        return "Error"
    lines = [line for line in out.splitlines() if line.startswith("RESULT:")]
    return lines[-1][7:].strip() if lines else "Error"


def hello_availability() -> str:
    """« Available » si Windows Hello (code PIN, empreinte, visage) est configuré."""
    return _hello("check", timeout=30)


def hello_verify(message: str) -> str:
    """Affiche la fenêtre Windows Hello. « Verified » si l'utilisateur s'est identifié."""
    return _hello("verify", message)
