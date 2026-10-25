# Installe Python (si besoin) et les bibliothèques de CoffreFort, puis lance installer.py.
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [Text.Encoding]::UTF8

function Find-Python {
    $cands = @()
    if (Get-Command py -ErrorAction SilentlyContinue) {
        try { $cands += (& py -3 -c "import sys; print(sys.executable)" 2>$null) } catch {}
    }
    $cands += Get-ChildItem "$env:LOCALAPPDATA\Programs\Python\Python3*\python.exe", "$env:ProgramFiles\Python3*\python.exe" -ErrorAction SilentlyContinue |
        Sort-Object FullName -Descending | ForEach-Object FullName
    foreach ($c in $cands) {
        # Le « python » du Microsoft Store (WindowsApps) n'est qu'un raccourci vers le Store : ignoré.
        if ($c -and (Test-Path $c) -and ($c -notlike '*WindowsApps*')) {
            $ok = & $c -c "import sys; print(sys.version_info >= (3, 10))" 2>$null
            if ($ok -eq 'True') { return $c }
        }
    }
    return $null
}

Write-Host "=== Installation de CoffreFort ===`n"
$python = Find-Python
if (-not $python) {
    if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
        Write-Host "Python est nécessaire. Installe-le depuis https://www.python.org/downloads/ puis relance ce fichier."
        exit 1
    }
    Write-Host "Installation de Python 3.12 (une seule fois, environ 1 minute)..."
    winget install --id Python.Python.3.12 -e --scope user --silent --accept-package-agreements --accept-source-agreements
    $python = Find-Python
    if (-not $python) { Write-Host "L'installation de Python a échoué. Installe-le depuis https://www.python.org/downloads/ puis relance."; exit 1 }
}
Write-Host "Python : $python`n"

Write-Host "Installation des bibliothèques de chiffrement..."
& $python -m pip install --disable-pip-version-check --quiet --upgrade cryptography argon2-cffi
if ($LASTEXITCODE -ne 0) { Write-Host "Échec de l'installation des bibliothèques (connexion Internet ?)."; exit 1 }

& $python "$PSScriptRoot\installer.py"
exit $LASTEXITCODE
