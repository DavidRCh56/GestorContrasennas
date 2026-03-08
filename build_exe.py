"""
Script para compilar el Gestor de Contraseñas como ejecutable (.exe).
Ejecutar con: python build_exe.py
"""

import subprocess
import sys
import os

def main():
    print("=" * 50)
    print("  Compilando Gestor de Contraseñas Seguro")
    print("=" * 50)

    # Verificar PyInstaller
    try:
        import PyInstaller
        print(f"[OK] PyInstaller {PyInstaller.__version__} encontrado")
    except ImportError:
        print("[!] PyInstaller no está instalado. Instalando...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "pyinstaller"])
        print("[OK] PyInstaller instalado")

    script_dir = os.path.dirname(os.path.abspath(__file__))
    main_script = os.path.join(script_dir, "generador_contraseñas.py")

    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--noconfirm",
        "--onefile",                    # Un solo .exe
        "--windowed",                   # Sin consola (app GUI)
        "--name", "GestorContraseñas",  # Nombre del .exe
        "--add-data", f"{os.path.join(script_dir, 'crypto_vault.py')};.",
        "--add-data", f"{os.path.join(script_dir, 'password_engine.py')};.",
        "--add-data", f"{os.path.join(script_dir, 'ui_engine.py')};.",
        "--add-data", f"{os.path.join(script_dir, 'icon.png')};.",
        "--icon", os.path.join(script_dir, "icon.ico"),
        "--hidden-import", "cryptography",
        "--hidden-import", "cryptography.hazmat.primitives.ciphers.aead",
        "--hidden-import", "cryptography.hazmat.primitives.kdf.pbkdf2",
        "--hidden-import", "cryptography.hazmat.primitives.hashes",
        "--distpath", os.path.join(script_dir, "dist"),
        "--workpath", os.path.join(script_dir, "build"),
        "--specpath", script_dir,
        main_script,
    ]

    print(f"\n[...] Compilando {main_script}...")
    print(f"      Esto puede tardar 1-2 minutos...\n")

    result = subprocess.run(cmd, cwd=script_dir)

    if result.returncode == 0:
        exe_path = os.path.join(script_dir, "dist", "GestorContraseñas.exe")
        print("\n" + "=" * 50)
        print("  ✅ COMPILACIÓN EXITOSA")
        print("=" * 50)
        print(f"\n  Ejecutable: {exe_path}")
        print(f"  Tamaño: {os.path.getsize(exe_path) / (1024*1024):.1f} MB")
        print(f"\n  Puedes copiar GestorContraseñas.exe a cualquier")
        print(f"  carpeta y ejecutarlo directamente.")
        print(f"\n  NOTA: La primera vez que lo ejecutes, vault.enc")
        print(f"  se creará en la misma carpeta que el .exe")
    else:
        print("\n[ERROR] La compilación falló. Revisa los errores arriba.")
        sys.exit(1)

if __name__ == "__main__":
    main()
