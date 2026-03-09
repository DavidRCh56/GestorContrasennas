"""
╔══════════════════════════════════════════════════════════════╗
║     GESTOR DE CONTRASEÑAS SEGURO v4.0                        ║
║                                                              ║
║  • Generador: contraseñas + passphrases + PINs              ║
║  • Bóveda AES-256-GCM / Argon2id con notas seguras          ║
║  • Importar desde Chrome, Firefox, Bitwarden, LastPass…     ║
║  • Modo portátil (USB), atajos de teclado                   ║
║  • Historial de contraseñas, vencimiento, duplicados        ║
╚══════════════════════════════════════════════════════════════╝
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import logging
import sys
import os
import ctypes
import webbrowser
import time
import threading
import shutil
from datetime import datetime, date

from password_engine import PasswordEngine
from crypto_vault import CryptoVault, CATEGORIES
from ui_engine import (
    C, FONT, MONO, AnimationEngine, ToastNotification, Tooltip,
    make_card, make_label, make_entry, make_button, make_separator,
    make_combobox_menu, _safe_config
)

# ═══════════════════════════════════════════════════════════════
#  DIRECTORIO DE DATOS — modo normal vs portátil
# ═══════════════════════════════════════════════════════════════

_APP_NAME = "GestorContraseñas"

def _get_exe_dir():
    if getattr(sys, 'frozen', False):
        return os.path.dirname(os.path.abspath(sys.executable))
    return os.path.dirname(os.path.abspath(__file__))

def _is_portable_mode():
    """Modo portátil activado si existe 'portable.flag' junto al exe."""
    return os.path.isfile(os.path.join(_get_exe_dir(), "portable.flag"))

def _get_data_dir():
    if _is_portable_mode():
        return os.path.join(_get_exe_dir(), _APP_NAME + "_data")
    if sys.platform == "win32":
        base = os.environ.get("LOCALAPPDATA", os.path.expanduser("~"))
    else:
        base = os.path.expanduser("~")
    return os.path.join(base, _APP_NAME)

APP_DIR = _get_data_dir()
os.makedirs(APP_DIR, exist_ok=True)

def _protect_data_folder():
    if sys.platform != "win32": return
    try:
        ctypes.windll.kernel32.SetFileAttributesW(APP_DIR, 0x2 | 0x4)
    except Exception: pass

_protect_data_folder()

def _migrate_old_vault():
    """Mueve vault.enc antiguo (junto al exe) a la carpeta de datos."""
    old = os.path.join(_get_exe_dir(), "vault.enc")
    new = os.path.join(APP_DIR, "vault.enc")
    if os.path.isfile(old) and not os.path.isfile(new):
        try: shutil.move(old, new)
        except Exception: pass

_migrate_old_vault()

# ═══════════════════════════════════════════════════════════════
#  LOGGING
# ═══════════════════════════════════════════════════════════════

LOG_DIR = os.path.join(APP_DIR, "logs")
os.makedirs(LOG_DIR, exist_ok=True)
log_filename = os.path.join(LOG_DIR, f"pm_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log")

file_fmt    = logging.Formatter(
    "%(asctime)s | %(levelname)-8s | %(name)-30s | %(funcName)-20s | L%(lineno)-4d | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S")
console_fmt = logging.Formatter("%(asctime)s | %(levelname)-8s | %(message)s", datefmt="%H:%M:%S")

root_logger = logging.getLogger("PasswordManager")
root_logger.setLevel(logging.DEBUG)
fh = logging.FileHandler(log_filename, encoding="utf-8")
fh.setLevel(logging.DEBUG); fh.setFormatter(file_fmt)
root_logger.addHandler(fh)
ch = logging.StreamHandler(sys.stdout)
ch.setLevel(logging.INFO); ch.setFormatter(console_fmt)
root_logger.addHandler(ch)

logger = logging.getLogger("PasswordManager.App")
logger.info("=" * 60)
logger.info(f"  Gestor de Contraseñas Seguro v4.0  |  {'PORTÁTIL' if _is_portable_mode() else 'NORMAL'}")
logger.info("=" * 60)

# ═══════════════════════════════════════════════════════════════
#  ANTI-CAPTURA
# ═══════════════════════════════════════════════════════════════

def set_screen_capture_protection(hwnd, enable=True):
    if sys.platform != "win32": return False
    try:
        flag   = 0x00000011 if enable else 0x00000000
        result = ctypes.windll.user32.SetWindowDisplayAffinity(hwnd, flag)
        if not result and enable:
            result = ctypes.windll.user32.SetWindowDisplayAffinity(hwnd, 0x00000001)
        return bool(result)
    except Exception: return False


# ═══════════════════════════════════════════════════════════════
#  TUTORIALES DE EXPORTACIÓN CSV
# ═══════════════════════════════════════════════════════════════

CSV_TUTORIALS = {
    "chrome": {
        "name":  "Google Chrome",
        "icon":  "🌐",
        "color": C["cyan"],
        "steps": [
            "1. Abre Chrome y ve a la barra de direcciones.",
            "2. Escribe:  chrome://password-manager/settings",
            "3. Pulsa Enter para ir a la página.",
            "4. Busca el apartado 'Exportar contraseñas'.",
            "5. Haz clic en 'Descargar archivo'.",
            "6. Confirma tu contraseña de Windows si te la pide.",
            "7. Guarda el archivo  Chrome_passwords.csv  en algún lugar.",
            "8. Vuelve aquí, selecciona 'Chrome' y elige ese archivo.",
            "⚠️  Borra el CSV después de importar — contiene contraseñas en texto plano.",
        ],
    },
    "firefox": {
        "name":  "Mozilla Firefox",
        "icon":  "🦊",
        "color": "#ff6b35",
        "steps": [
            "1. Abre Firefox.",
            "2. Haz clic en el menú ☰ (arriba a la derecha).",
            "3. Ve a  Contraseñas  (o pulsa Ctrl+Shift+Y).",
            "4. En la ventana 'Contraseñas de Firefox', haz clic en ⋮ (menú de 3 puntos).",
            "5. Selecciona  'Exportar contraseñas'.",
            "6. Acepta la advertencia y guarda el archivo  logins.csv.",
            "7. Vuelve aquí, selecciona 'Firefox' y elige ese archivo.",
            "⚠️  Borra el CSV después de importar.",
        ],
    },
    "bitwarden": {
        "name":  "Bitwarden",
        "icon":  "🛡️",
        "color": C["accent"],
        "steps": [
            "1. Inicia sesión en  vault.bitwarden.com  en el navegador.",
            "2. En el menú lateral ve a  Herramientas → Exportar bóveda.",
            "3. Elige el formato  .csv  (no JSON).",
            "4. Escribe tu contraseña maestra de Bitwarden para confirmar.",
            "5. Haz clic en 'Confirmar formato' y luego 'Exportar bóveda'.",
            "6. Guarda el archivo  bitwarden_export.csv.",
            "7. Vuelve aquí, selecciona 'Bitwarden' y elige ese archivo.",
            "⚠️  Borra el CSV después de importar.",
        ],
    },
    "lastpass": {
        "name":  "LastPass",
        "icon":  "🔴",
        "color": "#cc2929",
        "steps": [
            "1. Inicia sesión en  lastpass.com.",
            "2. En el menú lateral ve a  Avanzado → Exportar.",
            "3. Introduce tu contraseña maestra.",
            "4. La página mostrará el CSV en pantalla, o lo descargará automáticamente.",
            "5. Si se muestra en pantalla: selecciona todo (Ctrl+A), cópialo,",
            "   pégalo en un editor de texto y guárdalo como  lastpass.csv.",
            "6. Vuelve aquí, selecciona 'LastPass' y elige ese archivo.",
            "⚠️  Borra el CSV después de importar.",
        ],
    },
    "1password": {
        "name":  "1Password",
        "icon":  "🔑",
        "color": C["green"],
        "steps": [
            "1. Abre la app de escritorio 1Password.",
            "2. Ve al menú  Archivo → Exportar → Todos los elementos.",
            "3. Elige el formato  CSV.",
            "4. Introduce tu contraseña maestra de 1Password.",
            "5. Guarda el archivo  1password_export.csv.",
            "6. Vuelve aquí, selecciona '1Password' y elige ese archivo.",
            "⚠️  Borra el CSV después de importar.",
        ],
    },
    "generic": {
        "name":  "CSV Genérico",
        "icon":  "📄",
        "color": C["txt2"],
        "steps": [
            "El CSV debe tener estas columnas (primera fila = cabecera):",
            "  name      → Nombre / título del sitio",
            "  url       → Dirección web",
            "  username  → Usuario o email",
            "  password  → Contraseña  (obligatorio)",
            "",
            "Ejemplo de primera fila del CSV:",
            "  name,url,username,password",
            "  GitHub,https://github.com,usuario@email.com,MiContraseña123",
        ],
    },
}

NOTE_COLORS = [
    ("#7c5cfc", "Morado"),
    ("#00e6b0", "Verde"),
    ("#00d4ff", "Cian"),
    ("#ff6bcb", "Rosa"),
    ("#ffb74d", "Naranja"),
    ("#ff5252", "Rojo"),
    ("#8888aa", "Gris"),
]


# ═══════════════════════════════════════════════════════════════
#  APLICACIÓN PRINCIPAL
# ═══════════════════════════════════════════════════════════════

class PasswordManagerApp:
    AUTO_LOCK_MINUTES = 5

    def __init__(self):
        logger.info("Inicializando aplicación…")
        self.engine  = PasswordEngine()
        vault_path   = os.path.join(APP_DIR, "vault.enc")
        self.vault   = CryptoVault(vault_path)
        self.last_generated_password = None
        self._last_activity    = time.time()
        self._auto_lock_job    = None
        self._gen_mode         = "password"
        self._clipboard_clear_job = None
        self._failed_login_attempts = 0
        self._login_lockout_until   = 0.0

        self.root = tk.Tk()
        self.root.title("🔐 Gestor de Contraseñas Seguro v4.0")
        self.root.geometry("680x820")
        self.root.minsize(600, 660)
        self.root.configure(bg=C["bg"])
        self._center_window(680, 820)

        # Icono
        try:
            base_path = getattr(sys, '_MEIPASS', _get_exe_dir())
            icon_path = os.path.join(base_path, "icon.png")
            if os.path.isfile(icon_path):
                img = tk.PhotoImage(file=icon_path)
                self.root.iconphoto(True, img); self._icon_ref = img
        except Exception: pass

        # Actividad para auto-bloqueo
        self.root.bind_all("<Key>",    self._reset_activity)
        self.root.bind_all("<Button>", self._reset_activity)
        self.root.bind_all("<Motion>", self._reset_activity)

        # Atajos de teclado globales
        self.root.bind_all("<Control-g>", lambda e: self._on_generate())
        self.root.bind_all("<Control-c>", lambda e: self._on_copy())
        self.root.bind_all("<Control-l>", lambda e: self._quick_lock())
        self.root.bind_all("<Control-f>", lambda e: self._focus_search())
        self.root.bind_all("<Control-n>", lambda e: self._on_add_credential())

        # Notebook
        style = ttk.Style(); style.theme_use("clam")
        style.configure("TNotebook", background=C["bg"], borderwidth=0)
        style.configure("TNotebook.Tab", background=C["card"], foreground=C["txt"],
                        font=(FONT, 9, "bold"), padding=[14, 9])
        style.map("TNotebook.Tab",
                  background=[("selected", C["accent"])],
                  foreground=[("selected", "white")])

        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill="both", expand=True, padx=10, pady=10)

        self.gen_frame      = tk.Frame(self.notebook, bg=C["bg"])
        self.vault_frame    = tk.Frame(self.notebook, bg=C["bg"])
        self.security_frame = tk.Frame(self.notebook, bg=C["bg"])

        self.notebook.add(self.gen_frame,      text="  ⚡ Generador  ")
        self.notebook.add(self.vault_frame,    text="  🔑 Contraseñas  ")
        self.notebook.add(self.security_frame, text="  🛡️ Seguridad  ")

        self._build_generator_tab()
        self._build_vault_tab()
        self._build_security_tab()

        self.notebook.bind("<<NotebookTabChanged>>", self._on_tab_changed)
        logger.info("Aplicación v4.0 inicializada ✓")

    # ══════════════════════════════════════════════════════
    #  UTILIDADES GENERALES
    # ══════════════════════════════════════════════════════

    def _center_window(self, w, h):
        x = (self.root.winfo_screenwidth()//2) - (w//2)
        y = (self.root.winfo_screenheight()//2) - (h//2)
        self.root.geometry(f"{w}x{h}+{x}+{y}")

    def _reset_activity(self, event=None): self._last_activity = time.time()

    def _check_auto_lock(self):
        if self.vault.is_unlocked:
            if time.time()-self._last_activity > self.AUTO_LOCK_MINUTES*60:
                self.vault.lock(); self._show_login_screen()
                ToastNotification.show(self.root, "🔒 Bóveda bloqueada por inactividad", "warning")
        self._auto_lock_job = self.root.after(30000, self._check_auto_lock)

    def _start_auto_lock(self):
        self._last_activity = time.time()
        if self._auto_lock_job: self.root.after_cancel(self._auto_lock_job)
        self._check_auto_lock()

    def _on_tab_changed(self, event):
        tab_idx = self.notebook.index(self.notebook.select())
        try:
            hwnd = ctypes.windll.user32.GetParent(self.root.winfo_id())
            set_screen_capture_protection(hwnd, tab_idx == 1)
        except Exception: pass

    def _quick_lock(self):
        if self.vault.is_unlocked:
            self.vault.lock(); self._show_login_screen()
            ToastNotification.show(self.root, "🔒 Bóveda bloqueada", "info")

    def _focus_search(self):
        if hasattr(self, 'search_entry'):
            self.notebook.select(1)
            self.search_entry.focus_set()

    def _schedule_clipboard_clear(self, seconds=30):
        if self._clipboard_clear_job: self.root.after_cancel(self._clipboard_clear_job)
        def clear():
            try: self.root.clipboard_clear(); self.root.clipboard_append("")
            except Exception: pass
        self._clipboard_clear_job = self.root.after(seconds*1000, clear)

    def _strength_color(self, entropy):
        if entropy >= 128: return C["green"]
        elif entropy >= 80: return "#4caf50"
        elif entropy >= 50: return C["yellow"]
        return C["red"]

    def _copy_to_clip(self, text):
        self.root.clipboard_clear(); self.root.clipboard_append(text)
        self._schedule_clipboard_clear(30)
        ToastNotification.show(self.root, "✅ Copiado (se borrará en 30s)", "success")

    # ══════════════════════════════════════════════════════
    #  TAB 1: GENERADOR
    # ══════════════════════════════════════════════════════

    def _build_generator_tab(self):
        canvas = tk.Canvas(self.gen_frame, bg=C["bg"], highlightthickness=0)
        sb     = tk.Scrollbar(self.gen_frame, orient="vertical", command=canvas.yview)
        inner  = tk.Frame(canvas, bg=C["bg"])
        inner.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0,0), window=inner, anchor="nw")
        canvas.configure(yscrollcommand=sb.set)
        canvas.bind("<Configure>", lambda e: canvas.itemconfig(canvas.find_all()[0], width=e.width))
        canvas.bind_all("<MouseWheel>", lambda e: canvas.yview_scroll(int(-1*(e.delta/120)),"units"))
        sb.pack(side="right", fill="y"); canvas.pack(side="left", fill="both", expand=True)
        f = tk.Frame(inner, bg=C["bg"]); f.pack(fill="both", expand=True, padx=20, pady=10)

        make_label(f, "⚡ Generador", 16, bold=True, color=C["accent"]).pack(fill="x", pady=(0,2))
        hint = tk.Frame(f, bg=C["bg"]); hint.pack(fill="x", pady=(0,8))
        make_label(hint, "Ctrl+G generar  •  Ctrl+C copiar", 8, color=C["muted"]).pack(side="left")

        # ── Modo ──────────────────────
        mc = make_card(f, hover=False); mc.pack(fill="x", pady=(0,8), ipady=4, ipadx=10)
        make_label(mc, "🔀  MODO", 9, bold=True, color=C["txt2"]).pack(fill="x", padx=12, pady=(8,5))
        mf = tk.Frame(mc, bg=C["card"]); mf.pack(fill="x", padx=12, pady=(0,8))
        self._mode_btn_pw = make_button(mf, "🔑 Contraseña",
            lambda: self._switch_gen_mode("password"), bg_color=C["accent"], size=9, bold=True)
        self._mode_btn_pw.pack(side="left", padx=(0,4))
        self._mode_btn_pp = make_button(mf, "📝 Passphrase",
            lambda: self._switch_gen_mode("passphrase"), bg_color=C["input"], fg_color=C["txt"], size=9)
        self._mode_btn_pp.pack(side="left", padx=(0,4))
        self._mode_btn_pin = make_button(mf, "🔢 PIN",
            lambda: self._switch_gen_mode("pin"), bg_color=C["input"], fg_color=C["txt"], size=9)
        self._mode_btn_pin.pack(side="left")

        # Frames de opciones (uno activo a la vez)
        self._pw_options_frame  = tk.Frame(f, bg=C["bg"])
        self._pp_options_frame  = tk.Frame(f, bg=C["bg"])
        self._pin_options_frame = tk.Frame(f, bg=C["bg"])
        self._pw_options_frame.pack(fill="x")
        self._build_password_options(self._pw_options_frame)
        self._build_passphrase_options(self._pp_options_frame)
        self._build_pin_options(self._pin_options_frame)

        # ── Botón GENERAR ──
        self._gen_btn = make_button(f, "⚡  GENERAR  (Ctrl+G)", self._on_generate,
                                    size=12, bold=True, glow=True)
        self._gen_btn.pack(fill="x", pady=(5,8), ipady=5)

        # ── Resultado ──
        rc = make_card(f, hover=False); rc.pack(fill="x", pady=(0,8), ipady=5, ipadx=10)
        make_label(rc, "🔑  RESULTADO", 9, bold=True, color=C["txt2"]).pack(fill="x", padx=12, pady=(8,3))
        pw_f = tk.Frame(rc, bg=C["input"], highlightbackground=C["border"], highlightthickness=1)
        pw_f.pack(fill="x", padx=12, pady=(0,5))
        self.result_text = tk.Text(pw_f, height=3, font=(MONO,12), bg=C["input"], fg=C["green"],
            insertbackground=C["green"], relief="flat", wrap="char",
            selectbackground=C["accent"], selectforeground="white", padx=8, pady=8)
        self.result_text.pack(fill="x")
        self.result_text.insert("1.0", "Aquí aparecerá tu contraseña…")
        self.result_text.configure(state="disabled")

        af = tk.Frame(rc, bg=C["card"]); af.pack(fill="x", padx=12, pady=(0,3))
        self.copy_btn = make_button(af, "📋 Copiar", self._on_copy,
                                    bg_color=C["input"], fg_color=C["txt"], size=9)
        self.copy_btn.pack(side="left", padx=(0,4))
        Tooltip(self.copy_btn, "Ctrl+C")
        self.save_gen_btn = make_button(af, "💾 Guardar en Bóveda", self._on_save_generated,
                                        bg_color=C["input"], fg_color=C["txt"], size=9)
        self.save_gen_btn.pack(side="left", padx=(0,4))
        self.hibp_btn = make_button(af, "🛡️ Verificar HIBP", self._on_check_hibp,
                                    bg_color=C["input"], fg_color=C["cyan"], size=9)
        self.hibp_btn.pack(side="left")
        Tooltip(self.hibp_btn, "Comprueba filtraciones (k-Anonymity)")

        self.str_label  = make_label(rc, "Fortaleza: --", 9, color=C["muted"]); self.str_label.pack(fill="x", padx=12)
        self.ent_label  = make_label(rc, "Entropía: --",  8, color=C["muted"]); self.ent_label.pack(fill="x", padx=12)
        self.hibp_label = make_label(rc, "", 8, color=C["muted"]);               self.hibp_label.pack(fill="x", padx=12)
        self.str_bar    = tk.Canvas(rc, height=6, bg=C["input"], highlightthickness=0)
        self.str_bar.pack(fill="x", padx=12, pady=(3,8))

    def _build_password_options(self, parent):
        lc = make_card(parent); lc.pack(fill="x", pady=(0,8), ipady=5, ipadx=10)
        make_label(lc, "📏  LONGITUD", 9, bold=True, color=C["txt2"]).pack(fill="x", padx=12, pady=(8,3))
        sf = tk.Frame(lc, bg=C["card"]); sf.pack(fill="x", padx=12, pady=(0,5))
        self.length_var = tk.IntVar(value=20)
        self.length_lbl = make_label(sf, "20", 20, bold=True, color=C["accent"])
        self.length_lbl.configure(width=4); self.length_lbl.pack(side="left")
        self.length_slider = tk.Scale(sf, from_=4, to=128, orient="horizontal",
            variable=self.length_var, command=self._on_slider,
            bg=C["card"], fg=C["txt"], troughcolor=C["input"],
            highlightthickness=0, sliderrelief="flat", showvalue=False,
            sliderlength=20, font=(FONT,8))
        self.length_slider.pack(side="left", fill="x", expand=True, padx=(10,0))
        mf = tk.Frame(lc, bg=C["card"]); mf.pack(fill="x", padx=12, pady=(0,5))
        make_label(mf, "O escribe:", 9, color=C["muted"]).pack(side="left")
        self.len_entry = make_entry(mf, font_size=10)
        self.len_entry.configure(width=6, justify="center"); self.len_entry.pack(side="left", padx=(8,0))
        self.len_entry.insert(0, "20")
        self.len_entry.bind("<Return>", self._on_len_entry)
        self.len_entry.bind("<FocusOut>", self._on_len_entry)

        tc = make_card(parent); tc.pack(fill="x", pady=(0,8), ipady=5, ipadx=10)
        make_label(tc, "🔤  TIPOS DE CARACTERES", 9, bold=True, color=C["txt2"]).pack(fill="x", padx=12, pady=(8,5))
        self.var_low = tk.BooleanVar(value=True); self.var_up  = tk.BooleanVar(value=True)
        self.var_dig = tk.BooleanVar(value=True); self.var_sym = tk.BooleanVar(value=True)
        for var, icon, label in [(self.var_low,"abc","Minúsculas (a-z)"),
                                  (self.var_up, "ABC","Mayúsculas (A-Z)"),
                                  (self.var_dig,"123","Dígitos (0-9)"),
                                  (self.var_sym,"#$!","Símbolos")]:
            row = tk.Frame(tc, bg=C["card"]); row.pack(fill="x", padx=12, pady=1)
            tk.Checkbutton(row, variable=var, bg=C["card"], fg=C["txt"],
                selectcolor=C["input"], activebackground=C["card"],
                highlightthickness=0, relief="flat").pack(side="left")
            make_label(row, f" {icon}  {label}", 10).pack(side="left")

        sc = make_card(parent); sc.pack(fill="x", pady=(0,8), ipady=5, ipadx=10)
        make_label(sc, "⚙️  SÍMBOLOS PERSONALIZADOS", 9, bold=True, color=C["txt2"]).pack(fill="x", padx=12, pady=(8,3))
        self.sym_entry = make_entry(sc, font_family=MONO, font_size=11)
        self.sym_entry.pack(fill="x", padx=12, pady=(0,5))
        self.sym_entry.insert(0, "!@#$%^&*()-_=+[]{}|;:',.<>?/~`")

    def _build_passphrase_options(self, parent):
        pc = make_card(parent); pc.pack(fill="x", pady=(0,8), ipady=5, ipadx=10)
        make_label(pc, "📝  OPCIONES DE PASSPHRASE", 9, bold=True, color=C["txt2"]).pack(fill="x", padx=12, pady=(8,5))
        wf = tk.Frame(pc, bg=C["card"]); wf.pack(fill="x", padx=12, pady=(0,5))
        make_label(wf, "Palabras:", 10).pack(side="left")
        self.word_count_var = tk.IntVar(value=5)
        self.word_count_lbl = make_label(wf, "5", 16, bold=True, color=C["accent"])
        self.word_count_lbl.pack(side="left", padx=(10,10))
        tk.Scale(wf, from_=3, to=10, orient="horizontal", variable=self.word_count_var,
            command=lambda v: self.word_count_lbl.configure(text=str(int(float(v)))),
            bg=C["card"], fg=C["txt"], troughcolor=C["input"], highlightthickness=0,
            sliderrelief="flat", showvalue=False, sliderlength=20
        ).pack(side="left", fill="x", expand=True)
        sf = tk.Frame(pc, bg=C["card"]); sf.pack(fill="x", padx=12, pady=(0,3))
        make_label(sf, "Separador:", 10).pack(side="left")
        self.sep_entry = make_entry(sf, font_size=10)
        self.sep_entry.configure(width=5, justify="center"); self.sep_entry.pack(side="left", padx=(8,0))
        self.sep_entry.insert(0, "-")
        of = tk.Frame(pc, bg=C["card"]); of.pack(fill="x", padx=12, pady=(0,5))
        self.var_capitalize = tk.BooleanVar(value=False)
        tk.Checkbutton(of, text="  Capitalizar", variable=self.var_capitalize,
            bg=C["card"], fg=C["txt"], selectcolor=C["input"],
            activebackground=C["card"], highlightthickness=0, font=(FONT,10)).pack(side="left")
        self.var_add_num = tk.BooleanVar(value=True)
        tk.Checkbutton(of, text="  Añadir número", variable=self.var_add_num,
            bg=C["card"], fg=C["txt"], selectcolor=C["input"],
            activebackground=C["card"], highlightthickness=0, font=(FONT,10)).pack(side="left", padx=(15,0))
        make_label(pc, "📖 ~180 palabras en español", 8, color=C["muted"]).pack(padx=12, pady=(0,5))

    def _build_pin_options(self, parent):
        pc = make_card(parent); pc.pack(fill="x", pady=(0,8), ipady=5, ipadx=10)
        make_label(pc, "🔢  OPCIONES DE PIN", 9, bold=True, color=C["txt2"]).pack(fill="x", padx=12, pady=(8,5))

        lf = tk.Frame(pc, bg=C["card"]); lf.pack(fill="x", padx=12, pady=(0,5))
        make_label(lf, "Dígitos:", 10).pack(side="left")
        self.pin_len_var = tk.IntVar(value=6)
        self.pin_len_lbl = make_label(lf, "6", 16, bold=True, color=C["accent"])
        self.pin_len_lbl.pack(side="left", padx=(10,10))
        tk.Scale(lf, from_=4, to=12, orient="horizontal", variable=self.pin_len_var,
            command=lambda v: self.pin_len_lbl.configure(text=str(int(float(v)))),
            bg=C["card"], fg=C["txt"], troughcolor=C["input"], highlightthickness=0,
            sliderrelief="flat", showvalue=False, sliderlength=20
        ).pack(side="left", fill="x", expand=True)

        of = tk.Frame(pc, bg=C["card"]); of.pack(fill="x", padx=12, pady=(0,3))
        self.var_pin_no_seq = tk.BooleanVar(value=True)
        tk.Checkbutton(of, text="  Evitar secuencias (1234…)", variable=self.var_pin_no_seq,
            bg=C["card"], fg=C["txt"], selectcolor=C["input"],
            activebackground=C["card"], highlightthickness=0, font=(FONT,10)).pack(side="left")

        of2 = tk.Frame(pc, bg=C["card"]); of2.pack(fill="x", padx=12, pady=(0,3))
        self.var_pin_no_rep = tk.BooleanVar(value=True)
        tk.Checkbutton(of2, text="  Evitar repeticiones (1111…)", variable=self.var_pin_no_rep,
            bg=C["card"], fg=C["txt"], selectcolor=C["input"],
            activebackground=C["card"], highlightthickness=0, font=(FONT,10)).pack(side="left")

        of3 = tk.Frame(pc, bg=C["card"]); of3.pack(fill="x", padx=12, pady=(0,8))
        self.var_pin_sep = tk.BooleanVar(value=False)
        tk.Checkbutton(of3, text="  Separar en grupos (123-456)", variable=self.var_pin_sep,
            bg=C["card"], fg=C["txt"], selectcolor=C["input"],
            activebackground=C["card"], highlightthickness=0, font=(FONT,10)).pack(side="left")

        make_label(pc, "🔒 PINs criptográficamente seguros (CSPRNG del SO)", 8, color=C["muted"]).pack(padx=12, pady=(0,5))

    def _switch_gen_mode(self, mode):
        self._gen_mode = mode
        btn_map = {"password": self._mode_btn_pw,
                   "passphrase": self._mode_btn_pp,
                   "pin": self._mode_btn_pin}
        frame_map = {"password": self._pw_options_frame,
                     "passphrase": self._pp_options_frame,
                     "pin": self._pin_options_frame}
        for m, btn in btn_map.items():
            _safe_config(btn, bg=C["accent"] if m==mode else C["input"],
                         fg="white" if m==mode else C["txt"])
        for m, frm in frame_map.items():
            if m == mode:
                frm.pack(fill="x", before=self._gen_btn)
            else:
                frm.pack_forget()

    def _on_slider(self, val):
        v = int(float(val))
        self.length_lbl.configure(text=str(v))
        self.len_entry.delete(0, tk.END); self.len_entry.insert(0, str(v))

    def _on_len_entry(self, e=None):
        try:
            v = max(4, min(256, int(self.len_entry.get())))
            self.length_var.set(min(v, 128)); self.length_lbl.configure(text=str(v))
        except ValueError:
            self.len_entry.delete(0, tk.END); self.len_entry.insert(0, str(self.length_var.get()))

    def _on_generate(self, event=None):
        try:
            if self._gen_mode == "passphrase":
                result = self.engine.generate_passphrase(
                    word_count=self.word_count_var.get(),
                    separator=self.sep_entry.get() or "-",
                    capitalize=self.var_capitalize.get(),
                    add_number=self.var_add_num.get())
            elif self._gen_mode == "pin":
                result = self.engine.generate_pin(
                    length=self.pin_len_var.get(),
                    avoid_sequences=self.var_pin_no_seq.get(),
                    avoid_repeats=self.var_pin_no_rep.get(),
                    add_separator=self.var_pin_sep.get())
            else:
                try: length = int(self.len_entry.get())
                except ValueError: length = self.length_var.get()
                if not any([self.var_low.get(), self.var_up.get(),
                            self.var_dig.get(), self.var_sym.get()]):
                    ToastNotification.show(self.root, "Selecciona al menos un tipo de carácter.", "warning"); return
                result = self.engine.generate(
                    length=length, use_lower=self.var_low.get(),
                    use_upper=self.var_up.get(), use_digits=self.var_dig.get(),
                    use_symbols=self.var_sym.get(), custom_symbols=self.sym_entry.get())

            self.last_generated_password = result["password"]
            self.result_text.configure(state="normal")
            self.result_text.delete("1.0", tk.END)
            self.result_text.insert("1.0", result["password"])
            self.result_text.configure(state="disabled")

            sc = self._strength_color(result["entropy_bits"])
            self.str_label.configure(text=f"Fortaleza: {result['strength']}", fg=sc)
            info = f"Entropía: {result['entropy_bits']} bits | {result['generation_time_ms']} ms"
            if "charset_size" in result:
                info += f" | Charset: {result['charset_size']}"
            self.ent_label.configure(text=info)
            self.hibp_label.configure(text="", fg=C["muted"])
            AnimationEngine.animate_bar(self.str_bar, self.root, min(result["entropy_bits"]/200,1.0), sc)
            AnimationEngine.color_pulse(self._gen_btn, self.root, C["accent"], C["green"])
        except ValueError as e:
            ToastNotification.show(self.root, str(e), "warning")
        except Exception as e:
            logger.error(f"Error generando: {e}", exc_info=True)
            ToastNotification.show(self.root, str(e), "error")

    def _on_check_hibp(self):
        self.result_text.configure(state="normal")
        pw = self.result_text.get("1.0", tk.END).strip()
        self.result_text.configure(state="disabled")
        if not pw or pw == "Aquí aparecerá tu contraseña…":
            ToastNotification.show(self.root, "Primero genera una contraseña.", "info"); return
        self.hibp_label.configure(text="⏳ Verificando HIBP…", fg=C["yellow"])
        self.root.update_idletasks()
        def check():
            r = self.engine.check_hibp(pw)
            self.root.after(0, lambda: self._show_hibp_result(r))
        threading.Thread(target=check, daemon=True).start()

    def _show_hibp_result(self, result):
        if result["compromised"] is None:
            self.hibp_label.configure(text=result["message"], fg=C["yellow"])
        elif result["compromised"]:
            self.hibp_label.configure(text=result["message"], fg=C["red"])
            ToastNotification.show(self.root, result["message"], "error", 4000)
        else:
            self.hibp_label.configure(text=result["message"], fg=C["green"])

    def _on_copy(self, event=None):
        self.result_text.configure(state="normal")
        pw = self.result_text.get("1.0", tk.END).strip()
        self.result_text.configure(state="disabled")
        if pw and pw != "Aquí aparecerá tu contraseña…":
            self.root.clipboard_clear(); self.root.clipboard_append(pw)
            self._schedule_clipboard_clear(30)
            ToastNotification.show(self.root, "✅ Copiado (se borrará en 30s)", "success")
            AnimationEngine.bounce_text(self.copy_btn, self.root, "📋 Copiar", "✅ ¡Copiado!")
        else:
            ToastNotification.show(self.root, "Primero genera una contraseña.", "info")

    def _on_save_generated(self):
        if not self.last_generated_password:
            ToastNotification.show(self.root, "Primero genera una contraseña.", "info"); return
        if not self.vault.is_unlocked:
            ToastNotification.show(self.root, "Desbloquea la bóveda primero.", "warning"); return
        self._show_save_dialog(self.last_generated_password)

    def _show_save_dialog(self, password):
        dlg = tk.Toplevel(self.root); dlg.title("Guardar")
        dlg.geometry("440x500"); dlg.configure(bg=C["bg"])
        dlg.transient(self.root); dlg.grab_set()
        x = self.root.winfo_x()+120; y = self.root.winfo_y()+130
        dlg.geometry(f"+{x}+{y}")
        make_label(dlg, "💾 Guardar Contraseña", 13, bold=True).pack(padx=15, pady=(15,8))
        make_label(dlg, "●"*min(len(password),32), 10, color=C["green"]).pack(fill="x", padx=15, pady=(0,8))

        fields = {}
        for lbl, key, show in [
            ("Nombre:", "title", None), ("URL:", "site", None),
            ("Email / Usuario:", "email", None), ("Notas (opcional):", "notes", None),
        ]:
            make_label(dlg, lbl, 9, color=C["txt2"]).pack(fill="x", padx=15)
            e = make_entry(dlg, show=show); e.pack(fill="x", padx=15, pady=(0,5)); fields[key] = e

        make_label(dlg, "Categoría:", 9, color=C["txt2"]).pack(fill="x", padx=15)
        cat_mb, cat_var = make_combobox_menu(dlg, CATEGORIES, "📁 Otros")
        cat_mb.pack(fill="x", padx=15, pady=(0,5))

        make_label(dlg, "Vence el (opcional, YYYY-MM-DD):", 9, color=C["txt2"]).pack(fill="x", padx=15)
        exp_e = make_entry(dlg); exp_e.pack(fill="x", padx=15, pady=(0,8)); fields["expires"] = exp_e

        def save():
            title = fields["title"].get().strip()
            if not title:
                ToastNotification.show(dlg, "Introduce un nombre.", "warning"); return
            exp = fields["expires"].get().strip() or None
            if exp:
                try: date.fromisoformat(exp)
                except ValueError:
                    ToastNotification.show(dlg, "Fecha inválida. Usa YYYY-MM-DD.", "warning"); return
            try:
                self.vault.add_credential(title, fields["site"].get().strip(),
                    fields["email"].get().strip(), password,
                    notes=fields["notes"].get().strip(),
                    category=cat_var.get(), expires_at=exp)
                dlg.destroy()
                ToastNotification.show(self.root, f"'{title}' guardado ✓", "success")
                self._refresh_credentials_list()
            except Exception as e:
                ToastNotification.show(dlg, str(e), "error")
        make_button(dlg, "💾 Guardar", save, size=11, bold=True).pack(fill="x", padx=15, pady=(0,12))

    # ══════════════════════════════════════════════════════
    #  TAB 2: CONTRASEÑAS (bóveda)
    # ══════════════════════════════════════════════════════

    def _build_vault_tab(self):
        self.vault_container = tk.Frame(self.vault_frame, bg=C["bg"])
        self.vault_container.pack(fill="both", expand=True)
        if self.vault.is_vault_created: self._show_login_screen()
        else: self._show_create_master_screen()

    def _clear_vault_container(self):
        for w in self.vault_container.winfo_children(): w.destroy()

    def _show_create_master_screen(self):
        self._clear_vault_container(); f = self.vault_container
        make_label(f, "🔒", 30).pack(pady=(40,5))
        make_label(f, "Crear Contraseña Maestra", 16, bold=True).pack()
        make_label(f, "Protege toda tu bóveda. No se puede recuperar si la olvidas.",
                   9, color=C["txt2"]).pack(pady=(5,20))
        card = make_card(f, hover=False); card.pack(fill="x", padx=40, ipady=10)
        make_label(card, "Contraseña maestra:", 10, color=C["txt2"]).pack(fill="x", padx=15, pady=(10,3))
        self.master_pw1 = make_entry(card, show="●", font_size=12)
        self.master_pw1.pack(fill="x", padx=15, pady=(0,8))
        make_label(card, "Confirmar:", 10, color=C["txt2"]).pack(fill="x", padx=15, pady=(0,3))
        self.master_pw2 = make_entry(card, show="●", font_size=12)
        self.master_pw2.pack(fill="x", padx=15, pady=(0,10))
        make_label(card, "≥ 8 caracteres. Usa letras, números y símbolos.", 8, color=C["muted"]).pack(padx=15, pady=(0,10))
        make_button(f, "🔐 Crear Bóveda", self._on_create_vault,
                    size=12, bold=True, glow=True).pack(fill="x", padx=40, pady=15, ipady=4)

    def _on_create_vault(self):
        pw1 = self.master_pw1.get(); pw2 = self.master_pw2.get()
        if pw1 != pw2:
            ToastNotification.show(self.root, "Las contraseñas no coinciden.", "error"); return
        if len(pw1) < 8:
            ToastNotification.show(self.root, "Mínimo 8 caracteres.", "warning"); return
        try:
            self.vault.create_vault(pw1)
            ToastNotification.show(self.root, "✅ Bóveda creada con éxito", "success")
            self._show_manager_screen(); self._start_auto_lock()
        except Exception as e:
            ToastNotification.show(self.root, str(e), "error")

    def _show_login_screen(self):
        self._clear_vault_container(); f = self.vault_container
        make_label(f, "🔒", 30).pack(pady=(50,5))
        make_label(f, "Bóveda Bloqueada", 16, bold=True).pack()
        make_label(f, "Introduce tu contraseña maestra.", 9, color=C["txt2"]).pack(pady=(5,20))
        card = make_card(f, hover=False); card.pack(fill="x", padx=40, ipady=10)
        make_label(card, "Contraseña maestra:", 10, color=C["txt2"]).pack(fill="x", padx=15, pady=(10,3))
        self.login_pw = make_entry(card, show="●", font_size=12)
        self.login_pw.pack(fill="x", padx=15, pady=(0,10))
        self.login_pw.bind("<Return>", lambda e: self._on_unlock())
        self.login_status = make_label(f, "", 9, color=C["red"]); self.login_status.pack(pady=(5,0))
        make_button(f, "🔓 Desbloquear", self._on_unlock,
                    size=12, bold=True, glow=True).pack(fill="x", padx=40, pady=15, ipady=4)

    def _on_unlock(self):
        now = time.time()
        if now < self._login_lockout_until:
            remaining = int(self._login_lockout_until - now)
            self.login_status.configure(
                text=f"⛔ Bloqueado {remaining}s por demasiados intentos.", fg=C["red"])
            self.root.after(1000, lambda: self._on_unlock() if hasattr(self,'login_status') else None)
            return
        pw = self.login_pw.get()
        if not pw:
            self.login_status.configure(text="Introduce la contraseña.", fg=C["red"]); return
        self.login_status.configure(text="⏳ Desbloqueando…", fg=C["yellow"])
        self.root.update_idletasks()
        if self.vault.unlock(pw):
            self._failed_login_attempts = 0; self._login_lockout_until = 0.0
            self._show_manager_screen(); self._start_auto_lock()
            ToastNotification.show(self.root, "🔓 Bóveda desbloqueada", "success")
        else:
            self._failed_login_attempts += 1
            n = self._failed_login_attempts
            if n >= 5:
                cooldown = min(30*(2**(n-5)), 600)
                self._login_lockout_until = time.time()+cooldown
                self.login_status.configure(
                    text=f"🚫 {n} intentos fallidos. Bloqueado {cooldown}s.", fg=C["red"])
            else:
                self.login_status.configure(
                    text=f"❌ Contraseña incorrecta. ({5-n} intentos antes del bloqueo)", fg=C["red"])

    def _show_manager_screen(self):
        self._clear_vault_container(); f = self.vault_container
        stats = self.vault.get_statistics()

        # Header
        hdr = tk.Frame(f, bg=C["bg"]); hdr.pack(fill="x", padx=15, pady=(10,5))
        make_label(hdr, "🔓 Mis Contraseñas", 14, bold=True).pack(side="left")

        # Stats resumidos
        stats_parts = [f"📊 {stats['total']}"]
        if stats["weak"] > 0:       stats_parts.append(f"⚠️ {stats['weak']} débiles")
        if stats["duplicates"] > 0: stats_parts.append(f"🔁 {stats['duplicates']} dup.")
        if stats["expiring"] > 0:   stats_parts.append(f"⏰ {stats['expiring']} vencen")
        make_label(hdr, "  ".join(stats_parts), 8, color=C["txt2"]).pack(side="left", padx=(12,0))

        btn_f = tk.Frame(hdr, bg=C["bg"]); btn_f.pack(side="right")
        for icon, cmd, tip in [
            ("🔒", self._on_lock,                   "Bloquear (Ctrl+L)"),
            ("🔑", self._on_change_master_password,  "Cambiar contraseña maestra"),
            ("📤", self._on_export,                  "Exportar .pmex"),
            ("📥", self._on_import,                  "Importar .pmex"),
            ("📊", self._on_import_csv,              "Importar desde Chrome/Firefox/…"),
            ("➕", self._on_add_credential,           "Añadir credencial (Ctrl+N)"),
        ]:
            b = make_button(btn_f, icon, cmd, bg_color=C["input"], fg_color=C["txt"], size=9)
            b.pack(side="right", padx=2)
            Tooltip(b, tip)
        # Colorear el botón ➕
        btn_f.winfo_children()[0].configure(bg=C["accent"])

        # KDF info
        kdf_color = C["green"] if stats["kdf"] == "Argon2id" else C["yellow"]
        make_label(f, f"🔐 KDF: {stats['kdf']}", 7, color=kdf_color).pack(anchor="e", padx=15)

        # Búsqueda + filtro
        search_f = tk.Frame(f, bg=C["bg"]); search_f.pack(fill="x", padx=15, pady=(0,5))
        make_label(search_f, "🔍", 10).pack(side="left")
        self.search_var = tk.StringVar()
        self.search_var.trace_add("write", lambda *a: self._refresh_credentials_list())
        self.search_entry = make_entry(search_f, font_size=10)
        self.search_entry.configure(textvariable=self.search_var)
        self.search_entry.pack(side="left", fill="x", expand=True, padx=(5,5))
        self.cat_filter_mb, self.cat_filter_var = make_combobox_menu(
            search_f, ["Todas"]+CATEGORIES, "Todas", width=14)
        self.cat_filter_var.trace_add("write", lambda *a: self._refresh_credentials_list())
        self.cat_filter_mb.pack(side="left")

        # Lista de credenciales
        lf = tk.Frame(f, bg=C["bg"]); lf.pack(fill="both", expand=True, padx=10, pady=5)
        self.cred_canvas = tk.Canvas(lf, bg=C["bg"], highlightthickness=0)
        csb = tk.Scrollbar(lf, orient="vertical", command=self.cred_canvas.yview)
        self.cred_inner = tk.Frame(self.cred_canvas, bg=C["bg"])
        self.cred_inner.bind("<Configure>",
            lambda e: self.cred_canvas.configure(scrollregion=self.cred_canvas.bbox("all")))
        self.cred_canvas.create_window((0,0), window=self.cred_inner, anchor="nw")
        self.cred_canvas.configure(yscrollcommand=csb.set)
        self.cred_canvas.bind("<Configure>",
            lambda e: self.cred_canvas.itemconfig(self.cred_canvas.find_all()[0], width=e.width))
        csb.pack(side="right", fill="y"); self.cred_canvas.pack(side="left", fill="both", expand=True)
        self._refresh_credentials_list()

        # ── Zona de Peligro ──
        tk.Frame(f, bg=C["red"], height=1).pack(fill="x", padx=10, pady=(6,0))
        danger_bar = tk.Frame(f, bg="#1a0000", highlightbackground=C["red"], highlightthickness=1)
        danger_bar.pack(fill="x", padx=10, pady=(0,8), ipady=4)
        make_label(danger_bar, "⚠️  ZONA DE PELIGRO", 8, bold=True, color=C["red"]).pack(side="left", padx=(10,6))
        for text, cmd, tip in [
            ("💀  Desinstalar App",           self._on_uninstall_app,             "Borra todo + el .exe"),
            ("🗑️  Eliminar Todos los Datos",  self._on_delete_all_data_from_vault, "Borra bóveda, logs y backups"),
        ]:
            b = tk.Button(danger_bar, text=text, font=(FONT,8,"bold"),
                bg="#3a0000", fg=C["red"], activebackground="#5a0000",
                activeforeground="white", relief="flat", cursor="hand2",
                padx=10, pady=4, borderwidth=0,
                highlightbackground=C["red"], highlightthickness=1, command=cmd)
            b.pack(side="right", padx=(4,4))
            Tooltip(b, tip)

    def _refresh_credentials_list(self):
        if not hasattr(self, 'cred_inner'): return
        for w in self.cred_inner.winfo_children(): w.destroy()
        creds  = self.vault.credentials
        search = self.search_var.get().lower() if hasattr(self,'search_var') else ""
        cat_f  = self.cat_filter_var.get()     if hasattr(self,'cat_filter_var') else "Todas"
        if search:
            creds = [c for c in creds if search in c.get("title","").lower()
                     or search in c.get("site","").lower()
                     or search in c.get("email","").lower()]
        if cat_f != "Todas":
            creds = [c for c in creds if c.get("category","") == cat_f]
        if not creds:
            msg = "No hay resultados." if (search or cat_f!="Todas") else \
                  "No hay contraseñas guardadas.\nUsa '➕' o genera una y guárdala."
            make_label(self.cred_inner, msg, 10, color=C["muted"]).pack(pady=40); return

        # Duplicados para marcar las tarjetas
        dup_ids: set = set()
        for ids in self.vault.find_duplicates().values():
            dup_ids.update(ids)

        for cred in creds:
            self._build_credential_card(self.cred_inner, cred, cred["id"] in dup_ids)

    def _build_credential_card(self, parent, cred, is_duplicate=False):
        card = make_card(parent); card.pack(fill="x", pady=(0,6), ipady=6, ipadx=8)
        top  = tk.Frame(card, bg=C["card"]); top.pack(fill="x", padx=10, pady=(8,2))

        # Nombre + categoría + badges
        display_name = cred.get('title') or cred.get('site', 'Sin nombre')
        pw           = cred.get("password","")

        # Indicador de fortaleza
        import math as _math
        pw_entropy   = len(pw)*_math.log2(max(len(set(pw)),2)) if pw else 0
        dot_color    = self._strength_color(pw_entropy)
        tk.Label(top, text="●", font=(FONT,10), bg=C["card"], fg=dot_color).pack(side="left", padx=(0,4))

        make_label(top, display_name, 11, bold=True, color=C["accent"]).pack(side="left")
        make_label(top, f" {cred.get('category','📁 Otros')}", 8, color=C["txt2"]).pack(side="left", padx=(6,0))

        # Badges: duplicado, vencimiento
        badges_f = tk.Frame(top, bg=C["card"]); badges_f.pack(side="left", padx=(8,0))
        if is_duplicate:
            make_label(badges_f, "🔁 DUP", 7, bold=True, color=C["red"]).pack(side="left", padx=2)
        exp = cred.get("expires_at")
        if exp:
            try:
                delta = (date.fromisoformat(exp) - date.today()).days
                if delta < 0:
                    make_label(badges_f, "⛔ VENCIDA", 7, bold=True, color=C["red"]).pack(side="left", padx=2)
                elif delta <= 30:
                    make_label(badges_f, f"⏰ {delta}d", 7, bold=True, color=C["yellow"]).pack(side="left", padx=2)
            except ValueError: pass

        # Botones de acción en el encabezado
        for icon, cmd, fg in [
            ("🗑", lambda c=cred: self._on_delete_credential(c["id"]), C["red"]),
            ("✏️", lambda c=cred: self._on_edit_credential(c),         C["yellow"]),
            ("🕐", lambda c=cred: self._on_view_history(c),            C["txt2"]),
        ]:
            make_button(top, icon, cmd, bg_color=C["card"], fg_color=fg, size=9).pack(side="right", padx=1)

        # URL
        site_url = cred.get('site','')
        if site_url and site_url != display_name:
            url_r = tk.Frame(card, bg=C["card"]); url_r.pack(fill="x", padx=10)
            make_label(url_r, f"🔗 {site_url}", 8, color=C["muted"]).pack(side="left")

        # Email
        em_r = tk.Frame(card, bg=C["card"]); em_r.pack(fill="x", padx=10, pady=1)
        make_label(em_r, f"📧 {cred['email']}", 9, color=C["txt2"]).pack(side="left")
        make_button(em_r, "📋", lambda c=cred: self._copy_to_clip(c["email"]),
                    bg_color=C["card"], fg_color=C["txt2"], size=8).pack(side="right")

        # Contraseña
        pw_r = tk.Frame(card, bg=C["card"]); pw_r.pack(fill="x", padx=10, pady=1)
        pw_lbl = make_label(pw_r, "🔑 ●●●●●●●●●●●●", 9, color=C["muted"])
        pw_lbl.pack(side="left")
        def toggle_pw(label=pw_lbl, c=cred):
            if "●" in label.cget("text"):
                label.configure(text=f"🔑 {c['password']}", fg=C["green"])
                self.root.after(5000, lambda: _safe_config(label, text="🔑 ●●●●●●●●●●●●", fg=C["muted"]))
            else:
                label.configure(text="🔑 ●●●●●●●●●●●●", fg=C["muted"])
        make_button(pw_r, "👁", toggle_pw, bg_color=C["card"], fg_color=C["txt2"], size=8).pack(side="right")
        make_button(pw_r, "📋", lambda c=cred: self._copy_to_clip(c["password"]),
                    bg_color=C["card"], fg_color=C["txt2"], size=8).pack(side="right", padx=(0,3))

        # Quick Login
        action_r = tk.Frame(card, bg=C["card"]); action_r.pack(fill="x", padx=10, pady=(3,2))
        if site_url:
            make_button(action_r, "🚀 Quick Login", lambda c=cred: self._on_quick_login(c),
                        bg_color=C["accent"], fg_color="white", size=9).pack(side="left")
        # Vencimiento label
        if exp:
            make_label(action_r, f"  📅 Vence: {exp}", 7, color=C["muted"]).pack(side="left", padx=(8,0))

        if cred.get("notes"):
            make_label(card, f"📝 {cred['notes']}", 8, color=C["muted"]).pack(fill="x", padx=10, pady=(1,5))

    def _on_view_history(self, cred):
        history = cred.get("history", [])
        dlg = tk.Toplevel(self.root); dlg.title("🕐 Historial")
        dlg.geometry("400x320"); dlg.configure(bg=C["bg"])
        dlg.transient(self.root); dlg.grab_set()
        x = self.root.winfo_x()+140; y = self.root.winfo_y()+180; dlg.geometry(f"+{x}+{y}")
        make_label(dlg, f"🕐 Historial — {cred.get('title','')}", 12, bold=True).pack(padx=15, pady=(15,5))
        make_label(dlg, "Últimas contraseñas usadas (ocultas por seguridad):", 8, color=C["muted"]).pack(padx=15, pady=(0,10))
        if not history:
            make_label(dlg, "No hay historial aún.", 10, color=C["muted"]).pack(pady=20); return
        for i, h in enumerate(history):
            row = make_card(dlg, hover=False); row.pack(fill="x", padx=15, pady=2, ipady=4, ipadx=8)
            rf  = tk.Frame(row, bg=C["card"]); rf.pack(fill="x", padx=8)
            pw_lbl = make_label(rf, f"#{i+1}  {'●'*min(len(h['password']),20)}", 9, color=C["muted"])
            pw_lbl.pack(side="left")
            date_s = h.get("saved_at","")[:10]
            make_label(rf, f"  {date_s}", 7, color=C["muted"]).pack(side="left")
            def show_pw(lbl=pw_lbl, p=h["password"]):
                lbl.configure(text=f"  {p}", fg=C["green"])
                self.root.after(4000, lambda: _safe_config(lbl, text=f"  {'●'*min(len(p),20)}", fg=C["muted"]))
            make_button(rf, "👁", show_pw, bg_color=C["card"], fg_color=C["txt2"], size=8).pack(side="right")

    def _on_quick_login(self, cred):
        site = cred["site"].strip()
        url  = site if site.startswith(("http://","https://")) else "https://"+site
        self.root.clipboard_clear(); self.root.clipboard_append(cred["email"])
        try: webbrowser.open(url)
        except Exception as e:
            ToastNotification.show(self.root, f"Error: {e}", "error"); return
        ToastNotification.show(self.root, "📧 Email copiado. En 4s se copiará la contraseña.", "info", 3500)
        self.root.after(4000, lambda: (
            self.root.clipboard_clear(),
            self.root.clipboard_append(cred["password"]),
            ToastNotification.show(self.root, "🔑 Contraseña copiada.", "success")
        ))

    def _on_add_credential(self, event=None):
        if not self.vault.is_unlocked:
            ToastNotification.show(self.root, "Desbloquea la bóveda primero.", "warning"); return
        dlg = tk.Toplevel(self.root); dlg.title("➕ Nueva Credencial")
        dlg.geometry("440x540"); dlg.configure(bg=C["bg"])
        dlg.transient(self.root); dlg.grab_set()
        x=self.root.winfo_x()+120; y=self.root.winfo_y()+100; dlg.geometry(f"+{x}+{y}")
        make_label(dlg, "➕ Nueva Credencial", 13, bold=True).pack(padx=15, pady=(15,10))
        entries = {}
        for lbl, key in [("Nombre:","title"),("URL (opcional):","site"),
                          ("Email / Usuario:","email"),("Contraseña:","password"),("Notas (opcional):","notes")]:
            make_label(dlg, lbl, 9, color=C["txt2"]).pack(fill="x", padx=15)
            e = make_entry(dlg, show="●" if key=="password" else None)
            e.pack(fill="x", padx=15, pady=(0,5)); entries[key] = e
        make_label(dlg, "Categoría:", 9, color=C["txt2"]).pack(fill="x", padx=15)
        cat_mb, cat_var = make_combobox_menu(dlg, CATEGORIES, "📁 Otros")
        cat_mb.pack(fill="x", padx=15, pady=(0,5))
        make_label(dlg, "Vence el (YYYY-MM-DD, opcional):", 9, color=C["txt2"]).pack(fill="x", padx=15)
        exp_e = make_entry(dlg); exp_e.pack(fill="x", padx=15, pady=(0,8))
        def save():
            title = entries["title"].get().strip()
            if not title:
                ToastNotification.show(dlg, "Introduce un nombre.", "warning"); return
            exp = exp_e.get().strip() or None
            if exp:
                try: date.fromisoformat(exp)
                except ValueError:
                    ToastNotification.show(dlg, "Fecha inválida. Usa YYYY-MM-DD.", "warning"); return
            try:
                self.vault.add_credential(title, entries["site"].get().strip(),
                    entries["email"].get().strip(), entries["password"].get(),
                    notes=entries["notes"].get().strip(),
                    category=cat_var.get(), expires_at=exp)
                dlg.destroy(); self._refresh_credentials_list()
                ToastNotification.show(self.root, f"'{title}' añadido ✓", "success")
            except Exception as e: ToastNotification.show(dlg, str(e), "error")
        make_button(dlg, "💾 Guardar", save, size=11, bold=True).pack(fill="x", padx=15, pady=(0,12))

    def _on_edit_credential(self, cred):
        dlg = tk.Toplevel(self.root); dlg.title("✏️ Editar")
        dlg.geometry("440x560"); dlg.configure(bg=C["bg"])
        dlg.transient(self.root); dlg.grab_set()
        x=self.root.winfo_x()+120; y=self.root.winfo_y()+90; dlg.geometry(f"+{x}+{y}")
        make_label(dlg, "✏️ Editar Credencial", 13, bold=True).pack(padx=15, pady=(15,10))
        fields = {}
        for lbl, key in [("Nombre:","title"),("URL:","site"),("Email / Usuario:","email"),
                          ("Contraseña:","password"),("Notas:","notes")]:
            make_label(dlg, lbl, 9, color=C["txt2"]).pack(fill="x", padx=15)
            e = make_entry(dlg); e.pack(fill="x", padx=15, pady=(0,5))
            e.insert(0, cred.get(key,"")); fields[key] = e
        make_label(dlg, "Categoría:", 9, color=C["txt2"]).pack(fill="x", padx=15)
        cat_mb, cat_var = make_combobox_menu(dlg, CATEGORIES, cred.get("category","📁 Otros"))
        cat_mb.pack(fill="x", padx=15, pady=(0,5))
        make_label(dlg, "Vence el (YYYY-MM-DD, vacío = sin vencimiento):", 9, color=C["txt2"]).pack(fill="x", padx=15)
        exp_e = make_entry(dlg); exp_e.pack(fill="x", padx=15, pady=(0,8))
        exp_e.insert(0, cred.get("expires_at","") or "")
        def save_edit():
            title = fields["title"].get().strip()
            if not title:
                ToastNotification.show(dlg, "El nombre no puede estar vacío.", "warning"); return
            exp = exp_e.get().strip() or None
            if exp:
                try: date.fromisoformat(exp)
                except ValueError:
                    ToastNotification.show(dlg, "Fecha inválida. Usa YYYY-MM-DD.", "warning"); return
            try:
                self.vault.update_credential(cred["id"], title=title,
                    site=fields["site"].get().strip(), email=fields["email"].get().strip(),
                    password=fields["password"].get(), notes=fields["notes"].get().strip(),
                    category=cat_var.get(), expires_at=exp)
                dlg.destroy(); self._refresh_credentials_list()
                ToastNotification.show(self.root, "Credencial actualizada ✓", "success")
            except Exception as e: ToastNotification.show(dlg, str(e), "error")
        make_button(dlg, "💾 Guardar Cambios", save_edit, size=11, bold=True).pack(fill="x", padx=15, pady=(0,12))

    def _on_delete_credential(self, cred_id):
        if messagebox.askyesno("Confirmar", "¿Eliminar esta credencial? (irreversible)"):
            self.vault.delete_credential(cred_id)
            self._refresh_credentials_list()
            ToastNotification.show(self.root, "Credencial eliminada", "info")

    def _on_lock(self):
        self.vault.lock(); self._show_login_screen()
        ToastNotification.show(self.root, "🔒 Bóveda bloqueada", "info")

    def _on_change_master_password(self):
        dlg = tk.Toplevel(self.root); dlg.title("🔑 Cambiar Contraseña Maestra")
        dlg.geometry("420x360"); dlg.configure(bg=C["bg"])
        dlg.transient(self.root); dlg.grab_set()
        x=self.root.winfo_x()+120; y=self.root.winfo_y()+130; dlg.geometry(f"+{x}+{y}")
        make_label(dlg, "🔑 Cambiar Contraseña Maestra", 13, bold=True).pack(padx=15, pady=(15,5))
        make_label(dlg, "Se creará un backup automático antes del cambio.", 8, color=C["green"]).pack(padx=15, pady=(0,12))
        make_label(dlg, "Contraseña actual:", 9, color=C["txt2"]).pack(fill="x", padx=15)
        cur_e = make_entry(dlg, show="●", font_size=12); cur_e.pack(fill="x", padx=15, pady=(0,8))
        make_label(dlg, "Nueva contraseña (mín. 8):", 9, color=C["txt2"]).pack(fill="x", padx=15)
        new_e = make_entry(dlg, show="●", font_size=12); new_e.pack(fill="x", padx=15, pady=(0,8))
        make_label(dlg, "Confirmar nueva:", 9, color=C["txt2"]).pack(fill="x", padx=15)
        conf_e = make_entry(dlg, show="●", font_size=12); conf_e.pack(fill="x", padx=15, pady=(0,10))
        status_lbl = make_label(dlg, "", 9, color=C["red"]); status_lbl.pack(padx=15)
        def do_change():
            cur = cur_e.get(); new = new_e.get(); conf = conf_e.get()
            if not all([cur,new,conf]):
                _safe_config(status_lbl, text="Completa todos los campos.", fg=C["yellow"]); return
            if new != conf:
                _safe_config(status_lbl, text="Las nuevas contraseñas no coinciden.", fg=C["red"]); return
            if len(new) < 8:
                _safe_config(status_lbl, text="Mínimo 8 caracteres.", fg=C["yellow"]); return
            _safe_config(status_lbl, text="⏳ Derivando clave…", fg=C["yellow"])
            dlg.update_idletasks()
            try:
                ok = self.vault.change_master_password(cur, new)
                if ok:
                    dlg.destroy()
                    ToastNotification.show(self.root, "✅ Contraseña cambiada. Backup creado.", "success", 4000)
                else:
                    _safe_config(status_lbl, text="❌ Contraseña actual incorrecta.", fg=C["red"])
            except Exception as e:
                _safe_config(status_lbl, text=f"Error: {e}", fg=C["red"])
        make_button(dlg, "🔑 Cambiar", do_change,
                    bg_color=C["yellow"], fg_color="#000", size=11, bold=True).pack(fill="x", padx=15, pady=10)

    def _on_export(self):
        path = filedialog.asksaveasfilename(
            title="Exportar", defaultextension=".pmex",
            filetypes=[("PM Export","*.pmex"),("Todos","*.*")],
            initialfile=f"backup_{datetime.now().strftime('%Y%m%d')}.pmex")
        if not path: return
        dlg = tk.Toplevel(self.root); dlg.title("Contraseña de Exportación")
        dlg.geometry("380x180"); dlg.configure(bg=C["bg"])
        dlg.transient(self.root); dlg.grab_set()
        make_label(dlg, "🔑 Contraseña para el archivo:", 10, color=C["txt2"]).pack(fill="x", padx=15, pady=(15,5))
        pw_e = make_entry(dlg, show="●", font_size=12); pw_e.pack(fill="x", padx=15, pady=(0,10))
        def do_export():
            pw = pw_e.get()
            if len(pw) < 4:
                ToastNotification.show(dlg, "Mínimo 4 caracteres.", "warning"); return
            try:
                self.vault.export_encrypted(path, pw); dlg.destroy()
                ToastNotification.show(self.root, f"✅ Exportado: {os.path.basename(path)}", "success")
            except Exception as e: ToastNotification.show(dlg, str(e), "error")
        make_button(dlg, "📤 Exportar", do_export, size=11, bold=True).pack(fill="x", padx=15, pady=5)

    def _on_import(self):
        path = filedialog.askopenfilename(
            title="Importar", filetypes=[("PM Export","*.pmex"),("Todos","*.*")])
        if not path: return
        dlg = tk.Toplevel(self.root); dlg.title("Contraseña de Importación")
        dlg.geometry("380x180"); dlg.configure(bg=C["bg"])
        dlg.transient(self.root); dlg.grab_set()
        make_label(dlg, "🔑 Contraseña del archivo:", 10, color=C["txt2"]).pack(fill="x", padx=15, pady=(15,5))
        pw_e = make_entry(dlg, show="●", font_size=12); pw_e.pack(fill="x", padx=15, pady=(0,10))
        def do_import():
            try:
                count = self.vault.import_encrypted(path, pw_e.get())
                dlg.destroy(); self._refresh_credentials_list()
                ToastNotification.show(self.root, f"✅ {count} credenciales importadas", "success")
            except Exception as e: ToastNotification.show(dlg, str(e), "error")
        make_button(dlg, "📥 Importar", do_import, size=11, bold=True).pack(fill="x", padx=15, pady=5)

    def _on_import_csv(self):
        """Diálogo de importación CSV con selector de fuente y tutorial."""
        if not self.vault.is_unlocked:
            ToastNotification.show(self.root, "Desbloquea la bóveda primero.", "warning"); return

        dlg = tk.Toplevel(self.root); dlg.title("📊 Importar desde navegador / gestor")
        dlg.geometry("560x640"); dlg.configure(bg=C["bg"])
        dlg.transient(self.root); dlg.grab_set()
        x=self.root.winfo_x()+60; y=self.root.winfo_y()+60; dlg.geometry(f"+{x}+{y}")

        make_label(dlg, "📊 Importar Contraseñas", 13, bold=True).pack(padx=15, pady=(15,5))
        make_label(dlg, "Elige el origen para ver el tutorial de exportación:", 9, color=C["txt2"]).pack(padx=15, pady=(0,10))

        # Selector de fuente
        sources = list(CSV_TUTORIALS.keys())
        source_var = tk.StringVar(value="chrome")
        btn_row = tk.Frame(dlg, bg=C["bg"]); btn_row.pack(fill="x", padx=15, pady=(0,8))
        source_btns = {}
        for src in sources:
            t = CSV_TUTORIALS[src]
            b = tk.Button(btn_row, text=f"{t['icon']} {t['name'].split()[0]}",
                font=(FONT,8,"bold"), bg=C["input"], fg=C["txt"],
                activebackground=C["hover"], relief="flat", cursor="hand2",
                padx=8, pady=5, borderwidth=0)
            b.pack(side="left", padx=2)
            source_btns[src] = b

        # Panel tutorial
        tut_card = make_card(dlg, hover=False); tut_card.pack(fill="x", padx=15, pady=(0,8), ipady=6, ipadx=10)
        tut_title = make_label(tut_card, "", 10, bold=True); tut_title.pack(fill="x", padx=10, pady=(8,5))
        tut_frame = tk.Frame(tut_card, bg=C["card"]); tut_frame.pack(fill="x", padx=10, pady=(0,8))
        tut_labels = []

        def show_tutorial(src):
            source_var.set(src)
            t = CSV_TUTORIALS[src]
            for sb in source_btns.values():
                _safe_config(sb, bg=C["input"], fg=C["txt"])
            _safe_config(source_btns[src], bg=t["color"], fg="white")
            tut_title.configure(text=f"{t['icon']}  Cómo exportar desde {t['name']}", fg=t["color"])
            for lbl in tut_labels: lbl.destroy()
            tut_labels.clear()
            for step in t["steps"]:
                color = C["yellow"] if step.startswith("⚠️") else C["txt2"] if step.startswith(" ") else C["txt"]
                lbl = make_label(tut_frame, step, 8, color=color)
                lbl.pack(fill="x", pady=1)
                tut_labels.append(lbl)

        for src in sources:
            source_btns[src].configure(command=lambda s=src: show_tutorial(s))
        show_tutorial("chrome")

        # Selector de archivo
        file_frame = tk.Frame(dlg, bg=C["bg"]); file_frame.pack(fill="x", padx=15, pady=(0,8))
        file_var = tk.StringVar(value="")
        make_label(file_frame, "Archivo CSV:", 9, color=C["txt2"]).pack(anchor="w")
        file_row = tk.Frame(file_frame, bg=C["bg"]); file_row.pack(fill="x")
        file_entry = make_entry(file_row, font_size=9)
        file_entry.configure(textvariable=file_var, state="readonly")
        file_entry.pack(side="left", fill="x", expand=True, padx=(0,8))
        def browse():
            p = filedialog.askopenfilename(
                title="Seleccionar CSV", filetypes=[("CSV","*.csv"),("Todos","*.*")])
            if p: file_var.set(p)
        make_button(file_row, "📁 Buscar", browse, bg_color=C["input"], fg_color=C["txt"], size=9).pack(side="left")

        status_lbl = make_label(dlg, "", 9, color=C["muted"]); status_lbl.pack(padx=15)

        def do_import():
            path = file_var.get()
            if not path:
                ToastNotification.show(dlg, "Selecciona un archivo CSV.", "warning"); return
            src = source_var.get()
            _safe_config(status_lbl, text="⏳ Importando…", fg=C["yellow"])
            dlg.update_idletasks()
            try:
                count = self.vault.import_csv(path, src)
                dlg.destroy()
                self._refresh_credentials_list()
                ToastNotification.show(self.root, f"✅ {count} contraseñas importadas desde {CSV_TUTORIALS[src]['name']}", "success", 4000)
                if count > 0:
                    messagebox.showinfo("⚠️ Recuerda", "Importación completada.\n\n"
                        "⚠️  ELIMINA el archivo CSV ahora — contiene contraseñas en texto plano.")
            except Exception as e:
                _safe_config(status_lbl, text=f"Error: {e}", fg=C["red"])

        make_button(dlg, "📊  Importar Contraseñas", do_import,
                    size=11, bold=True, glow=True).pack(fill="x", padx=15, pady=(0,15))

    # ══════════════════════════════════════════════════════
    # ══════════════════════════════════════════════════════
    #  TAB 3: SEGURIDAD
    # ══════════════════════════════════════════════════════

    def _build_security_tab(self):
        canvas = tk.Canvas(self.security_frame, bg=C["bg"], highlightthickness=0)
        sb     = tk.Scrollbar(self.security_frame, orient="vertical", command=canvas.yview)
        inner  = tk.Frame(canvas, bg=C["bg"])
        inner.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0,0), window=inner, anchor="nw")
        canvas.configure(yscrollcommand=sb.set)
        canvas.bind("<Configure>", lambda e: canvas.itemconfig(canvas.find_all()[0], width=e.width))
        sb.pack(side="right", fill="y"); canvas.pack(side="left", fill="both", expand=True)
        f = tk.Frame(inner, bg=C["bg"]); f.pack(fill="both", expand=True, padx=20, pady=10)

        make_label(f, "🛡️ Centro de Seguridad", 16, bold=True, color=C["accent"]).pack(fill="x", pady=(0,2))
        make_label(f, "Herramientas de verificación y gestión de datos", 9, color=C["txt2"]).pack(fill="x", pady=(0,15))

        # ── Card 1: Verificar HIBP ──
        hc = make_card(f, hover=False); hc.pack(fill="x", pady=(0,10), ipady=5, ipadx=10)
        make_label(hc, "🔍  VERIFICAR CONTRASEÑA (HIBP)", 9, bold=True, color=C["txt2"]).pack(fill="x", padx=12, pady=(8,3))
        make_label(hc, "Solo se envían 5 chars del hash SHA-1. Tu contraseña nunca sale del dispositivo.", 8, color=C["muted"]).pack(fill="x", padx=12, pady=(0,8))
        input_f = tk.Frame(hc, bg=C["card"]); input_f.pack(fill="x", padx=12, pady=(0,5))
        self.hibp_manual_entry = make_entry(input_f, show="●", font_size=12)
        self.hibp_manual_entry.pack(side="left", fill="x", expand=True, padx=(0,8))
        self.hibp_manual_entry.bind("<Return>", lambda e: self._on_manual_hibp_check())
        self._hibp_pw_visible = False
        def toggle_hibp_vis():
            self._hibp_pw_visible = not self._hibp_pw_visible
            self.hibp_manual_entry.configure(show="" if self._hibp_pw_visible else "●")
            _safe_config(vis_btn, text="🙈" if self._hibp_pw_visible else "👁")
        vis_btn = make_button(input_f, "👁", toggle_hibp_vis, bg_color=C["card"], fg_color=C["txt2"], size=9)
        vis_btn.pack(side="left")
        make_button(hc, "🛡️  Verificar en HIBP", self._on_manual_hibp_check,
                    size=11, bold=True, glow=True).pack(fill="x", padx=12, pady=(5,5))
        self.hibp_manual_result = make_label(hc, "", 10, color=C["muted"])
        self.hibp_manual_result.pack(fill="x", padx=12, pady=(0,8))

        # ── Card 2: Auditar bóveda ──
        ac = make_card(f, hover=False); ac.pack(fill="x", pady=(0,10), ipady=5, ipadx=10)
        make_label(ac, "📊  AUDITORÍA DE BÓVEDA", 9, bold=True, color=C["txt2"]).pack(fill="x", padx=12, pady=(8,3))
        make_label(ac, "Verifica TODAS las contraseñas contra HIBP + detecta duplicados y débiles.", 8, color=C["muted"]).pack(fill="x", padx=12, pady=(0,8))
        make_button(ac, "🔎  Auditar Todas", self._on_audit_vault,
                    size=11, bold=True, glow=True).pack(fill="x", padx=12, pady=(0,5))
        self.audit_progress = make_label(ac, "", 9, color=C["muted"]); self.audit_progress.pack(fill="x", padx=12)
        self.audit_results_frame = tk.Frame(ac, bg=C["card"]); self.audit_results_frame.pack(fill="x", padx=12, pady=(5,8))

        # ── Card 3: Modo portátil ──
        pm = make_card(f, hover=False); pm.pack(fill="x", pady=(0,10), ipady=5, ipadx=10)
        make_label(pm, "💾  MODO PORTÁTIL (USB)", 9, bold=True, color=C["txt2"]).pack(fill="x", padx=12, pady=(8,3))
        current_mode = "PORTÁTIL" if _is_portable_mode() else "NORMAL (AppData)"
        mode_color   = C["green"] if _is_portable_mode() else C["cyan"]
        make_label(pm, f"Modo actual: {current_mode}", 9, bold=True, color=mode_color).pack(fill="x", padx=12, pady=(0,4))
        make_label(pm, "En modo portátil los datos se guardan junto al .exe (ideal para USB).\n"
                       "En modo normal se guardan en AppData (recomendado para uso fijo).", 8, color=C["muted"]).pack(fill="x", padx=12, pady=(0,8))
        pf = tk.Frame(pm, bg=C["card"]); pf.pack(fill="x", padx=12, pady=(0,8))
        make_button(pf, "✅ Activar Modo Portátil",   self._on_enable_portable,
                    bg_color=C["green_dim"], fg_color="white", size=9, bold=True).pack(side="left", padx=(0,6))
        make_button(pf, "❌ Desactivar Modo Portátil", self._on_disable_portable,
                    bg_color=C["input"], fg_color=C["txt2"], size=9).pack(side="left")

        # ── Card 4: Protecciones activas ──
        ic = make_card(f, hover=False); ic.pack(fill="x", pady=(0,10), ipady=5, ipadx=10)
        make_label(ic, "ℹ️  PROTECCIONES ACTIVAS", 9, bold=True, color=C["txt2"]).pack(fill="x", padx=12, pady=(8,5))
        from crypto_vault import ARGON2_AVAILABLE as _A2
        kdf_text = "Argon2id (64MB, t=3, p=4)" if _A2 else "PBKDF2-HMAC-SHA256 600k iter"
        kdf_col  = C["green"] if _A2 else C["yellow"]
        prots = [
            ("🔐", "AES-256-GCM",       "Cifrado autenticado de la bóveda"),
            ("🔑", kdf_text,             "Función de derivación de clave (KDF)"),
            ("📋", "Auto-limpieza",      "Portapapeles se borra en 30s"),
            ("⏰", "Auto-bloqueo",       f"Bóveda se bloquea tras {self.AUTO_LOCK_MINUTES} min"),
            ("🖥️", "Anti-captura",       "Protección contra screenshots (Windows)"),
            ("👁", "Auto-ocultar",       "Contraseñas se ocultan a los 5s"),
            ("🛡️", "HIBP k-Anonymity",   "Solo 5 chars del hash, nunca la contraseña"),
            ("🔁", "Detección duplicados","Avisa si reutilizas contraseñas"),
            ("🕐", "Historial",          f"Guarda las {5} últimas contraseñas por cuenta"),
            ("🔒", "Anti-brute-force",   "Bloqueo exponencial tras 5 intentos fallidos"),
            ("⌨️", "Atajos de teclado",  "Ctrl+G, Ctrl+C, Ctrl+L, Ctrl+F, Ctrl+N"),
        ]
        for icon, title, desc in prots:
            row = tk.Frame(ic, bg=C["card"]); row.pack(fill="x", padx=12, pady=1)
            col = kdf_col if "KDF" in desc or "Argon" in title else C["green"]
            make_label(row, f"{icon} {title}", 9, bold=True, color=col).pack(side="left")
            make_label(row, f"  —  {desc}", 8, color=C["muted"]).pack(side="left")

        # ── Card 5: Gestión de datos ──
        dc = make_card(f, hover=False); dc.pack(fill="x", pady=(0,10), ipady=5, ipadx=10)
        make_label(dc, "📁  GESTIÓN DE DATOS", 9, bold=True, color=C["txt2"]).pack(fill="x", padx=12, pady=(8,3))
        self.data_info_frame = tk.Frame(dc, bg=C["card"]); self.data_info_frame.pack(fill="x", padx=12, pady=(0,8))
        self._refresh_data_info()
        open_f = tk.Frame(dc, bg=C["card"]); open_f.pack(fill="x", padx=12, pady=(0,5))
        make_button(open_f, "📂 Abrir Carpeta", self._on_open_data_folder,
                    bg_color=C["input"], fg_color=C["cyan"], size=9).pack(side="left")
        make_button(open_f, "🔄 Refrescar", self._refresh_data_info,
                    bg_color=C["input"], fg_color=C["txt2"], size=8).pack(side="left", padx=(8,0))
        make_separator(dc, 5)
        for lbl_text, lbl_color, desc_text, btn_text, btn_cmd, btn_bg in [
            ("💾 Backup Manual", C["green"], "Copia de seguridad de vault.enc en backups/",
             "💾 Crear Backup",  self._on_create_backup, C["green_dim"]),
            ("🗂️ Borrar Logs",   C["yellow"], "Elimina archivos de log (la bóveda no se ve afectada)",
             "🗑️ Borrar Logs",   self._on_delete_logs,   C["input"]),
            ("🔐 Borrar Bóveda", C["red"], "Elimina vault.enc (doble confirmación + texto)",
             "🗑️ Borrar Bóveda", self._on_delete_vault_only, C["input"]),
        ]:
            sec = tk.Frame(dc, bg=C["card"]); sec.pack(fill="x", padx=12, pady=(0,5))
            make_label(sec, lbl_text, 9, bold=True, color=lbl_color).pack(anchor="w")
            make_label(sec, desc_text, 8, color=C["muted"]).pack(anchor="w")
            make_button(sec, btn_text, btn_cmd,
                        bg_color=btn_bg, fg_color=lbl_color, size=9, bold=True).pack(fill="x", pady=(3,0))
            make_separator(dc, 4)
        make_label(dc, "💀  Eliminar TODO: usa el botón 'Zona de Peligro' en la pestaña Contraseñas.", 8, color=C["red"]).pack(padx=12, pady=(0,8))

    def _on_manual_hibp_check(self):
        pw = self.hibp_manual_entry.get()
        if not pw:
            ToastNotification.show(self.root, "Introduce una contraseña.", "info"); return
        self.hibp_manual_result.configure(text="⏳ Verificando…", fg=C["yellow"])
        self.root.update_idletasks()
        def check():
            r = self.engine.check_hibp(pw)
            def upd():
                if r["compromised"] is None:   self.hibp_manual_result.configure(text=r["message"], fg=C["yellow"])
                elif r["compromised"]:          self.hibp_manual_result.configure(text=r["message"], fg=C["red"]); ToastNotification.show(self.root,"⚠️ ¡Comprometida!","error",4000)
                else:                           self.hibp_manual_result.configure(text=r["message"], fg=C["green"]); ToastNotification.show(self.root,"✅ Segura","success")
            self.root.after(0, upd)
        threading.Thread(target=check, daemon=True).start()

    def _on_audit_vault(self):
        if not self.vault.is_unlocked:
            ToastNotification.show(self.root, "Desbloquea la bóveda primero.", "warning"); return
        creds = self.vault.credentials
        if not creds:
            ToastNotification.show(self.root, "No hay credenciales.", "info"); return
        for w in self.audit_results_frame.winfo_children(): w.destroy()
        total = len(creds)
        self.audit_progress.configure(text=f"⏳ Auditando {total} contraseñas…", fg=C["yellow"])
        self.root.update_idletasks()
        def audit():
            results = []
            for i, cred in enumerate(creds):
                self.root.after(0, lambda i=i: self.audit_progress.configure(
                    text=f"⏳ Verificando {i+1}/{total}…", fg=C["yellow"]))
                results.append((cred, self.engine.check_hibp(cred["password"])))
                time.sleep(0.2)
            def show_results():
                compromised = [(c,h) for c,h in results if h.get("compromised")]
                dup_ids = set(); [dup_ids.update(v) for v in self.vault.find_duplicates().values()]
                weak_pw = [c for c in creds if len(c["password"])<10 or c["password"].isalpha() or c["password"].isdigit()]
                issues  = len(compromised) + len([c for c in creds if c["id"] in dup_ids]) + len(weak_pw)
                if issues == 0:
                    self.audit_progress.configure(text=f"✅ {total} contraseñas: todo OK", fg=C["green"])
                    ToastNotification.show(self.root, "✅ Auditoría completada: todo seguro", "success")
                else:
                    self.audit_progress.configure(text=f"⚠️ {issues} problemas de {total} contraseñas:", fg=C["red"])
                for cred, hibp in compromised:
                    row = tk.Frame(self.audit_results_frame, bg=C["card"]); row.pack(fill="x", pady=2)
                    make_label(row, f"🔴 {cred.get('title','?')}  —  {hibp.get('breach_count',0):,} filtraciones", 9, bold=True, color=C["red"]).pack(side="left")
                for cred in weak_pw:
                    if any(c["id"]==cred["id"] for c,_ in compromised): continue
                    row = tk.Frame(self.audit_results_frame, bg=C["card"]); row.pack(fill="x", pady=2)
                    make_label(row, f"🟡 {cred.get('title','?')}  —  Contraseña débil", 9, bold=True, color=C["yellow"]).pack(side="left")
                for cred in creds:
                    if cred["id"] in dup_ids and not any(c["id"]==cred["id"] for c,_ in compromised):
                        row = tk.Frame(self.audit_results_frame, bg=C["card"]); row.pack(fill="x", pady=2)
                        make_label(row, f"🔁 {cred.get('title','?')}  —  Contraseña duplicada", 9, bold=True, color=C["txt2"]).pack(side="left")
            self.root.after(0, show_results)
        threading.Thread(target=audit, daemon=True).start()

    # ── Modo portátil ─────────────────────────────────

    def _on_enable_portable(self):
        flag = os.path.join(_get_exe_dir(), "portable.flag")
        if os.path.isfile(flag):
            ToastNotification.show(self.root, "El modo portátil ya está activo.", "info"); return
        if messagebox.askyesno("Activar Modo Portátil",
                "¿Activar modo portátil?\n\n"
                "Los datos se guardarán junto al .exe en vez de en AppData.\n"
                "Útil para llevar la app en un USB.\n\n"
                "La app se reiniciará para aplicar el cambio."):
            try:
                open(flag, "w").close()
                messagebox.showinfo("✅ Modo Portátil Activado",
                    "Modo portátil activado.\nReinicia la aplicación para aplicar el cambio.\n\n"
                    f"Los nuevos datos se guardarán en:\n{_get_exe_dir()}")
                self.root.destroy(); sys.exit(0)
            except Exception as e:
                ToastNotification.show(self.root, f"Error: {e}", "error")

    def _on_disable_portable(self):
        flag = os.path.join(_get_exe_dir(), "portable.flag")
        if not os.path.isfile(flag):
            ToastNotification.show(self.root, "El modo portátil ya está desactivado.", "info"); return
        if messagebox.askyesno("Desactivar Modo Portátil",
                "¿Desactivar modo portátil?\n\n"
                "Los datos volverán a guardarse en AppData.\n"
                "La app se reiniciará para aplicar el cambio."):
            try:
                os.remove(flag)
                messagebox.showinfo("✅ Modo Normal Activado",
                    "Modo portátil desactivado.\nReinicia la aplicación.")
                self.root.destroy(); sys.exit(0)
            except Exception as e:
                ToastNotification.show(self.root, f"Error: {e}", "error")

    # ── Gestión de datos ──────────────────────────────

    def _get_dir_size(self, path):
        total = 0
        try:
            for entry in os.scandir(path):
                if entry.is_file():   total += entry.stat().st_size
                elif entry.is_dir():  total += self._get_dir_size(entry.path)
        except Exception: pass
        return total

    def _fmt_size(self, b):
        if b < 1024: return f"{b} B"
        elif b < 1024*1024: return f"{b/1024:.1f} KB"
        return f"{b/(1024*1024):.2f} MB"

    def _refresh_data_info(self):
        if not hasattr(self, 'data_info_frame'): return
        for w in self.data_info_frame.winfo_children(): w.destroy()
        vault_path  = os.path.join(APP_DIR, "vault.enc")
        log_dir     = os.path.join(APP_DIR, "logs")
        backup_dir  = os.path.join(APP_DIR, "backups")
        if os.path.isfile(vault_path):
            sz  = os.path.getsize(vault_path)
            mts = datetime.fromtimestamp(os.path.getmtime(vault_path)).strftime("%d/%m/%Y %H:%M")
            make_label(self.data_info_frame, f"🔐 vault.enc  —  {self._fmt_size(sz)}  —  {mts}", 8, color=C["green"]).pack(anchor="w")
        else:
            make_label(self.data_info_frame, "🔐 vault.enc  —  No existe", 8, color=C["muted"]).pack(anchor="w")
        if os.path.isdir(log_dir):
            n   = len([f for f in os.listdir(log_dir) if f.endswith(".log")])
            sz  = self._get_dir_size(log_dir)
            make_label(self.data_info_frame, f"📋 Logs  —  {n} archivos  —  {self._fmt_size(sz)}", 8, color=C["txt2"]).pack(anchor="w")
        if os.path.isdir(backup_dir):
            n   = len([f for f in os.listdir(backup_dir) if f.endswith(".enc")])
            sz  = self._get_dir_size(backup_dir)
            make_label(self.data_info_frame, f"💾 Backups  —  {n} archivos  —  {self._fmt_size(sz)}", 8, color=C["txt2"]).pack(anchor="w")
        make_label(self.data_info_frame, f"📂 {APP_DIR}", 7, color=C["muted"], font_family=MONO).pack(anchor="w", pady=(4,0))

    def _on_open_data_folder(self):
        try:
            if sys.platform=="win32": os.startfile(APP_DIR)
            elif sys.platform=="darwin": import subprocess; subprocess.Popen(["open",APP_DIR])
            else: import subprocess; subprocess.Popen(["xdg-open",APP_DIR])
            ToastNotification.show(self.root, "📂 Carpeta abierta", "info")
        except Exception as e: ToastNotification.show(self.root, f"Error: {e}", "error")

    def _on_create_backup(self):
        if not os.path.isfile(os.path.join(APP_DIR,"vault.enc")):
            ToastNotification.show(self.root, "No hay bóveda para hacer backup.", "warning"); return
        try:
            p = self.vault.create_backup()
            ToastNotification.show(self.root, f"✅ Backup: {os.path.basename(p)}", "success", 4000)
            self._refresh_data_info()
        except Exception as e: ToastNotification.show(self.root, f"Error: {e}", "error")

    def _on_delete_logs(self):
        log_dir = os.path.join(APP_DIR,"logs")
        if not os.path.isdir(log_dir):
            ToastNotification.show(self.root, "No hay logs.", "info"); return
        n = len([f for f in os.listdir(log_dir) if f.endswith(".log")])
        if n==0:
            ToastNotification.show(self.root, "No hay logs.", "info"); return
        if not messagebox.askyesno("Borrar Logs", f"¿Eliminar {n} log(s)?\nLa bóveda no se ve afectada."): return
        try:
            for h in list(root_logger.handlers):
                if isinstance(h, logging.FileHandler): h.close(); root_logger.removeHandler(h)
            deleted = 0
            for fn in os.listdir(log_dir):
                if fn.endswith(".log"):
                    try: os.remove(os.path.join(log_dir,fn)); deleted+=1
                    except Exception: pass
            ToastNotification.show(self.root, f"✅ {deleted} log(s) eliminados.", "success")
            self._refresh_data_info()
        except Exception as e: ToastNotification.show(self.root, f"Error: {e}", "error")

    def _on_delete_vault_only(self):
        vault_path = os.path.join(APP_DIR,"vault.enc")
        if not os.path.isfile(vault_path):
            ToastNotification.show(self.root, "No hay bóveda.", "info"); return
        if not messagebox.askyesno("⚠️ Borrar Bóveda",
                "¿Eliminar vault.enc?\n\nTodas tus contraseñas se borrarán.\n⚠️ IRREVERSIBLE."): return
        if not messagebox.askyesno("⚠️ Segunda confirmación", "¿Confirmas borrar la bóveda?\nNo hay forma de recuperarla."): return
        dlg = tk.Toplevel(self.root); dlg.title("Confirmación Final")
        dlg.geometry("400x190"); dlg.configure(bg=C["bg"])
        dlg.transient(self.root); dlg.grab_set()
        x=self.root.winfo_x()+130; y=self.root.winfo_y()+240; dlg.geometry(f"+{x}+{y}")
        make_label(dlg, "Escribe  BORRAR_VAULT  para confirmar:", 10, color=C["red"]).pack(padx=15, pady=(18,5))
        make_label(dlg, "(Solo la bóveda — logs y backups se conservan)", 8, color=C["muted"]).pack(padx=15, pady=(0,8))
        confirm_e = make_entry(dlg, font_size=12); confirm_e.pack(fill="x", padx=15, pady=(0,10))
        def do_delete():
            if confirm_e.get().strip() != "BORRAR_VAULT":
                ToastNotification.show(dlg, "Escribe exactamente: BORRAR_VAULT", "warning"); return
            dlg.destroy()
            if self.vault.is_unlocked: self.vault.lock()
            try:
                os.remove(vault_path)
                ToastNotification.show(self.root, "✅ Bóveda eliminada.", "success", 4000)
                self._refresh_data_info(); self._show_create_master_screen()
            except Exception as e: ToastNotification.show(self.root, f"Error: {e}", "error")
        make_button(dlg, "🗑️ BORRAR SOLO LA BÓVEDA", do_delete,
                    bg_color=C["red"], fg_color="white", size=10, bold=True).pack(fill="x", padx=15, pady=5)

    # ══════════════════════════════════════════════════════
    #  ZONA DE PELIGRO (métodos compartidos)
    # ══════════════════════════════════════════════════════

    def _danger_confirmation_dialog(self, title, lines, keyword, btn_label, btn_color,
                                    extra_warning=None, on_confirm=None):
        if not messagebox.askyesno(f"⚠️  {title}", "\n".join(lines)): return
        body2 = f"¿CONFIRMAS {title.lower()}?\nEsta acción es IRREVERSIBLE."
        if extra_warning: body2 += f"\n\n{extra_warning}"
        if not messagebox.askyesno(f"⚠️  Segunda confirmación", body2): return
        dlg = tk.Toplevel(self.root); dlg.title(f"Confirmación Final — {title}")
        dlg.geometry("430x210"); dlg.configure(bg=C["bg"])
        dlg.transient(self.root); dlg.grab_set(); dlg.resizable(False,False)
        x=self.root.winfo_x()+115; y=self.root.winfo_y()+220; dlg.geometry(f"+{x}+{y}")
        make_label(dlg, "Escribe exactamente para continuar:", 9, color=C["txt2"]).pack(padx=16, pady=(18,4))
        tk.Label(dlg, text=keyword, font=(MONO,13,"bold"), bg=C["bg"], fg=C["red"]).pack(padx=16, pady=(0,10))
        confirm_e = make_entry(dlg, font_size=12); confirm_e.pack(fill="x", padx=16, pady=(0,8))
        confirm_e.focus_set()
        status_lbl = make_label(dlg, "", 8, color=C["red"]); status_lbl.pack(padx=16)
        def attempt():
            if confirm_e.get().strip() != keyword:
                _safe_config(status_lbl, text=f"Incorrecto. Escribe: {keyword}"); return
            dlg.destroy()
            if on_confirm: on_confirm()
        confirm_e.bind("<Return>", lambda e: attempt())
        make_button(dlg, btn_label, attempt, bg_color=btn_color, fg_color="white",
                    size=10, bold=True).pack(fill="x", padx=16, pady=(4,12))

    def _on_delete_all_data_from_vault(self):
        def do():
            if self.vault.is_unlocked: self.vault.lock()
            for h in list(root_logger.handlers):
                if isinstance(h, logging.FileHandler): h.close(); root_logger.removeHandler(h)
            if os.path.isdir(APP_DIR): shutil.rmtree(APP_DIR, ignore_errors=True)
            messagebox.showinfo("✅ Datos Eliminados",
                "Todos los datos han sido eliminados.\n\n• vault.enc ✓\n• logs/ ✓\n• backups/ ✓\n\n"
                "La aplicación se cerrará.\nEl archivo .exe sigue en su lugar.")
            self.root.destroy(); sys.exit(0)
        self._danger_confirmation_dialog(
            title="Eliminar todos los datos",
            lines=["¿Eliminar TODOS los datos?\n",
                   "  • vault.enc  — TODAS tus contraseñas",
                   "  • logs/      — registros de actividad",
                   "  • backups/   — copias de seguridad\n",
                   "⚠️  El archivo .exe NO se elimina.",
                   "⚠️  Esta acción es IRREVERSIBLE."],
            keyword="BORRAR DATOS", btn_label="🗑️  ELIMINAR TODOS LOS DATOS",
            btn_color=C["red"],
            extra_warning="Exporta un .pmex antes si quieres conservar tus contraseñas.",
            on_confirm=do)

    def _on_uninstall_app(self):
        if getattr(sys,'frozen',False):
            app_file = os.path.abspath(sys.executable); is_exe = True
        else:
            app_file = os.path.abspath(__file__); is_exe = False
        app_name = os.path.basename(app_file)
        def do():
            if self.vault.is_unlocked: self.vault.lock()
            for h in list(root_logger.handlers):
                if isinstance(h, logging.FileHandler): h.close(); root_logger.removeHandler(h)
            if os.path.isdir(APP_DIR): shutil.rmtree(APP_DIR, ignore_errors=True)
            deleted_exe = False
            if sys.platform=="win32" and is_exe:
                bat = os.path.join(os.path.dirname(app_file),"_uninstall_tmp.bat")
                try:
                    with open(bat,"w") as bf:
                        bf.write(f'@echo off\ntimeout /t 2 /nobreak >nul\ndel /f /q "{app_file}"\ndel /f /q "%~f0"\n')
                    import subprocess
                    subprocess.Popen(["cmd","/c",bat],creationflags=subprocess.CREATE_NO_WINDOW,close_fds=True)
                    deleted_exe = True
                except Exception: pass
            else:
                try: os.remove(app_file); deleted_exe = True
                except Exception: pass
            exe_st = f"  • {app_name}  ✓" if deleted_exe else f"  • {app_name}  ⚠️ borrar manualmente"
            messagebox.showinfo("✅ Desinstalación Completada",
                f"Se han eliminado:\n\n  • vault.enc ✓\n  • logs/ ✓\n  • backups/ ✓\n{exe_st}\n\nCerrando.")
            self.root.destroy(); sys.exit(0)
        self._danger_confirmation_dialog(
            title="Desinstalar la aplicación",
            lines=["¿Desinstalar COMPLETAMENTE la aplicación?\n",
                   f"  • vault.enc — TODAS tus contraseñas",
                   "  • logs/ y backups/",
                   f"  • {app_name}  (el ejecutable)\n",
                   "💀  NO quedará NINGÚN archivo.",
                   "⚠️  Esta acción es IRREVERSIBLE."],
            keyword="DESINSTALAR APP", btn_label="💀  DESINSTALAR Y BORRAR TODO",
            btn_color="#660000",
            extra_warning="Exporta un .pmex ANTES. No habrá forma de recuperar nada.",
            on_confirm=do)

    def _on_uninstall_data(self):
        """Alias mantenido por compatibilidad — redirige al nuevo método."""
        self._on_delete_all_data_from_vault()

    # ══════════════════════════════════════════════════════
    #  RUN
    # ══════════════════════════════════════════════════════

    def run(self):
        logger.info("Lanzando aplicación…")
        try: self.root.mainloop()
        except KeyboardInterrupt: logger.info("Interrumpido")
        finally:
            if self.vault.is_unlocked: self.vault.lock()
            logger.info("Aplicación cerrada")


# ═══════════════════════════════════════════════════════════════
#  MAIN
# ═══════════════════════════════════════════════════════════════

if __name__ == "__main__":
    try:
        app = PasswordManagerApp()
        app.run()
    except Exception as e:
        logger.critical(f"Error fatal: {e}", exc_info=True)
        print(f"\n[ERROR FATAL] {e}\nLog: {log_filename}")
        input("Presiona Enter para salir…")
        sys.exit(1)