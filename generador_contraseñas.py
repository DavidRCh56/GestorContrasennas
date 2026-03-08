"""
╔══════════════════════════════════════════════════════════════╗
║     GESTOR DE CONTRASEÑAS SEGURO v3.0                        ║
║                                                              ║
║  • Generador con passphrases + verificación HIBP             ║
║  • Bóveda AES-256-GCM con categorías                        ║
║  • UI moderna con animaciones dinámicas                      ║
║  • Búsqueda, auto-bloqueo, export/import                    ║
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
from datetime import datetime

# Módulos propios
from password_engine import PasswordEngine
from crypto_vault import CryptoVault, CATEGORIES
from ui_engine import (
    C, FONT, MONO, AnimationEngine, ToastNotification, Tooltip,
    make_card, make_label, make_entry, make_button, make_separator,
    make_combobox_menu, _safe_config
)

# ═══════════════════════════════════════════════════════════════
#  DIRECTORIO DE DATOS (en %LOCALAPPDATA%)
# ═══════════════════════════════════════════════════════════════

# Los datos se guardan en %LOCALAPPDATA%\GestorContraseñas\
# para que persistan independientemente de dónde esté el .exe
_APP_NAME = "GestorContraseñas"

def _get_data_dir():
    """Obtiene el directorio de datos de la app en AppData."""
    if sys.platform == "win32":
        base = os.environ.get("LOCALAPPDATA", os.path.expanduser("~"))
    else:
        base = os.path.expanduser("~")
    return os.path.join(base, _APP_NAME)

APP_DIR = _get_data_dir()
os.makedirs(APP_DIR, exist_ok=True)

# Proteger la carpeta: oculta + sistema (Windows)
def _protect_data_folder():
    """Marca la carpeta de datos como oculta y de sistema."""
    if sys.platform != "win32":
        return
    try:
        import ctypes
        # FILE_ATTRIBUTE_HIDDEN (0x2) + FILE_ATTRIBUTE_SYSTEM (0x4)
        ctypes.windll.kernel32.SetFileAttributesW(APP_DIR, 0x2 | 0x4)
    except Exception:
        pass

_protect_data_folder()

# Migrar vault.enc antiguo (si existe junto al .exe/script)
def _migrate_old_vault():
    """Si hay un vault.enc junto al ejecutable, moverlo a AppData."""
    if getattr(sys, 'frozen', False):
        old_dir = os.path.dirname(os.path.abspath(sys.executable))
    else:
        old_dir = os.path.dirname(os.path.abspath(__file__))
    old_vault = os.path.join(old_dir, "vault.enc")
    new_vault = os.path.join(APP_DIR, "vault.enc")
    if os.path.isfile(old_vault) and not os.path.isfile(new_vault):
        try:
            shutil.move(old_vault, new_vault)
        except Exception:
            pass

_migrate_old_vault()

# ═══════════════════════════════════════════════════════════════
#  LOGGING
# ═══════════════════════════════════════════════════════════════

LOG_DIR = os.path.join(APP_DIR, "logs")
os.makedirs(LOG_DIR, exist_ok=True)
log_filename = os.path.join(LOG_DIR, f"pm_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log")

file_fmt = logging.Formatter(
    "%(asctime)s | %(levelname)-8s | %(name)-30s | %(funcName)-20s | L%(lineno)-4d | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
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
logger.info("  Gestor de Contraseñas Seguro v3.0")
logger.info("=" * 60)


# ═══════════════════════════════════════════════════════════════
#  PROTECCIÓN ANTI-CAPTURA
# ═══════════════════════════════════════════════════════════════

def set_screen_capture_protection(hwnd, enable=True):
    if sys.platform != "win32":
        return False
    try:
        user32 = ctypes.windll.user32
        flag = 0x00000011 if enable else 0x00000000
        result = user32.SetWindowDisplayAffinity(hwnd, flag)
        if not result and enable:
            result = user32.SetWindowDisplayAffinity(hwnd, 0x00000001)
        return bool(result)
    except Exception:
        return False


# ═══════════════════════════════════════════════════════════════
#  APLICACIÓN PRINCIPAL
# ═══════════════════════════════════════════════════════════════

class PasswordManagerApp:
    AUTO_LOCK_MINUTES = 5

    def __init__(self):
        logger.info("Inicializando aplicación...")
        self.engine = PasswordEngine()
        vault_path = os.path.join(APP_DIR, "vault.enc")
        self.vault = CryptoVault(vault_path)
        self.last_generated_password = None
        self._last_activity = time.time()
        self._auto_lock_job = None
        self._gen_mode = "password"  # "password" or "passphrase"
        self._clipboard_clear_job = None

        self.root = tk.Tk()
        self.root.title("🔐 Gestor de Contraseñas Seguro v3.0")
        self.root.geometry("660x800")
        self.root.minsize(580, 650)
        self.root.configure(bg=C["bg"])
        self._center_window(660, 800)

        # Set window icon
        try:
            base_path = getattr(sys, '_MEIPASS', os.path.dirname(os.path.abspath(__file__)))
            icon_path = os.path.join(base_path, "icon.png")
            if os.path.isfile(icon_path):
                icon_img = tk.PhotoImage(file=icon_path)
                self.root.iconphoto(True, icon_img)
                self._icon_ref = icon_img  # Keep reference to avoid GC
                logger.info("Icono de ventana establecido ✓")
        except Exception as e:
            logger.debug(f"No se pudo cargar el icono: {e}")

        # Track activity for auto-lock
        self.root.bind_all("<Key>", self._reset_activity)
        self.root.bind_all("<Button>", self._reset_activity)
        self.root.bind_all("<Motion>", self._reset_activity)

        # Notebook (pestañas)
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("TNotebook", background=C["bg"], borderwidth=0)
        style.configure("TNotebook.Tab", background=C["card"], foreground=C["txt"],
                        font=(FONT, 10, "bold"), padding=[18, 10])
        style.map("TNotebook.Tab",
                  background=[("selected", C["accent"])],
                  foreground=[("selected", "white")])

        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill="both", expand=True, padx=10, pady=10)

        # Tab 1: Generador
        self.gen_frame = tk.Frame(self.notebook, bg=C["bg"])
        self.notebook.add(self.gen_frame, text="  ⚡ Generador  ")
        self._build_generator_tab()

        # Tab 2: Mis Contraseñas
        self.vault_frame = tk.Frame(self.notebook, bg=C["bg"])
        self.notebook.add(self.vault_frame, text="  🔑 Mis Contraseñas  ")
        self._build_vault_tab()

        # Tab 3: Seguridad
        self.security_frame = tk.Frame(self.notebook, bg=C["bg"])
        self.notebook.add(self.security_frame, text="  🛡️ Seguridad  ")
        self._build_security_tab()

        self.notebook.bind("<<NotebookTabChanged>>", self._on_tab_changed)
        logger.info("Aplicación inicializada ✓")

    def _center_window(self, w, h):
        x = (self.root.winfo_screenwidth() // 2) - (w // 2)
        y = (self.root.winfo_screenheight() // 2) - (h // 2)
        self.root.geometry(f"{w}x{h}+{x}+{y}")

    def _reset_activity(self, event=None):
        self._last_activity = time.time()

    def _check_auto_lock(self):
        if self.vault.is_unlocked:
            idle = time.time() - self._last_activity
            if idle > self.AUTO_LOCK_MINUTES * 60:
                logger.info("Auto-bloqueo por inactividad")
                self.vault.lock()
                self._show_login_screen()
                ToastNotification.show(self.root, "🔒 Bóveda bloqueada por inactividad", "warning")
        self._auto_lock_job = self.root.after(30000, self._check_auto_lock)

    def _on_tab_changed(self, event):
        tab_idx = self.notebook.index(self.notebook.select())
        try:
            hwnd = ctypes.windll.user32.GetParent(self.root.winfo_id())
            set_screen_capture_protection(hwnd, tab_idx == 1)
        except Exception:
            pass

    # ══════════════════════════════════════════════════════
    #  TAB 1: GENERADOR
    # ══════════════════════════════════════════════════════

    def _build_generator_tab(self):
        canvas = tk.Canvas(self.gen_frame, bg=C["bg"], highlightthickness=0)
        sb = tk.Scrollbar(self.gen_frame, orient="vertical", command=canvas.yview)
        inner = tk.Frame(canvas, bg=C["bg"])
        inner.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=inner, anchor="nw")
        canvas.configure(yscrollcommand=sb.set)
        canvas.bind("<Configure>", lambda e: canvas.itemconfig(canvas.find_all()[0], width=e.width))
        canvas.bind_all("<MouseWheel>", lambda e: canvas.yview_scroll(int(-1*(e.delta/120)), "units"))
        sb.pack(side="right", fill="y"); canvas.pack(side="left", fill="both", expand=True)

        f = tk.Frame(inner, bg=C["bg"])
        f.pack(fill="both", expand=True, padx=20, pady=10)

        # Título
        make_label(f, "⚡ Generador de Contraseñas", 16, bold=True, color=C["accent"]).pack(fill="x", pady=(0,2))
        make_label(f, "Contraseñas criptográficamente seguras", 9, color=C["txt2"]).pack(fill="x", pady=(0,10))

        # ── Mode Switch: Password vs Passphrase ──
        mode_card = make_card(f, hover=False)
        mode_card.pack(fill="x", pady=(0, 8), ipady=4, ipadx=10)
        make_label(mode_card, "🔀  MODO DE GENERACIÓN", 9, bold=True, color=C["txt2"]).pack(fill="x", padx=12, pady=(8,5))
        mode_f = tk.Frame(mode_card, bg=C["card"]); mode_f.pack(fill="x", padx=12, pady=(0,8))

        self._mode_btn_pw = make_button(mode_f, "🔑 Contraseña", lambda: self._switch_gen_mode("password"),
                                        bg_color=C["accent"], size=9, bold=True)
        self._mode_btn_pw.pack(side="left", padx=(0,5))
        self._mode_btn_pp = make_button(mode_f, "📝 Frase (Passphrase)", lambda: self._switch_gen_mode("passphrase"),
                                        bg_color=C["input"], fg_color=C["txt"], size=9)
        self._mode_btn_pp.pack(side="left")

        # ── Password options frame ──
        self._pw_options_frame = tk.Frame(f, bg=C["bg"])
        self._pw_options_frame.pack(fill="x")
        self._build_password_options(self._pw_options_frame)

        # ── Passphrase options frame (hidden) ──
        self._pp_options_frame = tk.Frame(f, bg=C["bg"])
        self._build_passphrase_options(self._pp_options_frame)

        # Botón GENERAR
        self._gen_btn = make_button(f, "⚡  GENERAR", self._on_generate,
                                    size=12, bold=True, glow=True)
        self._gen_btn.pack(fill="x", pady=(5, 8), ipady=5)

        # Card: Resultado
        rc = make_card(f, hover=False); rc.pack(fill="x", pady=(0, 8), ipady=5, ipadx=10)
        make_label(rc, "🔑  RESULTADO", 9, bold=True, color=C["txt2"]).pack(fill="x", padx=12, pady=(8,3))

        pw_f = tk.Frame(rc, bg=C["input"], highlightbackground=C["border"], highlightthickness=1)
        pw_f.pack(fill="x", padx=12, pady=(0,5))
        self.result_text = tk.Text(pw_f, height=3, font=(MONO, 12), bg=C["input"], fg=C["green"],
            insertbackground=C["green"], relief="flat", wrap="char",
            selectbackground=C["accent"], selectforeground="white", padx=8, pady=8)
        self.result_text.pack(fill="x")
        self.result_text.insert("1.0", "Aquí aparecerá tu contraseña...")
        self.result_text.configure(state="disabled")

        af = tk.Frame(rc, bg=C["card"]); af.pack(fill="x", padx=12, pady=(0,3))
        self.copy_btn = make_button(af, "📋 Copiar", self._on_copy, bg_color=C["input"], fg_color=C["txt"], size=9)
        self.copy_btn.pack(side="left", padx=(0,5))
        self.save_gen_btn = make_button(af, "💾 Guardar en Bóveda", self._on_save_generated,
                                         bg_color=C["input"], fg_color=C["txt"], size=9)
        self.save_gen_btn.pack(side="left", padx=(0,5))
        self.hibp_btn = make_button(af, "🛡️ Verificar HIBP", self._on_check_hibp,
                                    bg_color=C["input"], fg_color=C["cyan"], size=9)
        self.hibp_btn.pack(side="left")
        Tooltip(self.hibp_btn, "Comprueba si esta contraseña ha sido filtrada\n(API Have I Been Pwned, k-Anonymity)")

        self.str_label = make_label(rc, "Fortaleza: --", 9, color=C["muted"])
        self.str_label.pack(fill="x", padx=12)
        self.ent_label = make_label(rc, "Entropía: --", 8, color=C["muted"])
        self.ent_label.pack(fill="x", padx=12)
        self.hibp_label = make_label(rc, "", 8, color=C["muted"])
        self.hibp_label.pack(fill="x", padx=12)
        self.str_bar = tk.Canvas(rc, height=6, bg=C["input"], highlightthickness=0)
        self.str_bar.pack(fill="x", padx=12, pady=(3,8))

    def _build_password_options(self, parent):
        # Longitud
        lc = make_card(parent); lc.pack(fill="x", pady=(0,8), ipady=5, ipadx=10)
        make_label(lc, "📏  LONGITUD", 9, bold=True, color=C["txt2"]).pack(fill="x", padx=12, pady=(8,3))
        sf = tk.Frame(lc, bg=C["card"]); sf.pack(fill="x", padx=12, pady=(0,5))
        self.length_var = tk.IntVar(value=20)
        self.length_lbl = make_label(sf, "20", 20, bold=True, color=C["accent"])
        self.length_lbl.configure(width=4); self.length_lbl.pack(side="left")
        self.length_slider = tk.Scale(sf, from_=4, to=128, orient="horizontal",
            variable=self.length_var, command=self._on_slider, bg=C["card"], fg=C["txt"],
            troughcolor=C["input"], highlightthickness=0, sliderrelief="flat",
            showvalue=False, sliderlength=20, font=(FONT, 8))
        self.length_slider.pack(side="left", fill="x", expand=True, padx=(10,0))
        mf = tk.Frame(lc, bg=C["card"]); mf.pack(fill="x", padx=12, pady=(0,5))
        make_label(mf, "O escribe:", 9, color=C["muted"]).pack(side="left")
        self.len_entry = make_entry(mf, font_size=10)
        self.len_entry.configure(width=6, justify="center")
        self.len_entry.pack(side="left", padx=(8,0))
        self.len_entry.insert(0, "20")
        self.len_entry.bind("<Return>", self._on_len_entry)
        self.len_entry.bind("<FocusOut>", self._on_len_entry)

        # Tipos
        tc = make_card(parent); tc.pack(fill="x", pady=(0,8), ipady=5, ipadx=10)
        make_label(tc, "🔤  TIPOS DE CARACTERES", 9, bold=True, color=C["txt2"]).pack(fill="x", padx=12, pady=(8,5))
        self.var_low = tk.BooleanVar(value=True)
        self.var_up = tk.BooleanVar(value=True)
        self.var_dig = tk.BooleanVar(value=True)
        self.var_sym = tk.BooleanVar(value=True)
        for var, icon, label in [(self.var_low,"abc","Minúsculas (a-z)"),
                                  (self.var_up,"ABC","Mayúsculas (A-Z)"),
                                  (self.var_dig,"123","Dígitos (0-9)"),
                                  (self.var_sym,"#$!","Símbolos")]:
            row = tk.Frame(tc, bg=C["card"]); row.pack(fill="x", padx=12, pady=1)
            tk.Checkbutton(row, variable=var, bg=C["card"], fg=C["txt"],
                selectcolor=C["input"], activebackground=C["card"],
                highlightthickness=0, relief="flat").pack(side="left")
            make_label(row, f" {icon}  {label}", 10).pack(side="left")

        # Símbolos custom
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
        self.word_slider = tk.Scale(wf, from_=3, to=10, orient="horizontal",
            variable=self.word_count_var, command=lambda v: self.word_count_lbl.configure(text=str(int(float(v)))),
            bg=C["card"], fg=C["txt"], troughcolor=C["input"], highlightthickness=0,
            sliderrelief="flat", showvalue=False, sliderlength=20, font=(FONT, 8))
        self.word_slider.pack(side="left", fill="x", expand=True)

        sf = tk.Frame(pc, bg=C["card"]); sf.pack(fill="x", padx=12, pady=(0,3))
        make_label(sf, "Separador:", 10).pack(side="left")
        self.sep_entry = make_entry(sf, font_size=10)
        self.sep_entry.configure(width=5, justify="center")
        self.sep_entry.insert(0, "-")
        self.sep_entry.pack(side="left", padx=(8,0))

        of = tk.Frame(pc, bg=C["card"]); of.pack(fill="x", padx=12, pady=(0,5))
        self.var_capitalize = tk.BooleanVar(value=False)
        tk.Checkbutton(of, text="  Capitalizar palabras", variable=self.var_capitalize,
            bg=C["card"], fg=C["txt"], selectcolor=C["input"],
            activebackground=C["card"], highlightthickness=0, font=(FONT, 10)).pack(side="left")
        self.var_add_num = tk.BooleanVar(value=True)
        tk.Checkbutton(of, text="  Añadir número", variable=self.var_add_num,
            bg=C["card"], fg=C["txt"], selectcolor=C["input"],
            activebackground=C["card"], highlightthickness=0, font=(FONT, 10)).pack(side="left", padx=(15,0))

        make_label(pc, "📖 Diccionario de ~180 palabras en español", 8, color=C["muted"]).pack(padx=12, pady=(0,5))

    def _switch_gen_mode(self, mode):
        self._gen_mode = mode
        if mode == "password":
            self._pp_options_frame.pack_forget()
            self._pw_options_frame.pack(fill="x", before=self._gen_btn)
            _safe_config(self._mode_btn_pw, bg=C["accent"], fg="white")
            _safe_config(self._mode_btn_pp, bg=C["input"], fg=C["txt"])
        else:
            self._pw_options_frame.pack_forget()
            self._pp_options_frame.pack(fill="x", before=self._gen_btn)
            _safe_config(self._mode_btn_pp, bg=C["accent"], fg="white")
            _safe_config(self._mode_btn_pw, bg=C["input"], fg=C["txt"])

    def _on_slider(self, val):
        v = int(float(val))
        self.length_lbl.configure(text=str(v))
        self.len_entry.delete(0, tk.END)
        self.len_entry.insert(0, str(v))

    def _on_len_entry(self, e=None):
        try:
            v = max(4, min(256, int(self.len_entry.get())))
            self.length_var.set(min(v, 128))
            self.length_lbl.configure(text=str(v))
        except ValueError:
            self.len_entry.delete(0, tk.END)
            self.len_entry.insert(0, str(self.length_var.get()))

    def _on_generate(self):
        logger.info("Botón GENERAR presionado")
        try:
            if self._gen_mode == "passphrase":
                result = self.engine.generate_passphrase(
                    word_count=self.word_count_var.get(),
                    separator=self.sep_entry.get() or "-",
                    capitalize=self.var_capitalize.get(),
                    add_number=self.var_add_num.get()
                )
            else:
                try:
                    length = int(self.len_entry.get())
                except ValueError:
                    length = self.length_var.get()
                if not any([self.var_low.get(), self.var_up.get(), self.var_dig.get(), self.var_sym.get()]):
                    ToastNotification.show(self.root, "Selecciona al menos un tipo de carácter.", "warning")
                    return
                result = self.engine.generate(
                    length=length, use_lower=self.var_low.get(), use_upper=self.var_up.get(),
                    use_digits=self.var_dig.get(), use_symbols=self.var_sym.get(),
                    custom_symbols=self.sym_entry.get())

            self.last_generated_password = result["password"]
            self.result_text.configure(state="normal")
            self.result_text.delete("1.0", tk.END)
            self.result_text.insert("1.0", result["password"])
            self.result_text.configure(state="disabled")

            sc = self._strength_color(result["entropy_bits"])
            self.str_label.configure(text=f"Fortaleza: {result['strength']}", fg=sc)
            info = f"Entropía: {result['entropy_bits']} bits | Tiempo: {result['generation_time_ms']} ms"
            if "charset_size" in result:
                info += f" | Charset: {result['charset_size']}"
            self.ent_label.configure(text=info)
            self.hibp_label.configure(text="", fg=C["muted"])

            # Animated bar
            pct = min(result["entropy_bits"] / 200.0, 1.0)
            AnimationEngine.animate_bar(self.str_bar, self.root, pct, sc)

            # Button pulse
            AnimationEngine.color_pulse(self._gen_btn, self.root, C["accent"], C["green"])

        except ValueError as e:
            ToastNotification.show(self.root, str(e), "warning")
        except Exception as e:
            logger.critical(f"Error generando: {e}", exc_info=True)
            ToastNotification.show(self.root, str(e), "error")

    def _on_check_hibp(self):
        """Verifica contra HIBP en un thread separado."""
        self.result_text.configure(state="normal")
        pw = self.result_text.get("1.0", tk.END).strip()
        self.result_text.configure(state="disabled")
        if not pw or pw == "Aquí aparecerá tu contraseña...":
            ToastNotification.show(self.root, "Primero genera una contraseña.", "info")
            return
        self.hibp_label.configure(text="⏳ Verificando en HIBP...", fg=C["yellow"])
        self.root.update_idletasks()

        def check():
            result = self.engine.check_hibp(pw)
            self.root.after(0, lambda: self._show_hibp_result(result))
        threading.Thread(target=check, daemon=True).start()

    def _show_hibp_result(self, result):
        if result["compromised"] is None:
            self.hibp_label.configure(text=result["message"], fg=C["yellow"])
        elif result["compromised"]:
            self.hibp_label.configure(text=result["message"], fg=C["red"])
            ToastNotification.show(self.root, result["message"], "error", 4000)
        else:
            self.hibp_label.configure(text=result["message"], fg=C["green"])
            ToastNotification.show(self.root, result["message"], "success")

    def _schedule_clipboard_clear(self, seconds=30):
        """Programa la limpieza del portapapeles tras N segundos."""
        if self._clipboard_clear_job:
            self.root.after_cancel(self._clipboard_clear_job)
        def clear():
            try:
                self.root.clipboard_clear()
                self.root.clipboard_append("")
                logger.debug("Portapapeles limpiado automáticamente")
            except Exception:
                pass
        self._clipboard_clear_job = self.root.after(seconds * 1000, clear)

    def _on_copy(self):
        self.result_text.configure(state="normal")
        pw = self.result_text.get("1.0", tk.END).strip()
        self.result_text.configure(state="disabled")
        if pw and pw != "Aquí aparecerá tu contraseña...":
            self.root.clipboard_clear(); self.root.clipboard_append(pw)
            self._schedule_clipboard_clear(30)
            ToastNotification.show(self.root, "✅ Copiado (se borrará en 30s)", "success")
            AnimationEngine.bounce_text(self.copy_btn, self.root, "📋 Copiar", "✅ ¡Copiado!")
        else:
            ToastNotification.show(self.root, "Primero genera una contraseña.", "info")

    def _on_save_generated(self):
        if not self.last_generated_password:
            ToastNotification.show(self.root, "Primero genera una contraseña.", "info")
            return
        if not self.vault.is_unlocked:
            ToastNotification.show(self.root, "Desbloquea la bóveda primero (pestaña Mis Contraseñas).", "warning")
            return
        self._show_save_dialog(self.last_generated_password)

    def _show_save_dialog(self, password):
        dlg = tk.Toplevel(self.root)
        dlg.title("Guardar Contraseña"); dlg.geometry("420x420")
        dlg.configure(bg=C["bg"]); dlg.transient(self.root); dlg.grab_set()
        x = self.root.winfo_x() + 120; y = self.root.winfo_y() + 150
        dlg.geometry(f"+{x}+{y}")

        make_label(dlg, "💾 Guardar Contraseña", 13, bold=True).pack(padx=15, pady=(15,8))
        make_label(dlg, "Contraseña:", 9, color=C["txt2"]).pack(fill="x", padx=15)
        make_label(dlg, "●" * min(len(password), 30), 10, color=C["green"]).pack(fill="x", padx=15, pady=(0,6))

        make_label(dlg, "Nombre:", 9, color=C["txt2"]).pack(fill="x", padx=15)
        title_e = make_entry(dlg); title_e.pack(fill="x", padx=15, pady=(0,5))

        make_label(dlg, "Categoría:", 9, color=C["txt2"]).pack(fill="x", padx=15)
        cat_mb, cat_var = make_combobox_menu(dlg, CATEGORIES, "📁 Otros")
        cat_mb.pack(fill="x", padx=15, pady=(0,5))

        make_label(dlg, "URL (opcional):", 9, color=C["txt2"]).pack(fill="x", padx=15)
        site_e = make_entry(dlg); site_e.pack(fill="x", padx=15, pady=(0,5))

        make_label(dlg, "Email / Usuario:", 9, color=C["txt2"]).pack(fill="x", padx=15)
        email_e = make_entry(dlg); email_e.pack(fill="x", padx=15, pady=(0,8))

        def save():
            title = title_e.get().strip()
            if not title:
                ToastNotification.show(dlg, "Introduce un nombre.", "warning")
                return
            try:
                self.vault.add_credential(title, site_e.get().strip(),
                    email_e.get().strip(), password, category=cat_var.get())
                dlg.destroy()
                ToastNotification.show(self.root, f"'{title}' guardado en la bóveda ✓", "success")
                self._refresh_credentials_list()
            except Exception as e:
                ToastNotification.show(dlg, str(e), "error")

        make_button(dlg, "💾 Guardar", save, size=11, bold=True).pack(fill="x", padx=15, pady=(0,10))

    def _strength_color(self, entropy):
        if entropy >= 128: return C["green"]
        elif entropy >= 80: return "#4caf50"
        elif entropy >= 50: return C["yellow"]
        return C["red"]

    # ══════════════════════════════════════════════════════
    #  TAB 2: BÓVEDA
    # ══════════════════════════════════════════════════════

    def _build_vault_tab(self):
        self.vault_container = tk.Frame(self.vault_frame, bg=C["bg"])
        self.vault_container.pack(fill="both", expand=True)
        if self.vault.is_vault_created:
            self._show_login_screen()
        else:
            self._show_create_master_screen()

    def _clear_vault_container(self):
        for w in self.vault_container.winfo_children():
            w.destroy()

    # ── Crear contraseña maestra ──

    def _show_create_master_screen(self):
        self._clear_vault_container()
        f = self.vault_container
        make_label(f, "🔒", 30).pack(pady=(40,5))
        make_label(f, "Crear Contraseña Maestra", 16, bold=True).pack()
        make_label(f, "Esta contraseña protege toda tu bóveda.\nRecuérdala bien, no se puede recuperar.",
                   9, color=C["txt2"]).pack(pady=(5,20))
        card = make_card(f, hover=False); card.pack(fill="x", padx=40, ipady=10)
        make_label(card, "Contraseña maestra:", 10, color=C["txt2"]).pack(fill="x", padx=15, pady=(10,3))
        self.master_pw1 = make_entry(card, show="●", font_size=12)
        self.master_pw1.pack(fill="x", padx=15, pady=(0,8))
        make_label(card, "Confirmar contraseña:", 10, color=C["txt2"]).pack(fill="x", padx=15, pady=(0,3))
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
            ToastNotification.show(self.root, "✅ Bóveda cifrada creada exitosamente", "success")
            self._show_manager_screen()
            self._start_auto_lock()
        except Exception as e:
            ToastNotification.show(self.root, str(e), "error")

    # ── Login ──

    def _show_login_screen(self):
        self._clear_vault_container()
        f = self.vault_container
        make_label(f, "🔒", 30).pack(pady=(50,5))
        make_label(f, "Bóveda Bloqueada", 16, bold=True).pack()
        make_label(f, "Introduce tu contraseña maestra para acceder.", 9, color=C["txt2"]).pack(pady=(5,20))
        card = make_card(f, hover=False); card.pack(fill="x", padx=40, ipady=10)
        make_label(card, "Contraseña maestra:", 10, color=C["txt2"]).pack(fill="x", padx=15, pady=(10,3))
        self.login_pw = make_entry(card, show="●", font_size=12)
        self.login_pw.pack(fill="x", padx=15, pady=(0,10))
        self.login_pw.bind("<Return>", lambda e: self._on_unlock())
        self.login_status = make_label(f, "", 9, color=C["red"])
        self.login_status.pack(pady=(5,0))
        make_button(f, "🔓 Desbloquear", self._on_unlock,
                    size=12, bold=True, glow=True).pack(fill="x", padx=40, pady=15, ipady=4)

    def _on_unlock(self):
        pw = self.login_pw.get()
        if not pw:
            self.login_status.configure(text="Introduce la contraseña."); return
        self.login_status.configure(text="Desbloqueando... (puede tardar)", fg=C["yellow"])
        self.root.update_idletasks()
        if self.vault.unlock(pw):
            self._show_manager_screen()
            self._start_auto_lock()
            ToastNotification.show(self.root, "🔓 Bóveda desbloqueada", "success")
        else:
            self.login_status.configure(text="❌ Contraseña incorrecta.", fg=C["red"])

    def _start_auto_lock(self):
        self._last_activity = time.time()
        if self._auto_lock_job:
            self.root.after_cancel(self._auto_lock_job)
        self._check_auto_lock()

    # ── Manager screen ──

    def _show_manager_screen(self):
        self._clear_vault_container()
        f = self.vault_container

        # Header
        hdr = tk.Frame(f, bg=C["bg"]); hdr.pack(fill="x", padx=15, pady=(10,5))
        make_label(hdr, "🔓 Mis Contraseñas", 14, bold=True).pack(side="left")

        # Stats
        stats = self.vault.get_statistics()
        stats_text = f"📊 {stats['total']} total"
        if stats["weak_passwords"] > 0:
            stats_text += f"  ⚠️ {stats['weak_passwords']} débiles"
        make_label(hdr, stats_text, 9, color=C["txt2"]).pack(side="left", padx=(15,0))

        btn_f = tk.Frame(hdr, bg=C["bg"]); btn_f.pack(side="right")
        make_button(btn_f, "🔒", self._on_lock, bg_color=C["input"], fg_color=C["txt"], size=9).pack(side="right", padx=2)
        Tooltip(btn_f.winfo_children()[-1], "Bloquear bóveda")
        make_button(btn_f, "📤", self._on_export, bg_color=C["input"], fg_color=C["txt"], size=9).pack(side="right", padx=2)
        Tooltip(btn_f.winfo_children()[-1], "Exportar credenciales cifradas")
        make_button(btn_f, "📥", self._on_import, bg_color=C["input"], fg_color=C["txt"], size=9).pack(side="right", padx=2)
        Tooltip(btn_f.winfo_children()[-1], "Importar credenciales")
        make_button(btn_f, "➕", self._on_add_credential, bg_color=C["accent"], size=9).pack(side="right", padx=2)
        Tooltip(btn_f.winfo_children()[-1], "Añadir credencial")

        # Search bar
        search_f = tk.Frame(f, bg=C["bg"]); search_f.pack(fill="x", padx=15, pady=(0,5))
        make_label(search_f, "🔍", 10).pack(side="left")
        self.search_var = tk.StringVar()
        self.search_var.trace_add("write", lambda *a: self._refresh_credentials_list())
        self.search_entry = make_entry(search_f, font_size=10)
        self.search_entry.configure(textvariable=self.search_var)
        self.search_entry.pack(side="left", fill="x", expand=True, padx=(5,5))

        # Category filter
        filter_opts = ["Todas"] + CATEGORIES
        self.cat_filter_mb, self.cat_filter_var = make_combobox_menu(search_f, filter_opts, "Todas", width=14)
        self.cat_filter_var.trace_add("write", lambda *a: self._refresh_credentials_list())
        self.cat_filter_mb.pack(side="left")

        # Credential list
        list_frame = tk.Frame(f, bg=C["bg"]); list_frame.pack(fill="both", expand=True, padx=10, pady=5)
        self.cred_canvas = tk.Canvas(list_frame, bg=C["bg"], highlightthickness=0)
        cred_sb = tk.Scrollbar(list_frame, orient="vertical", command=self.cred_canvas.yview)
        self.cred_inner = tk.Frame(self.cred_canvas, bg=C["bg"])
        self.cred_inner.bind("<Configure>", lambda e: self.cred_canvas.configure(scrollregion=self.cred_canvas.bbox("all")))
        self.cred_canvas.create_window((0,0), window=self.cred_inner, anchor="nw")
        self.cred_canvas.configure(yscrollcommand=cred_sb.set)
        self.cred_canvas.bind("<Configure>", lambda e: self.cred_canvas.itemconfig(
            self.cred_canvas.find_all()[0], width=e.width))
        cred_sb.pack(side="right", fill="y"); self.cred_canvas.pack(side="left", fill="both", expand=True)
        self._refresh_credentials_list()

    def _refresh_credentials_list(self):
        if not hasattr(self, 'cred_inner'):
            return
        for w in self.cred_inner.winfo_children():
            w.destroy()
        creds = self.vault.credentials

        # Filter by search
        search = self.search_var.get().lower() if hasattr(self, 'search_var') else ""
        if search:
            creds = [c for c in creds if search in c.get("title","").lower()
                     or search in c.get("site","").lower()
                     or search in c.get("email","").lower()]

        # Filter by category
        cat_filter = self.cat_filter_var.get() if hasattr(self, 'cat_filter_var') else "Todas"
        if cat_filter != "Todas":
            creds = [c for c in creds if c.get("category","") == cat_filter]

        if not creds:
            msg = "No hay resultados." if (search or cat_filter != "Todas") else "No hay contraseñas guardadas.\nUsa '➕' o genera una y guárdala."
            make_label(self.cred_inner, msg, 10, color=C["muted"]).pack(pady=40)
            return
        for cred in creds:
            self._build_credential_card(self.cred_inner, cred)

    def _build_credential_card(self, parent, cred):
        card = make_card(parent); card.pack(fill="x", pady=(0,6), ipady=6, ipadx=8)
        top = tk.Frame(card, bg=C["card"]); top.pack(fill="x", padx=10, pady=(8,2))
        cat = cred.get("category", "📁 Otros")
        display_name = cred.get('title') or cred.get('site', 'Sin nombre')
        name_lbl = make_label(top, f"{display_name}", 11, bold=True, color=C["accent"])
        name_lbl.pack(side="left")
        cat_lbl = make_label(top, f" {cat}", 8, color=C["txt2"])
        cat_lbl.pack(side="left", padx=(8,0))

        site_url = cred.get('site', '')
        if site_url and site_url != display_name:
            url_row = tk.Frame(card, bg=C["card"]); url_row.pack(fill="x", padx=10)
            make_label(url_row, f"🔗 {site_url}", 8, color=C["muted"]).pack(side="left")

        del_btn = make_button(top, "🗑", lambda c=cred: self._on_delete_credential(c["id"]),
                              bg_color=C["card"], fg_color=C["red"], size=9)
        del_btn.pack(side="right")
        edit_btn = make_button(top, "✏️", lambda c=cred: self._on_edit_credential(c),
                               bg_color=C["card"], fg_color=C["yellow"], size=9)
        edit_btn.pack(side="right", padx=(0,3))

        em_row = tk.Frame(card, bg=C["card"]); em_row.pack(fill="x", padx=10, pady=1)
        make_label(em_row, f"📧 {cred['email']}", 9, color=C["txt2"]).pack(side="left")
        make_button(em_row, "📋", lambda c=cred: self._copy_to_clip(c["email"]),
                    bg_color=C["card"], fg_color=C["txt2"], size=8).pack(side="right")

        pw_row = tk.Frame(card, bg=C["card"]); pw_row.pack(fill="x", padx=10, pady=1)
        pw_display = make_label(pw_row, "🔑 ●●●●●●●●●●●●", 9, color=C["muted"])
        pw_display.pack(side="left")

        def toggle_pw(label=pw_display, c=cred):
            if "●" in label.cget("text"):
                label.configure(text=f"🔑 {c['password']}", fg=C["green"])
                self.root.after(5000, lambda: _safe_config(label, text="🔑 ●●●●●●●●●●●●", fg=C["muted"]))
            else:
                label.configure(text="🔑 ●●●●●●●●●●●●", fg=C["muted"])

        make_button(pw_row, "👁", toggle_pw, bg_color=C["card"], fg_color=C["txt2"], size=8).pack(side="right")
        make_button(pw_row, "📋", lambda c=cred: self._copy_to_clip(c["password"]),
                    bg_color=C["card"], fg_color=C["txt2"], size=8).pack(side="right", padx=(0,3))

        action_row = tk.Frame(card, bg=C["card"]); action_row.pack(fill="x", padx=10, pady=(3,2))
        if site_url:
            make_button(action_row, "🚀 Quick Login", lambda c=cred: self._on_quick_login(c),
                        bg_color=C["accent"], fg_color="white", size=9).pack(side="left")

        if cred.get("notes"):
            make_label(card, f"📝 {cred['notes']}", 8, color=C["muted"]).pack(fill="x", padx=10, pady=(1,5))

    def _copy_to_clip(self, text):
        self.root.clipboard_clear(); self.root.clipboard_append(text)
        self._schedule_clipboard_clear(30)
        ToastNotification.show(self.root, "✅ Copiado (se borrará en 30s)", "success")

    def _on_quick_login(self, cred):
        site = cred["site"].strip()
        url = site if site.startswith(("http://", "https://")) else "https://" + site
        self.root.clipboard_clear(); self.root.clipboard_append(cred["email"])
        try:
            webbrowser.open(url)
        except Exception as e:
            ToastNotification.show(self.root, f"Error abriendo navegador: {e}", "error"); return
        ToastNotification.show(self.root, "📧 Email copiado. En 4s se copiará la contraseña.", "info", 3500)
        self.root.after(4000, lambda: (
            self.root.clipboard_clear(),
            self.root.clipboard_append(cred["password"]),
            ToastNotification.show(self.root, "🔑 Contraseña copiada. ¡Pégala ahora!", "success")
        ))

    def _on_add_credential(self):
        dlg = tk.Toplevel(self.root)
        dlg.title("Añadir Credencial"); dlg.geometry("420x480"); dlg.configure(bg=C["bg"])
        dlg.transient(self.root); dlg.grab_set()
        x = self.root.winfo_x() + 120; y = self.root.winfo_y() + 120
        dlg.geometry(f"+{x}+{y}")
        make_label(dlg, "➕ Nueva Credencial", 13, bold=True).pack(padx=15, pady=(15,10))

        entries = {}
        for label_text, key in [("Nombre:", "title"), ("Categoría:", "category"),
                                 ("URL (opcional):", "site"), ("Email / Usuario:", "email"),
                                 ("Contraseña:", "password"), ("Notas (opcional):", "notes")]:
            make_label(dlg, label_text, 9, color=C["txt2"]).pack(fill="x", padx=15)
            if key == "category":
                mb, var = make_combobox_menu(dlg, CATEGORIES, "📁 Otros")
                mb.pack(fill="x", padx=15, pady=(0,5))
                entries[key] = var
            else:
                e = make_entry(dlg, show="●" if key == "password" else None)
                e.pack(fill="x", padx=15, pady=(0,5))
                entries[key] = e

        def save():
            title = entries["title"].get().strip()
            if not title:
                ToastNotification.show(dlg, "Introduce un nombre.", "warning"); return
            try:
                self.vault.add_credential(title, entries["site"].get().strip(),
                    entries["email"].get().strip(), entries["password"].get(),
                    entries["notes"].get().strip(), entries["category"].get())
                dlg.destroy(); self._refresh_credentials_list()
                ToastNotification.show(self.root, f"'{title}' añadido ✓", "success")
            except Exception as e:
                ToastNotification.show(dlg, str(e), "error")
        make_button(dlg, "💾 Guardar", save, size=11, bold=True).pack(fill="x", padx=15, pady=10)

    def _on_edit_credential(self, cred):
        dlg = tk.Toplevel(self.root)
        dlg.title("Editar Credencial"); dlg.geometry("420x500"); dlg.configure(bg=C["bg"])
        dlg.transient(self.root); dlg.grab_set()
        x = self.root.winfo_x() + 120; y = self.root.winfo_y() + 100
        dlg.geometry(f"+{x}+{y}")
        make_label(dlg, "✏️ Editar Credencial", 13, bold=True).pack(padx=15, pady=(15,10))

        fields = {}
        for label_text, key in [("Nombre:", "title"), ("Categoría:", "category"),
                                 ("URL:", "site"), ("Email / Usuario:", "email"),
                                 ("Contraseña:", "password"), ("Notas:", "notes")]:
            make_label(dlg, label_text, 9, color=C["txt2"]).pack(fill="x", padx=15)
            if key == "category":
                mb, var = make_combobox_menu(dlg, CATEGORIES, cred.get("category", "📁 Otros"))
                mb.pack(fill="x", padx=15, pady=(0,5))
                fields[key] = var
            else:
                e = make_entry(dlg)
                e.pack(fill="x", padx=15, pady=(0,5))
                e.insert(0, cred.get(key, ""))
                fields[key] = e

        def save_edit():
            title = fields["title"].get().strip()
            if not title:
                ToastNotification.show(dlg, "El nombre no puede estar vacío.", "warning"); return
            try:
                self.vault.update_credential(cred["id"], title=title,
                    site=fields["site"].get().strip(), email=fields["email"].get().strip(),
                    password=fields["password"].get(), notes=fields["notes"].get().strip(),
                    category=fields["category"].get())
                dlg.destroy(); self._refresh_credentials_list()
                ToastNotification.show(self.root, "Credencial actualizada ✓", "success")
            except Exception as e:
                ToastNotification.show(dlg, str(e), "error")
        make_button(dlg, "💾 Guardar Cambios", save_edit, size=11, bold=True).pack(fill="x", padx=15, pady=10)

    def _on_delete_credential(self, cred_id):
        if messagebox.askyesno("Confirmar", "¿Eliminar esta credencial?\nEsta acción no se puede deshacer."):
            self.vault.delete_credential(cred_id)
            self._refresh_credentials_list()
            ToastNotification.show(self.root, "Credencial eliminada", "info")

    def _on_lock(self):
        self.vault.lock()
        self._show_login_screen()
        ToastNotification.show(self.root, "🔒 Bóveda bloqueada", "info")

    def _on_export(self):
        path = filedialog.asksaveasfilename(
            title="Exportar Credenciales Cifradas",
            defaultextension=".pmex", filetypes=[("PM Export", "*.pmex"), ("Todos", "*.*")],
            initialfile=f"backup_{datetime.now().strftime('%Y%m%d')}.pmex")
        if not path:
            return
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
                self.vault.export_encrypted(path, pw)
                dlg.destroy()
                ToastNotification.show(self.root, f"✅ Exportado a {os.path.basename(path)}", "success")
            except Exception as e:
                ToastNotification.show(dlg, str(e), "error")
        make_button(dlg, "📤 Exportar", do_export, size=11, bold=True).pack(fill="x", padx=15, pady=5)

    def _on_import(self):
        path = filedialog.askopenfilename(
            title="Importar Credenciales", filetypes=[("PM Export", "*.pmex"), ("Todos", "*.*")])
        if not path:
            return
        dlg = tk.Toplevel(self.root); dlg.title("Contraseña de Importación")
        dlg.geometry("380x180"); dlg.configure(bg=C["bg"])
        dlg.transient(self.root); dlg.grab_set()
        make_label(dlg, "🔑 Contraseña del archivo:", 10, color=C["txt2"]).pack(fill="x", padx=15, pady=(15,5))
        pw_e = make_entry(dlg, show="●", font_size=12); pw_e.pack(fill="x", padx=15, pady=(0,10))
        def do_import():
            try:
                count = self.vault.import_encrypted(path, pw_e.get())
                dlg.destroy()
                self._refresh_credentials_list()
                ToastNotification.show(self.root, f"✅ {count} credenciales importadas", "success")
            except Exception as e:
                ToastNotification.show(dlg, str(e), "error")
        make_button(dlg, "📥 Importar", do_import, size=11, bold=True).pack(fill="x", padx=15, pady=5)

    # ══════════════════════════════════════════════════════
    #  TAB 3: SEGURIDAD
    # ══════════════════════════════════════════════════════

    def _build_security_tab(self):
        canvas = tk.Canvas(self.security_frame, bg=C["bg"], highlightthickness=0)
        sb = tk.Scrollbar(self.security_frame, orient="vertical", command=canvas.yview)
        inner = tk.Frame(canvas, bg=C["bg"])
        inner.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=inner, anchor="nw")
        canvas.configure(yscrollcommand=sb.set)
        canvas.bind("<Configure>", lambda e: canvas.itemconfig(canvas.find_all()[0], width=e.width))
        sb.pack(side="right", fill="y"); canvas.pack(side="left", fill="both", expand=True)

        f = tk.Frame(inner, bg=C["bg"])
        f.pack(fill="both", expand=True, padx=20, pady=10)

        make_label(f, "🛡️ Centro de Seguridad", 16, bold=True, color=C["accent"]).pack(fill="x", pady=(0,2))
        make_label(f, "Herramientas para verificar la seguridad de tus contraseñas", 9, color=C["txt2"]).pack(fill="x", pady=(0,15))

        # ── Card 1: Verificar contraseña manual ──
        hc = make_card(f, hover=False); hc.pack(fill="x", pady=(0,10), ipady=5, ipadx=10)
        make_label(hc, "🔍  VERIFICAR CONTRASEÑA", 9, bold=True, color=C["txt2"]).pack(fill="x", padx=12, pady=(8,3))
        make_label(hc, "Comprueba si una contraseña ha aparecido en filtraciones de datos.", 9, color=C["muted"]).pack(fill="x", padx=12, pady=(0,5))
        make_label(hc, "Usa la API k-Anonymity de Have I Been Pwned. Solo se envían los", 8, color=C["muted"]).pack(fill="x", padx=12)
        make_label(hc, "primeros 5 caracteres del hash SHA-1, tu contraseña NUNCA se envía.", 8, color=C["muted"]).pack(fill="x", padx=12, pady=(0,8))

        input_f = tk.Frame(hc, bg=C["card"]); input_f.pack(fill="x", padx=12, pady=(0,5))
        self.hibp_manual_entry = make_entry(input_f, show="●", font_size=12)
        self.hibp_manual_entry.pack(side="left", fill="x", expand=True, padx=(0,8))
        self.hibp_manual_entry.bind("<Return>", lambda e: self._on_manual_hibp_check())

        # Toggle visibility button
        self._hibp_pw_visible = False
        def toggle_hibp_vis():
            self._hibp_pw_visible = not self._hibp_pw_visible
            self.hibp_manual_entry.configure(show="" if self._hibp_pw_visible else "●")
            _safe_config(vis_btn, text="🙈" if self._hibp_pw_visible else "👁")
        vis_btn = make_button(input_f, "👁", toggle_hibp_vis, bg_color=C["card"], fg_color=C["txt2"], size=9)
        vis_btn.pack(side="left")

        check_btn = make_button(hc, "🛡️  Verificar en HIBP", self._on_manual_hibp_check,
                                size=11, bold=True, glow=True)
        check_btn.pack(fill="x", padx=12, pady=(5,5))

        self.hibp_manual_result = make_label(hc, "", 10, color=C["muted"])
        self.hibp_manual_result.pack(fill="x", padx=12, pady=(0,8))

        # ── Card 2: Auditar bóveda ──
        ac = make_card(f, hover=False); ac.pack(fill="x", pady=(0,10), ipady=5, ipadx=10)
        make_label(ac, "📊  AUDITORÍA DE BÓVEDA", 9, bold=True, color=C["txt2"]).pack(fill="x", padx=12, pady=(8,3))
        make_label(ac, "Comprueba TODAS las contraseñas guardadas en tu bóveda\ncontra filtraciones conocidas. Requiere conexión a internet.", 9, color=C["muted"]).pack(fill="x", padx=12, pady=(0,8))

        audit_btn = make_button(ac, "🔎  Auditar Todas las Contraseñas", self._on_audit_vault,
                                size=11, bold=True, glow=True)
        audit_btn.pack(fill="x", padx=12, pady=(0,5))

        self.audit_progress = make_label(ac, "", 9, color=C["muted"])
        self.audit_progress.pack(fill="x", padx=12)

        self.audit_results_frame = tk.Frame(ac, bg=C["card"])
        self.audit_results_frame.pack(fill="x", padx=12, pady=(5,8))

        # ── Card 3: Info de seguridad ──
        ic = make_card(f, hover=False); ic.pack(fill="x", pady=(0,10), ipady=5, ipadx=10)
        make_label(ic, "ℹ️  PROTECCIONES ACTIVAS", 9, bold=True, color=C["txt2"]).pack(fill="x", padx=12, pady=(8,5))
        protections = [
            ("🔐", "AES-256-GCM", "Cifrado autenticado de la bóveda"),
            ("🔑", "PBKDF2 600K", "600.000 iteraciones para derivar la clave"),
            ("📋", "Auto-limpieza", "El portapapeles se borra tras 30 segundos"),
            ("⏰", "Auto-bloqueo", f"La bóveda se bloquea tras {self.AUTO_LOCK_MINUTES} min de inactividad"),
            ("🖥️", "Anti-captura", "Protección contra capturas de pantalla (Windows)"),
            ("👁", "Auto-ocultar", "Las contraseñas se ocultan tras 5 segundos"),
            ("🛡️", "HIBP k-Anonymity", "Solo 5 chars del hash se envían, nunca la contraseña"),
        ]
        for icon, title, desc in protections:
            row = tk.Frame(ic, bg=C["card"]); row.pack(fill="x", padx=12, pady=2)
            make_label(row, f"{icon} {title}", 9, bold=True, color=C["green"]).pack(side="left")
            make_label(row, f"  —  {desc}", 8, color=C["muted"]).pack(side="left")

        # Mostrar ubicación de datos
        loc_f = tk.Frame(ic, bg=C["card"]); loc_f.pack(fill="x", padx=12, pady=(8,5))
        make_label(loc_f, "📂 Datos guardados en:", 8, bold=True, color=C["txt2"]).pack(anchor="w")
        make_label(loc_f, APP_DIR, 8, color=C["muted"], font_family=MONO).pack(anchor="w")

        # ── Card 4: Desinstalar / Borrar datos ──
        dc = make_card(f, hover=False); dc.pack(fill="x", pady=(0,10), ipady=5, ipadx=10)
        make_label(dc, "⚠️  ELIMINAR TODOS LOS DATOS", 9, bold=True, color=C["red"]).pack(fill="x", padx=12, pady=(8,3))
        make_label(dc, "Elimina la bóveda, logs y todos los datos de la app.\nEsta acción es IRREVERSIBLE. Exporta tus contraseñas antes.", 9, color=C["muted"]).pack(fill="x", padx=12, pady=(0,8))
        make_button(dc, "🗑️  Eliminar Todos los Datos", self._on_uninstall_data,
                    bg_color=C["red"], fg_color="white", size=10, bold=True).pack(fill="x", padx=12, pady=(0,8))

    def _on_manual_hibp_check(self):
        """Verifica una contraseña introducida manualmente contra HIBP."""
        pw = self.hibp_manual_entry.get()
        if not pw:
            ToastNotification.show(self.root, "Introduce una contraseña para verificar.", "info")
            return
        self.hibp_manual_result.configure(text="⏳ Verificando en Have I Been Pwned...", fg=C["yellow"])
        self.root.update_idletasks()

        def check():
            result = self.engine.check_hibp(pw)
            def update_ui():
                if result["compromised"] is None:
                    self.hibp_manual_result.configure(text=result["message"], fg=C["yellow"])
                elif result["compromised"]:
                    self.hibp_manual_result.configure(text=result["message"], fg=C["red"])
                    ToastNotification.show(self.root, "⚠️ ¡Contraseña comprometida!", "error", 4000)
                else:
                    self.hibp_manual_result.configure(text=result["message"], fg=C["green"])
                    ToastNotification.show(self.root, "✅ Contraseña segura", "success")
            self.root.after(0, update_ui)
        threading.Thread(target=check, daemon=True).start()

    def _on_audit_vault(self):
        """Audita todas las contraseñas de la bóveda contra HIBP."""
        if not self.vault.is_unlocked:
            ToastNotification.show(self.root, "Desbloquea la bóveda primero.", "warning")
            return
        creds = self.vault.credentials
        if not creds:
            ToastNotification.show(self.root, "No hay credenciales para auditar.", "info")
            return

        # Clear previous results
        for w in self.audit_results_frame.winfo_children():
            w.destroy()

        total = len(creds)
        self.audit_progress.configure(text=f"⏳ Auditando {total} contraseñas...", fg=C["yellow"])
        self.root.update_idletasks()

        def audit():
            results = []
            for i, cred in enumerate(creds):
                self.root.after(0, lambda i=i: self.audit_progress.configure(
                    text=f"⏳ Verificando {i+1}/{total}...", fg=C["yellow"]))
                hibp = self.engine.check_hibp(cred["password"])
                results.append((cred, hibp))
                time.sleep(0.2)  # Rate limiting

            def show_results():
                compromised = [(c, h) for c, h in results if h.get("compromised")]
                weak_pw = [c for c in creds if len(c["password"]) < 10 or c["password"].isalpha() or c["password"].isdigit()]
                errors = [(c, h) for c, h in results if h.get("compromised") is None]

                if not compromised and not weak_pw:
                    self.audit_progress.configure(
                        text=f"✅ ¡Excelente! Ninguna de tus {total} contraseñas aparece en filtraciones.",
                        fg=C["green"])
                    ToastNotification.show(self.root, "✅ Auditoría completada: todo seguro", "success")
                else:
                    issues = len(compromised) + len(weak_pw)
                    self.audit_progress.configure(
                        text=f"⚠️ Se encontraron {issues} problemas de {total} contraseñas:",
                        fg=C["red"])

                for cred, hibp in compromised:
                    row = tk.Frame(self.audit_results_frame, bg=C["card"])
                    row.pack(fill="x", pady=2)
                    make_label(row, f"🔴 {cred.get('title', 'Sin nombre')}", 9, bold=True, color=C["red"]).pack(side="left")
                    count = hibp.get('breach_count', 0)
                    make_label(row, f"  — {count:,} filtraciones", 8, color=C["red"]).pack(side="left")

                for cred in weak_pw:
                    # Don't duplicate if already in compromised
                    if any(c["id"] == cred["id"] for c, _ in compromised):
                        continue
                    row = tk.Frame(self.audit_results_frame, bg=C["card"])
                    row.pack(fill="x", pady=2)
                    make_label(row, f"🟡 {cred.get('title', 'Sin nombre')}", 9, bold=True, color=C["yellow"]).pack(side="left")
                    make_label(row, "  — Contraseña débil", 8, color=C["yellow"]).pack(side="left")

                if errors:
                    row = tk.Frame(self.audit_results_frame, bg=C["card"])
                    row.pack(fill="x", pady=2)
                    make_label(row, f"⚪ {len(errors)} no verificadas (error de conexión)", 8, color=C["muted"]).pack(side="left")

            self.root.after(0, show_results)

        threading.Thread(target=audit, daemon=True).start()

    def _on_uninstall_data(self):
        """Elimina todos los datos de la app (vault, logs) con triple confirmación."""
        # Confirmación 1
        if not messagebox.askyesno("⚠️ Eliminar Datos",
                "¿Estás seguro de que quieres ELIMINAR TODOS los datos?\n\n"
                "• Bóveda cifrada (vault.enc)\n"
                "• Logs de ejecución\n"
                "• Toda la carpeta de datos\n\n"
                "Esta acción es IRREVERSIBLE."):
            return

        # Confirmación 2
        if not messagebox.askyesno("⚠️ ÚLTIMA CONFIRMACIÓN",
                "¿REALMENTE quieres eliminar TODO?\n\n"
                "Perderás TODAS tus contraseñas guardadas.\n"
                "Asegúrate de haber exportado antes."):
            return

        # Confirmación 3: escribir ELIMINAR
        dlg = tk.Toplevel(self.root)
        dlg.title("Confirmación Final"); dlg.geometry("380x180")
        dlg.configure(bg=C["bg"]); dlg.transient(self.root); dlg.grab_set()
        x = self.root.winfo_x() + 140; y = self.root.winfo_y() + 250
        dlg.geometry(f"+{x}+{y}")

        make_label(dlg, "Escribe ELIMINAR para confirmar:", 10, color=C["red"]).pack(padx=15, pady=(15,5))
        confirm_e = make_entry(dlg, font_size=12)
        confirm_e.pack(fill="x", padx=15, pady=(0,10))

        def do_delete():
            if confirm_e.get().strip() != "ELIMINAR":
                ToastNotification.show(dlg, "Escribe ELIMINAR exactamente.", "warning")
                return
            dlg.destroy()

            # Bloquear bóveda primero
            if self.vault.is_unlocked:
                self.vault.lock()

            # Eliminar todos los datos
            try:
                # Cerrar handlers de logging para liberar archivos
                for handler in root_logger.handlers[:]:
                    handler.close()
                    root_logger.removeHandler(handler)

                # Eliminar carpeta de datos completa
                if os.path.isdir(APP_DIR):
                    shutil.rmtree(APP_DIR, ignore_errors=True)

                messagebox.showinfo("✅ Datos Eliminados",
                    "Todos los datos han sido eliminados.\n\n"
                    "La aplicación se cerrará ahora.\n"
                    "Puedes borrar el .exe manualmente.")
                self.root.destroy()
                sys.exit(0)

            except Exception as e:
                messagebox.showerror("Error", f"Error al eliminar datos:\n{e}\n\n"
                    f"Puedes borrar manualmente la carpeta:\n{APP_DIR}")

        make_button(dlg, "🗑️ ELIMINAR TODO", do_delete,
                    bg_color=C["red"], fg_color="white", size=11, bold=True).pack(fill="x", padx=15, pady=5)

    # ══════════════════════════════════════════════════════
    #  RUN
    # ══════════════════════════════════════════════════════

    def run(self):
        logger.info("Lanzando aplicación...")
        try:
            self.root.mainloop()
        except KeyboardInterrupt:
            logger.info("Interrumpido por usuario")
        finally:
            if self.vault.is_unlocked:
                self.vault.lock()
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
        print(f"\n[ERROR FATAL] {e}")
        print(f"Log: {log_filename}")
        input("Presiona Enter para salir...")
        sys.exit(1)
