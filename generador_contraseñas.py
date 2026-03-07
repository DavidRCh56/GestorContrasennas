"""
╔══════════════════════════════════════════════════════════════╗
║     GESTOR DE CONTRASEÑAS SEGURO v2.0                       ║
║                                                              ║
║  • Generador de contraseñas criptográficamente seguras       ║
║  • Bóveda cifrada con AES-256-GCM                           ║
║  • Protección anti-captura de pantalla (Windows)             ║
╚══════════════════════════════════════════════════════════════╝
"""

import tkinter as tk
from tkinter import ttk, messagebox
import logging
import sys
import os
import ctypes
import webbrowser
import time
from datetime import datetime

# Módulos propios
from password_engine import PasswordEngine
from crypto_vault import CryptoVault

# ═══════════════════════════════════════════════════════════════
#  LOGGING
# ═══════════════════════════════════════════════════════════════

LOG_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs")
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
logger.info("  Gestor de Contraseñas Seguro v2.0")
logger.info("=" * 60)

# ═══════════════════════════════════════════════════════════════
#  CONSTANTES DE ESTILO
# ═══════════════════════════════════════════════════════════════

C = {
    "bg":          "#0f0f1a",
    "card":        "#1a1a2e",
    "input":       "#16213e",
    "hover":       "#1f3460",
    "accent":      "#6c63ff",
    "accent_h":    "#7f78ff",
    "green":       "#00d4aa",
    "yellow":      "#ffa726",
    "red":         "#ef5350",
    "txt":         "#e8e8f0",
    "txt2":        "#8888aa",
    "muted":       "#555577",
    "border":      "#2a2a4a",
    "border_f":    "#6c63ff",
}
FONT = "Segoe UI"
MONO = "Consolas"

# ═══════════════════════════════════════════════════════════════
#  PROTECCIÓN ANTI-CAPTURA DE PANTALLA
# ═══════════════════════════════════════════════════════════════

def set_screen_capture_protection(hwnd, enable=True):
    """Activa/desactiva protección anti-captura usando la API de Windows."""
    if sys.platform != "win32":
        logger.debug("Anti-captura no disponible (no es Windows)")
        return False
    try:
        user32 = ctypes.windll.user32
        # WDA_EXCLUDEFROMCAPTURE = 0x00000011 (Win10 2004+)
        # WDA_NONE = 0x00000000
        flag = 0x00000011 if enable else 0x00000000
        result = user32.SetWindowDisplayAffinity(hwnd, flag)
        if result:
            logger.info(f"Anti-captura {'activada' if enable else 'desactivada'} ✓")
        else:
            # Fallback a WDA_MONITOR = 0x00000001
            if enable:
                result = user32.SetWindowDisplayAffinity(hwnd, 0x00000001)
                logger.info(f"Anti-captura (fallback WDA_MONITOR): {'OK' if result else 'FALLO'}")
        return bool(result)
    except Exception as e:
        logger.warning(f"Error en anti-captura: {e}")
        return False


# ═══════════════════════════════════════════════════════════════
#  HELPERS DE UI
# ═══════════════════════════════════════════════════════════════

def make_card(parent):
    return tk.Frame(parent, bg=C["card"], highlightbackground=C["border"], highlightthickness=1)

def make_label(parent, text, size=10, bold=False, color=None, anchor="w", font_family=None):
    f = font_family or FONT
    w = "bold" if bold else "normal"
    return tk.Label(parent, text=text, font=(f, size, w), bg=parent.cget("bg"),
                    fg=color or C["txt"], anchor=anchor)

def make_entry(parent, show=None, font_family=None, font_size=10):
    f = font_family or FONT
    return tk.Entry(parent, font=(f, font_size), bg=C["input"], fg=C["txt"],
                    insertbackground=C["accent"], relief="flat",
                    highlightbackground=C["border"], highlightthickness=1,
                    highlightcolor=C["border_f"], show=show)

def make_button(parent, text, command, bg_color=None, fg_color="white", size=10, bold=False):
    bg = bg_color or C["accent"]
    w = "bold" if bold else "normal"
    btn = tk.Button(parent, text=text, font=(FONT, size, w), bg=bg, fg=fg_color,
                    activebackground=C["accent_h"], activeforeground="white",
                    relief="flat", cursor="hand2", padx=12, pady=6, command=command)
    hover_bg = C["accent_h"] if bg == C["accent"] else C["hover"]
    btn.bind("<Enter>", lambda e: btn.configure(bg=hover_bg))
    btn.bind("<Leave>", lambda e: btn.configure(bg=bg))
    return btn


# ═══════════════════════════════════════════════════════════════
#  APLICACIÓN PRINCIPAL
# ═══════════════════════════════════════════════════════════════

class PasswordManagerApp:

    def __init__(self):
        logger.info("Inicializando aplicación...")
        self.engine = PasswordEngine()
        vault_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vault.enc")
        self.vault = CryptoVault(vault_path)
        self.last_generated_password = None

        self.root = tk.Tk()
        self.root.title("🔐 Gestor de Contraseñas Seguro")
        self.root.geometry("620x750")
        self.root.minsize(550, 600)
        self.root.configure(bg=C["bg"])
        self._center_window(620, 750)

        # Notebook (pestañas)
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("TNotebook", background=C["bg"], borderwidth=0)
        style.configure("TNotebook.Tab", background=C["card"], foreground=C["txt"],
                        font=(FONT, 10, "bold"), padding=[15, 8])
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

        # Evento de cambio de pestaña (anti-captura)
        self.notebook.bind("<<NotebookTabChanged>>", self._on_tab_changed)

        logger.info("Aplicación inicializada ✓")

    def _center_window(self, w, h):
        x = (self.root.winfo_screenwidth() // 2) - (w // 2)
        y = (self.root.winfo_screenheight() // 2) - (h // 2)
        self.root.geometry(f"{w}x{h}+{x}+{y}")

    def _on_tab_changed(self, event):
        tab_idx = self.notebook.index(self.notebook.select())
        logger.debug(f"Pestaña cambiada a: {tab_idx}")
        try:
            hwnd = ctypes.windll.user32.GetParent(self.root.winfo_id())
            if tab_idx == 1:  # Pestaña vault
                set_screen_capture_protection(hwnd, True)
            else:
                set_screen_capture_protection(hwnd, False)
        except Exception:
            pass

    # ══════════════════════════════════════════════════════
    #  TAB 1: GENERADOR
    # ══════════════════════════════════════════════════════

    def _build_generator_tab(self):
        logger.info("Construyendo pestaña Generador...")

        # Scrollable
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
        make_label(f, "⚡ Generador de Contraseñas", 16, bold=True).pack(fill="x", pady=(0, 3))
        make_label(f, "Contraseñas criptográficamente seguras", 9, color=C["txt2"]).pack(fill="x", pady=(0, 10))

        # Card: Longitud
        lc = make_card(f); lc.pack(fill="x", pady=(0, 8), ipady=5, ipadx=10)
        make_label(lc, "📏  LONGITUD", 9, bold=True, color=C["txt2"]).pack(fill="x", padx=12, pady=(8, 3))

        sf = tk.Frame(lc, bg=C["card"]); sf.pack(fill="x", padx=12, pady=(0, 5))
        self.length_var = tk.IntVar(value=20)
        self.length_lbl = make_label(sf, "20", 20, bold=True, color=C["accent"])
        self.length_lbl.configure(width=4); self.length_lbl.pack(side="left")

        self.length_slider = tk.Scale(sf, from_=4, to=128, orient="horizontal",
            variable=self.length_var, command=self._on_slider, bg=C["card"], fg=C["txt"],
            troughcolor=C["input"], highlightthickness=0, sliderrelief="flat",
            showvalue=False, sliderlength=20, font=(FONT, 8))
        self.length_slider.pack(side="left", fill="x", expand=True, padx=(10, 0))

        mf = tk.Frame(lc, bg=C["card"]); mf.pack(fill="x", padx=12, pady=(0, 5))
        make_label(mf, "O escribe:", 9, color=C["muted"]).pack(side="left")
        self.len_entry = make_entry(mf, font_size=10)
        self.len_entry.configure(width=6, justify="center")
        self.len_entry.pack(side="left", padx=(8, 0))
        self.len_entry.insert(0, "20")
        self.len_entry.bind("<Return>", self._on_len_entry)
        self.len_entry.bind("<FocusOut>", self._on_len_entry)

        # Card: Tipos
        tc = make_card(f); tc.pack(fill="x", pady=(0, 8), ipady=5, ipadx=10)
        make_label(tc, "🔤  TIPOS DE CARACTERES", 9, bold=True, color=C["txt2"]).pack(fill="x", padx=12, pady=(8, 5))

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

        # Card: Símbolos custom
        sc = make_card(f); sc.pack(fill="x", pady=(0, 8), ipady=5, ipadx=10)
        make_label(sc, "⚙️  SÍMBOLOS PERSONALIZADOS", 9, bold=True, color=C["txt2"]).pack(fill="x", padx=12, pady=(8, 3))
        self.sym_entry = make_entry(sc, font_family=MONO, font_size=11)
        self.sym_entry.pack(fill="x", padx=12, pady=(0, 5))
        self.sym_entry.insert(0, "!@#$%^&*()-_=+[]{}|;:',.<>?/~`")

        # Botón GENERAR
        make_button(f, "⚡  GENERAR CONTRASEÑA", self._on_generate,
                    size=12, bold=True).pack(fill="x", pady=(5, 8), ipady=4)

        # Card: Resultado
        rc = make_card(f); rc.pack(fill="x", pady=(0, 8), ipady=5, ipadx=10)
        make_label(rc, "🔑  CONTRASEÑA GENERADA", 9, bold=True, color=C["txt2"]).pack(fill="x", padx=12, pady=(8, 3))

        pw_f = tk.Frame(rc, bg=C["input"], highlightbackground=C["border"], highlightthickness=1)
        pw_f.pack(fill="x", padx=12, pady=(0, 5))
        self.result_text = tk.Text(pw_f, height=3, font=(MONO, 12), bg=C["input"], fg=C["green"],
            insertbackground=C["green"], relief="flat", wrap="char",
            selectbackground=C["accent"], selectforeground="white", padx=8, pady=8)
        self.result_text.pack(fill="x")
        self.result_text.insert("1.0", "Aquí aparecerá tu contraseña...")
        self.result_text.configure(state="disabled")

        # Botones de acción
        af = tk.Frame(rc, bg=C["card"]); af.pack(fill="x", padx=12, pady=(0, 3))
        self.copy_btn = make_button(af, "📋 Copiar", self._on_copy, bg_color=C["input"], fg_color=C["txt"], size=9)
        self.copy_btn.pack(side="left", padx=(0, 5))
        self.save_gen_btn = make_button(af, "💾 Guardar en Bóveda", self._on_save_generated,
                                         bg_color=C["input"], fg_color=C["txt"], size=9)
        self.save_gen_btn.pack(side="left")

        # Indicadores
        self.str_label = make_label(rc, "Fortaleza: --", 9, color=C["muted"])
        self.str_label.pack(fill="x", padx=12)
        self.ent_label = make_label(rc, "Entropía: --", 8, color=C["muted"])
        self.ent_label.pack(fill="x", padx=12)
        self.str_bar = tk.Canvas(rc, height=5, bg=C["input"], highlightthickness=0)
        self.str_bar.pack(fill="x", padx=12, pady=(3, 8))

        logger.info("Pestaña Generador construida ✓")

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
            try:
                length = int(self.len_entry.get())
            except ValueError:
                length = self.length_var.get()

            if not any([self.var_low.get(), self.var_up.get(), self.var_dig.get(), self.var_sym.get()]):
                messagebox.showwarning("Atención", "Selecciona al menos un tipo de carácter.")
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
            self.ent_label.configure(text=f"Entropía: {result['entropy_bits']} bits | "
                                          f"Charset: {result['charset_size']} | "
                                          f"Tiempo: {result['generation_time_ms']} ms")
            self._draw_bar(result["entropy_bits"])

        except ValueError as e:
            messagebox.showwarning("Error", str(e))
        except Exception as e:
            logger.critical(f"Error generando: {e}", exc_info=True)
            messagebox.showerror("Error", str(e))

    def _on_copy(self):
        self.result_text.configure(state="normal")
        pw = self.result_text.get("1.0", tk.END).strip()
        self.result_text.configure(state="disabled")
        if pw and pw != "Aquí aparecerá tu contraseña...":
            self.root.clipboard_clear(); self.root.clipboard_append(pw)
            orig = self.copy_btn.cget("text")
            self.copy_btn.configure(text="✅ ¡Copiado!", fg=C["green"])
            self.root.after(1500, lambda: self.copy_btn.configure(text=orig, fg=C["txt"]))
        else:
            messagebox.showinfo("Info", "Primero genera una contraseña.")

    def _on_save_generated(self):
        """Guardar la contraseña generada en la bóveda."""
        if not self.last_generated_password:
            messagebox.showinfo("Info", "Primero genera una contraseña.")
            return

        if not self.vault.is_unlocked:
            messagebox.showinfo("Bóveda bloqueada",
                "Debes desbloquear tu bóveda primero.\n\n"
                "Ve a la pestaña 'Mis Contraseñas' e inicia sesión.")
            return

        # Diálogo para pedir nombre, sitio y email
        dlg = tk.Toplevel(self.root)
        dlg.title("Guardar Contraseña")
        dlg.geometry("400x340")
        dlg.configure(bg=C["bg"])
        dlg.transient(self.root); dlg.grab_set()
        x = self.root.winfo_x() + 110; y = self.root.winfo_y() + 180
        dlg.geometry(f"+{x}+{y}")

        make_label(dlg, "💾 Guardar Contraseña Generada", 13, bold=True).pack(padx=15, pady=(15, 10))
        make_label(dlg, "Contraseña:", 9, color=C["txt2"]).pack(fill="x", padx=15)
        pw_show = make_label(dlg, "●" * min(len(self.last_generated_password), 30), 10, color=C["green"])
        pw_show.pack(fill="x", padx=15, pady=(0, 8))

        make_label(dlg, "Nombre (ej: GitHub, Gmail...):", 9, color=C["txt2"]).pack(fill="x", padx=15)
        title_e = make_entry(dlg); title_e.pack(fill="x", padx=15, pady=(0, 6))

        make_label(dlg, "URL / Enlace (opcional):", 9, color=C["txt2"]).pack(fill="x", padx=15)
        site_e = make_entry(dlg); site_e.pack(fill="x", padx=15, pady=(0, 6))

        make_label(dlg, "Email / Usuario:", 9, color=C["txt2"]).pack(fill="x", padx=15)
        email_e = make_entry(dlg); email_e.pack(fill="x", padx=15, pady=(0, 10))

        def save():
            title = title_e.get().strip()
            if not title:
                messagebox.showwarning("Atención", "Introduce un nombre.", parent=dlg)
                return
            try:
                self.vault.add_credential(title, site_e.get().strip(),
                    email_e.get().strip(), self.last_generated_password)
                dlg.destroy()
                messagebox.showinfo("Guardado", f"'{title}' guardado en la bóveda ✓")
                self._refresh_credentials_list()
            except Exception as e:
                messagebox.showerror("Error", str(e), parent=dlg)

        make_button(dlg, "💾 Guardar", save, size=11, bold=True).pack(fill="x", padx=15, pady=(0, 10))

    def _strength_color(self, entropy):
        if entropy >= 128: return C["green"]
        elif entropy >= 80: return "#4caf50"
        elif entropy >= 50: return C["yellow"]
        return C["red"]

    def _draw_bar(self, entropy):
        self.str_bar.delete("all")
        self.str_bar.update_idletasks()
        w = max(self.str_bar.winfo_width(), 300)
        pct = min(entropy / 200.0, 1.0)
        self.str_bar.create_rectangle(0, 0, int(w * pct), 5,
                                      fill=self._strength_color(entropy), outline="")

    # ══════════════════════════════════════════════════════
    #  TAB 2: BÓVEDA DE CONTRASEÑAS
    # ══════════════════════════════════════════════════════

    def _build_vault_tab(self):
        logger.info("Construyendo pestaña Bóveda...")

        # Container que cambiará entre login y gestor
        self.vault_container = tk.Frame(self.vault_frame, bg=C["bg"])
        self.vault_container.pack(fill="both", expand=True)

        if self.vault.is_vault_created:
            self._show_login_screen()
        else:
            self._show_create_master_screen()

        logger.info("Pestaña Bóveda construida ✓")

    def _clear_vault_container(self):
        for w in self.vault_container.winfo_children():
            w.destroy()

    # ── Pantalla: Crear contraseña maestra ──

    def _show_create_master_screen(self):
        self._clear_vault_container()
        f = self.vault_container

        make_label(f, "🔒", 30).pack(pady=(40, 5))
        make_label(f, "Crear Contraseña Maestra", 16, bold=True).pack()
        make_label(f, "Esta contraseña protege toda tu bóveda.\nRecuérdala bien, no se puede recuperar.",
                   9, color=C["txt2"]).pack(pady=(5, 20))

        card = make_card(f); card.pack(fill="x", padx=40, ipady=10)

        make_label(card, "Contraseña maestra:", 10, color=C["txt2"]).pack(fill="x", padx=15, pady=(10, 3))
        self.master_pw1 = make_entry(card, show="●", font_size=12)
        self.master_pw1.pack(fill="x", padx=15, pady=(0, 8))

        make_label(card, "Confirmar contraseña:", 10, color=C["txt2"]).pack(fill="x", padx=15, pady=(0, 3))
        self.master_pw2 = make_entry(card, show="●", font_size=12)
        self.master_pw2.pack(fill="x", padx=15, pady=(0, 10))

        make_label(card, "≥ 8 caracteres. Usa letras, números y símbolos.", 8, color=C["muted"]).pack(padx=15, pady=(0, 10))

        make_button(f, "🔐 Crear Bóveda", self._on_create_vault,
                    size=12, bold=True).pack(fill="x", padx=40, pady=15, ipady=4)

    def _on_create_vault(self):
        pw1 = self.master_pw1.get()
        pw2 = self.master_pw2.get()
        if pw1 != pw2:
            messagebox.showwarning("Error", "Las contraseñas no coinciden.")
            return
        if len(pw1) < 8:
            messagebox.showwarning("Error", "Mínimo 8 caracteres.")
            return
        try:
            self.vault.create_vault(pw1)
            messagebox.showinfo("✓ Bóveda creada", "Tu bóveda cifrada ha sido creada exitosamente.")
            self._show_manager_screen()
        except Exception as e:
            messagebox.showerror("Error", str(e))

    # ── Pantalla: Login ──

    def _show_login_screen(self):
        self._clear_vault_container()
        f = self.vault_container

        make_label(f, "🔒", 30).pack(pady=(50, 5))
        make_label(f, "Bóveda Bloqueada", 16, bold=True).pack()
        make_label(f, "Introduce tu contraseña maestra para acceder.", 9, color=C["txt2"]).pack(pady=(5, 20))

        card = make_card(f); card.pack(fill="x", padx=40, ipady=10)
        make_label(card, "Contraseña maestra:", 10, color=C["txt2"]).pack(fill="x", padx=15, pady=(10, 3))
        self.login_pw = make_entry(card, show="●", font_size=12)
        self.login_pw.pack(fill="x", padx=15, pady=(0, 10))
        self.login_pw.bind("<Return>", lambda e: self._on_unlock())

        self.login_status = make_label(f, "", 9, color=C["red"])
        self.login_status.pack(pady=(5, 0))

        make_button(f, "🔓 Desbloquear", self._on_unlock,
                    size=12, bold=True).pack(fill="x", padx=40, pady=15, ipady=4)

    def _on_unlock(self):
        pw = self.login_pw.get()
        if not pw:
            self.login_status.configure(text="Introduce la contraseña.")
            return
        self.login_status.configure(text="Desbloqueando... (puede tardar unos segundos)", fg=C["yellow"])
        self.root.update_idletasks()

        if self.vault.unlock(pw):
            self._show_manager_screen()
        else:
            self.login_status.configure(text="❌ Contraseña incorrecta.", fg=C["red"])
            logger.warning("Intento de desbloqueo fallido")

    # ── Pantalla: Gestor de contraseñas ──

    def _show_manager_screen(self):
        self._clear_vault_container()
        f = self.vault_container

        # Header
        hdr = tk.Frame(f, bg=C["bg"]); hdr.pack(fill="x", padx=15, pady=(10, 5))
        make_label(hdr, "🔓 Mis Contraseñas", 14, bold=True).pack(side="left")
        make_button(hdr, "🔒 Bloquear", self._on_lock, bg_color=C["input"],
                    fg_color=C["txt"], size=9).pack(side="right")
        make_button(hdr, "➕ Añadir", self._on_add_credential, size=9).pack(side="right", padx=(0, 5))

        # Lista scrollable
        list_frame = tk.Frame(f, bg=C["bg"]); list_frame.pack(fill="both", expand=True, padx=10, pady=5)

        self.cred_canvas = tk.Canvas(list_frame, bg=C["bg"], highlightthickness=0)
        cred_sb = tk.Scrollbar(list_frame, orient="vertical", command=self.cred_canvas.yview)
        self.cred_inner = tk.Frame(self.cred_canvas, bg=C["bg"])
        self.cred_inner.bind("<Configure>", lambda e: self.cred_canvas.configure(scrollregion=self.cred_canvas.bbox("all")))
        self.cred_canvas.create_window((0, 0), window=self.cred_inner, anchor="nw")
        self.cred_canvas.configure(yscrollcommand=cred_sb.set)
        self.cred_canvas.bind("<Configure>", lambda e: self.cred_canvas.itemconfig(
            self.cred_canvas.find_all()[0], width=e.width))
        cred_sb.pack(side="right", fill="y"); self.cred_canvas.pack(side="left", fill="both", expand=True)

        self._refresh_credentials_list()

    def _refresh_credentials_list(self):
        """Recarga la lista de credenciales."""
        if not hasattr(self, 'cred_inner'):
            return
        for w in self.cred_inner.winfo_children():
            w.destroy()

        creds = self.vault.credentials
        if not creds:
            make_label(self.cred_inner, "No hay contraseñas guardadas.\nUsa '➕ Añadir' o genera una y guárdala.",
                       10, color=C["muted"]).pack(pady=40)
            return

        for cred in creds:
            self._build_credential_card(self.cred_inner, cred)

    def _build_credential_card(self, parent, cred):
        """Construye una tarjeta para una credencial."""
        card = make_card(parent)
        card.pack(fill="x", pady=(0, 6), ipady=6, ipadx=8)

        # Fila superior: título + acciones
        top = tk.Frame(card, bg=C["card"]); top.pack(fill="x", padx=10, pady=(8, 2))
        display_name = cred.get('title') or cred.get('site', 'Sin nombre')
        make_label(top, f"🌐 {display_name}", 11, bold=True, color=C["accent"]).pack(side="left")

        # URL (si existe y es diferente del título)
        site_url = cred.get('site', '')
        if site_url and site_url != display_name:
            url_row = tk.Frame(card, bg=C["card"]); url_row.pack(fill="x", padx=10, pady=0)
            make_label(url_row, f"🔗 {site_url}", 8, color=C["muted"]).pack(side="left")

        # Botón eliminar
        del_btn = make_button(top, "🗑", lambda c=cred: self._on_delete_credential(c["id"]),
                              bg_color=C["card"], fg_color=C["red"], size=9)
        del_btn.pack(side="right")

        # Botón editar
        edit_btn = make_button(top, "✏️", lambda c=cred: self._on_edit_credential(c),
                               bg_color=C["card"], fg_color=C["yellow"], size=9)
        edit_btn.pack(side="right", padx=(0, 3))

        # Email
        em_row = tk.Frame(card, bg=C["card"]); em_row.pack(fill="x", padx=10, pady=1)
        make_label(em_row, f"📧 {cred['email']}", 9, color=C["txt2"]).pack(side="left")
        make_button(em_row, "📋", lambda c=cred: self._copy_to_clip(c["email"]),
                    bg_color=C["card"], fg_color=C["txt2"], size=8).pack(side="right")

        # Contraseña (oculta)
        pw_row = tk.Frame(card, bg=C["card"]); pw_row.pack(fill="x", padx=10, pady=1)
        pw_display = make_label(pw_row, "🔑 ●●●●●●●●●●●●", 9, color=C["muted"])
        pw_display.pack(side="left")

        def toggle_pw(label=pw_display, c=cred):
            if "●" in label.cget("text"):
                label.configure(text=f"🔑 {c['password']}", fg=C["green"])
                self.root.after(5000, lambda: label.configure(text="🔑 ●●●●●●●●●●●●", fg=C["muted"]))
            else:
                label.configure(text="🔑 ●●●●●●●●●●●●", fg=C["muted"])

        make_button(pw_row, "👁", toggle_pw, bg_color=C["card"], fg_color=C["txt2"], size=8).pack(side="right")
        make_button(pw_row, "📋", lambda c=cred: self._copy_to_clip(c["password"]),
                    bg_color=C["card"], fg_color=C["txt2"], size=8).pack(side="right", padx=(0, 3))

        # Botones de acción: Quick Login + Editar
        action_row = tk.Frame(card, bg=C["card"]); action_row.pack(fill="x", padx=10, pady=(3, 2))
        make_button(action_row, "🚀 Quick Login", lambda c=cred: self._on_quick_login(c),
                    bg_color=C["accent"], fg_color="white", size=9).pack(side="left")
        make_button(action_row, "✏️ Editar", lambda c=cred: self._on_edit_credential(c),
                    bg_color=C["input"], fg_color=C["yellow"], size=9).pack(side="left", padx=(5, 0))

        # Notas
        if cred.get("notes"):
            make_label(card, f"📝 {cred['notes']}", 8, color=C["muted"]).pack(fill="x", padx=10, pady=(1, 5))

    def _copy_to_clip(self, text, notify=False):
        self.root.clipboard_clear(); self.root.clipboard_append(text)
        logger.info("Datos copiados al portapapeles")
        if notify:
            messagebox.showinfo("Copiado", "Datos copiados al portapapeles ✓")

    def _on_quick_login(self, cred):
        """
        Quick Login: copia el email al portapapeles, abre la URL en el navegador,
        y después de 4 segundos copia automáticamente la contraseña.
        
        Flujo para el usuario:
        1. Se copia el email → pegarlo en el campo de usuario
        2. Se abre la web en el navegador predeterminado
        3. Tras 4 seg se copia la contraseña → pegarla en el campo de contraseña
        """
        site = cred["site"].strip()
        logger.info(f"Quick Login para: {site}")

        # Normalizar la URL
        url = site
        if not url.startswith(("http://", "https://")):
            url = "https://" + url

        # Paso 1: Copiar email al portapapeles
        self.root.clipboard_clear()
        self.root.clipboard_append(cred["email"])
        logger.info("Email copiado al portapapeles")

        # Paso 2: Abrir en navegador
        try:
            webbrowser.open(url)
            logger.info(f"URL abierta en navegador: {url}")
        except Exception as e:
            logger.error(f"Error abriendo navegador: {e}")
            messagebox.showerror("Error", f"No se pudo abrir el navegador:\n{e}")
            return

        # Notificación
        messagebox.showinfo(
            "🚀 Quick Login",
            f"✅ Email/usuario copiado al portapapeles.\n"
            f"Pégalo en el campo de usuario (Ctrl+V).\n\n"
            f"⏳ En 4 segundos se copiará la contraseña\n"
            f"automáticamente para que la pegues."
        )

        # Paso 3: Después de 4 seg, copiar la contraseña
        def copy_password_delayed():
            self.root.clipboard_clear()
            self.root.clipboard_append(cred["password"])
            logger.info("Contraseña copiada al portapapeles (auto-delayed)")

        self.root.after(4000, copy_password_delayed)

    def _on_add_credential(self):
        """Diálogo para añadir credencial manualmente."""
        dlg = tk.Toplevel(self.root)
        dlg.title("Añadir Credencial")
        dlg.geometry("420x400"); dlg.configure(bg=C["bg"])
        dlg.transient(self.root); dlg.grab_set()
        x = self.root.winfo_x() + 100; y = self.root.winfo_y() + 150
        dlg.geometry(f"+{x}+{y}")

        make_label(dlg, "➕ Nueva Credencial", 13, bold=True).pack(padx=15, pady=(15, 10))

        for label_text, var_name in [("Nombre (ej: GitHub, Gmail...):", "d_title"),
                                      ("URL / Enlace (opcional):", "d_site"),
                                      ("Email / Usuario:", "d_email"),
                                      ("Contraseña:", "d_pw"),
                                      ("Notas (opcional):", "d_notes")]:
            make_label(dlg, label_text, 9, color=C["txt2"]).pack(fill="x", padx=15)
            e = make_entry(dlg, show="●" if "Contra" in label_text else None)
            e.pack(fill="x", padx=15, pady=(0, 6))
            setattr(self, var_name, e)

        def save():
            title = self.d_title.get().strip()
            if not title:
                messagebox.showwarning("Atención", "Introduce un nombre.", parent=dlg)
                return
            try:
                self.vault.add_credential(title, self.d_site.get().strip(),
                    self.d_email.get().strip(), self.d_pw.get(), self.d_notes.get().strip())
                dlg.destroy()
                self._refresh_credentials_list()
            except Exception as e:
                messagebox.showerror("Error", str(e), parent=dlg)

        make_button(dlg, "💾 Guardar", save, size=11, bold=True).pack(fill="x", padx=15, pady=10)

    def _on_edit_credential(self, cred):
        """Diálogo para editar una credencial existente."""
        dlg = tk.Toplevel(self.root)
        dlg.title("Editar Credencial")
        dlg.geometry("420x430"); dlg.configure(bg=C["bg"])
        dlg.transient(self.root); dlg.grab_set()
        x = self.root.winfo_x() + 100; y = self.root.winfo_y() + 130
        dlg.geometry(f"+{x}+{y}")

        make_label(dlg, "✏️ Editar Credencial", 13, bold=True).pack(padx=15, pady=(15, 10))

        fields = {}
        for label_text, key in [("Nombre:", "title"),
                                 ("URL / Enlace:", "site"),
                                 ("Email / Usuario:", "email"),
                                 ("Contraseña:", "password"),
                                 ("Notas (opcional):", "notes")]:
            make_label(dlg, label_text, 9, color=C["txt2"]).pack(fill="x", padx=15)
            e = make_entry(dlg)
            e.pack(fill="x", padx=15, pady=(0, 6))
            e.insert(0, cred.get(key, ""))
            fields[key] = e

        def save_edit():
            title = fields["title"].get().strip()
            if not title:
                messagebox.showwarning("Atención", "El nombre no puede estar vacío.", parent=dlg)
                return
            try:
                self.vault.update_credential(
                    cred["id"],
                    title=title,
                    site=fields["site"].get().strip(),
                    email=fields["email"].get().strip(),
                    password=fields["password"].get(),
                    notes=fields["notes"].get().strip()
                )
                dlg.destroy()
                self._refresh_credentials_list()
                logger.info(f"Credencial {cred['id']} editada desde UI")
            except Exception as e:
                messagebox.showerror("Error", str(e), parent=dlg)

        make_button(dlg, "💾 Guardar Cambios", save_edit, size=11, bold=True).pack(fill="x", padx=15, pady=10)

    def _on_delete_credential(self, cred_id):
        if messagebox.askyesno("Confirmar", "¿Eliminar esta credencial?\nEsta acción no se puede deshacer."):
            self.vault.delete_credential(cred_id)
            self._refresh_credentials_list()

    def _on_lock(self):
        self.vault.lock()
        self._show_login_screen()
        logger.info("Bóveda bloqueada por el usuario")

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
