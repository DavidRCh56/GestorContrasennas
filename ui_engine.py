"""
╔══════════════════════════════════════════════════════════════╗
║  UI ENGINE — Animaciones, Tooltips, Toast & Estilos v3.0     ║
╚══════════════════════════════════════════════════════════════╝
"""
import tkinter as tk
import math

# ═══════════════════════════════════════════════════════════════
#  PALETA DE COLORES MODERNA
# ═══════════════════════════════════════════════════════════════

C = {
    "bg":          "#0a0a14",
    "bg2":         "#0f0f1e",
    "card":        "#141428",
    "card_hover":  "#1a1a35",
    "input":       "#0d1025",
    "hover":       "#1f2855",
    "accent":      "#7c5cfc",
    "accent_h":    "#9b82ff",
    "accent_dim":  "#4a3a99",
    "green":       "#00e6b0",
    "green_dim":   "#00b38a",
    "yellow":      "#ffb74d",
    "red":         "#ff5252",
    "cyan":        "#00d4ff",
    "pink":        "#ff6bcb",
    "txt":         "#e8e8f8",
    "txt2":        "#8888aa",
    "muted":       "#555577",
    "border":      "#22224a",
    "border_f":    "#7c5cfc",
    "glow":        "#7c5cfc",
    "surface":     "#181830",
}
FONT = "Segoe UI"
MONO = "Consolas"


# ═══════════════════════════════════════════════════════════════
#  ANIMATION ENGINE
# ═══════════════════════════════════════════════════════════════

class AnimationEngine:
    """Motor de animaciones basado en timers de tkinter."""

    @staticmethod
    def fade_in(widget, root, duration=300, steps=12):
        """Simula fade-in cambiando el fondo gradualmente."""
        try:
            target_bg = widget.cget("bg")
        except Exception:
            return
        dark = C["bg"]
        AnimationEngine._color_transition(widget, root, dark, target_bg, duration, steps, "bg")

    @staticmethod
    def color_pulse(widget, root, color_from, color_to, duration=400, steps=10):
        """Pulso de color: va y vuelve."""
        def go_back():
            AnimationEngine._color_transition(widget, root, color_to, color_from, duration, steps, "bg")
        AnimationEngine._color_transition(widget, root, color_from, color_to, duration, steps, "bg", go_back)

    @staticmethod
    def _color_transition(widget, root, c_from, c_to, duration, steps, prop, callback=None):
        """Transición gradual de color."""
        try:
            r1, g1, b1 = AnimationEngine._hex_to_rgb(c_from)
            r2, g2, b2 = AnimationEngine._hex_to_rgb(c_to)
        except Exception:
            return
        delay = max(duration // steps, 10)

        def step(i):
            if i > steps:
                if callback:
                    callback()
                return
            try:
                t = i / steps
                t = t * t * (3 - 2 * t)  # smoothstep
                r = int(r1 + (r2 - r1) * t)
                g = int(g1 + (g2 - g1) * t)
                b = int(b1 + (b2 - b1) * t)
                widget.configure(**{prop: f"#{r:02x}{g:02x}{b:02x}"})
                root.after(delay, lambda: step(i + 1))
            except Exception:
                pass

        step(0)

    @staticmethod
    def animate_bar(canvas, root, target_pct, color, duration=500, steps=20):
        """Anima una barra de progreso."""
        delay = max(duration // steps, 10)
        canvas.update_idletasks()
        w = max(canvas.winfo_width(), 200)

        def step(i):
            if i > steps:
                return
            try:
                t = i / steps
                t = t * t * (3 - 2 * t)
                current_w = int(w * target_pct * t)
                canvas.delete("bar")
                canvas.create_rectangle(0, 0, current_w, 6, fill=color, outline="", tags="bar")
                root.after(delay, lambda: step(i + 1))
            except Exception:
                pass
        step(0)

    @staticmethod
    def bounce_text(widget, root, original_text, new_text, duration=1500):
        """Cambia texto con efecto bounce y lo restaura."""
        widget.configure(text=new_text)
        root.after(duration, lambda: _safe_config(widget, text=original_text))

    @staticmethod
    def _hex_to_rgb(hex_color):
        h = hex_color.lstrip("#")
        return int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16)


def _safe_config(widget, **kwargs):
    try:
        widget.configure(**kwargs)
    except Exception:
        pass


# ═══════════════════════════════════════════════════════════════
#  TOAST NOTIFICATIONS
# ═══════════════════════════════════════════════════════════════

class ToastNotification:
    """Notificaciones toast elegantes en la esquina."""

    _active_toasts = []

    @classmethod
    def show(cls, root, message, toast_type="info", duration=2500):
        colors = {
            "info": (C["accent"], "#ffffff"),
            "success": (C["green"], "#000000"),
            "warning": (C["yellow"], "#000000"),
            "error": (C["red"], "#ffffff"),
        }
        bg, fg = colors.get(toast_type, colors["info"])

        toast = tk.Toplevel(root)
        toast.overrideredirect(True)
        toast.attributes("-topmost", True)
        try:
            toast.attributes("-alpha", 0.95)
        except Exception:
            pass

        frame = tk.Frame(toast, bg=bg, padx=16, pady=10,
                         highlightbackground=C["border"], highlightthickness=1)
        frame.pack(fill="both", expand=True)

        tk.Label(frame, text=message, font=(FONT, 10, "bold"),
                 bg=bg, fg=fg, wraplength=300, justify="left").pack()

        # Position bottom-right
        root.update_idletasks()
        rx = root.winfo_rootx() + root.winfo_width() - 20
        ry = root.winfo_rooty() + root.winfo_height() - 60 - (len(cls._active_toasts) * 55)
        toast.update_idletasks()
        tw = toast.winfo_width()
        toast.geometry(f"+{rx - tw}+{ry}")

        cls._active_toasts.append(toast)

        def remove():
            try:
                toast.destroy()
                cls._active_toasts.remove(toast)
            except Exception:
                pass

        root.after(duration, remove)


# ═══════════════════════════════════════════════════════════════
#  TOOLTIP
# ═══════════════════════════════════════════════════════════════

class Tooltip:
    def __init__(self, widget, text):
        self.widget = widget
        self.text = text
        self.tip = None
        widget.bind("<Enter>", self._show)
        widget.bind("<Leave>", self._hide)

    def _show(self, event=None):
        x = self.widget.winfo_rootx() + 20
        y = self.widget.winfo_rooty() + self.widget.winfo_height() + 5
        self.tip = tk.Toplevel(self.widget)
        self.tip.overrideredirect(True)
        self.tip.attributes("-topmost", True)
        try:
            self.tip.attributes("-alpha", 0.92)
        except Exception:
            pass
        frame = tk.Frame(self.tip, bg=C["surface"], padx=8, pady=4,
                         highlightbackground=C["accent_dim"], highlightthickness=1)
        frame.pack()
        tk.Label(frame, text=self.text, font=(FONT, 9), bg=C["surface"],
                 fg=C["txt"], wraplength=250).pack()
        self.tip.geometry(f"+{x}+{y}")

    def _hide(self, event=None):
        if self.tip:
            self.tip.destroy()
            self.tip = None


# ═══════════════════════════════════════════════════════════════
#  UI HELPER FUNCTIONS
# ═══════════════════════════════════════════════════════════════

def make_card(parent, hover=True):
    card = tk.Frame(parent, bg=C["card"],
                    highlightbackground=C["border"], highlightthickness=1)
    if hover:
        card.bind("<Enter>", lambda e: _safe_config(card,
            highlightbackground=C["accent_dim"], bg=C["card_hover"]))
        card.bind("<Leave>", lambda e: _safe_config(card,
            highlightbackground=C["border"], bg=C["card"]))
    return card


def make_label(parent, text, size=10, bold=False, color=None, anchor="w", font_family=None):
    f = font_family or FONT
    w = "bold" if bold else "normal"
    return tk.Label(parent, text=text, font=(f, size, w), bg=parent.cget("bg"),
                    fg=color or C["txt"], anchor=anchor)


def make_entry(parent, show=None, font_family=None, font_size=10):
    f = font_family or FONT
    e = tk.Entry(parent, font=(f, font_size), bg=C["input"], fg=C["txt"],
                 insertbackground=C["accent"], relief="flat",
                 highlightbackground=C["border"], highlightthickness=1,
                 highlightcolor=C["border_f"], show=show)
    # Focus glow effect
    e.bind("<FocusIn>", lambda ev: _safe_config(e, highlightbackground=C["accent"], highlightthickness=2))
    e.bind("<FocusOut>", lambda ev: _safe_config(e, highlightbackground=C["border"], highlightthickness=1))
    return e


def make_button(parent, text, command, bg_color=None, fg_color="white",
                size=10, bold=False, glow=False):
    bg = bg_color or C["accent"]
    w = "bold" if bold else "normal"
    btn = tk.Button(parent, text=text, font=(FONT, size, w), bg=bg, fg=fg_color,
                    activebackground=C["accent_h"], activeforeground="white",
                    relief="flat", cursor="hand2", padx=14, pady=7, command=command,
                    borderwidth=0)
    hover_bg = C["accent_h"] if bg == C["accent"] else C["hover"]

    def on_enter(e):
        _safe_config(btn, bg=hover_bg)
        if glow:
            _safe_config(btn, highlightbackground=C["glow"], highlightthickness=2)

    def on_leave(e):
        _safe_config(btn, bg=bg)
        if glow:
            _safe_config(btn, highlightthickness=0)

    btn.bind("<Enter>", on_enter)
    btn.bind("<Leave>", on_leave)
    return btn


def make_separator(parent, pad_y=8):
    sep = tk.Frame(parent, bg=C["border"], height=1)
    sep.pack(fill="x", pady=pad_y)
    return sep


def make_combobox_menu(parent, options, default=None, width=18):
    """Custom dropdown using Menubutton (no ttk needed)."""
    var = tk.StringVar(value=default or options[0])
    mb = tk.Menubutton(parent, textvariable=var, font=(FONT, 9),
                       bg=C["input"], fg=C["txt"], relief="flat",
                       activebackground=C["hover"], activeforeground=C["txt"],
                       highlightbackground=C["border"], highlightthickness=1,
                       indicatoron=True, width=width, anchor="w", padx=8)
    menu = tk.Menu(mb, tearoff=0, bg=C["card"], fg=C["txt"],
                   activebackground=C["accent"], activeforeground="white",
                   font=(FONT, 9), relief="flat")
    for opt in options:
        menu.add_command(label=opt, command=lambda o=opt: var.set(o))
    mb.configure(menu=menu)
    return mb, var
