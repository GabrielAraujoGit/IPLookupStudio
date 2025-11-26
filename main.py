# main.py
"""
Verificador de IP — UI moderna com ttkbootstrap (Discord-like / glassmorphism)
Requisitos: requests, ttkbootstrap
Rodar: pip install requests ttkbootstrap
       python main.py
Mantém: validação IP/hostname, reverse DNS, ip-api, histórico, export.
"""

import ipaddress
import socket
import threading
import json
import time
from datetime import datetime, timezone
import tkinter as tk
from tkinter import filedialog, messagebox
from tkinter.scrolledtext import ScrolledText
import requests
import ttkbootstrap as tb
from ttkbootstrap.constants import *
import sys
import os

# -------------------------
# Config / constantes
# -------------------------
HISTORY_FILE = "ip_history.json"
HISTORY_LIMIT = 400
IP_API_URL = (
    "http://ip-api.com/json/{ip}"
    "?fields=status,message,query,reverse,country,regionName,"
    "city,zip,lat,lon,timezone,isp,org,as"
)

# Paleta (Discord-like)
PRIMARY = "#58F258"       # azul Discord
PRIMARY_DEEP = "#4F46E5"
BG = "#0F1113"
CARD = "#17191B"
GLASS = "#1E2124"
TEXT = "#E6EEF3"
MUTED = "#98A0B3"
NEON = "#9AA7FF"

# Fonte segura
FONT_UI = ("Arial", 10)
FONT_TITLE = ("Arial", 12, "bold")
FONT_MONO = ("Consolas", 10)

# -------------------------
# Lógica de análise (mesma funcionalidade)
# -------------------------
class IPAnalyzer:
    def __init__(self, timeout=6):
        self.timeout = timeout

    def validate_input(self, text):
        text = text.strip()
        if not text:
            raise ValueError("Entrada vazia.")
        # tentar como IP primeiro (IPv4/IPv6)
        try:
            addr = ipaddress.ip_address(text)
            return {"type": "ip", "input": text, "addr": addr}
        except ValueError:
            # tentar hostname
            try:
                infos = socket.getaddrinfo(text, None)
                ip = infos[0][4][0]
                return {"type": "hostname", "input": text, "addr": ip}
            except Exception as e:
                raise ValueError(f"Não é IP nem hostname resolvível: {e}")

    def reverse_dns(self, ip):
        try:
            name = socket.gethostbyaddr(ip)[0]
            return name
        except Exception:
            return None

    def geo_and_asn(self, ip):
        try:
            url = IP_API_URL.format(ip=ip)
            resp = requests.get(url, timeout=self.timeout)
            data = resp.json()
            if data.get("status") != "success":
                return {"error": data.get("message") or "Falha na API"}
            return {
                "query": data.get("query"),
                "country": data.get("country"),
                "region": data.get("regionName"),
                "city": data.get("city"),
                "zip": data.get("zip"),
                "lat": data.get("lat"),
                "lon": data.get("lon"),
                "timezone": data.get("timezone"),
                "isp": data.get("isp"),
                "org": data.get("org"),
                "as": data.get("as"),
                "reverse": data.get("reverse"),
            }
        except requests.RequestException as e:
            return {"error": f"Erro de conexão: {e}"}
        except ValueError:
            return {"error": "Resposta inesperada da API"}


# -------------------------
# App UI com ttkbootstrap
# -------------------------
class App:
    def __init__(self, root: tb.Window):
        self.root = root
        self.root.title("Verificador de IP — DNS • ASN • Geolocalização")
        self.root.geometry("980x600")
        self.root.minsize(820, 520)

        # estilo ttkbootstrap (usar um tema escuro como base)
        self.style = tb.Style(theme="darkly")  # base escura
        # ajustar paleta personalizada
        self.customize_theme()

        self.analyzer = IPAnalyzer()
        self.ip_history = self.load_history()

        self.build_ui()
        self.bind_shortcuts()

    def customize_theme(self):
        # Ajustes de cores para parecer Discord-like
        s = self.style
        try:
            s.configure("TFrame", background=BG)
            s.configure("Card.TFrame", background=GLASS)
            s.configure("Accent.TButton", foreground=TEXT, background=PRIMARY, font=FONT_UI)
            s.configure("Ghost.TButton", foreground=TEXT, background="#232526", font=FONT_UI)
            s.configure("TLabel", background=BG, foreground=TEXT, font=FONT_UI)
            s.configure("Title.TLabel", background=BG, foreground=TEXT, font=FONT_TITLE)
            s.configure("Muted.TLabel", background=BG, foreground=MUTED, font=FONT_UI)
        except Exception:
            pass
        # aplicar fundo da janela
        try:
            self.root.configure(background=BG)
        except Exception:
            pass

    def build_ui(self):
        # Topbar
        topbar = tb.Frame(self.root, bootstyle="secondary", padding=(12, 10))
        topbar.pack(side=TOP, fill=X)

        left = tb.Frame(topbar, bootstyle="secondary")
        left.pack(side=LEFT, anchor="w")
        # logo circular
        

        tb.Label(left, text="Verificador de IP", bootstyle="inverse", style="Title.TLabel").pack(side=LEFT, padx=(10,6))
        tb.Label(left, text="DNS • ASN • Geolocalização", style="Muted.TLabel").pack(side=LEFT, padx=(4,0))

        right = tb.Frame(topbar, bootstyle="secondary")
        right.pack(side=RIGHT, anchor="e")
        self.btn_export_top = tb.Button(right, text="Exportar Resultado", bootstyle="outline", command=self.export_result)
        self.btn_history_top = tb.Button(right, text="Histórico", bootstyle="outline", command=self.show_history_window)
        self.btn_export_top.pack(side=RIGHT, padx=6)
        self.btn_history_top.pack(side=RIGHT, padx=6)

        # Main content
        content = tb.Frame(self.root, padding=12)
        content.pack(fill=BOTH, expand=YES)

        # Left panel (form)
        left_panel = tb.Frame(content, width=340, bootstyle="Card.TFrame", padding=12)
        left_panel.pack(side=LEFT, fill=Y, padx=(0,12))
        left_panel.pack_propagate(False)

        tb.Separator(left_panel, orient="horizontal").pack(fill=X, pady=(0,8))

        tb.Label(left_panel, text="IP ou Hostname:", style="TLabel").pack(anchor="w", pady=(4,6))
        self.entry_ip = tb.Entry(left_panel, width=28)
        self.entry_ip.pack(fill=X)
        self.entry_ip.configure(font=FONT_UI)

        # Buttons
        btn_frame = tb.Frame(left_panel)
        btn_frame.pack(fill=X, pady=(12,6))

        self.btn_check = tb.Button(btn_frame, text="Verificar", bootstyle=(PRIMARY+"-outline"), command=self.on_check)
        self.btn_clear = tb.Button(btn_frame, text="Limpar", bootstyle="secondary-outline", command=self.on_clear)
        self.btn_check.pack(side=LEFT, fill=X, expand=YES, padx=(0,6))
        self.btn_clear.pack(side=LEFT)

        tb.Label(left_panel, text="Entrada aceita: IPv4/IPv6 ou hostname", style="Muted.TLabel").pack(anchor="w", pady=(10,0))

        # Right panel (result)
        right_panel = tb.Frame(content, bootstyle="Card.TFrame", padding=8)
        right_panel.pack(side=LEFT, fill=BOTH, expand=YES)

        header = tb.Frame(right_panel)
        header.pack(fill=X)
        tb.Label(header, text="Resultado", style="Title.TLabel").pack(side=LEFT)
        self.lbl_status = tb.Label(header, text="Pronto", style="Muted.TLabel")
        self.lbl_status.pack(side=RIGHT)

        # ScrolledText com estilo
        self.txt_result = ScrolledText(right_panel, wrap="word", height=18, bg="#0b0c0d", fg=TEXT, insertbackground=TEXT)
        self.txt_result.configure(font=FONT_MONO, bd=0)
        self.txt_result.pack(fill=BOTH, expand=YES, pady=(8,6))

        # Actions beneath the result
        actions = tb.Frame(right_panel)
        actions.pack(fill=X, pady=(4,4))
        self.btn_copy = tb.Button(actions, text="Copiar", bootstyle="secondary", command=self.copy_result)
        self.btn_save = tb.Button(actions, text="Salvar Resultado...", bootstyle="primary", command=self.export_result)
        self.btn_copy.pack(side=LEFT)
        self.btn_save.pack(side=RIGHT)

        # Footer status
        footer = tb.Frame(self.root, padding=(12,6))
        footer.pack(side=BOTTOM, fill=X)
        self.status_var = tk.StringVar(value="Pronto")
        tb.Label(footer, textvariable=self.status_var, style="Muted.TLabel").pack(side=LEFT)
        tb.Label(footer, text="I.P.A", style="Muted.TLabel").pack(side=RIGHT)

    def bind_shortcuts(self):
        # Enter to verify, Ctrl+S to save
        self.root.bind("<Return>", lambda e: self.on_check())
        self.root.bind("<Control-s>", lambda e: self.export_result())

    # -------------------------
    # Helpers UI
    # -------------------------
    def set_status(self, msg):
        self.status_var.set(msg)
        try:
            self.lbl_status.configure(text=msg)
        except Exception:
            pass

    def append_result(self, text, clear=False):
        self.txt_result.configure(state="normal")
        if clear:
            self.txt_result.delete("1.0", "end")
        self.txt_result.insert("end", text + "\n")
        self.txt_result.see("end")
        self.txt_result.configure(state="disabled")

    # -------------------------
    # Ações
    # -------------------------
    def on_clear(self):
        self.txt_result.configure(state="normal")
        self.txt_result.delete("1.0", "end")
        self.txt_result.configure(state="disabled")
        self.entry_ip.delete(0, "end")
        self.set_status("Pronto")

    def on_check(self):
        user_input = self.entry_ip.get().strip()
        # prevenir múltiplos cliques
        try:
            self.btn_check.configure(state="disabled")
        except Exception:
            pass
        self.set_status("Validando entrada...")
        t = threading.Thread(target=self._worker_check, args=(user_input,), daemon=True)
        t.start()

    def _worker_check(self, user_input):
        start_ts = time.time()
        try:
            info = self.analyzer.validate_input(user_input)
        except ValueError as e:
            self.root.after(0, lambda: self._on_error(str(e)))
            return

        ip = info["addr"]
        ip_str = str(ip)
        self.root.after(0, lambda: self.append_result(f"Analisando: {user_input} → {ip_str}", clear=True))
        self.root.after(0, lambda: self.set_status("Consultando DNS reverso e API..."))

        # DNS reverso
        reverse = self.analyzer.reverse_dns(ip_str)
        if reverse:
            self.root.after(0, lambda: self.append_result(f"DNS reverso (PTR): {reverse}"))
        else:
            self.root.after(0, lambda: self.append_result("DNS reverso (PTR): (nenhum)"))

        # geolocalização/ASN
        geo = self.analyzer.geo_and_asn(ip_str)
        if "error" in geo:
            self.root.after(0, lambda: self.append_result(f"Geolocalização/ASN: Erro — {geo['error']}"))
        else:
            lines = [
                f"IP: {geo.get('query')}",
                f"ASN / AS: {geo.get('as') or '—'}",
                f"ISP / Org: {geo.get('isp') or geo.get('org') or '—'}",
                f"País: {geo.get('country') or '—'}",
                f"Região: {geo.get('region') or '—'}",
                f"Cidade: {geo.get('city') or '—'}",
                f"ZIP: {geo.get('zip') or '—'}",
                f"Coordenadas: {geo.get('lat')},{geo.get('lon')}" if geo.get('lat') and geo.get('lon') else "Coordenadas: —",
                f"Fuso horário: {geo.get('timezone') or '—'}",
                f"Reverse (API): {geo.get('reverse') or '—'}",
            ]
            for ln in lines:
                self.root.after(0, lambda ln=ln: self.append_result(ln))

        # propriedades IP
        try:
            addr_obj = ipaddress.ip_address(ip_str)
            self.root.after(0, lambda: self.append_result(f"Versão IP: IPv{addr_obj.version}"))
            self.root.after(0, lambda: self.append_result(f"Privado: {addr_obj.is_private}"))
            self.root.after(0, lambda: self.append_result(f"Reservado: {addr_obj.is_reserved}"))
            self.root.after(0, lambda: self.append_result(f"Global: {addr_obj.is_global}"))
            if isinstance(addr_obj, ipaddress.IPv4Address):
                first_octet = int(ip_str.split('.')[0])
                if 0 <= first_octet <= 127:
                    classe = "A"
                elif 128 <= first_octet <= 191:
                    classe = "B"
                elif 192 <= first_octet <= 223:
                    classe = "C"
                else:
                    classe = "D/E"
                self.root.after(0, lambda: self.append_result(f"Classe (tradicional): {classe}"))
        except Exception:
            pass

        entry = {
            "input": user_input,
            "resolved": ip_str,
            "time": datetime.now(timezone.utc).isoformat()
        }
        self.record_history(entry)

        elapsed = time.time() - start_ts
        self.root.after(0, lambda: self.set_status(f"Pronto — {elapsed:.2f}s"))
        self.root.after(0, lambda: self.btn_check.configure(state="normal"))

    def _on_error(self, msg):
        messagebox.showerror("Erro", msg)
        self.set_status("Erro")
        try:
            self.btn_check.configure(state="normal")
        except Exception:
            pass

    # -------------------------
    # Histórico
    # -------------------------
    def record_history(self, entry):
        try:
            self.ip_history.append(entry)
            if len(self.ip_history) > HISTORY_LIMIT:
                self.ip_history = self.ip_history[-HISTORY_LIMIT:]
            with open(HISTORY_FILE, "w", encoding="utf-8") as fh:
                json.dump(self.ip_history, fh, ensure_ascii=False, indent=2)
        except Exception as e:
            print("Falha ao gravar histórico:", e)

    def load_history(self):
        try:
            with open(HISTORY_FILE, "r", encoding="utf-8") as fh:
                data = json.load(fh)
                if isinstance(data, list):
                    return data
        except FileNotFoundError:
            return []
        except Exception as e:
            print("Erro ao carregar histórico:", e)
        return []

    def show_history_window(self):
        if not self.ip_history:
            messagebox.showinfo("Histórico", "Nenhum item no histórico.")
            return

        win = tb.Toplevel(self.root)
        win.title("Histórico de consultas")
        win.geometry("760x440")
        win.transient(self.root)

        frame = tb.Frame(win, padding=12)
        frame.pack(fill=BOTH, expand=YES)

        # Lista com scrollbar
        listbox = tk.Listbox(frame, bg="#0b0c0d", fg=TEXT, bd=0, highlightthickness=0, font=FONT_UI)
        listbox.pack(side=LEFT, fill=BOTH, expand=YES)
        scrollbar = tb.Scrollbar(frame, orient="vertical", command=listbox.yview)
        scrollbar.pack(side=RIGHT, fill=Y)
        listbox.config(yscrollcommand=scrollbar.set)

        for idx, it in enumerate(reversed(self.ip_history)):
            ts = it.get("time", "")
            txt = f"{idx+1:03d} — {it.get('input')} → {it.get('resolved')}  [{ts}]"
            listbox.insert("end", txt)

        btns = tb.Frame(win, padding=(12,6))
        btns.pack(fill=X, side=BOTTOM)
        tb.Button(btns, text="Exportar JSON", bootstyle="outline", command=self._export_history).pack(side=LEFT)
        tb.Button(btns, text="Fechar", bootstyle="outline", command=win.destroy).pack(side=RIGHT)

    def _export_history(self):
        path = filedialog.asksaveasfilename(title="Salvar histórico como", defaultextension=".json",
                                            filetypes=[("JSON", "*.json")])
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(self.ip_history, fh, ensure_ascii=False, indent=2)
            messagebox.showinfo("Exportar", f"Histórico salvo em {path}")
        except Exception as e:
            messagebox.showerror("Erro", f"Falha ao salvar histórico: {e}")

    # -------------------------
    # Export / copiar
    # -------------------------
    def export_result(self):
        txt = self.txt_result.get("1.0", "end").strip()
        if not txt:
            messagebox.showinfo("Exportar", "Não há resultado para exportar.")
            return
        path = filedialog.asksaveasfilename(title="Salvar resultado como", defaultextension=".txt",
                                            filetypes=[("Texto", "*.txt")])
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(txt)
            messagebox.showinfo("Exportar", f"Resultado salvo em {path}")
        except Exception as e:
            messagebox.showerror("Erro", f"Falha ao salvar resultado: {e}")

    def copy_result(self):
        txt = self.txt_result.get("1.0", "end").strip()
        if not txt:
            messagebox.showinfo("Copiar", "Não há texto para copiar.")
            return
        self.root.clipboard_clear()
        self.root.clipboard_append(txt)
        messagebox.showinfo("Copiar", "Resultado copiado para a área de transferência.")

# -------------------------
# Entrypoint
# -------------------------
def main():
    app_root = tb.Window(title="Verificador de IP — DNS • ASN • Geolocalização", themename="darkly")
    # garantir que o diretório atual seja o script path (para histórico relativo)
    try:
        os.chdir(os.path.dirname(os.path.abspath(__file__)))
    except Exception:
        pass

    App(app_root)
    try:
        app_root.mainloop()
    except KeyboardInterrupt:
        sys.exit(0)

if __name__ == "__main__":
    main()
