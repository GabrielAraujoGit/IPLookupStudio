import ipaddress
import socket
import threading
import json
import time
from datetime import datetime, timezone
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import requests

HISTORY_FILE = "ip_history.json"
HISTORY_LIMIT = 200
IP_API_URL = (
    "http://ip-api.com/json/{ip}"
    "?fields=status,message,query,reverse,country,regionName,"
    "city,zip,lat,lon,timezone,isp,org,as"
)

class IPAnalyzer:
    def __init__(self, timeout=6):
        self.timeout = timeout

    def validate_input(self, text):
        text = text.strip()
        if not text:
            raise ValueError("Entrada vazia.")
        # Tentar resolver como IP primeiro (IPv4/IPv6)
        try:
            addr = ipaddress.ip_address(text)
            return {"type": "ip", "input": text, "addr": addr}
        except ValueError:
            # Não é IP puro, pode ser hostname. Tentar resolver DNS A/AAAA.
            try:
                # socket.getaddrinfo lida com IPv4 e IPv6, retorna tuplas
                infos = socket.getaddrinfo(text, None)
                # escolher o primeiro resultado para obter IP
                ip = infos[0][4][0]
                return {"type": "hostname", "input": text, "addr": ip}
            except Exception as e:
                raise ValueError(f"Entrada não é um IP válido nem um hostname resolvível: {e}")

    def reverse_dns(self, ip):
        try:
            name = socket.gethostbyaddr(ip)[0]
            return name
        except Exception:
            return None

    def geo_and_asn(self, ip):
        """
        Consulta o serviço ip-api.com (gratuito, sem token).
        Retorna dicionário com campos de geolocalização e ASN/ISP.
        """
        try:
            url = IP_API_URL.format(ip=ip)
            resp = requests.get(url, timeout=self.timeout)
            data = resp.json()
            print("DEBUG:", data)
            if data.get("status") != "success":
                return {"error": data.get("message") or "Falha na API"}
            # normalizar campos
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
                "as": data.get("as"),  # ex: "AS15169 Google LLC"
                "reverse": data.get("reverse"),
            }
        except requests.RequestException as e:
            return {"error": f"Erro de conexão: {e}"}
        except ValueError:
            return {"error": "Resposta inesperada da API"}

class App(ttk.Frame):
    def __init__(self, master):
        super().__init__(master)
        self.master = master
        master.title("Verificador de IP — DNS • ASN • Geolocalização")
        master.geometry("650x420")
        master.minsize(520, 360)
        self.pack(fill="both", expand=True, padx=10, pady=10)

        self.analyzer = IPAnalyzer()
        self.ip_history = self.load_history()

        self.create_widgets()

    def create_widgets(self):
        # Entrada e botões
        entry_frame = ttk.Frame(self)
        entry_frame.pack(fill="x", pady=(0,10))

        ttk.Label(entry_frame, text="IP ou Hostname:").grid(row=0, column=0, sticky="w")
        self.entry_ip = ttk.Entry(entry_frame)
        self.entry_ip.grid(row=0, column=1, sticky="ew", padx=8)
        entry_frame.columnconfigure(1, weight=1)

        self.btn_check = ttk.Button(entry_frame, text="Verificar", command=self.on_check)
        self.btn_check.grid(row=0, column=2, padx=4)

        self.btn_clear = ttk.Button(entry_frame, text="Limpar", command=self.on_clear)
        self.btn_clear.grid(row=0, column=3, padx=4)

        # Resultado
        result_frame = ttk.LabelFrame(self, text="Resultado")
        result_frame.pack(fill="both", expand=True)

        self.txt_result = tk.Text(result_frame, height=12, wrap="word")
        self.txt_result.pack(fill="both", expand=True, padx=6, pady=6)
        self.txt_result.configure(state="disabled", bg="white")

        # Rodapé: histórico e export
        footer = ttk.Frame(self)
        footer.pack(fill="x", pady=(8,0))

        self.btn_history = ttk.Button(footer, text="Mostrar Histórico", command=self.show_history_window)
        self.btn_history.pack(side="left")

        self.btn_export = ttk.Button(footer, text="Exportar Resultado", command=self.export_result)
        self.btn_export.pack(side="right")

        self.status_var = tk.StringVar(value="Pronto")
        self.lbl_status = ttk.Label(self, textvariable=self.status_var)
        self.lbl_status.pack(side="bottom", anchor="w", pady=(6,0))

    def set_status(self, msg):
        self.status_var.set(msg)

    def append_result(self, text, clear=False):
        self.txt_result.configure(state="normal")
        if clear:
            self.txt_result.delete("1.0", "end")
        self.txt_result.insert("end", text + "\n")
        self.txt_result.see("end")
        self.txt_result.configure(state="disabled")

    def on_clear(self):
        self.txt_result.configure(state="normal")
        self.txt_result.delete("1.0", "end")
        self.txt_result.configure(state="disabled")

    def on_check(self):
        user_input = self.entry_ip.get().strip()
        # desabilitar botão enquanto a consulta ocorre
        self.btn_check.config(state="disabled")
        self.set_status("Validando entrada...")
        # rodar análise em thread para não travar GUI
        thread = threading.Thread(target=self._worker_check, args=(user_input,), daemon=True)
        thread.start()

    def _worker_check(self, user_input):
        start_ts = time.time()
        try:
            info = self.analyzer.validate_input(user_input)
        except ValueError as e:
            self.master.after(0, lambda: self._on_error(str(e)))
            return

        ip = info["addr"]
        # Garantir que ip é string
        ip_str = str(ip)

        # Atualizar UI com IP resolvido
        self.master.after(0, lambda: self.append_result(f"Analisando: {user_input} → {ip_str}", clear=True))
        self.master.after(0, lambda: self.set_status("Consultando DNS reverso e API..."))

        # DNS reverso local (rápido)
        reverse = self.analyzer.reverse_dns(ip_str)
        if reverse:
            self.master.after(0, lambda: self.append_result(f"DNS reverso: {reverse}"))
        else:
            self.master.after(0, lambda: self.append_result("DNS reverso: (nenhum encontrado)"))

        # Uso de ip-api para geolocalização/ASN
        geo = self.analyzer.geo_and_asn(ip_str)
        if "error" in geo:
            self.master.after(0, lambda: self.append_result(f"Geolocalização/ASN: Erro — {geo['error']}"))
        else:
            # Montar saída organizada
            lines = [
                f"IP: {geo.get('query')}",
                f"ASN / AS: {geo.get('as') or '—'}",
                f"ISP: {geo.get('isp') or geo.get('org') or '—'}",
                f"País: {geo.get('country') or '—'}",
                f"Região: {geo.get('region') or '—'}",
                f"Cidade: {geo.get('city') or '—'}",
                f"ZIP: {geo.get('zip') or '—'}",
                f"Coordenadas: {geo.get('lat')},{geo.get('lon')}" if geo.get('lat') and geo.get('lon') else "Coordenadas: —",
                f"Fuso horário: {geo.get('timezone') or '—'}",
                f"Reverse (API): {geo.get('reverse') or '—'}",
            ]
            for ln in lines:
                self.master.after(0, lambda ln=ln: self.append_result(ln))

        # Informações booleanas e de classe (para IPv4)
        try:
            addr_obj = ipaddress.ip_address(ip_str)
            self.master.after(0, lambda: self.append_result(f"Versão IP: IPv{addr_obj.version}"))
            self.master.after(0, lambda: self.append_result(f"Privado: {addr_obj.is_private}"))
            self.master.after(0, lambda: self.append_result(f"Reservado: {addr_obj.is_reserved}"))
            self.master.after(0, lambda: self.append_result(f"Global: {addr_obj.is_global}"))
            # Classe A/B/C apenas se IPv4
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
                self.master.after(0, lambda: self.append_result(f"Classe (clássica): {classe}"))
        except Exception:
            pass

        # Registrar histórico (com timestamp)
        entry = {
            "input": user_input,
            "resolved": ip_str,
            "time": datetime.now(timezone.utc).isoformat()
        }
        self.record_history(entry)

        elapsed = time.time() - start_ts
        self.master.after(0, lambda: self.set_status(f"Pronto — {elapsed:.2f}s"))
        self.master.after(0, lambda: self.btn_check.config(state="normal"))

    def _on_error(self, msg):
        messagebox.showerror("Erro", msg)
        self.set_status("Erro")
        self.btn_check.config(state="normal")

    def record_history(self, entry):
        # carregar, adicionar, limitar e salvar
        try:
            self.ip_history.append(entry)
            # limitar
            if len(self.ip_history) > HISTORY_LIMIT:
                self.ip_history = self.ip_history[-HISTORY_LIMIT:]
            with open(HISTORY_FILE, "w", encoding="utf-8") as fh:
                json.dump(self.ip_history, fh, ensure_ascii=False, indent=2)
        except Exception as e:
            # não bloquear o usuário por falha no histórico
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
        win = tk.Toplevel(self.master)
        win.title("Histórico de consultas")
        win.geometry("600x400")
        frm = ttk.Frame(win)
        frm.pack(fill="both", expand=True, padx=8, pady=8)

        lb = tk.Listbox(frm)
        lb.pack(side="left", fill="both", expand=True)
        scrollbar = ttk.Scrollbar(frm, orient="vertical", command=lb.yview)
        scrollbar.pack(side="right", fill="y")
        lb.config(yscrollcommand=scrollbar.set)

        for idx, it in enumerate(reversed(self.ip_history)):
            ts = it.get("time", "")
            txt = f"{idx+1:03d} — {it.get('input')} → {it.get('resolved')} @ {ts}"
            lb.insert("end", txt)

        btn_frame = ttk.Frame(win)
        btn_frame.pack(fill="x", pady=6)
        ttk.Button(btn_frame, text="Exportar JSON", command=lambda: self._export_history()).pack(side="left", padx=6)
        ttk.Button(btn_frame, text="Fechar", command=win.destroy).pack(side="right", padx=6)

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

def main():
    root = tk.Tk()
    style = ttk.Style(root)
    # usar tema nativo quando disponível
    try:
        style.theme_use('clam')
    except Exception:
        pass
    app = App(root)
    root.mainloop()

if __name__ == "__main__":
    main()
