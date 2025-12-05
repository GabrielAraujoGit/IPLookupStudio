

import ipaddress
import socket
import threading
import json
import time
from datetime import datetime, timezone
import os
import sys
import requests
import ttkbootstrap as tb
from ttkbootstrap.constants import *
import tkinter as tk
from tkinter import filedialog, messagebox
from tkinter.scrolledtext import ScrolledText


HISTORY_FILE = "ip_history.json"
CONFIG_FILE = "config.json"
HISTORY_LIMIT = 500

IP_API_URL = "http://ip-api.com/json/{ip}?fields=status,message,query,reverse,country,regionName,city,zip,lat,lon,timezone,isp,org,as"

RDAP_URL = "https://rdap.org/ip/{ip}"
BGPVIEW_URL = "https://api.bgpview.io/ip/{ip}"

IPINFO_URL = "https://ipinfo.io/{ip}/json"
ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"
IPQS_URL = "https://ipqualityscore.com/api/json/ip/{api_key}/{ip}"
IPDATA_URL = "https://api.ipdata.co/{ip}"

PRIMARY = "#5865F2"
BG = "#0F1113"
GLASS = "#1E2124"
TEXT = "#E6EEF3"
MUTED = "#98A0B3"
FONT_UI = ("Arial", 10)
FONT_TITLE = ("Arial", 12, "bold")
FONT_MONO = ("Consolas", 10)

# -------------------------
# Helper: load/save config
# -------------------------
def load_config():
    default = {
        "IPINFO_TOKEN": "",
        "ABUSEIPDB_KEY": "",
        "IPQS_KEY": "",
        "IPDATA_KEY": "",
    }
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r", encoding="utf-8") as fh:
                user = json.load(fh)
                default.update(user or {})
        except Exception:
            pass
    return default

def save_config(cfg):
    try:
        with open(CONFIG_FILE, "w", encoding="utf-8") as fh:
            json.dump(cfg, fh, indent=2)
        return True
    except Exception as e:
        print("Erro ao salvar config:", e)
        return False

class IPAnalyzer:
    def __init__(self, timeout=6):
        self.timeout = timeout

    def validate_input(self, text):
        text = text.strip()
        if not text:
            raise ValueError("Entrada vazia.")
        try:
            addr = ipaddress.ip_address(text)
            return {"type": "ip", "input": text, "addr": addr}
        except ValueError:
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
            r = requests.get(url, timeout=self.timeout)
            data = r.json()
            if data.get("status") != "success":
                return {"error": data.get("message") or "Falha na API ip-api"}
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
            return {"error": f"Erro de conexão ip-api: {e}"}
        except ValueError:
            return {"error": "Resposta inesperada da API ip-api"}


def query_rdap(ip, timeout=8):
    try:
        url = RDAP_URL.format(ip=ip)
        r = requests.get(url, timeout=timeout)
        if r.status_code != 200:
            return {"error": f"RDAP status {r.status_code}"}
        return r.json()
    except Exception as e:
        return {"error": f"RDAP erro: {e}"}

def query_bgpview(ip, timeout=8):
    try:
        url = BGPVIEW_URL.format(ip=ip)
        r = requests.get(url, timeout=timeout)
        if r.status_code != 200:
            return {"error": f"BGPView status {r.status_code}"}
        return r.json()
    except Exception as e:
        return {"error": f"BGPView erro: {e}"}

def query_ipinfo(ip, token, timeout=8):
    try:
        params = {}
        headers = {}
        if token:
            params["token"] = token
        url = IPINFO_URL.format(ip=ip)
        r = requests.get(url, params=params, headers=headers, timeout=timeout)
        if r.status_code not in (200, 201):
            return {"error": f"ipinfo status {r.status_code}"}
        return r.json()
    except Exception as e:
        return {"error": f"ipinfo erro: {e}"}

def query_abuseipdb(ip, key, max_age_days=90, timeout=8):
    if not key:
        return {"error": "No AbuseIPDB key"}
    try:
        headers = {
            "Accept": "application/json",
            "Key": key
        }
        params = {
            "ipAddress": ip,
            "maxAgeInDays": max_age_days
        }
        r = requests.get(ABUSEIPDB_URL, headers=headers, params=params, timeout=timeout)
        if r.status_code != 200:
            return {"error": f"AbuseIPDB status {r.status_code} - {r.text}"}
        return r.json()
    except Exception as e:
        return {"error": f"AbuseIPDB erro: {e}"}

def query_ipqualityscore(ip, api_key, timeout=8):
    if not api_key:
        return {"error": "No IPQS key"}
    try:
        url = IPQS_URL.format(api_key=api_key, ip=ip)
        r = requests.get(url, timeout=timeout)
        if r.status_code != 200:
            return {"error": f"IPQS status {r.status_code}"}
        return r.json()
    except Exception as e:
        return {"error": f"IPQS erro: {e}"}

def query_ipdata(ip, api_key, timeout=8):
    # ipdata supports ?api-key=KEY
    try:
        params = {}
        if api_key:
            params["api-key"] = api_key
        url = IPDATA_URL.format(ip=ip)
        r = requests.get(url, params=params, timeout=timeout)
        if r.status_code not in (200, 201):
            return {"error": f"ipdata status {r.status_code}"}
        return r.json()
    except Exception as e:
        return {"error": f"ipdata erro: {e}"}

class App:
    def __init__(self, root: tb.Window):
        self.root = root
        self.root.title("IPLookup Studio")
        self.root.geometry("1100x680")
        self.root.minsize(900, 620)

        # style
        self.style = tb.Style(theme="darkly")
        self.style.configure("TFrame", background=BG)
        self.style.configure("Card.TFrame", background=GLASS)
        self.style.configure("TLabel", background=BG, foreground=TEXT, font=FONT_UI)
        self.style.configure("Title.TLabel", background=BG, foreground=TEXT, font=FONT_TITLE)
        self.style.configure("Muted.TLabel", background=BG, foreground=MUTED, font=FONT_UI)

        # load config
        self.config = load_config()

        self.analyzer = IPAnalyzer()
        self.ip_history = self.load_history()

        self.build_ui()
        self.bind_shortcuts()

    def build_ui(self):
        topbar = tb.Frame(self.root, padding=8)
        topbar.pack(side=tk.TOP, fill=tk.X)

        left = tb.Frame(topbar)
        left.pack(side=tk.LEFT, anchor="w")
        logo = tk.Canvas(left, width=40, height=40, highlightthickness=0, bg=BG)
        logo.create_oval(6,6,34,34, fill=PRIMARY, outline="")
        logo.create_text(20,20, text="IP", fill="white", font=("Arial", 10, "bold"))
        logo.pack(side=tk.LEFT)
        tb.Label(left, text="IPLookup Studio", style="Title.TLabel").pack(side=tk.LEFT, padx=(8,6))
        tb.Label(left, text="DNS • ASN • Geolocalização • Segurança • WHOIS • BGP", style="Muted.TLabel").pack(side=tk.LEFT)

        right = tb.Frame(topbar)
        right.pack(side=tk.RIGHT)
        tb.Button(right, text="Settings", bootstyle="outline", command=self.open_settings).pack(side=tk.RIGHT, padx=6)
        tb.Button(right, text="Histórico", bootstyle="outline", command=self.show_history_window).pack(side=tk.RIGHT, padx=6)

        content = tb.Frame(self.root, padding=12)
        content.pack(fill=tk.BOTH, expand=1)

        # Left panel (form + quick info)
        left_panel = tb.Frame(content, width=360, bootstyle="Card.TFrame", padding=12)
        left_panel.pack(side=tk.LEFT, fill=tk.Y, padx=(0,12))
        left_panel.pack_propagate(False)

        tb.Label(left_panel, text="IP ou Hostname:", style="TLabel").pack(anchor="w")
        self.entry_ip = tb.Entry(left_panel)
        self.entry_ip.pack(fill=tk.X, pady=(6,8))
        self.entry_ip.configure(font=FONT_UI)

        btn_frame = tb.Frame(left_panel)
        btn_frame.pack(fill=tk.X, pady=(4,8))
        self.btn_check = tb.Button(btn_frame, text="Verificar", bootstyle=(PRIMARY+"-outline"), command=self.on_check)
        self.btn_clear = tb.Button(btn_frame, text="Limpar", bootstyle="secondary-outline", command=self.on_clear)
        self.btn_check.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0,6))
        self.btn_clear.pack(side=tk.LEFT)

        # Quick summary card
        summary_card = tb.Frame(left_panel, bootstyle="Card.TFrame", padding=8)
        summary_card.pack(fill=tk.X, pady=(10,0))
        tb.Label(summary_card, text="Resumo Rápido", style="Title.TLabel").pack(anchor="w")
        self.summary_text = tb.Label(summary_card, text="—", style="TLabel", bootstyle="muted")
        self.summary_text.pack(anchor="w", pady=(6,0))

        # Right panel (tabs for sections)
        right_panel = tb.Frame(content, bootstyle="Card.TFrame", padding=8)
        right_panel.pack(side=tk.LEFT, fill=tk.BOTH, expand=1)

        header = tb.Frame(right_panel)
        header.pack(fill=tk.X)
        tb.Label(header, text="Resultado", style="Title.TLabel").pack(side=tk.LEFT)
        self.lbl_status = tb.Label(header, text="Pronto", style="Muted.TLabel")
        self.lbl_status.pack(side=tk.RIGHT)

        # Tabs (Overview, Security, WHOIS, BGP, Raw)
        self.notebook = tb.Notebook(right_panel)
        self.notebook.pack(fill=tk.BOTH, expand=1, pady=(6,0))

        # Overview tab
        self.tab_overview = tb.Frame(self.notebook, padding=8)
        self.notebook.add(self.tab_overview, text="Overview")
        self.txt_overview = ScrolledText(self.tab_overview, wrap="word", bg="#0b0c0d", fg=TEXT, font=FONT_MONO)
        self.txt_overview.pack(fill=tk.BOTH, expand=1)

        # Security tab
        self.tab_security = tb.Frame(self.notebook, padding=8)
        self.notebook.add(self.tab_security, text="Segurança")
        self.txt_security = ScrolledText(self.tab_security, wrap="word", bg="#0b0c0d", fg=TEXT, font=FONT_MONO)
        self.txt_security.pack(fill=tk.BOTH, expand=1)

        # WHOIS/RDAP tab
        self.tab_rdap = tb.Frame(self.notebook, padding=8)
        self.notebook.add(self.tab_rdap, text="WHOIS / RDAP")
        self.txt_rdap = ScrolledText(self.tab_rdap, wrap="word", bg="#0b0c0d", fg=TEXT, font=FONT_MONO)
        self.txt_rdap.pack(fill=tk.BOTH, expand=1)

        # BGP tab
        self.tab_bgp = tb.Frame(self.notebook, padding=8)
        self.notebook.add(self.tab_bgp, text="BGP")
        self.txt_bgp = ScrolledText(self.tab_bgp, wrap="word", bg="#0b0c0d", fg=TEXT, font=FONT_MONO)
        self.txt_bgp.pack(fill=tk.BOTH, expand=1)

        # Raw tab (dump all API JSONs)
        self.tab_raw = tb.Frame(self.notebook, padding=8)
        self.notebook.add(self.tab_raw, text="Raw JSON")
        self.txt_raw = ScrolledText(self.tab_raw, wrap="word", bg="#0b0c0d", fg=TEXT, font=FONT_MONO)
        self.txt_raw.pack(fill=tk.BOTH, expand=1)

        # Bottom actions
        actions = tb.Frame(self.root, padding=(12,8))
        actions.pack(side=tk.BOTTOM, fill=tk.X)
        self.btn_copy = tb.Button(actions, text="Copiar Overview", bootstyle="secondary", command=self.copy_overview)
        self.btn_save = tb.Button(actions, text="Salvar Overview...", bootstyle="primary", command=self.export_overview)
        self.btn_copy.pack(side=tk.LEFT)
        self.btn_save.pack(side=tk.RIGHT)

    def bind_shortcuts(self):
        self.root.bind("<Return>", lambda e: self.on_check())
        self.root.bind("<Control-s>", lambda e: self.export_overview())


    def set_status(self, msg):
        try:
            self.lbl_status.configure(text=msg)
        except Exception:
            pass

    def append_tab(self, widget: ScrolledText, text, clear=False):
        widget.configure(state="normal")
        if clear:
            widget.delete("1.0", "end")
        widget.insert("end", text + "\n")
        widget.see("end")
        widget.configure(state="disabled")

    def on_clear(self):
        for w in (self.txt_overview, self.txt_security, self.txt_rdap, self.txt_bgp, self.txt_raw):
            w.configure(state="normal")
            w.delete("1.0", "end")
            w.configure(state="disabled")
        self.entry_ip.delete(0, "end")
        self.summary_text.configure(text="—")
        self.set_status("Pronto")

    def on_check(self):
        user_input = self.entry_ip.get().strip()
        try:
            self.btn_check.configure(state="disabled")
        except Exception:
            pass
        self.set_status("Validando entrada...")
        t = threading.Thread(target=self._worker_all, args=(user_input,), daemon=True)
        t.start()

    def _worker_all(self, user_input):
        start = time.time()
        try:
            info = self.analyzer.validate_input(user_input)
        except ValueError as e:
            self.root.after(0, lambda: self._on_error(str(e)))
            return

        ip = str(info["addr"])
        self.root.after(0, lambda: self.append_tab(self.txt_overview, f"Analisando: {user_input} → {ip}", clear=True))
        self.root.after(0, lambda: self.set_status("Consultando serviços..."))

        # Basic dns reverse + ip-api
        reverse = self.analyzer.reverse_dns(ip)
        geo = self.analyzer.geo_and_asn(ip)

        if "error" in geo:
            self.root.after(0, lambda: self.append_tab(self.txt_overview, f"ip-api: Erro — {geo['error']}"))
        else:
            self.root.after(0, lambda: self.append_tab(self.txt_overview, f"IP: {geo.get('query')}"))
            self.root.after(0, lambda: self.append_tab(self.txt_overview, f"ASN / AS: {geo.get('as') or '—'}"))
            self.root.after(0, lambda: self.append_tab(self.txt_overview, f"ISP / Org: {geo.get('isp') or geo.get('org') or '—'}"))
            self.root.after(0, lambda: self.append_tab(self.txt_overview, f"País: {geo.get('country') or '—'}"))
            self.root.after(0, lambda: self.append_tab(self.txt_overview, f"Região: {geo.get('region') or '—'}"))
            self.root.after(0, lambda: self.append_tab(self.txt_overview, f"Cidade: {geo.get('city') or '—'}"))
            self.root.after(0, lambda: self.append_tab(self.txt_overview, f"ZIP: {geo.get('zip') or '—'}"))
            coords = f"{geo.get('lat')},{geo.get('lon')}" if geo.get('lat') and geo.get('lon') else "—"
            self.root.after(0, lambda: self.append_tab(self.txt_overview, f"Coordenadas: {coords}"))
            self.root.after(0, lambda: self.append_tab(self.txt_overview, f"Fuso horário: {geo.get('timezone') or '—'}"))
            self.root.after(0, lambda: self.append_tab(self.txt_overview, f"Reverse (API): {geo.get('reverse') or '—'}"))

        self.root.after(0, lambda: self.append_tab(self.txt_overview, f"DNS reverso (PTR): {reverse or '(nenhum)'}"))

        # properties
        try:
            addr_obj = ipaddress.ip_address(ip)
            self.root.after(0, lambda: self.append_tab(self.txt_overview, f"Versão IP: IPv{addr_obj.version}"))
            self.root.after(0, lambda: self.append_tab(self.txt_overview, f"Privado: {addr_obj.is_private}"))
        except Exception:
            pass

        # Query advanced APIs in parallel (fire-and-join)
        results = {}
        threads = []

        def run_q(name, func, *args, **kwargs):
            def _run():
                try:
                    results[name] = func(*args, **kwargs)
                except Exception as e:
                    results[name] = {"error": str(e)}
            th = threading.Thread(target=_run, daemon=True)
            th.start()
            threads.append(th)

        cfg = self.config
        run_q("rdap", query_rdap, ip)
        run_q("bgpview", query_bgpview, ip)
        run_q("ipinfo", query_ipinfo, ip, cfg.get("IPINFO_TOKEN", ""))
        run_q("abuseipdb", query_abuseipdb, ip, cfg.get("ABUSEIPDB_KEY", ""))
        run_q("ipqs", query_ipqualityscore, ip, cfg.get("IPQS_KEY", ""))
        run_q("ipdata", query_ipdata, ip, cfg.get("IPDATA_KEY", ""))

        # wait for threads
        for th in threads:
            th.join(timeout=10)

        # render RDAP (WHOIS-like)
        rdap = results.get("rdap", {"error": "no response"})
        if "error" in rdap:
            self.root.after(0, lambda: self.append_tab(self.txt_rdap, f"RDAP: {rdap['error']}", clear=True))
        else:
            self.root.after(0, lambda: self.append_tab(self.txt_rdap, "RDAP (raw):", clear=True))
            # Summarize rdap: handle keys safely
            try:
                entity = rdap.get("entities", [])
                self.root.after(0, lambda: self.append_tab(self.txt_rdap, f"Network / object: {rdap.get('name') or rdap.get('handle') or '—'}"))
                if "remarks" in rdap and rdap.get("remarks"):
                    for r in rdap.get("remarks")[:3]:
                        self.root.after(0, lambda r=r: self.append_tab(self.txt_rdap, f"Remark: {r.get('description', [''])[0][:200]}"))
                # entities contacts
                if entity:
                    for e in entity[:4]:
                        self.root.after(0, lambda e=e: self.append_tab(self.txt_rdap, f"Entity: {e.get('handle') or e.get('vcardArray', [''])[0]}"))
            except Exception as e:
                self.root.after(0, lambda: self.append_tab(self.txt_rdap, f"RDAP parse error: {e}"))
            # also dump raw JSON in raw tab
            self.root.after(0, lambda: self.append_tab(self.txt_raw, f"RDAP:\n{json.dumps(rdap, indent=2)}", clear=False))

        # render BGP
        bgp = results.get("bgpview", {"error": "no response"})
        if "error" in bgp:
            self.root.after(0, lambda: self.append_tab(self.txt_bgp, f"BGPView: {bgp['error']}", clear=True))
        else:
            data = bgp.get("data", {})
            prefixes = data.get("prefixes", {}).get("ipv4_prefixes") or data.get("prefix", [])
            self.root.after(0, lambda: self.append_tab(self.txt_bgp, "BGPView (summary):", clear=True))
            try:
                asn = data.get("asn", {}).get("asn")
                self.root.after(0, lambda: self.append_tab(self.txt_bgp, f"ASN: {asn}"))
                for p in data.get("prefixes", {}).get("ipv4_prefixes", [])[:6]:
                    self.root.after(0, lambda p=p: self.append_tab(self.txt_bgp, f"Prefix: {p.get('prefix')} — {p.get('description', '')}"))
            except Exception:
                pass
            self.root.after(0, lambda: self.append_tab(self.txt_raw, f"BGPView:\n{json.dumps(bgp, indent=2)}"))

        # render ipinfo
        ipinfo = results.get("ipinfo", {})
        if "error" in ipinfo:
            self.root.after(0, lambda: self.append_tab(self.txt_overview, f"ipinfo: {ipinfo['error']}"))
        else:
            if ipinfo:
                self.root.after(0, lambda: self.append_tab(self.txt_overview, "ipinfo (extra):"))
                for k in ("ip", "org", "hostname", "city", "region", "country", "postal", "loc", "readme"):
                    if ipinfo.get(k):
                        self.root.after(0, lambda k=k: self.append_tab(self.txt_overview, f"{k}: {ipinfo.get(k)}"))
                self.root.after(0, lambda: self.append_tab(self.txt_raw, f"ipinfo:\n{json.dumps(ipinfo, indent=2)}"))

        # render AbuseIPDB
        abuse = results.get("abuseipdb", {})
        if "error" in abuse:
            self.root.after(0, lambda: self.append_tab(self.txt_security, f"AbuseIPDB: {abuse['error']}", clear=True))
        else:
            # structure: data -> abuseConfidenceScore etc.
            try:
                data = abuse.get("data", {})
                score = data.get("abuseConfidenceScore")
                reports = data.get("reports", [])
                self.root.after(0, lambda: self.append_tab(self.txt_security, "AbuseIPDB:"))
                self.root.after(0, lambda: self.append_tab(self.txt_security, f"Abuse Confidence Score: {score}"))
                self.root.after(0, lambda: self.append_tab(self.txt_security, f"Total Reports: {len(reports)}"))
                if reports:
                    for r in reports[:4]:
                        self.root.after(0, lambda r=r: self.append_tab(self.txt_security, f"- {r.get('reportedAt')} by {r.get('reporterId')}: {r.get('comment')[:120]}"))
                self.root.after(0, lambda: self.append_tab(self.txt_raw, f"AbuseIPDB:\n{json.dumps(abuse, indent=2)}"))
            except Exception as e:
                self.root.after(0, lambda: self.append_tab(self.txt_security, f"AbuseIPDB parse error: {e}"))

        # render IPQS
        ipqs = results.get("ipqs", {})
        if "error" in ipqs:
            self.root.after(0, lambda: self.append_tab(self.txt_security, f"IPQS: {ipqs['error']}"))
        else:
            try:
                # IPQS response has fields: fraud_score, vpn, proxy, tor, active_vpn, active_tor, recent_abuse, bot_status
                self.root.after(0, lambda: self.append_tab(self.txt_security, "IPQualityScore (IPQS):"))
                for k in ("fraud_score", "vpn", "proxy", "tor", "bot_status", "recent_abuse", "active_vpn", "active_tor"):
                    if k in ipqs:
                        self.root.after(0, lambda k=k: self.append_tab(self.txt_security, f"{k}: {ipqs.get(k)}"))
                self.root.after(0, lambda: self.append_tab(self.txt_raw, f"IPQS:\n{json.dumps(ipqs, indent=2)}"))
            except Exception as e:
                self.root.after(0, lambda: self.append_tab(self.txt_security, f"IPQS parse error: {e}"))

        # render ipdata
        ipdata = results.get("ipdata", {})
        if "error" in ipdata:
            self.root.after(0, lambda: self.append_tab(self.txt_overview, f"ipdata: {ipdata['error']}"))
        else:
            try:
                if ipdata:
                    self.root.after(0, lambda: self.append_tab(self.txt_overview, "ipdata (extra):"))
                    for k in ("asn", "carrier", "time_zone", "threat", "flag"):
                        if ipdata.get(k):
                            self.root.after(0, lambda k=k: self.append_tab(self.txt_overview, f"{k}: {ipdata.get(k)}"))
                    self.root.after(0, lambda: self.append_tab(self.txt_raw, f"ipdata:\n{json.dumps(ipdata, indent=2)}"))
            except Exception as e:
                self.root.after(0, lambda: self.append_tab(self.txt_overview, f"ipdata parse error: {e}"))

        # summary quick
        qsummary = []
        if geo and not geo.get("error"):
            qsummary.append(f"{geo.get('query')} — {geo.get('country') or ''} — {geo.get('city') or ''}")
        if results.get("ipqs") and isinstance(results["ipqs"], dict):
            score = results["ipqs"].get("fraud_score")
            if score is not None:
                qsummary.append(f"Threat / Fraud score: {score}")
        if results.get("abuseipdb") and "data" in results.get("abuseipdb", {}):
            acs = results["abuseipdb"]["data"].get("abuseConfidenceScore")
            if acs is not None:
                qsummary.append(f"Abuse score: {acs}")
        if not qsummary:
            qsummary = ["—"]
        self.root.after(0, lambda: self.summary_text.configure(text=" | ".join(qsummary[:3])))

        # save history succinct
        hist_entry = {
            "input": user_input,
            "resolved": ip,
            "time": datetime.now(timezone.utc).isoformat(),
            "geo": geo if isinstance(geo, dict) else None,
            "rdap": rdap if isinstance(rdap, dict) else None,
            "bgp": bgp if isinstance(bgp, dict) else None,
            "ipqs": ipqs if isinstance(ipqs, dict) else None,
            "abuseipdb": abuse if isinstance(abuse, dict) else None,
            "ipinfo": ipinfo if isinstance(ipinfo, dict) else None,
            "ipdata": ipdata if isinstance(ipdata, dict) else None,
        }
        self.record_history(hist_entry)

        elapsed = time.time() - start
        self.root.after(0, lambda: self.set_status(f"Pronto — {elapsed:.2f}s"))
        self.root.after(0, lambda: self.btn_check.configure(state="normal"))

    def _on_error(self, msg):
        messagebox.showerror("Erro", msg)
        self.set_status("Erro")
        try:
            self.btn_check.configure(state="normal")
        except Exception:
            pass

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
        if os.path.exists(HISTORY_FILE):
            try:
                with open(HISTORY_FILE, "r", encoding="utf-8") as fh:
                    data = json.load(fh)
                    if isinstance(data, list):
                        return data
            except Exception as e:
                print("Erro ao carregar histórico:", e)
        return []

    def show_history_window(self):
        if not self.ip_history:
            messagebox.showinfo("Histórico", "Nenhum item no histórico.")
            return
        win = tb.Toplevel(self.root)
        win.title("Histórico de consultas")
        win.geometry("900x520")
        frame = tb.Frame(win, padding=12)
        frame.pack(fill=tk.BOTH, expand=1)
        listbox = tk.Listbox(frame, bg="#0b0c0d", fg=TEXT, bd=0, font=FONT_UI)
        listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=1)
        scrollbar = tb.Scrollbar(frame, orient="vertical", command=listbox.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        listbox.config(yscrollcommand=scrollbar.set)
        for idx, it in enumerate(reversed(self.ip_history)):
            ts = it.get("time", "")
            txt = f"{idx+1:03d} — {it.get('input')} → {it.get('resolved')}  [{ts}]"
            listbox.insert("end", txt)
        btns = tb.Frame(win, padding=(12,8))
        btns.pack(fill=tk.X, side=tk.BOTTOM)
        tb.Button(btns, text="Exportar JSON", bootstyle="outline", command=self._export_history).pack(side=tk.LEFT)
        tb.Button(btns, text="Copiar item selecionado", bootstyle="outline", command=lambda: self._copy_history_item(listbox)).pack(side=tk.LEFT, padx=(8,0))
        tb.Button(btns, text="Fechar", bootstyle="outline", command=win.destroy).pack(side=tk.RIGHT)

    def _copy_history_item(self, listbox):
        sel = listbox.curselection()
        if not sel:
            messagebox.showinfo("Histórico", "Selecione um item.")
            return
        idx = sel[0]
        # reversed order used above
        item = list(reversed(self.ip_history))[idx]
        self.root.clipboard_clear()
        self.root.clipboard_append(json.dumps(item, indent=2))
        messagebox.showinfo("Histórico", "Item copiado para área de transferência.")

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

    def copy_overview(self):
        txt = self.txt_overview.get("1.0", "end").strip()
        if not txt:
            messagebox.showinfo("Copiar", "Nenhum texto para copiar.")
            return
        self.root.clipboard_clear()
        self.root.clipboard_append(txt)
        messagebox.showinfo("Copiar", "Overview copiado.")

    def export_overview(self):
        txt = self.txt_overview.get("1.0", "end").strip()
        if not txt:
            messagebox.showinfo("Exportar", "Nenhum texto para salvar.")
            return
        path = filedialog.asksaveasfilename(title="Salvar overview como", defaultextension=".txt",
                                            filetypes=[("Texto", "*.txt")])
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(txt)
            messagebox.showinfo("Exportar", f"Overview salvo em {path}")
        except Exception as e:
            messagebox.showerror("Erro", f"Falha ao salvar overview: {e}")
    def open_settings(self):
        win = tb.Toplevel(self.root)
        win.title("Settings — API Keys")
        win.geometry("540x300")
        frm = tb.Frame(win, padding=12)
        frm.pack(fill=tk.BOTH, expand=1)

        tb.Label(frm, text="Insira suas chaves de API (opcionais). Salve para persistir em config.json", style="TLabel").pack(anchor="w", pady=(0,8))

        # ipinfo
        tb.Label(frm, text="ipinfo token:", style="TLabel").pack(anchor="w")
        ipinfo_e = tb.Entry(frm)
        ipinfo_e.pack(fill=tk.X, pady=(0,6))
        ipinfo_e.insert(0, self.config.get("IPINFO_TOKEN", ""))

        tb.Label(frm, text="AbuseIPDB key:", style="TLabel").pack(anchor="w")
        abuse_e = tb.Entry(frm)
        abuse_e.pack(fill=tk.X, pady=(0,6))
        abuse_e.insert(0, self.config.get("ABUSEIPDB_KEY", ""))

        tb.Label(frm, text="IPQualityScore key:", style="TLabel").pack(anchor="w")
        ipqs_e = tb.Entry(frm)
        ipqs_e.pack(fill=tk.X, pady=(0,6))
        ipqs_e.insert(0, self.config.get("IPQS_KEY", ""))

        tb.Label(frm, text="ipdata key:", style="TLabel").pack(anchor="w")
        ipdata_e = tb.Entry(frm)
        ipdata_e.pack(fill=tk.X, pady=(0,6))
        ipdata_e.insert(0, self.config.get("IPDATA_KEY", ""))

        def _save():
            self.config["IPINFO_TOKEN"] = ipinfo_e.get().strip()
            self.config["ABUSEIPDB_KEY"] = abuse_e.get().strip()
            self.config["IPQS_KEY"] = ipqs_e.get().strip()
            self.config["IPDATA_KEY"] = ipdata_e.get().strip()
            ok = save_config(self.config)
            if ok:
                messagebox.showinfo("Settings", "Configurações salvas.")
                win.destroy()
            else:
                messagebox.showerror("Settings", "Falha ao salvar configurações.")

        btns = tb.Frame(frm)
        btns.pack(fill=tk.X, pady=(12,0))
        tb.Button(btns, text="Salvar", bootstyle="primary", command=_save).pack(side=tk.RIGHT)
        tb.Button(btns, text="Fechar", bootstyle="outline", command=win.destroy).pack(side=tk.RIGHT, padx=(0,8))

def main():
    try:
        os.chdir(os.path.dirname(os.path.abspath(__file__)))
    except Exception:
        pass
    app_root = tb.Window(title="Verificador de IP — Avançado", themename="darkly")
    App(app_root)
    try:
        app_root.mainloop()
    except KeyboardInterrupt:
        sys.exit(0)

if __name__ == "__main__":
    main()
