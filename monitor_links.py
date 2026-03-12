import customtkinter as ctk
import subprocess
import platform
import threading
import requests
import re
import socket
import ipaddress

# Configurações de tema
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")


class NocUltimateApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("NOC Ultimate Tool v2.3 - Central de Diagnóstico")
        self.geometry("950x850")
        self.process = None
        self.stop_requested = False
        self.cache_operadoras = {}

        # --- TÍTULO ---
        self.label_titulo = ctk.CTkLabel(self, text="Painel de Automação NOC", font=("Roboto", 24, "bold"))
        self.label_titulo.pack(pady=15)

        # --- ENTRADA PRINCIPAL ---
        self.frame_input = ctk.CTkFrame(self)
        self.frame_input.pack(pady=10, padx=20, fill="x")

        self.entry_ip = ctk.CTkEntry(self.frame_input, placeholder_text="Digite IP, Bloco ou MAC...", width=450)
        self.entry_ip.pack(side="left", padx=15, pady=15)

        # --- BOTÕES DE AÇÃO ---
        self.frame_btns = ctk.CTkFrame(self, fg_color="transparent")
        self.frame_btns.pack(pady=10)

        # Linha 1 de Botões
        self.btn_trace = ctk.CTkButton(self.frame_btns, text="Rastrear Rota", command=self.start_analysis_thread,
                                       fg_color="green")
        self.btn_trace.pack(side="left", padx=5)

        self.btn_whois = ctk.CTkButton(self.frame_btns, text="Consultar Operadora", command=self.start_ip_lookup,
                                       fg_color="#2980b9")
        self.btn_whois.pack(side="left", padx=5)

        self.btn_scan = ctk.CTkButton(self.frame_btns, text="Scan Portas", command=self.start_port_scan,
                                      fg_color="#1f538d")
        self.btn_scan.pack(side="left", padx=5)

        # Linha 2 de Botões
        self.frame_btns_2 = ctk.CTkFrame(self, fg_color="transparent")
        self.frame_btns_2.pack(pady=5)

        self.btn_calc = ctk.CTkButton(self.frame_btns_2, text="Calcular Bloco", command=self.start_calc_ptp,
                                      fg_color="#1f538d")
        self.btn_calc.pack(side="left", padx=5)

        self.btn_mac = ctk.CTkButton(self.frame_btns_2, text="Identificar MAC", command=self.start_mac_lookup,
                                     fg_color="#d35400")
        self.btn_mac.pack(side="left", padx=5)

        self.btn_parar = ctk.CTkButton(self.frame_btns_2, text="Parar Execução", command=self.stop_analysis,
                                       fg_color="red", state="disabled")
        self.btn_parar.pack(side="left", padx=5)

        # --- SAÍDA (CONSOLE) ---
        self.textbox = ctk.CTkTextbox(self, width=900, height=450, font=("Consolas", 12))
        self.textbox.pack(pady=15, padx=20)

        self.status_label = ctk.CTkLabel(self, text="Status: Pronto", font=("Roboto", 14, "bold"))
        self.status_label.pack(pady=10)

    def log(self, text):
        self.textbox.insert("end", text + "\n")
        self.textbox.see("end")

    # --- FUNÇÃO DE CONSULTA DE OPERADORA (WHOIS IP) ---
    def start_ip_lookup(self):
        ip = self.entry_ip.get().split('/')[0].strip()
        if not ip: return
        self.textbox.delete("1.0", "end")
        threading.Thread(target=self.run_ip_lookup, args=(ip,), daemon=True).start()

    def run_ip_lookup(self, ip):
        self.log(f"Consultando informações do IP: {ip}...")
        try:
            # Consulta avançada
            res = requests.get(f"http://ip-api.com/json/{ip}?fields=status,message,country,regionName,city,isp,org,as",
                               timeout=3)
            data = res.json()
            if data['status'] == 'success':
                self.log("-" * 50)
                self.log(f"OPERADORA:  {data.get('isp')}")
                self.log(f"ASN:        {data.get('as')}")
                self.log(f"ORGANIZAÇÃO:{data.get('org')}")
                self.log(f"LOCALIDADE: {data.get('city')}, {data.get('regionName')} - {data.get('country')}")
                self.log("-" * 50)
            else:
                self.log(f"Erro: {data.get('message')}")
        except:
            self.log("Erro: Não foi possível conectar à base de dados de IPs.")

    # --- LÓGICA DE MAC ---
    def start_mac_lookup(self):
        mac = self.entry_ip.get().strip()
        if mac:
            self.textbox.delete("1.0", "end")
            threading.Thread(target=self.run_mac_lookup, args=(mac,), daemon=True).start()

    def run_mac_lookup(self, mac):
        clean_mac = re.sub(r'[^a-fA-F0-9]', '', mac)
        try:
            res = requests.get(f"https://api.macvendors.com/{clean_mac[:6]}", timeout=3)
            self.log(f"MAC: {mac}\nFABRICANTE: {res.text if res.status_code == 200 else 'Não encontrado'}")
        except:
            self.log("Erro na consulta de MAC.")

    # --- LÓGICA DE TRACEROUTE ---
    def start_analysis_thread(self):
        threading.Thread(target=self.run_analysis, daemon=True).start()

    def run_analysis(self):
        ip_target = self.entry_ip.get().split('/')[0].strip()
        if not ip_target: return
        self.stop_requested = False
        self.btn_trace.configure(state="disabled")
        self.btn_parar.configure(state="normal")
        self.textbox.delete("1.0", "end")
        cmd = ['tracert', '-d', ip_target] if platform.system().lower() == 'windows' else ['traceroute', '-n',
                                                                                           ip_target]
        self.process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1,
                                        shell=True)
        for line in iter(self.process.stdout.readline, ''):
            if self.stop_requested: break
            self.log(line.strip())
        self.btn_trace.configure(state="normal")
        self.btn_parar.configure(state="disabled")

    # --- LÓGICA DE PORTAS ---
    def start_port_scan(self):
        ip = self.entry_ip.get().split('/')[0].strip()
        if ip: threading.Thread(target=self.run_port_scan, args=(ip,), daemon=True).start()

    def run_port_scan(self, ip):
        self.textbox.delete("1.0", "end")
        portas = {22: "SSH", 80: "HTTP", 443: "HTTPS", 2288: "Serviço 2288", 8299: "Winbox/RB", 9999: "Web Custom",
                  3389: "RDP", 8080: "HTTP", 8888: "HTTP"}
        for porta, nome in portas.items():
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1.0)
            result = sock.connect_ex((ip, porta))
            self.log(f"Porta {porta} ({nome}): {'ABERTA ✅' if result == 0 else 'FECHADA ❌'}")
            sock.close()

    # --- LÓGICA DE BLOCO PTP ---
    def start_calc_ptp(self):
        raw_ip = self.entry_ip.get().strip()
        if not raw_ip: return
        self.textbox.delete("1.0", "end")
        try:
            val = raw_ip if '/' in raw_ip else raw_ip + "/30"
            rede = ipaddress.ip_network(val, strict=False)
            hosts = list(rede.hosts())
            self.log(
                f"Network: {rede.network_address}\nFirst:   {hosts[0]}\nLast:    {hosts[-1]}\nBroadcast: {rede.broadcast_address}\nMask:    {rede.netmask}\n")
            for ip in rede:
                ultimo = int(str(ip).split('.')[-1])
                self.log(f"{ip} -> {'OPERADORA (Ímpar)' if ultimo % 2 != 0 else 'CLIENTE (Par)'}")
        except Exception as e:
            self.log(f"Erro: {e}")

    def stop_analysis(self):
        self.stop_requested = True
        if self.process: self.process.terminate()


if __name__ == "__main__":
    app = NocUltimateApp()
    app.mainloop()