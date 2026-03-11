import customtkinter as ctk
import subprocess
import platform
import threading
import requests
import re

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")


class NocAutoApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("NOC Automation - Real Time Trace & Diagnosis")
        self.geometry("850x650")
        self.process = None
        self.stop_requested = False
        self.cache_operadoras = {}

        # --- UI ---
        self.label = ctk.CTkLabel(self, text="Diagnóstico de Rota e Ponto de Falha", font=("Roboto", 20))
        self.label.pack(pady=10)

        self.entry_ip = ctk.CTkEntry(self, placeholder_text="IP do Cliente...", width=300)
        self.entry_ip.pack(pady=5)

        self.frame_btns = ctk.CTkFrame(self, fg_color="transparent")
        self.frame_btns.pack(pady=10)

        self.btn_analisar = ctk.CTkButton(self.frame_btns, text="Rastrear Rota", command=self.start_analysis_thread,
                                          fg_color="green")
        self.btn_analisar.pack(side="left", padx=5)

        self.btn_parar = ctk.CTkButton(self.frame_btns, text="Parar", command=self.stop_analysis, fg_color="red",
                                       state="disabled")
        self.btn_parar.pack(side="left", padx=5)

        self.textbox = ctk.CTkTextbox(self, width=800, height=350, font=("Consolas", 12))
        self.textbox.pack(pady=10, padx=20)

        self.status_label = ctk.CTkLabel(self, text="Status: Pronto", font=("Roboto", 14, "bold"))
        self.status_label.pack(pady=10)

    def log(self, text):
        self.textbox.insert("end", text + "\n")
        self.textbox.see("end")

    def get_ip_info(self, ip):
        if ip in self.cache_operadoras: return self.cache_operadoras[ip]
        try:
            if ip.startswith(("10.", "192.168.", "172.16.")): return "[Rede Local]"
            response = requests.get(f"http://ip-api.com/json/{ip}?fields=status,as,isp", timeout=1.5)
            data = response.json()
            if data.get('status') == 'success':
                info = f"[{data.get('isp')} - {data.get('as')}]"
                self.cache_operadoras[ip] = info
                return info
        except:
            pass
        return ""

    def run_analysis(self):
        ip_target = self.entry_ip.get().strip()
        if not ip_target: return

        self.stop_requested = False
        self.btn_analisar.configure(state="disabled")
        self.btn_parar.configure(state="normal")
        self.textbox.delete("1.0", "end")
        self.status_label.configure(text="Status: Analisando...", text_color="yellow")

        cmd = ['tracert', '-d', ip_target] if platform.system().lower() == 'windows' else ['traceroute', '-n',
                                                                                           ip_target]
        self.process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)

        ip_pattern = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')
        last_good_ip = "Nenhum (falha no início)"
        last_good_info = ""
        failure_detected = False

        for line in iter(self.process.stdout.readline, ''):
            if self.stop_requested: break
            clean_line = line.strip()
            if not clean_line: continue

            match = ip_pattern.search(clean_line)

            if match:
                found_ip = match.group(1)
                info = self.get_ip_info(found_ip)
                last_good_ip = found_ip
                last_good_info = info
                self.log(f"{clean_line}  >>>  {info}")
            else:
                self.log(clean_line)
                # Se a linha tem asterisco e ainda não marcamos a falha
                if "*" in clean_line and not failure_detected:
                    failure_detected = True
                    self.log("\n" + "!" * 50)
                    self.log(f"ALERTA: A rota parou de responder após este ponto!")
                    self.log(f"ÚLTIMO SALTO : {last_good_ip} {last_good_info}")
                    self.log("!" * 50 + "\n")
                    self.status_label.configure(text="Status: FALHA DETECTADA", text_color="orange")

        self.process.terminate()

        # Ping final para ver se o cliente está realmente morto
        is_up = subprocess.call(['ping', '-n' if platform.system().lower() == 'windows' else '-c', '1', ip_target],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0

        if is_up:
            self.status_label.configure(text=f"Status Final: {ip_target} está UP (mas com bloqueio de ICMP no trajeto)",
                                        text_color="green")
        else:
            self.status_label.configure(text=f"Status Final: {ip_target} está DOWN", text_color="red")

        self.btn_analisar.configure(state="normal")
        self.btn_parar.configure(state="disabled")

    def stop_analysis(self):
        self.stop_requested = True
        if self.process: self.process.terminate()

    def start_analysis_thread(self):
        threading.Thread(target=self.run_analysis, daemon=True).start()


if __name__ == "__main__":
    app = NocAutoApp()
    app.mainloop()