import tkinter as tk
from tkinter import messagebox, scrolledtext
import subprocess
import threading
import os
import sys
import random
import toml
import re

class FrpGUI:
    def __init__(self, master):
        self.master = master
        master.title("frp GUI Client")
        master.geometry("500x500")  # 윈도우 크기 조정

        # 레이아웃 개선을 위한 프레임 생성
        input_frame = tk.Frame(master)
        input_frame.pack(pady=10)

        output_frame = tk.Frame(master)
        output_frame.pack(pady=10, fill='both', expand=True)

        # 장치명 (proxy name)
        tk.Label(input_frame, text="장치명(Device Name):").grid(row=0, column=0, sticky='e')
        self.device_name = tk.Entry(input_frame)
        self.device_name.grid(row=0, column=1)

        # 서버 주소
        tk.Label(input_frame, text="서버 주소(Server Address):").grid(row=1, column=0, sticky='e')
        self.server_addr = tk.Entry(input_frame)
        self.server_addr.grid(row=1, column=1)

        # 서버 포트
        tk.Label(input_frame, text="서버 포트(Server Port):").grid(row=2, column=0, sticky='e')
        self.server_port = tk.Entry(input_frame)
        self.server_port.grid(row=2, column=1)

        # 인증 토큰
        tk.Label(input_frame, text="인증 토큰(Auth Token):").grid(row=3, column=0, sticky='e')
        self.auth_token = tk.Entry(input_frame, show="*")
        self.auth_token.grid(row=3, column=1)

        # 로컬 포트
        tk.Label(input_frame, text="로컬 포트(Local Port):").grid(row=4, column=0, sticky='e')
        self.local_port = tk.Entry(input_frame)
        self.local_port.grid(row=4, column=1)

        # 원격 포트
        tk.Label(input_frame, text="원격 포트(Remote Port):").grid(row=5, column=0, sticky='e')
        self.remote_port = tk.Entry(input_frame)
        self.remote_port.grid(row=5, column=1)

        # 시작 및 중지 버튼
        self.start_button = tk.Button(input_frame, text="시작(Start)", command=self.start_frp)
        self.start_button.grid(row=6, column=0, pady=10)

        self.stop_button = tk.Button(input_frame, text="중지(Stop)", command=self.stop_frp, state='disabled')
        self.stop_button.grid(row=6, column=1)

        # 출력 영역
        tk.Label(output_frame, text="frpc 출력:").pack()
        self.output_text = scrolledtext.ScrolledText(output_frame, height=10)
        self.output_text.pack(fill='both', expand=True)

        # 프로세스 저장 변수
        self.frp_process = None
        self.process_thread = None  # 프로세스 모니터링 스레드
        self.stop_event = threading.Event()  # 스레드 중지를 위한 이벤트

        # 프로그램 시작 시 설정 불러오기
        self.load_config()

        # 창 닫기 이벤트
        self.master.protocol("WM_DELETE_WINDOW", self.on_closing)

    def load_config(self):
        if os.path.exists("frpc.toml"):
            try:
                with open("frpc.toml", "r", encoding='utf-8') as config_file:
                    config = toml.load(config_file)

                # [common] 섹션
                common = config.get('common', {})
                self.server_addr.insert(0, common.get('server_addr', ''))
                self.server_port.insert(0, str(common.get('server_port', '')))
                self.auth_token.insert(0, common.get('token', ''))

                # 프록시 섹션 (common 제외한 첫 번째 섹션)
                for section_name in config:
                    if section_name != 'common':
                        proxy = config[section_name]
                        self.device_name.insert(0, section_name)
                        self.local_port.insert(0, str(proxy.get('local_port', '')))
                        self.remote_port.insert(0, str(proxy.get('remote_port', '')))
                        break
            except Exception as e:
                messagebox.showerror("오류", f"설정 파일을 불러오는 중 오류가 발생했습니다:\n{e}")

    def generate_proxy_name(self):
        device_name = self.device_name.get().strip()
        # 공백 제거 로직 추가
        device_name = device_name.replace(' ', '')
    
        if not device_name:
            # UUID 대신 단순 랜덤 문자열 사용
            device_name = ''.join(random.choices('ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', k=10))
        return device_name


    def validate_port(self, port_str):
        try:
            port = int(port_str)
            if 1 <= port <= 65535:
                return port
            else:
                return None
        except ValueError:
            return None

    def generate_config(self, remote_port, proxy_name):
        # toml 형식으로 설정 파일 생성
        config = {
            'common': {
                'server_addr': self.server_addr.get(),
                'server_port': int(self.server_port.get()),
                'token': self.auth_token.get()
            },
            proxy_name: {
                'type': 'tcp',
                'local_port': int(self.local_port.get()),
                'remote_port': remote_port
            }
        }
        with open("frpc.toml", "w", encoding='utf-8') as config_file:
            toml.dump(config, config_file)

	# 포트 범위 검증
    def validate_port(self, port_str):
        try:
            port = int(port_str)
            if 1 <= port <= 65535:
                return port
            else:
                return None
        except ValueError:
            return None

    def start_frp(self):
        # 이미 실행 중인지 확인
        if self.frp_process and self.frp_process.poll() is None:
            messagebox.showwarning("경고", "frpc가 이미 실행 중입니다.")
            return

        # 필수 입력값 확인
        if not self.server_addr.get().strip():
            messagebox.showerror("오류", "서버 주소를 입력하세요.")
            return
        if not self.server_port.get().strip():
            messagebox.showerror("오류", "서버 포트를 입력하세요.")
            return
        if not self.local_port.get().strip():
            messagebox.showerror("오류", "로컬 포트를 입력하세요.")
            return

        # 서버 포트와 로컬 포트 유효성 검사
        server_port = self.validate_port(self.server_port.get().strip())
        local_port = self.validate_port(self.local_port.get().strip())

        if server_port is None:
            messagebox.showerror("오류", "서버 포트는 1에서 65535 사이의 숫자여야 합니다.")
            return
        if local_port is None:
            messagebox.showerror("오류", "로컬 포트는 1에서 65535 사이의 숫자여야 합니다.")
            return

        self.start_button.config(state='disabled')
        self.stop_button.config(state='normal')
        self.stop_event.clear()  # 스레드 중지 이벤트 초기화

        # run_frp_with_retry 스레드 시작
        self.process_thread = threading.Thread(target=self.run_frp_with_retry, daemon=True)
        self.process_thread.start()

    def run_frp_with_retry(self):
        max_retries = 10
        retries = 0
        port_assigned = False

        while retries < max_retries and not port_assigned and not self.stop_event.is_set():
            # 원격 포트 결정
            remote_port_input = self.remote_port.get().strip()
            if not remote_port_input:
                # 빈 칸이면 랜덤 포트 할당
                remote_port = random.randint(10000, 65535)
            else:
                remote_port = self.validate_port(remote_port_input)
                if remote_port is None:
                    messagebox.showerror("오류", "원격 포트는 1에서 65535 사이의 숫자여야 합니다.")
                    self.start_button.config(state='normal')
                    self.stop_button.config(state='disabled')
                    return

            # 프록시 이름 생성 (사용자의 입력 혹은 랜덤 문자열)
            proxy_name = self.generate_proxy_name()

            # 설정 파일 생성
            self.generate_config(remote_port, proxy_name)

            frp_executable = "frpc.exe" if os.name == 'nt' else "frpc"
            frp_path = getattr(sys, '_MEIPASS', os.path.dirname(os.path.abspath(__file__)))
            frp_full_path = os.path.join(frp_path, frp_executable)

            if not os.path.exists(frp_full_path):
                messagebox.showerror("오류", f"frp 실행 파일을 찾을 수 없습니다: {frp_full_path}")
                self.start_button.config(state='normal')
                self.stop_button.config(state='disabled')
                return

            # 출력 영역 초기화
            self.output_text.delete(1.0, tk.END)
            self.output_text.insert(tk.END, f"원격 포트(remote_port): {remote_port}로 시도 중...\n")
            self.output_text.see(tk.END)

            # 기존 프로세스 종료
            if self.frp_process and self.frp_process.poll() is None:
                self.frp_process.terminate()
                self.frp_process.wait()

            # frpc 실행
            try:
                if os.name == 'nt':
                    creationflags = subprocess.CREATE_NO_WINDOW
                    self.frp_process = subprocess.Popen([frp_full_path, "-c", "frpc.toml"],
                                                        stdout=subprocess.PIPE,
                                                        stderr=subprocess.STDOUT,
                                                        universal_newlines=True,
                                                        encoding='utf-8',
                                                        creationflags=creationflags)
                else:
                    self.frp_process = subprocess.Popen([frp_full_path, "-c", "frpc.toml"],
                                                        stdout=subprocess.PIPE,
                                                        stderr=subprocess.STDOUT,
                                                        universal_newlines=True,
                                                        encoding='utf-8')


                port_in_use = False

                # 초기 출력 모니터링
                while True:
                    if self.stop_event.is_set():
                        break
                    line = self.frp_process.stdout.readline()
                    if not line:
                        break
                    self.output_text.insert(tk.END, line)
                    self.output_text.see(tk.END)

                    # 상세한 상태 정보 파싱 및 출력
                    self.parse_and_display_status(line)

                    if "port already used" in line or "the proxy is already in use" in line or "proxy .* already exists" in line:
                        port_in_use = True
                        break
                    if "start proxy success" in line:
                        port_assigned = True
                        break
                    if "start error" in line:
                        port_in_use = True
                        break

                if port_in_use:
                    self.output_text.insert(tk.END, f"포트 {remote_port}는 이미 사용 중입니다. 다른 포트로 재시도합니다.\n")
                    self.output_text.see(tk.END)
                    self.frp_process.terminate()
                    self.frp_process.wait()
                    retries += 1
                    # 다음 루프에서 랜덤 포트를 할당하도록 원격 포트 필드 초기화
                    self.remote_port.delete(0, tk.END)
                    continue
                elif not port_assigned:
                    # 다른 에러 발생 시 재시도하지 않고 종료
                    self.frp_process.terminate()
                    self.frp_process.wait()
                    break

                # 성공적으로 시작된 경우 원격 포트 업데이트
                self.remote_port.delete(0, tk.END)
                self.remote_port.insert(0, str(remote_port))

                # 성공 후 지속적으로 로그 모니터링
                while True:
                    if self.stop_event.is_set():
                        break
                    line = self.frp_process.stdout.readline()
                    if not line:
                        break
                    self.output_text.insert(tk.END, line)
                    self.output_text.see(tk.END)
                    self.parse_and_display_status(line)

                self.frp_process.stdout.close()
                self.frp_process.wait()

            except Exception as e:
                if not self.stop_event.is_set():
                    self.output_text.insert(tk.END, f"에러 발생: {str(e)}\n")
                    self.output_text.see(tk.END)
                self.frp_process = None
                break

        if not port_assigned and not self.stop_event.is_set():
            messagebox.showerror("오류", "frpc를 시작할 수 없습니다. 재시도 횟수를 초과했습니다.")
            self.start_button.config(state='normal')
            self.stop_button.config(state='disabled')
        elif port_assigned and not self.stop_event.is_set():
            self.output_text.insert(tk.END, f"원격 포트(remote_port): {self.remote_port.get()}로 frpc가 시작되었습니다.\n")
            self.output_text.see(tk.END)

    def parse_and_display_status(self, line):
        # ANSI 이스케이프 시퀀스 제거
        ansi_escape = re.compile(r'\x1B\[[0-?]*[ -/]*[@-~]')
        clean_line = ansi_escape.sub('', line)

        # 로그 메시지 파싱 및 상태 출력
        if "start frpc service for config file" in clean_line:
            self.output_text.insert(tk.END, "frpc 서비스를 시작합니다.\n")
        elif "try to connect to server" in clean_line:
            self.output_text.insert(tk.END, "서버에 연결을 시도합니다...\n")
        elif "login to server success" in clean_line:
            self.output_text.insert(tk.END, "서버에 성공적으로 로그인했습니다.\n")
        elif "start proxy success" in clean_line:
            self.output_text.insert(tk.END, "프록시가 성공적으로 시작되었습니다.\n")
        elif "client exit success" in clean_line:
            self.output_text.insert(tk.END, "클라이언트가 성공적으로 종료되었습니다.\n")

        self.output_text.see(tk.END)

    def stop_frp(self):
        self.stop_event.set()  # 스레드 중지 이벤트 설정
        if self.frp_process and self.frp_process.poll() is None:
            self.frp_process.terminate()
            self.frp_process.wait()
            self.frp_process = None  # 프로세스 변수 초기화
        self.output_text.insert(tk.END, "frpc가 중지되었습니다.\n")
        self.output_text.see(tk.END)
        self.start_button.config(state='normal')
        self.stop_button.config(state='disabled')

    def on_closing(self):
        if self.frp_process and self.frp_process.poll() is None:
            if messagebox.askyesno("종료 확인", "현재 연결이 끊어집니다. 종료하시겠습니까?"):
                self.stop_frp()
                self.master.destroy()
            else:
                return
        else:
            self.master.destroy()

if __name__ == "__main__":
    root = tk.Tk()
    app = FrpGUI(root)
    root.mainloop()
