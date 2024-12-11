import tkinter as tk
from tkinter import messagebox, scrolledtext, filedialog
import subprocess
import threading
import os
import sys
import toml
import re

class FrpsGUI:
    def __init__(self, master):
        self.master = master
        master.title("frps GUI Server")
        master.geometry("600x650")

        # 설정 변수 초기화
        self.config = {}
        self.frps_process = None
        self.process_thread = None
        self.stop_event = threading.Event()

        # GUI 구성
        self.create_widgets()

        # 설정 파일 로드
        self.load_config()

        # 창 닫기 이벤트 처리
        self.master.protocol("WM_DELETE_WINDOW", self.on_closing)

        # 자동 시작 옵션이 체크되어 있으면 서버 시작
        if self.autostart_var.get():
            self.start_frps()

    def create_widgets(self):
        # 노트북 위젯으로 탭 구성
        try:
            import tkinter.ttk as ttk
        except ImportError:
            import ttk

        notebook = ttk.Notebook(self.master)
        notebook.pack(expand=True, fill='both')

        # 설정 탭
        self.settings_frame = tk.Frame(notebook)
        notebook.add(self.settings_frame, text='설정(Settings)')

        # 로그 탭
        self.log_frame = tk.Frame(notebook)
        notebook.add(self.log_frame, text='로그(Log)')

        # 설정 프레임 구성
        self.create_settings_tab()

        # 로그 프레임 구성
        self.create_log_tab()

    def create_settings_tab(self):
        frame = self.settings_frame

        # 설정 항목들을 그룹화하여 프레임으로 묶기
        network_frame = tk.LabelFrame(frame, text="네트워크 설정", padx=10, pady=10)
        network_frame.pack(fill="x", padx=10, pady=5)

        tk.Label(network_frame, text="Bind 주소:").grid(row=0, column=0, sticky='e')
        self.bind_addr = tk.Entry(network_frame)
        self.bind_addr.grid(row=0, column=1, pady=2)
        self.bind_addr.insert(0, "0.0.0.0")  # 기본값

        tk.Label(network_frame, text="Bind 포트:").grid(row=1, column=0, sticky='e')
        self.bind_port = tk.Entry(network_frame)
        self.bind_port.grid(row=1, column=1, pady=2)
        self.bind_port.insert(0, "7000")  # 기본값

        tk.Label(network_frame, text="대시보드 포트:").grid(row=2, column=0, sticky='e')
        self.dashboard_port = tk.Entry(network_frame)
        self.dashboard_port.grid(row=2, column=1, pady=2)
        self.dashboard_port.insert(0, "7500")  # 기본값

        tk.Label(network_frame, text="대시보드 사용자 이름:").grid(row=3, column=0, sticky='e')
        self.dashboard_user = tk.Entry(network_frame)
        self.dashboard_user.grid(row=3, column=1, pady=2)
        self.dashboard_user.insert(0, "admin")  # 기본값

        tk.Label(network_frame, text="대시보드 비밀번호:").grid(row=4, column=0, sticky='e')
        self.dashboard_pwd = tk.Entry(network_frame, show="*")
        self.dashboard_pwd.grid(row=4, column=1, pady=2)
        self.dashboard_pwd.insert(0, "admin")  # 기본값

        security_frame = tk.LabelFrame(frame, text="보안 설정", padx=10, pady=10)
        security_frame.pack(fill="x", padx=10, pady=5)

        tk.Label(security_frame, text="인증 토큰(Token):").grid(row=0, column=0, sticky='e')
        self.token = tk.Entry(security_frame, show="*")
        self.token.grid(row=0, column=1, pady=2)

        log_frame = tk.LabelFrame(frame, text="로그 설정", padx=10, pady=10)
        log_frame.pack(fill="x", padx=10, pady=5)

        tk.Label(log_frame, text="로그 레벨:").grid(row=0, column=0, sticky='e')
        self.log_level = tk.StringVar()
        self.log_level.set("info")
        log_levels = ["trace", "debug", "info", "warn", "error"]
        self.log_level_menu = tk.OptionMenu(log_frame, self.log_level, *log_levels)
        self.log_level_menu.grid(row=0, column=1, pady=2)

        tk.Label(log_frame, text="로그 파일 저장:").grid(row=1, column=0, sticky='e')
        self.log_file_var = tk.BooleanVar()
        self.log_file_var.set(False)  # 기본값: False (로그 파일 저장 안 함)
        self.log_file_check = tk.Checkbutton(log_frame, text="로그 파일에 저장", variable=self.log_file_var)
        self.log_file_check.grid(row=1, column=1, pady=2, sticky='w')

        tk.Label(log_frame, text="로그 최대 저장 일수:").grid(row=2, column=0, sticky='e')
        self.log_max_days = tk.Entry(log_frame)
        self.log_max_days.grid(row=2, column=1, pady=2)
        self.log_max_days.insert(0, "3")

        option_frame = tk.LabelFrame(frame, text="옵션", padx=10, pady=10)
        option_frame.pack(fill="x", padx=10, pady=5)

        self.autostart_var = tk.BooleanVar()
        self.autostart_check = tk.Checkbutton(option_frame, text="프로그램 시작 시 서버 자동 시작", variable=self.autostart_var)
        self.autostart_check.grid(row=0, column=0, pady=2, sticky='w')

        # 설정 저장 및 서버 실행 버튼
        button_frame = tk.Frame(frame)
        button_frame.pack(pady=10)

        self.start_button = tk.Button(button_frame, text="서버 시작(Start Server)", command=self.start_frps)
        self.start_button.grid(row=0, column=0, padx=5)

        self.stop_button = tk.Button(button_frame, text="서버 중지(Stop Server)", command=self.stop_frps, state='disabled')
        self.stop_button.grid(row=0, column=1, padx=5)

        self.save_button = tk.Button(button_frame, text="설정 저장(Save Config)", command=self.save_config)
        self.save_button.grid(row=0, column=2, padx=5)

    def create_log_tab(self):
        frame = self.log_frame

        tk.Label(frame, text="frps 로그 출력:").pack()

        self.log_text = scrolledtext.ScrolledText(frame, height=30)
        self.log_text.pack(fill='both', expand=True)

    def load_config(self):
        if os.path.exists("frps.toml"):
            try:
                with open("frps.toml", "r", encoding='utf-8') as config_file:
                    self.config = toml.load(config_file)

                # 설정 값을 GUI에 반영
                common = self.config.get('common', {})
                self.bind_addr.delete(0, tk.END)
                self.bind_addr.insert(0, common.get('bind_addr', '0.0.0.0'))

                self.bind_port.delete(0, tk.END)
                self.bind_port.insert(0, str(common.get('bind_port', '7000')))

                self.dashboard_port.delete(0, tk.END)
                self.dashboard_port.insert(0, str(common.get('dashboard_port', '7500')))

                self.dashboard_user.delete(0, tk.END)
                self.dashboard_user.insert(0, common.get('dashboard_user', 'admin'))

                self.dashboard_pwd.delete(0, tk.END)
                self.dashboard_pwd.insert(0, common.get('dashboard_pwd', 'admin'))

                self.token.delete(0, tk.END)
                self.token.insert(0, common.get('token', ''))

                self.log_level.set(common.get('log_level', 'info'))

                self.log_file_var.set(common.get('log_file_enabled', False))

                self.log_max_days.delete(0, tk.END)
                self.log_max_days.insert(0, str(common.get('log_max_days', '3')))

                # 자동 시작 옵션
                self.autostart_var.set(common.get('autostart', False))

            except Exception as e:
                messagebox.showerror("오류", f"설정 파일을 불러오는 중 오류가 발생했습니다:\n{e}")
        else:
            # 설정 파일이 없으면 기본값으로 설정
            self.config = {}

    def save_config(self):
        # 설정 값을 저장
        self.config['common'] = {
            'bind_addr': self.bind_addr.get(),
            'bind_port': int(self.bind_port.get()),
            'dashboard_port': int(self.dashboard_port.get()),
            'dashboard_user': self.dashboard_user.get(),
            'dashboard_pwd': self.dashboard_pwd.get(),
            'token': self.token.get(),
            'log_level': self.log_level.get(),
            'log_file_enabled': self.log_file_var.get(),
            'log_max_days': int(self.log_max_days.get()),
            'disable_log_color': True,
            'autostart': self.autostart_var.get()
        }

        try:
            with open("frps.toml", "w") as config_file:
                toml.dump(self.config, config_file)
        except Exception as e:
            messagebox.showerror("오류", f"설정 파일을 저장하는 중 오류가 발생했습니다:\n{e}")

    def start_frps(self):
        # 이미 실행 중인 경우
        if self.frps_process and self.frps_process.poll() is None:
            messagebox.showwarning("경고", "frps가 이미 실행 중입니다.")
            return

        # 설정 저장
        self.save_config()

        # frps 실행 파일 확인
        frps_executable = "frps.exe"
        frps_path = getattr(sys, '_MEIPASS', os.path.dirname(os.path.abspath(__file__)))
        frps_full_path = os.path.join(frps_path, frps_executable)

        if not os.path.exists(frps_full_path):
            # 실행 파일 선택 대화상자 표시
            frps_full_path = filedialog.askopenfilename(title="frps 실행 파일 선택", filetypes=[("frps 실행 파일", "frps.exe")])
            if not frps_full_path:
                messagebox.showerror("오류", "frps 실행 파일을 찾을 수 없습니다.")
                return

        # 로그 영역 초기화
        self.log_text.delete(1.0, tk.END)

        # 설정 파일 생성
        self.generate_frps_config()

        # 서버 시작
        # frps 실행 시 인코딩 지정
        try:
            self.stop_event.clear()
            if os.name == 'nt':
                self.frps_process = subprocess.Popen([frps_full_path, "-c", "frps.toml"],
                                                     stdout=subprocess.PIPE,
                                                     stderr=subprocess.STDOUT,
                                                     universal_newlines=True,
                                                     encoding='utf-8',
                                                     creationflags=subprocess.CREATE_NO_WINDOW)
            else:
                self.frps_process = subprocess.Popen([frps_full_path, "-c", "frps.toml"],
                                                     stdout=subprocess.PIPE,
                                                     stderr=subprocess.STDOUT,
                                                     universal_newlines=True,
                                                     encoding='utf-8')

            self.process_thread = threading.Thread(target=self.monitor_frps_output, daemon=True)
            self.process_thread.start()

            self.start_button.config(state='disabled')
            self.stop_button.config(state='normal')
        except Exception as e:
            messagebox.showerror("오류", f"frps를 시작하는 중 오류가 발생했습니다:\n{e}")


    def generate_frps_config(self):
        # frps.toml 설정 파일 생성
        common_config = self.config.get('common', {})
        frps_config = {'common': common_config}

        # log_file 설정 처리
        if not self.log_file_var.get():
            # 로그 파일 저장 안 함
            frps_config['common']['log_file'] = ''
        else:
            # 로그 파일 저장
            frps_config['common']['log_file'] = 'frps.log'

        # 설정 파일 저장 시 UTF-8 인코딩 명시
        with open('frps.toml', 'w', encoding='utf-8') as f:
            toml.dump(frps_config, f)

    def stop_frps(self):
        self.stop_event.set()
        if self.frps_process and self.frps_process.poll() is None:
            self.frps_process.terminate()
            self.frps_process.wait()
            self.frps_process = None
        self.log_text.insert(tk.END, "frps가 중지되었습니다.\n")
        self.log_text.see(tk.END)
        self.start_button.config(state='normal')
        self.stop_button.config(state='disabled')

    def monitor_frps_output(self):
        while True:
            if self.stop_event.is_set():
                break
            line = self.frps_process.stdout.readline()
            if not line:
                break
            self.log_text.insert(tk.END, self.clean_ansi_escape(line))
            self.log_text.see(tk.END)
        self.frps_process.stdout.close()
        self.frps_process.wait()

    def clean_ansi_escape(self, text):
        ansi_escape = re.compile(r'\x1B\[[0-?]*[ -/]*[@-~]')
        return ansi_escape.sub('', text)

    def on_closing(self):
        if self.frps_process and self.frps_process.poll() is None:
            if messagebox.askyesno("종료 확인", "서버가 실행 중입니다. 종료하시겠습니까?"):
                self.stop_frps()
                self.master.destroy()
            else:
                return
        else:
            self.master.destroy()

if __name__ == "__main__":
    root = tk.Tk()
    app = FrpsGUI(root)
    root.mainloop()
