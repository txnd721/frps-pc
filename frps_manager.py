import tkinter as tk
from tkinter import ttk, messagebox
import subprocess
import os
import sys
import time
import threading
import win32api
import win32con
import win32gui
import pystray
from PIL import Image

class FRPSManager:
    def __init__(self, root):
        self.root = root
        self.version = "1.0.0"
        self.root.title(f"FRPS 服务管理器 v{self.version}")
        self.root.geometry("600x400")
        
        # FRPS版本信息
        self.frps_version = "未知"
        
        self.frps_process = None
        self.tray_icon = None
        
        # 设置窗口关闭事件
        self.root.protocol('WM_DELETE_WINDOW', self.on_close)
        
        # 创建Notebook标签页
        self.notebook = ttk.Notebook(root)
        self.notebook.pack(pady=10, padx=10, fill="both", expand=True)
        
        # 配置标签页
        self.config_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.config_tab, text="配置")
        
        # 创建配置框架
        self.config_frame = ttk.Frame(self.config_tab)
        self.config_frame.pack(pady=10, padx=10, fill="x")
        
        # 第一组：绑定端口和Token
        self.bind_frame = ttk.LabelFrame(self.config_frame, text="基本配置")
        self.bind_frame.grid(row=0, column=0, padx=5, pady=5, sticky="nsew")
        
        ttk.Label(self.bind_frame, text="绑定端口:").grid(row=0, column=0, padx=5, pady=5)
        self.bind_port = ttk.Entry(self.bind_frame)
        self.bind_port.grid(row=0, column=1, padx=5, pady=5)
        self.bind_port.insert(0, "7000")
        
        ttk.Label(self.bind_frame, text="Token:").grid(row=0, column=2, padx=5, pady=5)
        self.token = ttk.Entry(self.bind_frame, show="*")
        self.token.grid(row=0, column=3, padx=5, pady=5)
        self.token.insert(0, "12345678")
        self.token_show = tk.IntVar()
        ttk.Checkbutton(self.bind_frame, text="显示", variable=self.token_show, command=lambda: self.toggle_show(self.token, self.token_show)).grid(row=0, column=4, padx=5, pady=5)
        
        # 第二组：Web管理设置
        self.web_frame = ttk.LabelFrame(self.config_frame, text="Web管理")
        self.web_frame.grid(row=1, column=0, padx=5, pady=5, sticky="nsew")
        
        ttk.Label(self.web_frame, text="Web管理端口:").grid(row=0, column=0, padx=5, pady=5)
        self.web_port = ttk.Entry(self.web_frame)
        self.web_port.grid(row=0, column=1, padx=5, pady=5)
        self.web_port.insert(0, "7500")
        
        ttk.Label(self.web_frame, text="用户名:").grid(row=1, column=0, padx=5, pady=5)
        self.web_user = ttk.Entry(self.web_frame)
        self.web_user.grid(row=1, column=1, padx=5, pady=5)
        self.web_user.insert(0, "admin")
        
        ttk.Label(self.web_frame, text="密码:").grid(row=1, column=2, padx=5, pady=5)
        self.web_pass = ttk.Entry(self.web_frame, show="*")
        self.web_pass.grid(row=1, column=3, padx=5, pady=5)
        self.web_pass.insert(0, "admin")
        self.pass_show = tk.IntVar()
        ttk.Checkbutton(self.web_frame, text="显示", variable=self.pass_show, command=lambda: self.toggle_show(self.web_pass, self.pass_show)).grid(row=1, column=4, padx=5, pady=5)
        
        # 第三组：协议端口设置
        self.protocol_frame = ttk.LabelFrame(self.config_frame, text="协议端口")
        self.protocol_frame.grid(row=2, column=0, padx=5, pady=5, sticky="nsew")
        
        ttk.Label(self.protocol_frame, text="HTTP端口:").grid(row=0, column=0, padx=5, pady=5)
        self.http_port = ttk.Entry(self.protocol_frame)
        self.http_port.grid(row=0, column=1, padx=5, pady=5)
        self.http_port.insert(0, "80")
        
        ttk.Label(self.protocol_frame, text="HTTPS端口:").grid(row=1, column=0, padx=5, pady=5)
        self.https_port = ttk.Entry(self.protocol_frame)
        self.https_port.grid(row=1, column=1, padx=5, pady=5)
        self.https_port.insert(0, "443")
        
        ttk.Label(self.protocol_frame, text="KCP端口:").grid(row=0, column=2, padx=5, pady=5)
        self.kcp_port = ttk.Entry(self.protocol_frame)
        self.kcp_port.grid(row=0, column=3, padx=5, pady=5)
        self.kcp_port.insert(0, "7001")
        
        
        
        # 控制按钮
        self.btn_frame = ttk.Frame(self.config_tab)
        self.btn_frame.pack(pady=10)
        
        self.start_btn = ttk.Button(self.btn_frame, text="启动服务", command=self.start_frps)
        self.start_btn.pack(side="left", padx=5)
        
        self.stop_btn = ttk.Button(self.btn_frame, text="停止服务", command=self.stop_frps, state="disabled")
        self.stop_btn.pack(side="left", padx=5)
        
        self.restart_btn = ttk.Button(self.btn_frame, text="重启服务", command=self.restart_frps, state="disabled")
        self.restart_btn.pack(side="left", padx=5)
        
        # 开机自启设置
        self.auto_start = tk.IntVar()
        ttk.Checkbutton(self.btn_frame, text="开机自启", variable=self.auto_start, command=self.toggle_auto_start).pack(side="left", padx=5)
        
        # 延迟启动设置
        ttk.Label(self.btn_frame, text="延迟启动(秒):").pack(side="left", padx=5)
        self.delay_entry = ttk.Entry(self.btn_frame, width=8)
        self.delay_entry.insert(0, "10")
        self.delay_entry.pack(side="left", padx=5)
        
        # 日志标签页
        self.log_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.log_tab, text="日志")
        
        # 日志显示
        self.log_frame = ttk.LabelFrame(self.log_tab, text="日志")
        self.log_frame.pack(pady=10, padx=10, fill="both", expand=True)
        
        self.log_text = tk.Text(self.log_frame, wrap="word")
        self.log_text.pack(fill="both", expand=True, padx=5, pady=5)
        
        # 加载现有配置
        self.load_config()
    
    def load_config(self):
        config_path = os.path.join(os.path.dirname(__file__), "frps.toml")
        if os.path.exists(config_path):
            with open(config_path, "r") as f:
                for line in f:
                    if line.startswith("bindPort"):
                        port = line.split("=")[1].strip()
                        self.bind_port.delete(0, tk.END)
                        self.bind_port.insert(0, port)
                    elif line.startswith("webServer.port"):
                        port = line.split("=")[1].strip()
                        self.web_port.delete(0, tk.END)
                        self.web_port.insert(0, port)
                    elif line.startswith("webServer.user"):
                        user = line.split("=")[1].strip().strip('"')
                        self.web_user.delete(0, tk.END)
                        self.web_user.insert(0, user)
                    elif line.startswith("webServer.password"):
                        password = line.split("=")[1].strip().strip('"')
                        self.web_pass.delete(0, tk.END)
                        self.web_pass.insert(0, password)
                    elif line.startswith("auth.token"):
                        token = line.split("=")[1].strip().strip('"')
                        self.token.delete(0, tk.END)
                        self.token.insert(0, token)
                    elif line.startswith("vhostHTTPPort"):
                        port = line.split("=")[1].strip()
                        self.http_port.delete(0, tk.END)
                        self.http_port.insert(0, port)
                    elif line.startswith("vhostHTTPSPort"):
                        port = line.split("=")[1].strip()
                        self.https_port.delete(0, tk.END)
                        self.https_port.insert(0, port)
                    elif line.startswith("kcpBindPort"):
                        port = line.split("=")[1].strip()
                        self.kcp_port.delete(0, tk.END)
                        self.kcp_port.insert(0, port)
                    
    
    def save_config(self):
        # 获取当前可执行文件所在目录
        if getattr(sys, 'frozen', False):
            # 打包后的可执行文件路径
            base_path = os.path.dirname(sys.executable)
        else:
            # 开发环境路径
            base_path = os.path.dirname(os.path.abspath(__file__))
            
        config_path = os.path.join(base_path, "frps.toml")
        with open(config_path, "w") as f:
            f.write(f"bindPort = {self.bind_port.get()}\n")
            f.write(f"webServer.port = {self.web_port.get()}\n")
            f.write(f"webServer.user = \"{self.web_user.get()}\"\n")
            f.write(f"webServer.password = \"{self.web_pass.get()}\"\n")
            f.write(f"auth.token = \"{self.token.get()}\"\n")
            f.write(f"vhostHTTPPort = {self.http_port.get()}\n")
            f.write(f"vhostHTTPSPort = {self.https_port.get()}\n")
            f.write(f"kcpBindPort = {self.kcp_port.get()}\n")


    
    def is_port_in_use(self, port):
        import socket
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            return s.connect_ex(('localhost', int(port))) == 0
            
    def _run_frps(self):
        try:
            # 获取当前可执行文件所在目录
            if getattr(sys, 'frozen', False):
                # 打包后的可执行文件路径
                base_path = os.path.dirname(sys.executable)
            else:
                # 开发环境路径
                base_path = os.path.dirname(os.path.abspath(__file__))
                
            frps_path = os.path.join(base_path, "frps.exe")
            
            # 如果不存在frps.exe，则报错
            if not os.path.exists(frps_path):
                self.root.after(0, lambda: messagebox.showerror("错误", f"未找到frps.exe文件！路径: {frps_path}"))
                return
                
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            startupinfo.wShowWindow = subprocess.SW_HIDE
            
            # 获取frps版本
            version_output = subprocess.check_output([frps_path, "--version"], creationflags=subprocess.CREATE_NO_WINDOW, startupinfo=startupinfo)
            self.frps_version = version_output.decode().strip()
            
            # 更新UI中的版本显示
            self.root.after(0, lambda: self.config_frame.config(text=f"FRPS 配置 (版本: {self.frps_version})"))
            
            self.frps_process = subprocess.Popen(
                [frps_path, "-c", "frps.toml"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                creationflags=subprocess.CREATE_NO_WINDOW | subprocess.DETACHED_PROCESS,
                close_fds=True,
                universal_newlines=True,
                startupinfo=startupinfo
            )
            # 启动日志轮询线程
            self.log_thread = threading.Thread(target=self._poll_logs, daemon=True)
            self.log_thread.start()
        except Exception as e:
            self.root.after(0, lambda: messagebox.showerror("错误", f"启动FRPS服务失败: {str(e)}"))
            if self.frps_process:
                try:
                    self.frps_process.terminate()
                    self.frps_process.wait(timeout=1)
                except:
                    pass
                finally:
                    self.frps_process = None
    
    def toggle_inputs(self, state):
        """切换所有输入框的可用状态"""
        self.bind_port.config(state=state)
        self.token.config(state=state)
        self.web_port.config(state=state)
        self.web_user.config(state=state)
        self.web_pass.config(state=state)
        self.http_port.config(state=state)
        self.https_port.config(state=state)
        self.kcp_port.config(state=state)
    
    def start_frps(self):
        self.save_config()
        self.log("正在检查端口占用情况...")
        
        # 并行检查端口占用
        ports_to_check = [
            ("绑定端口", self.bind_port.get()),
            ("Web管理端口", self.web_port.get()),
            ("HTTP端口", self.http_port.get()),
            ("HTTPS端口", self.https_port.get()),
            ("KCP端口", self.kcp_port.get())
        ]
        
        import concurrent.futures
        with concurrent.futures.ThreadPoolExecutor() as executor:
            futures = {executor.submit(self.is_port_in_use, port): (port_name, port) 
                      for port_name, port in ports_to_check}
            
            for future in concurrent.futures.as_completed(futures):
                port_name, port = futures[future]
                if future.result():
                    messagebox.showerror("错误", f"{port_name} {port} 已被占用，请更换端口或关闭占用程序！")
                    return
        
        self.log("端口检查完成，正在启动服务...")
            
        # 获取当前可执行文件所在目录
        if getattr(sys, 'frozen', False):
            # 打包后的可执行文件路径
            base_path = os.path.dirname(sys.executable)
        else:
            # 开发环境路径
            base_path = os.path.dirname(os.path.abspath(__file__))
            
        frps_path = os.path.join(base_path, "frps.exe")
        if not os.path.exists(frps_path):
            messagebox.showerror("错误", f"未找到frps.exe文件！路径: {frps_path}")
            return
        
        # 启动新线程运行FRPS
        import threading
        threading.Thread(target=self._run_frps, daemon=True).start()
        
        self.start_btn.config(state="disabled")
        self.stop_btn.config(state="normal")
        self.restart_btn.config(state="normal")
        self.toggle_inputs("disabled")
        self.log("FRPS服务正在启动...")
        
        # 启动日志轮询线程
        self.log_thread = threading.Thread(target=self._poll_logs, daemon=True)
        self.log_thread.start()
    
    def stop_frps(self):
        if self.frps_process:
            try:
                # 确保进程终止
                try:
                    self.frps_process.terminate()
                    self.frps_process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    self.frps_process.kill()
                    self.log("FRPS服务强制终止")
                except Exception as e:
                    self.log(f"终止进程时出错: {str(e)}")
                finally:
                    if hasattr(self, 'log_thread') and self.log_thread.is_alive():
                        self.log_thread.join(timeout=1)
                    self.frps_process = None
                    self.start_btn.config(state="normal")
                    self.stop_btn.config(state="disabled")
                    self.restart_btn.config(state="disabled")
                    self.toggle_inputs("normal")
                    self.log("FRPS服务已停止")
            except Exception as e:
                self.log(f"停止FRPS服务失败: {str(e)}")
                self.root.after(0, lambda: messagebox.showerror("错误", f"停止FRPS服务失败: {str(e)}"))
            
    def restart_frps(self):
        self.stop_frps()
        self.start_frps()
        if self.frps_process:
            self.restart_btn.config(state="normal")
            self.log("FRPS服务已重启")
    
    def toggle_show(self, entry, var):
        if var.get() == 1:
            entry.config(show="")
        else:
            entry.config(show="*")
            
    def toggle_auto_start(self):
        import winreg
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, 
                            "Software\\Microsoft\\Windows\\CurrentVersion\\Run", 
                            0, winreg.KEY_SET_VALUE)
        app_path = os.path.abspath(__file__)
        
        if self.auto_start.get() == 1:
            try:
                # 添加延迟启动参数
                delay_seconds = self.delay_entry.get()
                try:
                    delay_seconds = int(delay_seconds)
                    if delay_seconds < 0:
                        raise ValueError
                except ValueError:
                    messagebox.showerror("错误", "延迟时间必须为正整数")
                    self.auto_start.set(0)
                    return
                
                winreg.SetValueEx(key, "FRPSManager", 0, winreg.REG_SZ, 
                                 f'"{app_path}" --delay {delay_seconds}')
                self.log(f"已设置开机自启，延迟{delay_seconds}秒后启动")
            except Exception as e:
                messagebox.showerror("错误", f"设置开机自启失败: {str(e)}")
        else:
            try:
                winreg.DeleteValue(key, "FRPSManager")
                self.log("已取消开机自启")
            except WindowsError:
                pass
            except Exception as e:
                messagebox.showerror("错误", f"取消开机自启失败: {str(e)}")
                
    def toggle_scheduled_start(self):
        if self.scheduled_start.get() == 1:
            try:
                import subprocess
                import datetime
                
                # 获取设置的时间
                time_str = self.time_entry.get()
                try:
                    hour, minute = map(int, time_str.split(':'))
                    if not (0 <= hour <= 23 and 0 <= minute <= 59):
                        raise ValueError
                except:
                    messagebox.showerror("错误", "时间格式不正确，请使用HH:MM格式")
                    self.scheduled_start.set(0)
                    return
                
                # 创建任务计划
                app_path = os.path.abspath(__file__)
                task_name = "FRPSManager_ScheduledStart"
                
                # 删除现有任务（如果存在）
                subprocess.run(['schtasks', '/delete', '/tn', task_name, '/f'], shell=True)
                
                # 创建新任务
                cmd = f'schtasks /create /tn "{task_name}" /tr "\"{app_path}\"" /sc daily /st {time_str} /rl highest'
                subprocess.run(cmd, shell=True)
                
                self.log(f"已设置定时启动，每天 {time_str} 自动启动服务")
            except Exception as e:
                messagebox.showerror("错误", f"设置定时启动失败: {str(e)}")
                self.scheduled_start.set(0)
        else:
            try:
                # 删除任务计划
                task_name = "FRPSManager_ScheduledStart"
                subprocess.run(['schtasks', '/delete', '/tn', task_name, '/f'], shell=True)
                self.log("已取消定时启动")
            except Exception as e:
                messagebox.showerror("错误", f"取消定时启动失败: {str(e)}")
        
    def log(self, message):
        # 移除ANSI颜色代码
        import re
        from datetime import datetime
        message = re.sub(r'\x1b\[[0-9;]*[mK]', '', message)
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        self.log_text.insert(tk.END, f"[{timestamp}] {message}\n")
        self.log_text.see(tk.END)
        self.save_log_to_file(f"[{timestamp}] {message}")
        
    def save_log_to_file(self, message):
        # 获取当前可执行文件所在目录
        if getattr(sys, 'frozen', False):
            # 打包后的可执行文件路径
            base_path = os.path.dirname(sys.executable)
        else:
            # 开发环境路径
            base_path = os.path.dirname(os.path.abspath(__file__))
            
        log_dir = os.path.join(base_path, "logs")
        if not os.path.exists(log_dir):
            os.makedirs(log_dir)
            
        log_file = os.path.join(log_dir, "frps.log")
        with open(log_file, "a", encoding="utf-8") as f:
            f.write(f"{message}\n")
            
        # 每次保存日志时检查是否需要清理旧日志
        self.clean_old_logs()
        
    def _poll_logs(self):
        """后台线程轮询日志文件并更新UI"""
        log_file = os.path.join(os.path.dirname(__file__), "logs", "frps.log")
        last_size = 0
        
        while self.frps_process and self.frps_process.poll() is None:
            try:
                if os.path.exists(log_file):
                    current_size = os.path.getsize(log_file)
                    if current_size > last_size:
                        with open(log_file, "r", encoding="utf-8") as f:
                            f.seek(last_size)
                            new_content = f.read()
                            if new_content:
                                self.root.after(0, self.log_text.insert, tk.END, new_content)
                                self.root.after(0, self.log_text.see, tk.END)
                            last_size = current_size
            except Exception as e:
                pass
            time.sleep(0.1)
    
    def clean_old_logs(self):
        log_dir = os.path.join(os.path.dirname(__file__), "logs")
        if not os.path.exists(log_dir):
            return
            
        now = time.time()
        for filename in os.listdir(log_dir):
            filepath = os.path.join(log_dir, filename)
            if os.path.isfile(filepath):
                file_time = os.path.getmtime(filepath)
                if (now - file_time) > 7 * 24 * 60 * 60:  # 7天前的文件
                    try:
                        os.remove(filepath)
                        self.log(f"已删除过期日志文件: {filename}")
                    except Exception as e:
                        self.log(f"删除日志文件失败: {str(e)}")

    def minimize_to_tray(self):
        """最小化到系统托盘"""
        if not messagebox.askyesno("确认", "确定要最小化到托盘吗？"):
            return
            
        self.root.withdraw()
        
        # 创建托盘图标
        try:
            image = Image.open(os.path.join(os.path.dirname(__file__), "icon.ico"))
            menu = (
                pystray.MenuItem('显示窗口', self.restore_from_tray),
                pystray.MenuItem('退出', self.quit_application)
            )
            self.tray_icon = pystray.Icon("FRPS Manager", image, "FRPS 服务管理器", menu)
            
            # 在单独线程中运行托盘图标
            import threading
            self.tray_thread = threading.Thread(target=self.tray_icon.run, daemon=True)
            self.tray_thread.start()
            
            # 记录日志
            self.log("程序已最小化到系统托盘，FRPS服务继续在后台运行")
        except Exception as e:
            self.log(f"创建托盘图标失败: {str(e)}")
            self.root.deiconify()
            
    def on_close(self):
        """处理窗口关闭事件"""
        if self.frps_process and self.frps_process.poll() is None:
            if messagebox.askyesno("确认", "FRPS服务正在运行，确定要最小化到托盘吗？"):
                self.minimize_to_tray()
            else:
                self.stop_frps()
                self.root.destroy()
        else:
            self.root.destroy()
            
    def restore_from_tray(self):
        """从托盘恢复窗口"""
        if self.tray_icon:
            self.tray_icon.stop()
            self.tray_icon = None
        self.root.deiconify()
        self.log("程序已从系统托盘恢复")
        
    def quit_application(self):
        """退出应用程序"""
        if self.frps_process and self.frps_process.poll() is None:
            self.stop_frps()
        if self.tray_icon:
            self.tray_icon.stop()
        self.root.destroy()
    
    def restore_from_tray(self):
        """从托盘恢复窗口"""
        if self.tray_icon:
            self.tray_icon.stop()
            self.tray_icon = None
        self.root.deiconify()
    
    def quit_application(self):
        """退出应用程序"""
        # 添加确认弹窗
        if not messagebox.askyesno("确认", "确定要退出FRPS服务管理器吗？"):
            return
            
        if self.frps_process:
            self.stop_frps()
        if self.tray_icon:
            self.tray_icon.stop()
            if hasattr(self, 'tray_thread') and self.tray_thread.is_alive() and self.tray_thread != threading.current_thread():
                self.tray_thread.join(timeout=1)
        self.root.quit()
        os._exit(0)
        
    def on_close(self):
        """处理窗口关闭事件"""
        self.quit_application()

if __name__ == "__main__":
    root = tk.Tk()
    app = FRPSManager(root)
    root.mainloop()
