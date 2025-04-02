import tkinter as tk
from tkinter import ttk, messagebox
import subprocess
import os

class FRPSManager:
    def __init__(self, root):
        self.root = root
        self.root.title("FRPS 服务管理器 v0.61")
        self.root.geometry("600x400")
        
        self.frps_process = None
        
        # 创建Notebook标签页
        self.notebook = ttk.Notebook(root)
        self.notebook.pack(pady=10, padx=10, fill="both", expand=True)
        
        # 配置标签页
        self.config_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.config_tab, text="配置")
        
        # 创建配置框架
        self.config_frame = ttk.LabelFrame(self.config_tab, text="FRPS 配置")
        self.config_frame.pack(pady=10, padx=10, fill="x")
        
        # 绑定端口和Token设置
        ttk.Label(self.config_frame, text="绑定端口:").grid(row=0, column=0, padx=5, pady=5)
        self.bind_port = ttk.Entry(self.config_frame)
        self.bind_port.grid(row=0, column=1, padx=5, pady=5)
        self.bind_port.insert(0, "7000")
        
        ttk.Label(self.config_frame, text="Token:").grid(row=0, column=2, padx=5, pady=5)
        self.token = ttk.Entry(self.config_frame, show="*")
        self.token.grid(row=0, column=3, padx=5, pady=5)
        self.token.insert(0, "12345678")
        self.token_show = tk.IntVar()
        ttk.Checkbutton(self.config_frame, text="显示", variable=self.token_show, command=lambda: self.toggle_show(self.token, self.token_show)).grid(row=0, column=4, padx=5, pady=5)
        
        # Web管理设置
        ttk.Label(self.config_frame, text="Web管理端口:").grid(row=2, column=0, padx=5, pady=5)
        self.web_port = ttk.Entry(self.config_frame)
        self.web_port.grid(row=2, column=1, padx=5, pady=5)
        self.web_port.insert(0, "7500")
        
        ttk.Label(self.config_frame, text="用户名:").grid(row=3, column=0, padx=5, pady=5)
        self.web_user = ttk.Entry(self.config_frame)
        self.web_user.grid(row=3, column=1, padx=5, pady=5)
        self.web_user.insert(0, "admin")
        
        ttk.Label(self.config_frame, text="密码:").grid(row=4, column=0, padx=5, pady=5)
        self.web_pass = ttk.Entry(self.config_frame, show="*")
        self.web_pass.grid(row=4, column=1, padx=5, pady=5)
        self.web_pass.insert(0, "admin")
        self.pass_show = tk.IntVar()
        ttk.Checkbutton(self.config_frame, text="显示", variable=self.pass_show, command=lambda: self.toggle_show(self.web_pass, self.pass_show)).grid(row=4, column=2, padx=5, pady=5)
        
        # 新增协议端口设置
        ttk.Label(self.config_frame, text="HTTP端口:").grid(row=5, column=0, padx=5, pady=5)
        self.http_port = ttk.Entry(self.config_frame)
        self.http_port.grid(row=5, column=1, padx=5, pady=5)
        self.http_port.insert(0, "80")
        
        ttk.Label(self.config_frame, text="HTTPS端口:").grid(row=6, column=0, padx=5, pady=5)
        self.https_port = ttk.Entry(self.config_frame)
        self.https_port.grid(row=6, column=1, padx=5, pady=5)
        self.https_port.insert(0, "443")
        
        ttk.Label(self.config_frame, text="KCP端口:").grid(row=5, column=2, padx=5, pady=5)
        self.kcp_port = ttk.Entry(self.config_frame)
        self.kcp_port.grid(row=5, column=3, padx=5, pady=5)
        self.kcp_port.insert(0, "7001")
        
        ttk.Label(self.config_frame, text="HTTP代理端口:").grid(row=6, column=2, padx=5, pady=5)
        self.http_proxy_port = ttk.Entry(self.config_frame)
        self.http_proxy_port.grid(row=6, column=3, padx=5, pady=5)
        self.http_proxy_port.insert(0, "8080")
        
        ttk.Label(self.config_frame, text="最大连接池:").grid(row=7, column=0, padx=5, pady=5)
        self.max_pool_count = ttk.Entry(self.config_frame)
        self.max_pool_count.grid(row=7, column=1, padx=5, pady=5)
        self.max_pool_count.insert(0, "100")
        
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
                    elif line.startswith("httpProxyPort"):
                        port = line.split("=")[1].strip()
                        self.http_proxy_port.delete(0, tk.END)
                        self.http_proxy_port.insert(0, port)
                    elif line.startswith("maxPoolCount"):
                        count = line.split("=")[1].strip()
                        self.max_pool_count.delete(0, tk.END)
                        self.max_pool_count.insert(0, count)
    
    def save_config(self):
        config_path = os.path.join(os.path.dirname(__file__), "frps.toml")
        with open(config_path, "w") as f:
            f.write(f"bindPort = {self.bind_port.get()}\n")
            f.write(f"webServer.port = {self.web_port.get()}\n")
            f.write(f"webServer.user = \"{self.web_user.get()}\"\n")
            f.write(f"webServer.password = \"{self.web_pass.get()}\"\n")
            f.write(f"auth.token = \"{self.token.get()}\"\n")
            f.write(f"vhostHTTPPort = {self.http_port.get()}\n")
            f.write(f"vhostHTTPSPort = {self.https_port.get()}\n")
            f.write(f"kcpBindPort = {self.kcp_port.get()}\n")
            f.write(f"httpProxyPort = {self.http_proxy_port.get()}\n")
            f.write(f"maxPoolCount = {self.max_pool_count.get()}\n")

    
    def start_frps(self):
        self.save_config()
        
        frps_path = os.path.join(os.path.dirname(__file__), "frps.exe")
        if not os.path.exists(frps_path):
            messagebox.showerror("错误", "未找到frps.exe文件！")
            return
        
        try:
            self.frps_process = subprocess.Popen(
                [frps_path, "-c", "frps.toml"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            self.start_btn.config(state="disabled")
            self.stop_btn.config(state="normal")
            self.restart_btn.config(state="normal")
            self.log("FRPS服务已启动")
        except Exception as e:
            messagebox.showerror("错误", f"启动FRPS服务失败: {str(e)}")
    
    def stop_frps(self):
        if self.frps_process:
            self.frps_process.terminate()
            self.frps_process = None
            self.start_btn.config(state="normal")
            self.stop_btn.config(state="disabled")
            self.restart_btn.config(state="disabled")
            self.log("FRPS服务已停止")
            
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
                winreg.SetValueEx(key, "FRPSManager", 0, winreg.REG_SZ, app_path)
                self.log("已设置开机自启")
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
        
    def log(self, message):
        self.log_text.insert(tk.END, message + "\n")
        self.log_text.see(tk.END)

if __name__ == "__main__":
    root = tk.Tk()
    app = FRPSManager(root)
    root.mainloop()
