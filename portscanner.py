#!/usr/bin/env python3
"""
Enhanced Python Port Scanner & Networking Toolkit (Tkinter)
- Cross‑platform ping & traceroute helpers
- Threaded TCP port scanner with graceful stop
- IP/range parsing including wildcard a.b.c.* convenience
- Ping sweep host discovery
- Basic banner grabbing (safe, read‑only)
- Live log pane + desktop notifications (if plyer installed)
- Results table with export to CSV
- Network graph visualisation (networkx + matplotlib) showing discovered hosts
- Telemetry log to telemetry.log

Tested on Python 3.9+; optional libraries: matplotlib, networkx
"""

import os
import sys
import csv
import socket
import ipaddress
import threading
import queue
import subprocess
from datetime import datetime

import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox

# Optional deps for notifications and graph
try:
    from plyer import notification  # type: ignore
    def send_notification(title, message):
        try:
            notification.notify(title=title, message=message, timeout=5)
        except Exception:
            pass
except Exception:
    def send_notification(title, message):
        pass

# Optional: network graph
GRAPH_AVAILABLE = True
try:
    import matplotlib
    matplotlib.use("TkAgg")
    import matplotlib.pyplot as plt
    from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
    import networkx as nx
except Exception:
    GRAPH_AVAILABLE = False

# Hide console window (Windows only)
if os.name == 'nt':
    try:
        import ctypes
        ctypes.windll.user32.ShowWindow(ctypes.windll.kernel32.GetConsoleWindow(), 0)
    except Exception:
        pass

# -------------------------- Telemetry ---------------------------

def log_telemetry(event: str) -> None:
    try:
        with open("telemetry.log", "a", encoding="utf-8") as f:
            f.write(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {event}\n")
    except Exception:
        # Never crash the app for telemetry failures
        pass

log_telemetry("Application started")

# --------------------------- Helpers ----------------------------

def is_windows() -> bool:
    return os.name == 'nt'

def safe_int(s: str, default: int) -> int:
    try:
        return int(s)
    except Exception:
        return default

# ----------------------- Network primitives ---------------------

def check_port(ip_address: str, port_number: int, timeout: float = 1.0, grab_banner: bool = False):
    """Return tuple (ip, port, open:bool, banner:str|None, err:str|None)."""
    banner = None
    err = None
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            result = s.connect_ex((ip_address, port_number))
            if result == 0:
                if grab_banner:
                    try:
                        s.settimeout(0.8)
                        # Try to read a short banner without sending data
                        data = s.recv(128)
                        if data:
                            banner = data.decode(errors='replace').strip()
                    except Exception:
                        pass
                return (ip_address, port_number, True, banner, None)
            else:
                return (ip_address, port_number, False, None, None)
    except Exception as e:
        err = str(e)
        return (ip_address, port_number, False, None, err)


def run_ping_once(target: str, count: int = 1, timeout: int = 1000) -> bool:
    """Simple reachability check used for host discovery. Returns True if reachable."""
    try:
        if is_windows():
            cmd = ["ping", "-n", str(count), "-w", str(timeout), target]
        else:
            # On Unix, timeout is in seconds and -W is per-packet timeout
            sec = max(1, int(timeout/1000))
            cmd = ["ping", "-c", str(count), "-W", str(sec), target]
        result = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return result.returncode == 0
    except Exception:
        return False


def run_ping_verbose(target: str) -> str:
    try:
        if is_windows():
            output = subprocess.check_output(["ping", "-n", "4", target], universal_newlines=True)
        else:
            output = subprocess.check_output(["ping", "-c", "4", target], universal_newlines=True)
        return output
    except subprocess.CalledProcessError as e:
        return f"Ping failed: {e}"
    except Exception as e:
        return f"Ping error: {e}"


def run_traceroute(target: str) -> str:
    try:
        if is_windows():
            output = subprocess.check_output(["tracert", target], universal_newlines=True)
        else:
            # Prefer 'traceroute', fallback to 'tracepath'
            try:
                output = subprocess.check_output(["traceroute", target], universal_newlines=True)
            except Exception:
                output = subprocess.check_output(["tracepath", target], universal_newlines=True)
        return output
    except subprocess.CalledProcessError as e:
        return f"Traceroute failed: {e}"
    except Exception as e:
        return f"Traceroute error: {e}"

# -------------------- Input parsing utilities -------------------

def get_ip_list(ip_input: str):
    """Accepts CIDR (e.g. 192.168.1.0/24), wildcard a.b.c.*, or single IP/hostname."""
    ip_input = ip_input.strip()
    if not ip_input:
        return []
    # Hostname resolution if not an IP/cidr/wildcard
    if any(ch.isalpha() for ch in ip_input) and "*" not in ip_input and "/" not in ip_input:
        try:
            ip = socket.gethostbyname(ip_input)
            return [ip]
        except Exception:
            return [ip_input]

    if "*" in ip_input:
        base = ip_input.replace("*", "0")
        try:
            network = ipaddress.IPv4Network(base + "/24", strict=False)
            return [str(ip) for ip in network.hosts()]
        except Exception:
            return []
    try:
        network = ipaddress.ip_network(ip_input, strict=False)
        # Exclude network/broadcast for IPv4
        if isinstance(network, ipaddress.IPv4Network):
            return [str(ip) for ip in network.hosts()]
        return [str(ip) for ip in network]
    except Exception:
        # Fallback: single IP string
        return [ip_input]


def get_port_list(port_input: str):
    ports = set()
    for part in port_input.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            try:
                start, end = map(int, part.split("-"))
                if start > end:
                    start, end = end, start
                ports.update(range(max(1, start), min(65535, end) + 1))
            except Exception:
                continue
        else:
            try:
                p = int(part)
                if 1 <= p <= 65535:
                    ports.add(p)
            except Exception:
                continue
    return sorted(ports)

# -------------------------- GUI App -----------------------------

class ScannerApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        root.title("Python Port Scanner & Networking Tools")
        root.geometry("1000x820")

        self.stop_event = threading.Event()
        self.executor = None
        self.scan_thread = None
        self.result_rows = []  # list of dicts for table/CSV

        self._build_ui()

    # -------------------- UI construction --------------------
    def _build_ui(self):
        outer = ttk.Frame(self.root, padding=10)
        outer.pack(fill=tk.BOTH, expand=True)

        # Inputs
        grid = ttk.Frame(outer)
        grid.pack(fill=tk.X)

        ttk.Label(grid, text="Target IP / Range / Hostname:").grid(column=0, row=0, sticky=tk.W)
        self.ip_entry = ttk.Entry(grid, width=45)
        self.ip_entry.grid(column=1, row=0, sticky=tk.W, padx=(6, 20))
        self.ip_entry.insert(0, "127.0.0.1")

        ttk.Label(grid, text="Ports (e.g. 22,80 or 1-1024):").grid(column=0, row=1, sticky=tk.W)
        self.ports_entry = ttk.Entry(grid, width=45)
        self.ports_entry.grid(column=1, row=1, sticky=tk.W, padx=(6, 20))
        self.ports_entry.insert(0, "1-100")

        ttk.Label(grid, text="Threads:").grid(column=0, row=2, sticky=tk.W)
        self.threads_entry = ttk.Entry(grid, width=10)
        self.threads_entry.grid(column=1, row=2, sticky=tk.W, padx=(6, 0))
        self.threads_entry.insert(0, "100")

        ttk.Button(grid, text="Use Common Ports", command=self.use_common_ports).grid(column=0, row=3, pady=4, sticky=tk.W)
        ttk.Button(grid, text="Start Scan", command=self.run_scan).grid(column=1, row=3, pady=4, sticky=tk.W)
        ttk.Button(grid, text="Stop Scan", command=self.stop_scan).grid(column=1, row=3, padx=(110,0), pady=4, sticky=tk.W)
        ttk.Button(grid, text="Export CSV", command=self.export_csv).grid(column=1, row=3, padx=(200,0), pady=4, sticky=tk.W)

        # Extra tools
        tools = ttk.LabelFrame(outer, text="Extra Networking Tools", padding=10)
        tools.pack(fill=tk.X, pady=(8,4))

        ttk.Label(tools, text="Target:").grid(column=0, row=0, sticky=tk.W)
        self.tool_target = ttk.Entry(tools, width=50)
        self.tool_target.grid(column=1, row=0, sticky=tk.W, padx=(6, 20))
        self.tool_target.insert(0, "8.8.8.8")

        ttk.Button(tools, text="Ping", command=self.run_ping_gui).grid(column=0, row=1, pady=4, sticky=tk.W)
        ttk.Button(tools, text="Traceroute", command=self.run_traceroute_gui).grid(column=1, row=1, pady=4, sticky=tk.W)

        # Results table
        table_frame = ttk.LabelFrame(outer, text="Results", padding=6)
        table_frame.pack(fill=tk.BOTH, expand=True)

        cols = ("ip", "port", "status", "banner")
        self.tree = ttk.Treeview(table_frame, columns=cols, show='headings', height=10)
        for c, w in zip(cols, (150, 90, 100, 520)):
            self.tree.heading(c, text=c.capitalize())
            self.tree.column(c, width=w, anchor=tk.W)
        self.tree.pack(fill=tk.BOTH, expand=True)

        # Log
        self.log_text = scrolledtext.ScrolledText(outer, width=120, height=12)
        self.log_text.pack(fill=tk.BOTH, expand=False, pady=(6,6))

        # Graph
        graph_frame = ttk.LabelFrame(outer, text="Network Graph", padding=6)
        graph_frame.pack(fill=tk.BOTH, expand=True)
        if GRAPH_AVAILABLE:
            self.figure = plt.Figure(figsize=(6,3), dpi=100)
            self.ax = self.figure.add_subplot(111)
            self.canvas = FigureCanvasTkAgg(self.figure, master=graph_frame)
            self.canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
            self.G = nx.Graph()
        else:
            ttk.Label(graph_frame, text="Graph packages not installed. Install 'matplotlib' and 'networkx' to enable.").pack(anchor=tk.W)

    # ------------------------- Actions -------------------------
    def append_log(self, text: str):
        self.log_text.insert(tk.END, text + "\n")
        self.log_text.see(tk.END)

    def use_common_ports(self):
        self.ports_entry.delete(0, tk.END)
        self.ports_entry.insert(0, "21,22,23,25,53,80,110,135,139,143,443,445,993,995,3306,3389,8080")

    def run_ping_gui(self):
        target = self.tool_target.get().strip()
        self.append_log(f"[?] Running ping on {target}...")
        result = run_ping_verbose(target)
        self.append_log(result)
        send_notification("Ping Complete", f"Ping to {target} completed.")
        log_telemetry(f"Ping run on {target}")

    def run_traceroute_gui(self):
        target = self.tool_target.get().strip()
        self.append_log(f"[?] Running traceroute on {target}...")
        result = run_traceroute(target)
        self.append_log(result)
        send_notification("Traceroute Complete", f"Traceroute to {target} completed.")
        log_telemetry(f"Traceroute run on {target}")

    def export_csv(self):
        if not self.result_rows:
            messagebox.showinfo("Export CSV", "No results to export yet.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV files", ".csv")])
        if not path:
            return
        try:
            with open(path, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=["ip", "port", "status", "banner"]) 
                writer.writeheader()
                for row in self.result_rows:
                    writer.writerow(row)
            self.append_log(f"[+] Exported CSV to {path}")
        except Exception as e:
            messagebox.showerror("Export CSV", f"Failed to export: {e}")

    def stop_scan(self):
        self.stop_event.set()
        self.append_log("[!] Stop requested… waiting for workers to finish.")

    def run_scan(self):
        if self.scan_thread and self.scan_thread.is_alive():
            messagebox.showwarning("Scan in progress", "Please stop the current scan before starting a new one.")
            return
        self.stop_event.clear()
        ip_input = self.ip_entry.get()
        ports_input = self.ports_entry.get()
        threads = safe_int(self.threads_entry.get(), 50)

        ip_list = get_ip_list(ip_input)
        port_list = get_port_list(ports_input)
        if not ip_list or not port_list:
            messagebox.showerror("Invalid input", "Please provide valid target(s) and port(s).")
            return

        # Clear previous
        self.tree.delete(*self.tree.get_children())
        self.result_rows.clear()
        if GRAPH_AVAILABLE:
            self.G.clear()
            self.ax.clear()
            self.canvas.draw()

        self.append_log(f"\n[!] Starting scan with {threads} threads…")
        self.append_log(f"[!] Scanning {len(ip_list)} hosts and {len(port_list)} ports\n")
        log_telemetry(f"Scan started on {len(ip_list)} IPs and {len(port_list)} ports")

        # Kick worker thread
        self.scan_thread = threading.Thread(target=self._scan_worker, args=(ip_list, port_list, threads), daemon=True)
        self.scan_thread.start()

    # --------------------- Core scan logic ---------------------
    def _scan_worker(self, ip_list, port_list, threads):
        # Host discovery first (ping sweep)
        live_hosts = []
        self.append_log("[?] Performing ping sweep for host discovery…")
        for ip in ip_list:
            if self.stop_event.is_set():
                break
            if run_ping_once(ip, count=1, timeout=500):
                live_hosts.append(ip)
                self.append_log(f"[+] Host up: {ip}")
        if not live_hosts:
            self.append_log("[-] No live hosts detected (continuing to scan targets anyway).")
            live_hosts = ip_list[:]  # still attempt

        # Prepare work queue
        tasks = queue.Queue()
        for ip in live_hosts:
            for port in port_list:
                tasks.put((ip, port))

        open_count = 0
        lock = threading.Lock()

        def worker():
            nonlocal open_count
            while not self.stop_event.is_set():
                try:
                    ip, port = tasks.get_nowait()
                except queue.Empty:
                    break
                ip_, port_, is_open, banner, err = check_port(ip, port, timeout=1.0, grab_banner=True)
                status = "OPEN" if is_open else "closed"
                if is_open:
                    open_count += 1
                if err:
                    self.append_log(f"[!] Error {ip}:{port} -> {err}")
                if is_open:
                    row = {"ip": ip_, "port": port_, "status": status, "banner": banner or ""}
                    with lock:
                        self.result_rows.append(row)
                        self.tree.insert("", tk.END, values=(ip_, port_, status, banner or ""))
                tasks.task_done()

        workers = []
        for _ in range(max(1, threads)):
            t = threading.Thread(target=worker, daemon=True)
            workers.append(t)
            t.start()
        for t in workers:
            t.join()

        # Summaries
        if open_count == 0:
            self.append_log("[-] No open ports found.")
        else:
            self.append_log(f"[?] Found {open_count} open ports.")
            # Beep on Windows only
            if is_windows():
                try:
                    import winsound
                    winsound.Beep(1000, 300)
                except Exception:
                    pass

        self.append_log("[?] Scan complete.\n")
        send_notification("Port Scan Complete", f"{open_count} open ports found.")
        log_telemetry("Scan completed")

        # Update graph after scan
        if GRAPH_AVAILABLE:
            try:
                self._update_graph(live_hosts)
            except Exception as e:
                self.append_log(f"[!] Graph update failed: {e}")

    # ---------------------- Graph rendering --------------------
    def _update_graph(self, live_hosts):
        """Render a simple network graph: a star from \"LocalNet\" to each live host.
        Node size encodes number of open services.
        """
        self.G.clear()
        center = "LocalNet"
        self.G.add_node(center)

        # Count open ports per host
        counts = {}
        for row in self.result_rows:
            counts[row["ip"]] = counts.get(row["ip"], 0) + 1

        for host in sorted(set(live_hosts)):
            self.G.add_node(host)
            self.G.add_edge(center, host)

        sizes = []
        for node in self.G.nodes:
            if node == center:
                sizes.append(800)
            else:
                sizes.append(200 + 60 * counts.get(node, 0))

        self.ax.clear()
        pos = nx.spring_layout(self.G, seed=7)
        nx.draw(self.G, pos=pos, ax=self.ax, with_labels=True, node_size=sizes, font_size=8)
        self.ax.set_title("Discovered Hosts (node size = # open ports)")
        self.ax.axis('off')
        self.canvas.draw()


# --------------------------- Main -------------------------------

def main():
    root = tk.Tk()
    # Tk 8.6+ themed
    try:
        root.call('tk', 'scaling', 1.1)
    except Exception:
        pass

    style = ttk.Style(root)
    try:
        if is_windows():
            style.theme_use('vista')
        else:
            style.theme_use('clam')
    except Exception:
        pass

    app = ScannerApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
