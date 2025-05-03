import tkinter as tk
from tkinter import messagebox, scrolledtext
import asyncio
import aiohttp
from tkinter import filedialog

from scan_modules.sql_injection import scan_sql_injection
from scan_modules.xss import scan_xss
from scan_modules.cmdi import scan_cmdi
from scan_modules.traversal import scan_traversal

class VulnerabilityScannerGUI:
    def __init__(self, root):
        self.root = root
        root.title("ModBod Vulnerability Scanner")

        self.url_label = tk.Label(root, text="Enter URL:")
        self.url_label.pack()

        self.url_entry = tk.Entry(root, width=50)
        self.url_entry.pack()

        self.sql_check = tk.Checkbutton(root, text="SQL Injection", var=tk.BooleanVar(value=True))
        self.sql_check.pack()

        self.xss_check = tk.Checkbutton(root, text="XSS", var=tk.BooleanVar(value=True))
        self.xss_check.pack()

        self.cmdi_check = tk.Checkbutton(root, text="Command Injection", var=tk.BooleanVar(value=True))
        self.cmdi_check.pack()

        self.traversal_check = tk.Checkbutton(root, text="Directory Traversal", var=tk.BooleanVar(value=True))
        self.traversal_check.pack()

        self.scan_button = tk.Button(root, text="Start Scan", command=self.start_scan)
        self.scan_button.pack(pady=5)

        self.result_box = scrolledtext.ScrolledText(root, height=15, width=80)
        self.result_box.pack()

        self.progress_bar = tk.Progressbar(root, length=200, mode="indeterminate")
        self.progress_bar.pack(pady=5)

        self.save_button = tk.Button(root, text="Save Results", command=self.save_results)
        self.save_button.pack()

        self.results = []

    def display_results(self, results):
        self.result_box.delete(1.0, tk.END)
        if results:
            for url, msg in results:
                self.result_box.insert(tk.END, f"[!] {msg} at {url}\n")
        else:
            self.result_box.insert(tk.END, "[+] No vulnerabilities found.\n")

    def start_scan(self):
        url = self.url_entry.get().strip()
        if not url:
            messagebox.showerror("Input Error", "Please enter a valid URL.")
            return

        # Check which scans to run
        selected_scans = []
        if self.sql_check.var.get():
            selected_scans.append(scan_sql_injection)
        if self.xss_check.var.get():
            selected_scans.append(scan_xss)
        if self.cmdi_check.var.get():
            selected_scans.append(scan_cmdi)
        if self.traversal_check.var.get():
            selected_scans.append(scan_traversal)

        if not selected_scans:
            messagebox.showerror("Input Error", "Please select at least one scan type.")
            return
        
        self.result_box.insert(tk.END, "[*] Scanning...\n")
        self.progress_bar.start()
        asyncio.run(self.run_scan(url, selected_scans))

    async def run_scan(self, url, selected_scans):
        self.results.clear()
        async with aiohttp.ClientSession() as session:
            for scan in selected_scans:
                scan_results = await scan(session, url)
                self.results.extend(scan_results)
        self.display_results(self.results)
        self.progress_bar.stop()

    def save_results(self):
        if not self.results:
            messagebox.showwarning("No Results", "There are no results to save.")
            return
        
        file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text Files", "*.txt")])
        if not file_path:
            return

        with open(file_path, "w") as f:
            for url, msg in self.results:
                f.write(f"[!] {msg} at {url}\n")
        messagebox.showinfo("Saved", f"Results saved to {file_path}")

if __name__ == "__main__":
    root = tk.Tk()
    app = VulnerabilityScannerGUI(root)
    root.mainloop()
