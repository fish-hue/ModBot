import tkinter as tk
from tkinter import messagebox, scrolledtext, filedialog
from tkinter import ttk  # for Progressbar
import asyncio
import aiohttp

from scan_modules.sql_injection import scan_sql_injection
from scan_modules.xss import scan_xss
from scan_modules.cmdi import scan_cmdi
from scan_modules.traversal import scan_traversal
from scan_modules.idor import scan_idor

class VulnerabilityScannerGUI:
    def __init__(self, root):
        self.root = root
        root.title("ModBod Vulnerability Scanner")

        tk.Label(root, text="Enter URL:").pack()

        self.url_entry = tk.Entry(root, width=50)
        self.url_entry.pack()

        # Define and store checkbox variables
        self.sql_var = tk.BooleanVar(value=True)
        self.xss_var = tk.BooleanVar(value=True)
        self.cmdi_var = tk.BooleanVar(value=True)
        self.traversal_var = tk.BooleanVar(value=True)
        self.idor_var = tk.BooleanVar(value=False)

        tk.Checkbutton(root, text="SQL Injection", variable=self.sql_var).pack()
        tk.Checkbutton(root, text="XSS", variable=self.xss_var).pack()
        tk.Checkbutton(root, text="Command Injection", variable=self.cmdi_var).pack()
        tk.Checkbutton(root, text="Directory Traversal", variable=self.traversal_var).pack()
        tk.Checkbutton(root, text="Broken Access Control (IDOR)", variable=self.idor_var).pack()

        self.scan_button = tk.Button(root, text="Start Scan", command=self.start_scan)
        self.scan_button.pack(pady=5)

        self.result_box = scrolledtext.ScrolledText(root, height=15, width=80)
        self.result_box.pack()

        self.progress_bar = ttk.Progressbar(root, length=200, mode="indeterminate")
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

        selected_scans = []
        if self.sql_var.get(): selected_scans.append(scan_sql_injection)
        if self.xss_var.get(): selected_scans.append(scan_xss)
        if self.cmdi_var.get(): selected_scans.append(scan_cmdi)
        if self.traversal_var.get(): selected_scans.append(scan_traversal)
        if self.idor_var.get(): selected_scans.append(scan_idor)

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
                try:
                    scan_results = await scan(session, url)
                    self.results.extend(scan_results)
                except Exception as e:
                    self.results.append((url, f"Error during {scan.__name__}: {str(e)}"))
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
