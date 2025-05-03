import tkinter as tk
from tkinter import messagebox, scrolledtext
import asyncio
import aiohttp

from scan_modules.sql_injection import scan_sql_injection
from scan_modules.xss import scan_xss
from scan_modules.cmdi import scan_cmdi
from scan_modules.traversal import scan_traversal

class VulnerabilityScannerGUI:
    def __init__(self, root):
        self.root = root
        root.title("ModBot Vulnerability Scanner")

        self.url_label = tk.Label(root, text="Enter URL:")
        self.url_label.pack()

        self.url_entry = tk.Entry(root, width=50)
        self.url_entry.pack()

        self.scan_button = tk.Button(root, text="Start Scan", command=self.start_scan)
        self.scan_button.pack(pady=5)

        self.result_box = scrolledtext.ScrolledText(root, height=15, width=80)
        self.result_box.pack()

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
        self.result_box.insert(tk.END, "[*] Scanning...\n")
        asyncio.run(self.run_scan(url))

    async def run_scan(self, url):
        results = []
        async with aiohttp.ClientSession() as session:
            results += await scan_sql_injection(session, url)
            results += await scan_xss(session, url)
            results += await scan_cmdi(session, url)
            results += await scan_traversal(session, url)
        self.display_results(results)

if __name__ == "__main__":
    root = tk.Tk()
    app = VulnerabilityScannerGUI(root)
    root.mainloop()
