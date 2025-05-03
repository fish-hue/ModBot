import tkinter as tk
from tkinter import messagebox, scrolledtext, filedialog
from tkinter import ttk  # for Progressbar
import webbrowser
import asyncio
import aiohttp
import hashlib
import requests
import logging  # Import logging to handle errors
from bs4 import BeautifulSoup
from urllib.parse import urljoin

from scan_modules.sql_injection import scan_sql_injection
from scan_modules.xss import scan_xss
from scan_modules.cmdi import scan_cmdi
from scan_modules.traversal import scan_traversal
from scan_modules.idor import scan_idor
from integrity_check import check_file_integrity, check_software_integrity  # Import the functions


class VulnerabilityScannerGUI:
    def __init__(self, root):
        self.root = root
        root.title("ModBot Vulnerability Scanner")

        tk.Label(root, text="Enter URL:").pack()

        self.url_entry = tk.Entry(root, width=50)
        self.url_entry.pack()

        self.proxy_label = tk.Label(root, text="Proxy (optional):")
        self.proxy_label.pack()

        self.proxy_entry = tk.Entry(root, width=50)
        self.proxy_entry.pack()

        # Default free proxy (example from ProxyScrape or a similar service)
        self.default_proxy = "http://51.15.221.37:9999"  # Replace with any free proxy URL

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

        # Frame to hold Start and Stop buttons
        button_frame = tk.Frame(root)
        button_frame.pack(pady=5)

        self.scan_button = tk.Button(button_frame, text="Start Scan", command=self.start_scan)
        self.scan_button.pack(side=tk.LEFT, padx=5)

        self.stop_button = tk.Button(button_frame, text="Stop Scan", command=self.stop_scan, state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT, padx=5)

        self.result_box = scrolledtext.ScrolledText(root, height=15, width=80)
        self.result_box.pack()

        self.progress_bar = ttk.Progressbar(root, length=200, mode="indeterminate")
        self.progress_bar.pack(pady=5)

        self.save_button = tk.Button(root, text="Save Results", command=self.save_results)
        self.save_button.pack()

        # Add a button to display proxy resources information
        self.proxy_info_button = tk.Button(root, text="Proxy Resources", command=self.show_proxy_resources)
        self.proxy_info_button.pack(pady=5)

        # Add a button to check file integrity
        self.integrity_button = tk.Button(root, text="Check File Integrity", command=self.check_integrity)
        self.integrity_button.pack(pady=5)

        # Add a button to check software version integrity
        self.software_integrity_button = tk.Button(root, text="Check Software Integrity", command=self.check_software_integrity)
        self.software_integrity_button.pack(pady=5)

        self.results = []
        self._stop_scan_flag = asyncio.Event()  # Use asyncio.Event for asynchronous stopping

    def check_integrity(self):
        file_path = filedialog.askopenfilename(title="Select a file to check integrity")
        if not file_path:
            return

        # Example expected hash for demonstration (you would replace this with actual expected hashes)
        expected_hash = 'd2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2'

        result = check_file_integrity(file_path, expected_hash, hash_algorithm='sha256')
        if result:
            messagebox.showinfo("Integrity Check", "File integrity is valid!")
        else:
            messagebox.showerror("Integrity Check", "File integrity is compromised!")

    def check_software_integrity(self):
        # Example expected version for software (you would replace with actual software version)
        installed_version = '1.0.0'
        expected_version = '1.0.0'

        result = check_software_integrity(expected_version, installed_version)
        if result:
            messagebox.showinfo("Software Integrity", "Software version is correct.")
        else:
            messagebox.showerror("Software Integrity", "Software version mismatch!")

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

        proxy = self.proxy_entry.get().strip() or self.default_proxy
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

        # Enable Stop button, Disable Start button
        self.scan_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self._stop_scan_flag.clear()  # Clear the stop flag for a new scan

        # Use create_task instead of asyncio.run to avoid the issue with Tkinter's event loop
        loop = asyncio.get_event_loop()
        loop.create_task(self.run_scan(url, selected_scans, proxy))

    def stop_scan(self):
        self.result_box.insert(tk.END, "\n[*] Stopping scan...\n")
        self._stop_scan_flag.set()  # Set the stop flag to stop the scan
        self.progress_bar.stop()  # Ensure the progress bar stops immediately

    async def run_scan(self, url, selected_scans, proxy):
        self.results.clear()
        async with aiohttp.ClientSession() as session:
            for scan in selected_scans:
                # Check the stop flag before starting each scan module
                if self._stop_scan_flag.is_set():
                    self.result_box.insert(tk.END, "[*] Scan stopped by user.\n")
                    break  # Exit the loop if stop is requested

                scan_results = await scan(session, url, proxy, stop_event=self._stop_scan_flag)  # Pass the stop event
                self.results.extend(scan_results)

                # Check the stop flag again after a scan module completes
                if self._stop_scan_flag.is_set():
                    self.result_box.insert(tk.END, "[*] Scan stopped by user.\n")
                    break  # Exit the loop if stop is requested

        self.display_results(self.results)
        self.progress_bar.stop()

        # Disable Stop button, Enable Start button
        self.scan_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)

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

    def show_proxy_resources(self):
        proxy_info = """
1. Free Proxies (Public Proxies):
   - Us-Proxy.org (https://www.us-proxy.org/)
   - ProxyScrape (https://www.proxyscrape.com/)
   - Spys.one (https://spys.one/)

2. Premium Proxies:
   - Bright Data (formerly Luminati) (https://brightdata.com/)
   - Smartproxy (https://smartproxy.com/)
   - Oxylabs (https://oxylabs.io/)

3. Rotating Proxies:
   - ScraperAPI (https://www.scraperapi.com/)
   - GeoSurf (https://www.geosurf.com/)

4. VPN-based Proxies:
   - NordVPN (https://nordvpn.com/)
   - ExpressVPN (https://www.expressvpn.com/)
"""
        webbrowser.open("https://www.proxyscrape.com/")  # Open proxy website for the user
        messagebox.showinfo("Proxy Resources", proxy_info)

        # Create a new window to display the proxy information
        proxy_window = tk.Toplevel(self.root)
        proxy_window.title("Proxy Resources")

        # Add a scrollable text widget to display the proxy resources
        proxy_text = scrolledtext.ScrolledText(proxy_window, height=20, width=80)
        proxy_text.insert(tk.END, proxy_info)
        proxy_text.config(state=tk.DISABLED)  # Make the text widget read-only
        proxy_text.pack(padx=10, pady=10)

        # Add clickable links
        self.add_hyperlinks(proxy_text, proxy_info)

        # Add a close button
        close_button = tk.Button(proxy_window, text="Close", command=proxy_window.destroy)
        close_button.pack(pady=5)

    def add_hyperlinks(self, text_widget, text_content):
        """
        This function adds clickable links in the text widget.
        """
        for line in text_content.splitlines():
            if "http" in line:
                start = text_widget.index(tk.END)
                text_widget.insert(tk.END, line + '\n')
                text_widget.tag_add("hyperlink", start, text_widget.index(tk.END))
                text_widget.tag_config("hyperlink", foreground="blue", underline=True)
                text_widget.tag_bind("hyperlink", "<Button-1>", lambda e, url=line.split('(')[-1][:-1]: webbrowser.open(url))

# Your file integrity check function
async def crawl_for_files(url, file_extensions=None):
    if file_extensions is None:
        file_extensions = [
            ".pdf", ".mp3", ".jpeg", ".jpg", ".png", ".txt", ".zip", ".tar", ".gz", 
            ".rar", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".csv", 
            ".json", ".xml", ".apk", ".exe", ".tar.gz", ".7z", ".mp4", ".mkv", 
            ".avi", ".webm", ".flv", ".bmp", ".svg", ".css", ".js"
        ]

    files = []
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url) as response:
                soup = BeautifulSoup(await response.text(), "html.parser")

                # Find all anchor tags (<a>) with href attributes
                for link in soup.find_all("a", href=True):
                    href = link['href']
                    # Check if the link ends with any of the specified file extensions
                    if any(href.endswith(ext) for ext in file_extensions):
                        full_url = urljoin(url, href)
                        files.append(full_url)

    except Exception as e:
        print(f"Error crawling {url}: {e}")

    return files

if __name__ == "__main__":
    root = tk.Tk()
    app = VulnerabilityScannerGUI(root)
    root.mainloop()
