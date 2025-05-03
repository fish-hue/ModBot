```markdown
# ModBot

A simple asynchronous vulnerability scanner with a Tkinter GUI that supports multiple vulnerability checks, including SQL Injection, XSS, Command Injection, and Directory Traversal. The tool scans a given URL for common security vulnerabilities and allows users to view the results in the GUI and save them to a text file.

## Features

*   **Asynchronous Scanning:** Perform multiple vulnerability checks concurrently for faster scans.
*   **Scan Types:**
    *   SQL Injection
    *   XSS (Cross-Site Scripting)
    *   Command Injection
    *   Directory Traversal
*   **Interactive GUI:** Built with Tkinter for ease of use.
*   **Progress Bar:** Displays the scanning progress.
*   **Save Results:** Option to save scan results to a text file.

## Requirements

*   Python 3.7+
*   `aiohttp` (for asynchronous HTTP requests)
*   `Tkinter` (for the GUI interface - usually comes with Python)

## Installation

1.  **Clone the repository:**

    ```bash
    git clone https://github.com/fish-hue/ModBot.git
    cd ModBot
    ```

2.  **Install the required packages:**
    It’s recommended to create a virtual environment for the project.

    Using `venv`:

    ```bash
    python -m venv venv
    source venv/bin/activate  # On Windows, use venv\Scripts\activate
    ```

    Install dependencies:

    ```bash
    pip install -r requirements.txt
    ```

    If `aiohttp` is not installed automatically, you can manually install it:

    ```bash
    pip install aiohttp
    ```

## Usage

### GUI Usage:

1.  **Launch the application:**

    ```bash
    python gui.py
    ```

2.  **Steps to use the scanner:**

    *   Enter the URL you want to scan in the input field.
    *   Select scan types you want to perform (SQL Injection, XSS, Command Injection, Directory Traversal).
    *   Click "Start Scan" to begin scanning. The progress bar will show while scanning.
    *   View the results in the scrolled text box.
    *   Click "Save Results" to save the scan results to a file.

