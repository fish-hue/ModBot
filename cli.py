# Project file: cli.py
import argparse
from core.scanner_runner import run_scans

parser = argparse.ArgumentParser(description="ABot Vulnerability Scanner")
parser.add_argument('--url', required=True, help='Target URL')
parser.add_argument('--xss', action='store_true', help='Enable XSS scan')
parser.add_argument('--sql', action='store_true', help='Enable SQLi scan')
parser.add_argument('--cmd', action='store_true', help='Enable Command Injection scan')
parser.add_argument('--redir', action='store_true', help='Enable Open Redirect scan')
parser.add_argument('--traversal', action='store_true', help='Enable Directory Traversal scan')
parser.add_argument('--crawl', action='store_true', help='Enable file crawling')
parser.add_argument('--headers', nargs='*', help='Custom headers in format Key:Value')
parser.add_argument('--cookies', help='Cookies as a string')
parser.add_argument('--proxy', help='HTTP proxy')
parser.add_argument('--timeout', type=int, default=10, help='Request timeout in seconds')
parser.add_argument('--retries', type=int, default=2, help='Retry count for failed requests')
parser.add_argument('--output', choices=['json', 'html', 'text'], default='text', help='Output format')

args = parser.parse_args()

options = {
    'url': args.url,
    'scan_types': {
        'xss': args.xss,
        'sql': args.sql,
        'cmd': args.cmd,
        'redir': args.redir,
        'traversal': args.traversal,
        'crawl': args.crawl,
    },
    'headers': dict(h.split(':', 1) for h in args.headers) if args.headers else {},
    'cookies': args.cookies,
    'proxy': args.proxy,
    'timeout': args.timeout,
    'retries': args.retries,
    'output': args.output,
}

run_scans(options)
