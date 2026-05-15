"""
DARE — Logger Utility
"""

import datetime
import os


class Logger:
    def __init__(self, verbose: bool = False, output_file: str = None):
        self.verbose = verbose
        self.output_file = output_file
        self._log_buffer = []

        if output_file:
            os.makedirs(os.path.dirname(output_file) if os.path.dirname(output_file) else ".", exist_ok=True)

    def _timestamp(self):
        return datetime.datetime.now().strftime("%H:%M:%S")

    def _write(self, msg: str):
        self._log_buffer.append(msg)
        if self.output_file:
            clean = self._strip_ansi(msg)
            with open(self.output_file, "a") as f:
                f.write(clean + "\n")

    def _strip_ansi(self, text: str) -> str:
        import re
        return re.sub(r'\033\[[0-9;]*m', '', text)

    def info(self, msg: str):
        line = f"\033[1;34m[*]\033[0m [{self._timestamp()}] {msg}"
        print(line)
        self._write(line)

    def success(self, msg: str):
        line = f"\033[1;32m[+]\033[0m [{self._timestamp()}] {msg}"
        print(line)
        self._write(line)

    def warn(self, msg: str):
        line = f"\033[1;33m[!]\033[0m [{self._timestamp()}] {msg}"
        print(line)
        self._write(line)

    def error(self, msg: str):
        line = f"\033[1;31m[-]\033[0m [{self._timestamp()}] {msg}"
        print(line)
        self._write(line)

    def debug(self, msg: str):
        if self.verbose:
            line = f"\033[0;37m[~]\033[0m [{self._timestamp()}] {msg}"
            print(line)
            self._write(line)

    def result(self, label: str, value: str):
        line = f"  \033[1;36m{label:<25}\033[0m {value}"
        print(line)
        self._write(line)

    def section(self, title: str):
        line = f"\n\033[1;35m{'─'*10} {title} {'─'*10}\033[0m"
        print(line)
        self._write(line)

    def raw(self, msg: str):
        print(msg)
        self._write(msg)
