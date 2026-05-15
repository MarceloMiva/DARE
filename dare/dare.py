#!/usr/bin/env python3
"""
╔═══════════════════════════════════════════════════════════╗
║         DARE — Dynamic Attack & Recon Engine              ║
║         Multi-Module CTF & Penetration Testing CLI        ║
╚═══════════════════════════════════════════════════════════╝

Author:  Fashipe Oluwadamilare Ayoola
License: MIT
GitHub:  https://github.com/Damilare/dare

DISCLAIMER: This tool is intended for authorized security testing,
CTF competitions, and educational purposes ONLY. Always obtain
written permission before testing any system you do not own.
Unauthorized use is illegal and unethical.
"""

import sys
import os
import argparse
from utils.banner import print_banner, print_menu
from utils.logger import Logger

# Module imports
from modules.recon import ReconModule
from modules.scanner import ScannerModule
from modules.web import WebModule
from modules.hash_tools import HashModule
from modules.encoder import EncoderModule
from modules.exploit_helper import ExploitHelperModule


def main():
    print_banner()

    parser = argparse.ArgumentParser(
        description="DARE — Multi-module CTF/Pentest Framework",
        formatter_class=argparse.RawTextHelpFormatter
    )

    parser.add_argument(
        "--module", "-m",
        choices=["recon", "scan", "web", "hash", "encode", "exploit", "interactive"],
        default="interactive",
        help=(
            "Module to run:\n"
            "  recon      - OSINT & DNS recon\n"
            "  scan       - Port & service scanner\n"
            "  web        - Web app enumeration\n"
            "  hash       - Hash identification & cracking\n"
            "  encode     - Encoding/decoding utilities\n"
            "  exploit    - Exploit suggestion helper\n"
            "  interactive - Launch interactive menu (default)"
        )
    )
    parser.add_argument("--target", "-t", help="Target IP, domain, or URL")
    parser.add_argument("--output", "-o", help="Save output to file")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")

    args = parser.parse_args()

    log = Logger(verbose=args.verbose, output_file=args.output)

    if args.module == "interactive" or not args.target:
        interactive_menu(log)
    else:
        run_module(args.module, args.target, log)


def interactive_menu(log):
    """Launch the interactive menu loop."""
    modules = {
        "1": ("Recon & OSINT",        lambda t: ReconModule(t, log).run()),
        "2": ("Port & Service Scan",  lambda t: ScannerModule(t, log).run()),
        "3": ("Web Enumeration",      lambda t: WebModule(t, log).run()),
        "4": ("Hash Tools",           lambda t: HashModule(t, log).run()),
        "5": ("Encoder / Decoder",    lambda t: EncoderModule(t, log).run()),
        "6": ("Exploit Helper",       lambda t: ExploitHelperModule(t, log).run()),
    }

    while True:
        print_menu(modules)
        choice = input("\n\033[1;36m[dare]>\033[0m ").strip()

        if choice.lower() in ("q", "quit", "exit"):
            print("\n\033[1;33m[*] Exiting DARE. Stay ethical, Damilare!\033[0m\n")
            sys.exit(0)

        if choice not in modules:
            print("\033[1;31m[-] Invalid choice. Try again.\033[0m")
            continue

        target = input("\033[1;36m[+] Enter target (IP/domain/URL or leave blank): \033[0m").strip()
        if not target:
            target = None

        try:
            modules[choice][1](target)
        except KeyboardInterrupt:
            print("\n\033[1;33m[!] Module interrupted.\033[0m")


def run_module(module_name, target, log):
    """Run a module directly via CLI args."""
    dispatch = {
        "recon":   ReconModule,
        "scan":    ScannerModule,
        "web":     WebModule,
        "hash":    HashModule,
        "encode":  EncoderModule,
        "exploit": ExploitHelperModule,
    }
    cls = dispatch.get(module_name)
    if cls:
        cls(target, log).run()
    else:
        log.error(f"Unknown module: {module_name}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\033[1;33m[!] Interrupted by user. Goodbye.\033[0m\n")
        sys.exit(0)
