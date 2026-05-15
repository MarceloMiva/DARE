"""
DARE — Hash Tools Module

Covers:
  - Hash identification (MD5, SHA1/256/512, bcrypt, NTLM, etc.)
  - Hash generation
  - Wordlist-based hash cracking (dictionary attack)
  - Common hash comparison
"""

import hashlib
import re


HASH_PATTERNS = {
    "MD5":          (r"^[a-f0-9]{32}$",   "md5"),
    "SHA1":         (r"^[a-f0-9]{40}$",   "sha1"),
    "SHA224":       (r"^[a-f0-9]{56}$",   "sha224"),
    "SHA256":       (r"^[a-f0-9]{64}$",   "sha256"),
    "SHA384":       (r"^[a-f0-9]{96}$",   "sha384"),
    "SHA512":       (r"^[a-f0-9]{128}$",  "sha512"),
    "NTLM":         (r"^[A-F0-9]{32}$",   None),
    "bcrypt":       (r"^\$2[ayb]\$.{56}$", None),
    "SHA512crypt":  (r"^\$6\$.{8,16}\$.{86}$", None),
    "MD5crypt":     (r"^\$1\$.{8}\$.{22}$",    None),
    "MySQL323":     (r"^[a-f0-9]{16}$",   None),
    "CRC32":        (r"^[a-f0-9]{8}$",    None),
}

DEFAULT_WORDLIST = [
    "password", "123456", "password123", "admin", "letmein", "qwerty",
    "monkey", "dragon", "master", "sunshine", "princess", "shadow",
    "football", "superman", "batman", "hello", "welcome", "login",
    "pass", "test", "root", "toor", "guest", "default", "abc123",
    "1234", "12345", "123456789", "iloveyou", "111111", "654321",
    "pa$$word", "P@ssword", "P@ssw0rd", "Admin123", "Password1",
]


class HashModule:
    NAME = "Hash Tools"

    def __init__(self, target: str, log):
        self.target = target
        self.log = log

    def run(self):
        self.log.section("Hash Tools")

        options = {
            "1": ("Identify Hash",        self.identify),
            "2": ("Generate Hash",        self.generate),
            "3": ("Dictionary Crack",     self.crack),
            "4": ("Compare Hashes",       self.compare),
        }

        print()
        for k, (name, _) in options.items():
            print(f"  \033[1;32m[{k}]\033[0m {name}")
        print()

        choice = input("\033[1;36m[hash]> \033[0m").strip()
        if choice in options:
            options[choice][1]()
        else:
            self.log.error("Invalid option.")

    def identify(self):
        self.log.section("Hash Identification")
        h = input("  Enter hash: ").strip()
        if not h:
            return

        matches = []
        for name, (pattern, _) in HASH_PATTERNS.items():
            if re.match(pattern, h, re.IGNORECASE):
                matches.append(name)

        if matches:
            self.log.success(f"Possible type(s): {', '.join(matches)}")
            self.log.info(f"Hash length: {len(h)} characters")
        else:
            self.log.warn(f"Unrecognized hash format (length={len(h)})")

    def generate(self):
        self.log.section("Hash Generation")
        text = input("  Enter plaintext to hash: ").strip()
        if not text:
            return

        algos = ["md5", "sha1", "sha224", "sha256", "sha384", "sha512"]
        for algo in algos:
            h = hashlib.new(algo, text.encode()).hexdigest()
            self.log.result(algo.upper(), h)

    def crack(self):
        self.log.section("Dictionary Hash Crack")
        target_hash = input("  Enter hash to crack: ").strip().lower()
        if not target_hash:
            return

        # Identify likely algorithm
        algo = None
        for name, (pattern, lib_algo) in HASH_PATTERNS.items():
            if re.match(pattern, target_hash, re.IGNORECASE) and lib_algo:
                algo = lib_algo
                self.log.info(f"Detected type: {name} ({lib_algo})")
                break

        if not algo:
            algo_input = input("  Could not auto-detect. Enter algo (md5/sha1/sha256/sha512): ").strip()
            algo = algo_input or "md5"

        # Load wordlist
        wordlist_path = input("  Wordlist path [leave blank for built-in mini list]: ").strip()
        if wordlist_path:
            try:
                with open(wordlist_path, "r", errors="ignore") as f:
                    words = [line.strip() for line in f if line.strip()]
                self.log.info(f"Loaded {len(words)} words from {wordlist_path}")
            except FileNotFoundError:
                self.log.error(f"File not found: {wordlist_path}")
                return
        else:
            words = DEFAULT_WORDLIST
            self.log.warn(f"Using built-in wordlist ({len(words)} words).")

        self.log.info("Cracking...")
        for word in words:
            hashed = hashlib.new(algo, word.encode()).hexdigest()
            if hashed == target_hash:
                self.log.success(f"CRACKED! Hash = '{target_hash}' → Plaintext = '{word}'")
                return

        self.log.warn("Not cracked with current wordlist. Try a larger list (e.g. rockyou.txt).")

    def compare(self):
        self.log.section("Hash Comparison")
        h1 = input("  Hash 1: ").strip().lower()
        h2 = input("  Hash 2: ").strip().lower()
        if h1 == h2:
            self.log.success("Hashes MATCH.")
        else:
            self.log.error("Hashes do NOT match.")
