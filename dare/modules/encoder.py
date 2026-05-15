"""
DARE — Encoder / Decoder Module

Covers:
  - Base64 encode/decode
  - URL encode/decode
  - HTML entity encode/decode
  - Hex encode/decode
  - ROT13 / Caesar cipher
  - Binary encode/decode
  - JWT decode (header + payload)
"""

import base64
import urllib.parse
import html
import binascii
import json


class EncoderModule:
    NAME = "Encoder / Decoder"

    def __init__(self, target: str, log):
        self.target = target
        self.log = log

    def run(self):
        self.log.section("Encoder / Decoder")

        options = {
            "1":  ("Base64 Encode",        lambda t: self._b64(t, encode=True)),
            "2":  ("Base64 Decode",        lambda t: self._b64(t, encode=False)),
            "3":  ("URL Encode",           lambda t: self._url(t, encode=True)),
            "4":  ("URL Decode",           lambda t: self._url(t, encode=False)),
            "5":  ("HTML Entity Encode",   lambda t: self._html(t, encode=True)),
            "6":  ("HTML Entity Decode",   lambda t: self._html(t, encode=False)),
            "7":  ("Hex Encode",           lambda t: self._hex(t, encode=True)),
            "8":  ("Hex Decode",           lambda t: self._hex(t, encode=False)),
            "9":  ("ROT13",                lambda t: self._rot13(t)),
            "10": ("Caesar Cipher",        lambda t: self._caesar(t)),
            "11": ("Binary Encode",        lambda t: self._binary(t, encode=True)),
            "12": ("Binary Decode",        lambda t: self._binary(t, encode=False)),
            "13": ("JWT Decode",           lambda t: self._jwt_decode(t)),
            "14": ("Auto-Detect & Decode", lambda t: self._auto_detect(t)),
        }

        print()
        for k, (name, _) in options.items():
            print(f"  \033[1;32m[{k:>2}]\033[0m {name}")
        print()

        choice = input("\033[1;36m[encode]> \033[0m").strip()
        if choice not in options:
            self.log.error("Invalid option.")
            return

        text = input("  Input text: ").strip()
        if not text:
            self.log.error("No input provided.")
            return

        result = options[choice][1](text)
        if result is not None:
            self.log.success(f"Result:\n\n  {result}\n")

    def _b64(self, text: str, encode: bool) -> str:
        try:
            if encode:
                return base64.b64encode(text.encode()).decode()
            else:
                return base64.b64decode(text.encode()).decode("utf-8", errors="replace")
        except Exception as e:
            self.log.error(f"Base64 error: {e}")

    def _url(self, text: str, encode: bool) -> str:
        if encode:
            return urllib.parse.quote(text, safe="")
        else:
            return urllib.parse.unquote(text)

    def _html(self, text: str, encode: bool) -> str:
        if encode:
            return html.escape(text)
        else:
            return html.unescape(text)

    def _hex(self, text: str, encode: bool) -> str:
        try:
            if encode:
                return text.encode().hex()
            else:
                return bytes.fromhex(text).decode("utf-8", errors="replace")
        except Exception as e:
            self.log.error(f"Hex error: {e}")

    def _rot13(self, text: str) -> str:
        result = []
        for c in text:
            if 'a' <= c <= 'z':
                result.append(chr((ord(c) - ord('a') + 13) % 26 + ord('a')))
            elif 'A' <= c <= 'Z':
                result.append(chr((ord(c) - ord('A') + 13) % 26 + ord('A')))
            else:
                result.append(c)
        return ''.join(result)

    def _caesar(self, text: str) -> str:
        try:
            shift = int(input("  Shift value (1-25): ").strip())
        except ValueError:
            self.log.error("Invalid shift value.")
            return None
        result = []
        for c in text:
            if 'a' <= c <= 'z':
                result.append(chr((ord(c) - ord('a') + shift) % 26 + ord('a')))
            elif 'A' <= c <= 'Z':
                result.append(chr((ord(c) - ord('A') + shift) % 26 + ord('A')))
            else:
                result.append(c)
        return ''.join(result)

    def _binary(self, text: str, encode: bool) -> str:
        try:
            if encode:
                return ' '.join(format(ord(c), '08b') for c in text)
            else:
                bits = text.replace(' ', '')
                chars = [bits[i:i+8] for i in range(0, len(bits), 8)]
                return ''.join(chr(int(b, 2)) for b in chars if len(b) == 8)
        except Exception as e:
            self.log.error(f"Binary error: {e}")

    def _jwt_decode(self, token: str) -> str:
        """Decode a JWT without verifying signature (inspection only)."""
        parts = token.split('.')
        if len(parts) != 3:
            self.log.error("Not a valid JWT (expected 3 parts separated by '.')")
            return None

        results = []
        for i, label in enumerate(["Header", "Payload"]):
            part = parts[i]
            # Pad for base64
            padded = part + '=' * (4 - len(part) % 4)
            try:
                decoded = base64.urlsafe_b64decode(padded).decode('utf-8', errors='replace')
                parsed = json.loads(decoded)
                results.append(f"\n  [{label}]\n  {json.dumps(parsed, indent=2)}")
            except Exception as e:
                results.append(f"\n  [{label}] Raw: {padded} (parse error: {e})")

        results.append("\n  [Signature] <not verified — inspection only>")
        return '\n'.join(results)

    def _auto_detect(self, text: str) -> str:
        """Try common encodings and display results."""
        output = []

        # Base64
        try:
            b64 = base64.b64decode(text + '==').decode('utf-8', errors='replace')
            if b64.isprintable():
                output.append(f"Base64    → {b64}")
        except Exception:
            pass

        # URL decode
        url = urllib.parse.unquote(text)
        if url != text:
            output.append(f"URL       → {url}")

        # Hex
        try:
            hexval = bytes.fromhex(text).decode('utf-8', errors='replace')
            if hexval.isprintable():
                output.append(f"Hex       → {hexval}")
        except Exception:
            pass

        # ROT13
        rot = self._rot13(text)
        if rot != text:
            output.append(f"ROT13     → {rot}")

        if output:
            return '\n  '.join(output)
        else:
            return "Could not auto-detect encoding."
