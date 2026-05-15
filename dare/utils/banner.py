"""
DARE — Banner & Menu Display
Dynamic Attack & Recon Engine
"""

BANNER = """
\033[1;32m
  ██████╗  █████╗ ██████╗ ███████╗
  ██╔══██╗██╔══██╗██╔══██╗██╔════╝
  ██║  ██║███████║██████╔╝█████╗  
  ██║  ██║██╔══██║██╔══██╗██╔══╝  
  ██████╔╝██║  ██║██║  ██║███████╗
  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝
\033[0m\033[1;36m
     D y n a m i c   A t t a c k   &   R e c o n   E n g i n e
\033[0m\033[0;37m
     by Fashipe Oluwadamilare Ayoola
\033[0m\033[1;31m     [ Authorized testing & CTFs ONLY — Unauthorized use is illegal ]\033[0m
"""

def print_banner():
    print(BANNER)
    print("\033[1;34m" + "─" * 70 + "\033[0m")


def print_menu(modules: dict):
    print("\n\033[1;34m" + "─" * 40 + "\033[0m")
    print("\033[1;36m  MODULES\033[0m")
    print("\033[1;34m" + "─" * 40 + "\033[0m")
    for key, (name, _) in modules.items():
        print(f"  \033[1;32m[{key}]\033[0m  {name}")
    print(f"  \033[1;31m[q]\033[0m  Quit")
    print("\033[1;34m" + "─" * 40 + "\033[0m")
