import os
from colorama import Fore, Style, init

class Color:
    BLUE = '\033[94m'
    GREEN = '\033[1;92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    CYAN = '\033[96m'
    RESET = '\033[0m'
    ORANGE = '\033[38;5;208m'
    BOLD = '\033[1m'
    UNBOLD = '\033[22m'

init(autoreset=True)

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def display_menu():
    title = r"""
.____                   __ ____  ___.__                
|    |    ____  _______/  |\   \/  /|  |   __________  
|    |   /  _ \/  ___/\   __\     / |  |  /  ___/  _ \ 
|    |__(  <_> )___ \  |  | /     \ |  |__\___ (  <_> )
|_______ \____/____  > |__|/___/\  \|____/____  >____/ 
        \/         \/            \_/          \/       
    """
    print(Color.ORANGE + Style.BRIGHT + title.center(63))
    print(Fore.WHITE + Style.BRIGHT + "─" * 63)
    border_color = Color.CYAN + Style.BRIGHT
    option_color = Fore.WHITE + Style.BRIGHT  
    
    print(border_color + "┌" + "─" * 61 + "┐")
    
    options = [
        "1] LFi Scanner",
        "2] OR Scanner",
        "3] SQLi Scanner",
        "4] XSS Scanner",
        "5] tool Update",
        "6] Exit"
    ]
    
    for option in options:
        print(border_color + "│" + option_color + option.ljust(59) + border_color + "│")
    
    print(border_color + "└" + "─" * 61 + "┘")
    
    authors = "Created by: Coffinxp, HexSh1dow, Naho and AnonKryptiQuz "
    instructions = "Select an option by entering the corresponding number:"
    
    print(Fore.WHITE + Style.BRIGHT + "─" * 63)
    print(Fore.WHITE + Style.BRIGHT + authors.center(63))
    print(Fore.WHITE + Style.BRIGHT + "─" * 63)
    print(Fore.WHITE + Style.BRIGHT + instructions.center(63))
    print(Fore.WHITE + Style.BRIGHT + "─" * 63)

def print_exit_menu():
    clear_screen()
    print(f"{Color.RED}\n\nSession Off..\n")
    exit()
