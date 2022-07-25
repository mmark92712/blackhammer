# -*- coding: utf-8 -*-

class Colors:
    cerror =        "\u001b[38;5;160m"
    cinfo =         "\u001b[38;5;6m"
    cwarning =      "\033[38;5;209m"
    creset =        "\033[0m"

    @staticmethod
    def info(message: str, newline=True):
        Colors._print(Colors.cinfo, message, newline)

    @staticmethod
    def error(message: str, newline=True):
        Colors._print(Colors.cerror, message, newline)
    
    @staticmethod
    def warn(message: str, newline=True):
        Colors._print(Colors.cwarning, message, newline)

    @staticmethod
    def _print(color, message, newline):
        if newline:
            print(color + message + Colors.creset)
        else: print(color + "\r\t" + message + Colors.creset, end="")

    @staticmethod
    def debug(caller:str, msg:str):
        print(f'In {Colors.cwarning}{caller}{Colors.creset}: {msg}.')