# -*- coding: utf-8 -*-

class Colors:
    cerror =        "\u001b[38;5;160m"
    cinfo =         "\u001b[38;5;6m"
    cwarning =      "\033[38;5;209m"
    creset =        "\033[0m"


    @staticmethod
    def debug(caller:str, msg:str):
        print(f'In {Colors.cwarning}{caller}{Colors.creset}: {msg}')


    @staticmethod
    def info(msg:str):
        print(f'{Colors.cinfo}INFO: {Colors.creset}{msg}')


    @staticmethod
    def warn(msg:str):
        print(f'{Colors.cwarning}WARN: {Colors.creset}{msg}')


    @staticmethod
    def error(msg:str):
        print(f'{Colors.cerror}ERROR: {Colors.creset}{msg}')