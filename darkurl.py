#!/usr/bin/env python
#------------------------------------------------------
#      BY: JATIN TIWARI from INDIA :)
#      YouTube: https://www.youtube.com/c/jatin.tiwari0
#      Github: https://github.com/jatintiwari0/darkURL
#------------------------------------------------------
from platform import python_version
from sys import exit, argv
from argparse import ArgumentParser
from nmap import PortScanner
from whois import whois

version = python_version().startswith('2', 0, len(python_version()))
if version:
    print('Are you using python version {}\n'
          'Please, use version 3.X of python'.format(python_version()))
    exit(1)

from os import system

RED, WHITE, GREEN, END, YELLOW = '\033[91m', '\33[97m', '\033[1;32m', '\033[0m', '\33[93m'

unicodes = [{'\u0430':'Cyrillic Small Letter A'},
         {'\u03F2':'Greek Lunate Sigma Symbol'},
         {'\u0435':'Cyrillic Small Letter Ie'},
         {'\u043E':'Cyrillic Small Letter O'},
         {'\u0440':'Cyrillic Small Letter Er'},
         {'\u0455':'Cyrillic Small Letter Dze'},
         {'\u0501':'Cyrillic Small Letter Komi De'},
         {'\u051B':'Cyrillic Small Letter Qa'},
         {'\u051D':'Cyrillic Small Letter We'}]

def message(output=False):
    system('clear')
    printParser('''{0}                                                                   

                                                                                 
_______                                                                    .---. 
\  ___ `'.                          .                                      |   | 
 ' |--.\  \                       .'|                                      |   | 
 | |    \  '           .-,.--.  .'  |                              .-,.--. |   | 
 | |     |  '    __    |  .-. |<    |                              |  .-. ||   | 
 | |     |  | .:--.'.  | |  | | |   | ____                 _    _  | |  | ||   | 
 | |     ' .'/ |   \ | | |  | | |   | \ .'                | '  / | | |  | ||   | 
 | |___.' /' `" __ | | | |  '-  |   |/  .                .' | .' | | |  '- |   | 
/_______.'/   .'.''| | | |      |    /\  \               /  | /  | | |     |   | 
\_______|/   / /   | |_| |      |   |  \  \             |   `'.  | | |     '---' 
             \ \._,\ '/|_|      '    \  \  \            '   .'|  '/|_|           
              `--'  `"         '------'  '---'           `-'  `--'               


[ by JATIN{0}TIWARI{1} -  @JATINTIWARI0 ]\n'''.format(RED, END), output)

def cleanTxt(txt):
    for i in (RED, WHITE, GREEN, END, YELLOW):
        txt = txt.replace(i, '')
    return txt

def cleanFile(output):
    arq = open(output, 'w')
    arq.write('')
    arq.close()

def checkAval(domain):
    try:
        return whois(domain).registrar
    except:
        return None

def printParser(txt, output=False):
    print(txt)
    if output:
        arq = open(output, 'a')
        arq.write(cleanTxt(txt)+'\n')
        arq.close()

def printOriginal(url, checkConnection, output):
    printParser('{0}[{1}~{0}]{1} Original: {2}'.format(GREEN, END, url), output)
    if checkConnection: printParser(check_url(url), output)

def makeDARK(char, unicd, uninum, newurl, oldurl, output):
    printParser('\n{0}[{1}*{0}]{1} Domain name: %s\n{0}[{1}*{0}]{1} Char replaced: %s\n{0}[{1}*{0}]{1} Using Unicode: %s\n{0}[{1}*{0}]{1} Unicode number: %s\n{0}[{1}*{0}]{1} DARK URL: {3}%s{1}'.format(GREEN, END, YELLOW, RED) % (oldurl, char, unicd, uninum, newurl), output)

import itertools

def gen(url, tld, checkConnection=False, output=False, aval=False):
    url = url.lower()

    darks = [{'a':'\u0430'},{'c': '\u03F2'}, {'e': '\u0435'}, {'o': '\u043E'}, {'p': '\u0440'}, {'s': '\u0455'}, {'d': '\u0501'}, {'q': '\u051B'}, {'w': '\u051D'}]
    e_matchs = []

    for em in darks:
        if list(em)[0].upper() in url.upper():
            e_matchs.append(list(em)[0])

    cst = ''
    for ch in e_matchs:
        cst += list(ch)[0]

    words = []
    for i in range(1, 9):
        for j in itertools.combinations(cst, i):
            temp = ''.join(j)
            words.append(temp)

    for word in words:
        newurl = url
        unicd = []
        name = []
        chars = []
        for w in word:
            for em in darks:
                if list(em)[0] == w:
                    chr = em[list(em)[0]]
                    unicd.append(chr)
                    chars.append(w)
                    for u in unicodes:
                        if list(u)[0] == chr:
                            name.append(u[chr])
                    newurl = newurl.replace(w, chr)
        makeDARK(chars, unicd, name, newurl+tld, url, output)
        if checkConnection: printParser(check_url(newurl+tld), output)
        if aval:
            if checkAval(newurl+tld) is None:
                printParser('{0}[{1}*{0}]{1} Available domain'.format(GREEN, END), output)
            else:
                printParser('{0}[{1}!{0}]{1} Unavailable domain'.format(YELLOW, END), output)

# -------------- BEGIN CHECKURL MODULE----------------- #
def check_url(url):

    '''
    Check connection
    :param url: suspicious url
    :return: status of connection
    '''

    nmScan = PortScanner()
    result = nmScan.scan(url, arguments='-sn')

    if int(result['nmap']['scanstats']['uphosts']) > 0:
        msg = '{0}[{1}*{0}]{1} Connection test: UP'.format(GREEN, END)
    else:
        msg = '{0}[{1}!{0}]{1} Connection test: DOWN'.format(YELLOW, END)

    return msg

def check_DARK(url):

    '''
    Check DARK chars in URL
    :param url: suspicious URL
    :return: result of check and the DARK chars
    '''

    bad_chars = ['\u0430', '\u03F2', '\u0435', '\u043E', '\u0440', '\u0455', '\u0501', '\u051B', '\u051D']
    result = [bad_chars[i] for i in range(len(bad_chars)) if bad_chars[i] in url]

    if result:
        msg = '{0}[{1}*{0}]{1} DARK URL detected: {2}{3}{1}'.format(GREEN,END,RED,url)
        msg += '\n{0}[{1}*{0}]{1} Unicode characters used: {2}'.format(GREEN,END,result)
    else:
        msg = '{0}[{1}!{0}]{1} DARK URL NOT detected: {2}'.format(YELLOW, END, url)

    return msg

def urls_list(file, checkConnection, output):
    '''
    Read the file to verify DARK URL
    :param file: file with a list of DARK URLs 
    :return: file reading
    '''

    with open(file) as arq:
        urls = [f.strip() for f in arq]
    for i in range(len(urls)):
        printParser(check_DARK(urls[i]), output)
        if checkConnection:
            printParser(check_url(urls[i]), output)
        printParser('', output)

# -------------- END CHECKURL MODULE ----------------- #

def parseHandler():
    parser = ArgumentParser(usage="darkurl.py [options]", description="Generate unicode DARK domains for IDN Homograph Attack and detect them.")
    parser.add_argument("-g", dest="generate", action="store_true", help="Generate unicode DARK domains")
    parser.add_argument("-d", dest="domain", help="Domain name with termination (example.com)")
    parser.add_argument("-c", dest="checkConnection", action="store_true", help="Check generated/input domain connections")
    parser.add_argument("-o", dest="output", help="Save generated DARK domains to a file")
    parser.add_argument("-f", dest="filepath", help="Import domains from a file and check them")
    parser.add_argument("-a", dest="aval", action="store_true", help="Check if domain is available")

    if len(argv) == 1:
        parser.print_help()
        exit(1)
    
    args = parser.parse_args()
    domain = '' if args.domain is None else args.domain
    generate = args.generate
    checkConnection = args.checkConnection
    filepath = args.filepath
    output = args.output
    aval = args.aval
    tld = ''
    for x in domain.split('.')[1:]:
        tld += '.' + x
    if output:
        cleanFile(output)
        message(output)
    if generate and not domain or generate and domain and filepath or domain and filepath:
        parser.print_help()
    elif generate and len(domain) > 0:        
        printOriginal(domain, checkConnection, output)
        gen(domain.split('.')[0], tld, checkConnection, output, aval)
    elif len(domain) > 0:
        printParser(check_DARK(domain), output)
    elif filepath:
        urls_list(filepath, checkConnection, output)
    if checkConnection and not filepath and not generate:
        printParser(check_url(domain), output)
    if output:
        print('\n{1}[{2}*{1}]{2} Logs stored to {0}'.format(output, GREEN, END))

if __name__ == '__main__':
    try:
        message()
        parseHandler()
    except KeyboardInterrupt:
        exit()
