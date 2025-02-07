import json, requests, threading, ssl, socket, hashlib, tempfile, csv, urllib3, sys, time, platform, ctypes, logging, webbrowser, os, uuid, htmllistparse, re, wget, datetime, importlib
from mods.logger import info, warn, error, cyan
from flask import Flask, request, jsonify, render_template
from pypresence import Presence
from colorama import Fore
from discord_webhook import DiscordWebhook, DiscordEmbed
from pkg_resources import parse_version

import traceback

urllib3.disable_warnings()
logging.disable(logging.CRITICAL)
sys.dont_write_bytecode = True

logging.getLogger('werkzeug').setLevel(logging.ERROR)
cli = sys.modules['flask.cli']
cli.show_server_banner = lambda *x: None

VERSION = '0.2'

MACHINE_OS = platform.system()
if not MACHINE_OS in ['Windows', 'Darwin']:
    sys.exit()
IP_ADDRESS = ''
HWID = str(uuid.getnode())
MACHINE_ID = platform.node()

DISCORD_USER = None
DISCORD_ID = None




SITES = [
    #{ 'name': 'AIME', 'status': 0, 'id': 'aime', 'folder': 'aime' },
    #{ 'name': 'AMBUSH', 'status': 0, 'id': 'ambush', 'folder': 'ambush' },
    #{ 'name': 'ASOS', 'status': 0, 'id': 'asos', 'folder': 'asos' },
    { 'name' : 'ASPHALT', 'status': 0, 'id': 'asphalt', 'folder': 'asphalt' },
    { 'name' : 'AMAZON', 'status': 0, 'id': 'amazon', 'folder': 'amazon' },
    { 'name' : 'ATMO', 'status': 0, 'id': 'atmo', 'folder': 'atmo' },
    { 'name' : 'BOL', 'status': 0, 'id': 'bol', 'folder': 'bol' },
    #{ 'name' : 'B4B', 'status': 0, 'id': 'b4b', 'folder': 'b4b' },
    #{ 'name': 'CULTURE', 'status': 0, 'id': 'culture', 'folder': 'culture' },
    { 'name' : 'DEFSHOP', 'status': 0, 'id': 'defshop', 'folder': 'defshop' },
    { 'name' : 'DISNEY', 'status': 0, 'id': 'disney', 'folder': 'disney' },
    { 'name' : 'DIRECT', 'status': 0, 'id': 'direct', 'folder': 'direct' },
    #{ 'name' : 'ELCORTE', 'status': 0, 'id': 'elcorte', 'folder': 'elcorte' },
    #{ 'name' : 'FOOTPATROL', 'status': 0, 'id': 'footpatrol', 'folder': 'footpatrol' },
    #{ 'name': 'HERE', 'status': 0, 'id': 'here', 'folder': 'here' },
    #{ 'name': 'GALERIES', 'status': 0, 'id': 'galeries', 'folder': 'galeries' },
    { 'name': 'GAMESTOP', 'status': 0, 'id': 'gamestop', 'folder': 'gamestop' },
    #{ 'name': 'HYPEDCARTEL', 'status': 0, 'id': 'hypedcartel', 'folder': 'hypedcartel' },
    { 'name': 'KADEWE', 'status': 0, 'id': 'kadewe', 'folder': 'kadewe' },
    #{ 'name': 'KICKZ', 'status': 0, 'id': 'kickz', 'folder': 'kickz' },
    #{ 'name': 'LVR', 'status': 0, 'id': 'lvr', 'folder': 'lvr' },
    { 'name': 'MEDIAMARKET', 'status': 0, 'id': 'mediamarket', 'folder': 'mediamarket' },
    { 'name': 'MICROMANIA', 'status': 0, 'id': 'micromania', 'folder': 'micromania' },
    { 'name' : 'MTOYS', 'status': 0, 'id': 'mtoys', 'folder': 'mtoys' },
    { 'name': 'MUELLER', 'status': 0, 'id': 'mueller', 'folder': 'mueller' },
    { 'name': 'NEWBALANCE', 'status': 0, 'id': 'newbalance', 'folder': 'newbalance' },
    #{ 'name': 'OFF-WHITE', 'status': 0, 'id': 'offwhite', 'folder': 'offwhite' },
    { 'name': 'SIDESTEP', 'status': 0, 'id': 'sidestep', 'folder': 'sidestep' },
    #{ 'name': 'SLAMJAM', 'status': 0, 'id': 'slamjam', 'folder': 'slamjam' },
    #{ 'name': 'SNIPES', 'status': 0, 'id': 'snipes', 'folder': 'snipes' },
    { 'name': 'SENSE', 'status': 0, 'id': 'sense', 'folder': 'sense' },
    { 'name': 'SPIELE', 'status': 0, 'id': 'spiele', 'folder': 'spiele' },
    { 'name': 'STYLEFILE', 'status': 0, 'id': 'stylefile', 'folder': 'stylefile' },
    #{ 'name': 'SUSI', 'status': 0, 'id': 'susi', 'folder': 'susi' },
    { 'name': 'OTTO', 'status': 0, 'id': 'otto', 'folder': 'otto' },
    { 'name': 'OQIUM', 'status': 0, 'id': 'oqium', 'folder': 'oqium' },
    { 'name': 'TOYS', 'status': 0, 'id': 'toys', 'folder': 'toys' },
    { 'name': 'WEARE', 'status': 0, 'id': 'weare', 'folder': 'weare' },
    { 'name': 'WEHKAMP', 'status': 0, 'id': 'wehkamp', 'folder': 'wehkamp' },
    { 'name': 'XBOX', 'status': 0, 'id': 'xbox', 'folder': 'xbox' },
]

def getInput(text):
    asctime = str(datetime.datetime.now()).replace('.', ',')[:-3]
    print (f'[{asctime}] {Fore.YELLOW}{text}: ', end='')
def readConfig():
    try:
        path = os.path.join(os.path.dirname(sys.argv[0]), 'config.json')
        return json.load(open(path, 'r'))
    except Exception as e:
        error(f'Failed reading your config file - {e}')
        sys.exit()
def readTasks(site):
    try:
        if MACHINE_OS == 'Darwin':
            path = os.path.dirname('__file__').rsplit('/', 1)[0]
            path = os.path.join(os.path.dirname(sys.argv[0]), f'{site}/tasks.csv')
        elif MACHINE_OS == 'Windows':
            path = os.path.dirname('__file__').rsplit('\\', 1)[0]
            path = os.path.join(os.path.dirname(sys.argv[0]), f'{site}/tasks.csv')
        tasks = csv.DictReader(open(f'{path}', 'r'))
        return tasks
    except:
        return None
def getIP():
    try:
        return requests.get('https://myexternalip.com/raw', verify=False).text
    except:
        pass

IP_ADDRESS = getIP()
CONFIG = readConfig()

class MainWrapper():

    def __init__(self):
        self.scriptmenu()

    def is_admin(self):
        try:
            return ctypes.windll.shell32.IsUserAnAdmin()
        except:
            return False

    def timer(self):
        user_time = datetime.datetime.strptime(input(), "%d-%m-%Y %H:%M:%S")
        now = datetime.datetime.now()
        delta = int((user_time-now).total_seconds())
        t = delta - 15
        warn(f'Sleeping for {t} seconds...')
        return t

    def scriptmenu(self):

        info(f"Welcome - Monitors {VERSION}")
        if 'mobilemode' in CONFIG.keys() and CONFIG['mobilemode'] != '':
            from scripts.mobile import START
            threading.Thread(target=START, args=([CONFIG['webhook'], VERSION])).start()
        else:
            while True:
                for site in SITES:
                    i = str(SITES.index(site))
                    spaces = ' ' * (2 - len(i))
                    if site['status'] == 0:
                        info(f'[{spaces}{i}] {site["name"]}')
                    elif site['status'] == 1:
                        warn(f'[{spaces}{i}] {site["name"]}')
                    elif site['status'] == 2:
                        error(f'[{spaces}{i}] {site["name"]}')
                print("-------------------------------------------------------------------------------------------")
                getInput('-- [Please select]')
                site = input().strip()
                try:
                    site = int(site)
                    site = SITES[site]
                    break
                except:
                    error('Invalid site chosen')
                    continue
            tasks = readTasks(site['folder'])
            if not tasks:
                error('Failed reading tasks. Please check your tasks.csv file.')
                sys.exit(1)
            else:
                modes = [1,2,3]
                username = None
                password = None
                while True:
                    warn('[MODE 1]: RUN TASKS')
                    warn('[MODE 2]: INPUT LINK / SKU')
                    warn('[MODE 3]: TIMER')
                    if site['id'] == 'einhalb':
                        modes.append(4)
                        warn('[MODE 4]: START WITH LINK AND CREDENTIALS')
                    elif site['id'] == 'starcow':
                        modes.append(4)
                        warn('[MODE 4]: CREATE SESSIONS')
                    getInput('-- [Please select]')
                    mode = input().strip()
                    try:
                        mode = int(mode)
                        if not mode in modes:
                            raise Exception
                        else:
                            break
                    except:
                        error('Invalid mode chosen')
                        continue
                if mode == 1:
                    inp = None
                if mode == 2:
                    getInput('[INPUT LINK]')
                    inp = input().strip()
                elif mode == 3:
                    warn('TIMER NEEDS TO BE IN THIS FORMAT: DD-MM-YYYY HH:MM:SS')
                    t = self.timer()
                    time.sleep(t)
                elif mode == 4 and site['id'] == 'einhalb':
                    getInput('[INPUT LINK]')
                    inp = input().strip()
                    getInput('[INPUT USERNAME]')
                    username = input().strip()
                    getInput('[INPUT PASSWORD]')
                    password = input().strip()
                else:
                    inp = None
                i = 0
                module = getattr(importlib.import_module(f'scripts.{site["id"]}'), site['id'].upper())
                if site['id'] == 'awlab':
                    for row in list(tasks)[:20]:
                        i += 1
                        if inp != None:
                            if 'VARIANT' in row.keys():
                                row['VARIANT'] = inp
                            elif 'SKU' in row.keys():
                                row['SKU'] = inp
                            elif 'PID' in row.keys():
                                row['PID'] = inp  
                            else:
                                row['LINK'] = inp
                        threading.Thread(target=module, args=([row, CONFIG['webhook'], VERSION, i,DISCORD_ID])).start()
                if site['id'] == 'susi':
                    for row in list(tasks)[:200]:
                        i += 1
                        if inp != None:
                            if 'VARIANT' in row.keys():
                                row['VARIANT'] = inp
                            elif 'SKU' in row.keys():
                                row['SKU'] = inp
                            elif 'PID' in row.keys():
                                row['PID'] = inp  
                            else:
                                row['LINK'] = inp
                        threading.Thread(target=module, args=([row, CONFIG['webhook'], VERSION, i,DISCORD_ID])).start()
                if site['id'] == 'sugar':
                    for row in list(tasks)[:10]:
                        i += 1
                        if inp != None:
                            if 'VARIANT' in row.keys():
                                row['VARIANT'] = inp
                            elif 'SKU' in row.keys():
                                row['SKU'] = inp
                            elif 'PID' in row.keys():
                                row['PID'] = inp  
                            else:
                                row['LINK'] = inp
                        threading.Thread(target=module, args=([row, CONFIG['webhook'], VERSION, i,DISCORD_ID])).start()
                else:
                    for row in tasks:
                        i += 1
                        if inp != None:
                            if 'VARIANT' in row.keys():
                                row['VARIANT'] = inp
                            elif 'SKU' in row.keys():
                                row['SKU'] = inp
                            elif 'PID' in row.keys():
                                row['PID'] = inp  
                            else:
                                row['LINK'] = inp
                        if mode == 4 and site['id'] == 'einhalb':
                            row['USERNAME'] = username
                            row['PASSWORD'] = password
                        elif mode == 4 and site['id'] == 'starcow':
                            row['MODE'] = 'CREATE'
                        threading.Thread(target=module, args=([row, CONFIG['webhook'], VERSION, i,DISCORD_ID])).start()

threading.Thread(target=MainWrapper).start()