import json, requests, threading, csv, urllib3, sys, random, base64, platform, random, ctypes, logging, os, time, re, urllib, cloudscraper, names, lxml, string, pytz, js2py
from datetime import datetime
from mods.logger import info, warn, error
from discord_webhook import DiscordWebhook, DiscordEmbed
from bs4 import BeautifulSoup as bs
from playsound import playsound
from twocaptcha import TwoCaptcha
from card_identifier.card_type import identify_card_type
from hawk_cf_api.hawk_cf import CF_2, Cf_challenge_3
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers.aead import AESCCM
from cryptography.hazmat.backends import default_backend
from os import urandom
from autosolveclient.autosolve import AutoSolve
import traceback
import ssl

urllib3.disable_warnings()
machineOS = platform.system()
sys.dont_write_bytecode = True

threads = {}
ipaddr = None

UNIQUE_ID = int(time.time() * 1000) * 2**random.randint(10,16)
AUTO_SOLVE = None
CAPTCHA_TOKENS = []
CAPTCHA = None

checkoutnum = 0
carted = 0
failed = 0

def perform_request(self, method, url, *args, **kwargs):
    if "proxies" in kwargs or "proxy"  in kwargs:
        return super(cloudscraper.CloudScraper, self).request(method, url, *args, **kwargs)
    else:
        return super(cloudscraper.CloudScraper, self).request(method, url, *args, **kwargs,proxies=self.proxies)
cloudscraper.CloudScraper.perform_request = perform_request

@staticmethod
def is_New_Captcha_Challenge(resp):
    try:
        return (
                cloudscraper.CloudScraper.is_Captcha_Challenge(resp)
                and re.search(
                    r'cpo.src\s*=\s*"/cdn-cgi/challenge-platform/?\w?/?\w?/orchestrate/captcha/v1',
                    resp.text,
                    re.M | re.S
                )
                and re.search(r'window._cf_chl_opt', resp.text, re.M | re.S)
        )
    except AttributeError:
        pass

    return False
cloudscraper.CloudScraper.is_New_Captcha_Challenge = is_New_Captcha_Challenge

#normal challenge
@staticmethod
def is_New_IUAM_Challenge(resp):
    try:
        return (
                resp.headers.get('Server', '').startswith('cloudflare')
                and resp.status_code in [429, 503]
                and re.search(
                    r'cpo.src\s*=\s*"/cdn-cgi/challenge-platform/?\w?/?\w?/orchestrate/jsch/v1',
                    resp.text,
                    re.M | re.S
                )
                and re.search(r'window._cf_chl_opt', resp.text, re.M | re.S)
        )
    except AttributeError:
        pass

    return False
cloudscraper.CloudScraper.is_New_IUAM_Challenge = is_New_IUAM_Challenge

## fingerprint challenge
def is_fingerprint_challenge(resp):
    try:
        if resp.status_code == 429:
            if "/fingerprint/script/" in resp.text:
                return True
        return False
    except:
        pass



def configWriter(json_obj, w_file):

    if machineOS == "Darwin":
        path = os.path.dirname(__file__).rsplit('/', 1)[0]
        path = os.path.join(os.path.dirname(sys.argv[0]), w_file)
    elif machineOS == "Windows":
        path = os.path.dirname(__file__).rsplit('\\', 1)[0]
        path = os.path.join(os.path.dirname(sys.argv[0]), w_file)

    path = os.path.dirname(__file__).rsplit('/', 1)[0]

    with open(f'{path}', 'w') as f:
        json.dump(json_obj, f, indent=4)
        f.close()

try:
    if machineOS == "Darwin":
        path = os.path.dirname(__file__).rsplit('/', 1)[0]
        path = os.path.join(os.path.dirname(sys.argv[0]), "config.json")
    elif machineOS == "Windows":
        path = os.path.dirname(__file__).rsplit('\\', 1)[0]
        path = os.path.join(os.path.dirname(sys.argv[0]), "config.json")
    with open(f'{path}', 'r') as f:
        config = json.load(f)
        f.close()
except Exception as e:
    error("FAILED TO READ CONFIG FILE")
    pass

def balancefunc():
    try:
        solver = TwoCaptcha(config['2captcha'])
        balance = solver.balance()
        return balance
    except:
        balance = 'Unkown'
        return balance

class KICKZ():

    def __init__(self, row, webhook, version, i, DISCORD_ID):

        self.logs_path = os.path.join(os.path.dirname(sys.argv[0]), 'kickz/exceptions.log')
        try:
            if machineOS == "Darwin":
                path = os.path.dirname(__file__).rsplit('/', 1)[0]
                path = os.path.join(os.path.dirname(sys.argv[0]), 'kickz/proxies.txt')
            elif machineOS == "Windows": 
                path = os.path.dirname(__file__).rsplit('\\', 1)[0]
                path = os.path.join(os.path.dirname(sys.argv[0]), "kickz/proxies.txt")
            with open(f'{path}', 'r') as f:
                proxylist = f.read()
                if proxylist == '':
                    self.all_proxies = None
                else:
                    self.all_proxies = proxylist.split('\n')
                f.close()

        except:
            error("Failed To Read Proxies File - using no proxies")
            self.all_proxies = None

        if config['anticaptcha'] != "":
            self.captcha = {
                'provider': 'anticaptcha',
                'api_key': config['anticaptcha']
            }
        elif config['2captcha'] != "":
            self.captcha={
                'provider': '2captcha',
                'api_key':config['2captcha']
            }
        else:
            error('2Captcha or AntiCaptcha needed. Stopping task.')
            sys.exit(1)

        ssl_context = ssl.create_default_context()
        ssl_context.set_ciphers('ECDH-RSA-NULL-SHA:ECDH-RSA-RC4-SHA:ECDH-RSA-DES-CBC3-SHA:ECDH-RSA-AES128-SHA:ECDH-RSA-AES256-SHA:ECDH-ECDSA-NULL-SHA:ECDH-ECDSA-RC4-SHA:ECDH-ECDSA-DES-CBC3-SHA:ECDH-ECDSA-AES128-SHA:ECDH-ECDSA-AES256-SHA:ECDHE-RSA-NULL-SHA:ECDHE-RSA-RC4-SHA:ECDHE-RSA-DES-CBC3-SHA:ECDHE-RSA-AES128-SHA:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-NULL-SHA:ECDHE-ECDSA-RC4-SHA:ECDHE-ECDSA-DES-CBC3-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-ECDSA-AES256-SHA:AECDH-NULL-SHA:AECDH-RC4-SHA:AECDH-DES-CBC3-SHA:AECDH-AES128-SHA:AECDH-AES256-SHA')
        ssl_context.set_ecdh_curve('prime256v1')
        ssl_context.options |= (ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3 | ssl.OP_NO_TLSv1_3 | ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1)
        ssl_context.check_hostname=False

        self.s = cloudscraper.create_scraper(
            browser={
                'browser': 'chrome',
                'mobile': False,
                'platform': 'windows'
                },
                captcha=self.captcha,
                doubleDown=False,
                ssl_context = ssl_context,
                requestPostHook=self.injection
        )

        self.pidmonitor = row['PID']
        self.mode = row['MODE']

        self.discord = DISCORD_ID
    
        self.twoCaptcha = str(config['2captcha'])
        
        self.delay = int(config['delay'])
        self.timeout = 120
          
        self.balance = balancefunc()
        self.threadID = '%03d' % i
        self.webhook_url = webhook
        self.version = version
        self.build_proxy()
        self.monster = config['capmonster']


        self.bar()

        self.warn('Task started!')
        if self.mode == 'D':
            self.monitor()
        else:
            self.search()

    def error(self, text):
        message = f'[TASK {self.threadID}] - [KICKZ] [{self.pidmonitor}] - {text}'
        error(message)

    # Green logging

    def success(self, text):
        message = f'[TASK {self.threadID}] - [KICKZ] [{self.pidmonitor}] - {text}'
        info(message)

    # Yellow logging

    def warn(self, text):
        message = f'[TASK {self.threadID}] - [KICKZ] [{self.pidmonitor}] - {text}'
        warn(message)

    def build_proxy(self):
        cookies = self.s.cookies
        self.s = cloudscraper.create_scraper(
            captcha=self.captcha,
            browser={
                'browser': 'chrome',
                'mobile': False,
                'platform': 'windows'
            },
            requestPostHook=self.injection
        )
        self.s.cookies = cookies
        if self.all_proxies == [] or not self.all_proxies:
            return None
        else:
            self.px = random.choice(self.all_proxies)
            splitted = self.px.split(':')
            if len(splitted) == 2:
                self.s.proxies = {
                    'http': 'http://{}'.format(self.px),
                    'https': 'http://{}'.format(self.px)
                }
                return None
            
            elif len(splitted) == 4:
                self.s.proxies = {
                    'http': 'http://{}:{}@{}:{}'.format(splitted[2], splitted[3], splitted[0], splitted[1]),
                    'https': 'http://{}:{}@{}:{}'.format(splitted[2], splitted[3], splitted[0], splitted[1])
                }
                return None
            else:
                self.error('Invalid proxy: "{}", rotating'.format(self.px))
                return None


    def bar(self):
        if machineOS.lower() == 'windows':
            ctypes.windll.kernel32.SetConsoleTitleW(
                f' Monitors {self.version} - Running KICKZ | 2cap Balance: {self.balance} | Carted: {carted} | Checkout: {checkoutnum} | Failed: {failed}')
        else:
            sys.stdout.write(f'\x1b]2; Monitors {self.version} - Running KICKZ | 2cap Balance: {self.balance} | Carted: {carted} | Checkout: {checkoutnum} | Failed: {failed}\x07')

    def injection(self, session, response):
        if session.is_New_IUAM_Challenge(response):
            self.warn('Solving Cloudflare v2 api 2')
            return CF_2(session,response,key="",captcha=False,debug=False).solve() 
        elif session.is_New_Captcha_Challenge(response):
            self.warn('Solving Cloudflare v2 api 2')
            return CF_2(session,response,key="",captcha=True,debug=False).solve() 
        else:
            return response

    def search(self):
        while True: 
            try:
                r = self.s.get(
                    f'https://www.kickz.com/de/search/?q={self.pidmonitor}', 
                    timeout = self.timeout
                )
                if r.status_code == 200:
                    soup = bs(r.text, features='lxml')
                    m = soup.find('div',{'class':'l-plp_grid'}).find_all('section',{'class':'b-product_tile'})
                    title = []
                    img = []
                    pid = []
                    url = []
                    with open('kickz/data.json', 'r') as f:
                        data = json.load(f)
                    for i in m:
                        if 'T-Shirt' not in i['data-product-name']:
                            if 'JACKET' not in i['data-product-name']:
                                if 'ZION' not in i['data-product-name']:
                                    if 'HOODY' not in i['data-product-name']:
                                        if 'TIGHT' not in i['data-product-name']:
                                            if i['data-pid'] not in data.keys():
                                                title.append(i['data-product-name'])
                                                pid.append(i['data-pid'])
                                                img.append(i.find('img',{'loading':'lazy'})['src'])
                                                url.append(i.find('a',{'class':'b-product_tile-image_link'})['href'])
                                                
                    if not title:
                        self.warn('No new products found, monitoring...')
                        time.sleep(self.delay)
                        continue

                    tot = zip(title,pid,img,url)
                    self.connect = list(tot)
                    
                    with open('kickz/data.json', 'r') as f:
                        data = json.load(f)

                    for z in pid:
                        if z not in data.keys():
                            self.success('New product found!')
                            for b in self.connect:
                                if z == b[1]:
                                    data[b[1]] = b[0]
                                    with open('kickz/data.json', 'w') as f:
                                        json.dump(data, f, indent=4)
                                    f.close()
                                    link = f'https://www.kickz.com{b[3]}'
                                    addre = 'https://www.kickz.com/de/checkout/?step=shipping'
                                    cart = 'https://www.kickz.com/de/cart/'
                                    sito = 'https://www.kickz.com/de'
                                    webhook = DiscordWebhook(url=self.webhook_url, content = "")
                                    embed = DiscordEmbed(title=f'{b[0]}', url = link, description = '`New Product Detected!`', color = 0x715aff)
                                    embed.add_embed_field(name='**Site**', value = f'[Kickz]({sito})', inline = True)
                                    embed.add_embed_field(name='**Pid**', value = f'`{b[1]}`', inline = True)
                                    embed.add_embed_field(name='**Checkout Links**', value = f'[Cart]({cart})\n[Checkout]({addre})', inline = False)
                                    embed.set_thumbnail(url=f'{b[2]}')
                                    embed.set_footer(text = f" Monitor - Kickz", icon_url = "")
                                    webhook.add_embed(embed)
                                    webhook.execute()
                    time.sleep(self.delay)
                    continue
                elif r.status_code >= 500 and r.status_code <= 600:
                    self.warn('Site dead, retrying...')
                    time.sleep(self.delay)
                    continue   
                elif r.status_code == 403:
                    self.error('Proxy banned, rotating proxies...')
                    self.build_proxy()
                    time.sleep(self.delay)
                    continue   
                elif r.status_code == 429:
                    self.error('Rate limit, rotating proxies...')
                    self.build_proxy()
                    continue
                else:
                    self.error(f'Unkown error: {r.status_code}, rotating proxies...')
                    self.build_proxy()
                    continue       
            except (requests.exceptions.ProxyError, requests.exceptions.ConnectTimeout, requests.exceptions.ReadTimeout, requests.exceptions.ConnectionError):
                self.error('Connection error, retrying...')
                self.s.cookies.clear()
                self.build_proxy()
                continue
            except Exception as e:
                open(self.logs_path, 'a+').write(f'{e}\n')
                self.error(f'Unable to fetch sizes {e}, retrying...')
                self.build_proxy()
                continue

    def monitor(self):
        p = 0
        while True:
            try:
                self.warn('Getting product...')
                r = self.s.get(
                    f'https://www.kickz.com/on/demandware.store/Sites-Kickz-DE-AT-INT-Site/en/Product-Variation?pid={self.pidmonitor}&quantity=1&ajax=true'
                )
                if r.status_code == 200:
                    r_json = json.loads(r.text)
                    if r_json['product']['releaseClassification']['isComingSoon'] == False:
                        if r_json['product']['available'] == True:
                            self.success('Product instock!')
                            title = r_json['product']['productName']
                            pid = r_json['product']['itemID']
                            
                            price = r_json['product']['price']['sales']['formatted']
                            image = r_json['product']['images']['large'][0]['url']
                            variation = r_json['product']['variationAttributes']
                            size = []
                            load = []
                            for i in variation:
                                if i['attributeId'] == 'size':
                                    for x in i['values']:
                                        if x['selectable'] == True:
                                            size.append(x['displayValue'])
                                            load.append(x['value'])
                            tot = zip(size,load)
                            self.connect = list(tot)

                            if p == 0:
                                self.check = os.path.join(os.path.dirname(sys.argv[0]), f'kickz/{pid}.log')
                                open(self.check, 'a+').write(f'{size}')
                            else:
                                with open(f'kickz/{pid}.log', 'r') as f:
                                    if len(f.read()) == len(str(size)):
                                        self.warn('Sizes didnt change, retrying...')
                                        time.sleep(2)
                                        continue
                            now = datetime.now()
                            timestamp = str(datetime.timestamp(now)).split('.')[0]
                            self.lonk = f'https://www.kickz.com/de/p/{pid}.html?goat={timestamp}'
                            addre = 'https://www.kickz.com/de/checkout/?step=shipping'
                            cart = 'https://www.kickz.com/de/cart/'
                            sito = 'https://www.kickz.com/de'
                            webhook = DiscordWebhook(url=self.webhook_url, content = "")
                            embed = DiscordEmbed(title=title, url = self.lonk, description = f'`{pid}`', color = 0x715aff)
                            embed.add_embed_field(name='**Site**', value = f'[Kickz]({sito})', inline = True)
                            embed.add_embed_field(name='**Price**', value = f'`{price}`', inline = True)
                            emb = []
                            for z in size:
                                for i in self.connect:
                                    if z == i[0]:
                                        emb.append(f'{i[0]} - [LOAD](https://www.kickz.com/de/p/{pid}.html?size={i[1]})')
                            sizesToPing = [emb[x:x+4] for x in range(0, len(emb), 4)]
                            z= ""
                            for s in sizesToPing:
                                z= ('\n'.join(str(x) for x in s))
                                embed.add_embed_field(name="**Sizes**", value=z, inline=False)
                            embed.add_embed_field(name='**Checkout Links**', value = f'[Cart]({cart})\n[Checkout]({addre})', inline = True)
                            embed.add_embed_field(name='**Regions**', value = f'[IT :flag_it:](https://www.kickz.com/it/p/{pid}.html?goat={timestamp}) - [UK :flag_gb:](https://www.kickz.com/uk/p/{pid}.html?goat={timestamp}) - [ES :flag_es:](https://www.kickz.com/es/p/{pid}.html?goat={timestamp})\n[FR :flag_fr:](https://www.kickz.com/fr/p/{pid}.html?goat={timestamp}) - [NL :flag_nl:](https://www.kickz.com/nl/p/{pid}.html?goat={timestamp}) - [CH :flag_ch:](https://www.kickz.com/ch/p/{pid}.html?goat={timestamp})', inline = True)
                            embed.set_thumbnail(url=image)
                            embed.set_footer(text = f" Monitor - Kickz", icon_url = "")
                            webhook.add_embed(embed)
                            webhook.execute()
                            self.success('Webhook sent!')
                            if p == 0:
                                p = 1
                            else:
                                os.remove(f'kickz/{pid}.log')
                                p = 0
                            time.sleep(5)
                            continue
                        else:
                            self.warn('Product oos, retrying...')
                            time.sleep(self.delay)
                            continue
                    else:
                        self.warn('Product not dropped yet, retrying...')
                        time.sleep(self.delay)
                        continue
                elif r.status_code >= 500 and r.status_code <= 600:
                    self.warn('Site dead, retrying...')
                    time.sleep(self.delay)
                    continue   
                elif r.status_code == 403:
                    self.error('Proxy banned, rotating proxies...')
                    self.build_proxy()
                    time.sleep(self.delay)
                    continue   
                elif r.status_code == 429:
                    self.error('Rate limit, rotating proxies...')
                    self.build_proxy()
                    continue
                elif r.status_code == 404:
                    self.error('Page not loaded, monitoring...')
                    time.sleep(self.delay)
                    continue
                else:
                    self.error(f'Unkown error: {r.status_code}, rotating proxies...')
                    self.build_proxy()
                    continue       
            except (requests.exceptions.ProxyError, requests.exceptions.ConnectTimeout, requests.exceptions.ReadTimeout, requests.exceptions.ConnectionError):
                self.error('Connection error, retrying...')
                self.s.cookies.clear()
                self.build_proxy()
                continue
            except Exception as e:
                open(self.logs_path, 'a+').write(f'{e}\n')
                self.error(f'Unable to fetch sizes {e}, retrying...')
                self.build_proxy()
                continue

