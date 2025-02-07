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

class GALERIES():

    def __init__(self, row, webhook, version, i, DISCORD_ID):

        self.logs_path = os.path.join(os.path.dirname(sys.argv[0]), 'galeries/exceptions.log')
        try:
            if machineOS == "Darwin":
                path = os.path.dirname(__file__).rsplit('/', 1)[0]
                path = os.path.join(os.path.dirname(sys.argv[0]), 'galeries/proxies.txt')
            elif machineOS == "Windows": 
                path = os.path.dirname(__file__).rsplit('\\', 1)[0]
                path = os.path.join(os.path.dirname(sys.argv[0]), "galeries/proxies.txt")
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

        self.pidmonitor = row['KW']

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

        self.search()

    def error(self, text):
        message = f'[TASK {self.threadID}] - [GALERIES] [{self.pidmonitor}] - {text}'
        error(message)

    # Green logging

    def success(self, text):
        message = f'[TASK {self.threadID}] - [GALERIES] [{self.pidmonitor}] - {text}'
        info(message)

    # Yellow logging

    def warn(self, text):
        message = f'[TASK {self.threadID}] - [GALERIES] [{self.pidmonitor}] - {text}'
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
                f' Monitors {self.version} - Running GALERIES | 2cap Balance: {self.balance} | Carted: {carted} | Checkout: {checkoutnum} | Failed: {failed}')
        else:
            sys.stdout.write(f'\x1b]2; Monitors {self.version} - Running GALERIES | 2cap Balance: {self.balance} | Carted: {carted} | Checkout: {checkoutnum} | Failed: {failed}\x07')

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
        headers = {
            'sec-ch-ua': '"Chromium";v="92", " Not A;Brand";v="99", "Google Chrome";v="92"',
            'Accept': 'application/json',
            'sec-ch-ua-mobile': '?0',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.159 Safari/537.36',
            'content-type': 'application/x-www-form-urlencoded',
            'Origin': 'https://www.galerieslafayette.com',
            'Sec-Fetch-Site': 'cross-site',
            'Sec-Fetch-Mode': 'cors',
            'Sec-Fetch-Dest': 'empty',
            'Referer': 'https://www.galerieslafayette.com/',
            'Accept-Encoding': 'gzip, deflate, br',
            'Accept-Language': 'en,it-IT;q=0.9,it;q=0.8,en-US;q=0.7,de;q=0.6,es;q=0.5,fr;q=0.4'
        }
        payload = {"requests":[{"indexName":"prod_gl_products","params":f"query={self.pidmonitor}&page=0&analyticsTags=%5B%22INSTANTSEARCH%22%2C%22INSTANTSEARCH_MOBILE%22%5D&getRankingInfo=true&facetingAfterDistinct=true&facets=%5B%22dynamicAttributes%22%2C%22nonNumericAttributes.GroupeProduit%22%2C%22nonNumericAttributes.brand%22%2C%22nonNumericAttributes.color%22%2C%22nonNumericAttributes.size%22%2C%22price.current%22%2C%22categories.univers%22%2C%22price.discount%22%5D&tagFilters="}]}
        while True: 
            try:
                r = self.s.post(
                    f'https://cdz6bknqrw-dsn.algolia.net/1/indexes/*/queries?x-algolia-agent=Algolia%20for%20vanilla%20JavaScript%20(lite)%203.30.0%3Binstantsearch.js%202.10.4%3BJS%20Helper%202.26.1&x-algolia-application-id=CDZ6BKNQRW&x-algolia-api-key=e4306e50d5efa978338e2b3b29bfaa9c', 
                    json = payload,
                    headers = headers,
                    timeout = self.timeout
                )
                if r.status_code == 200:
                    r_json = json.loads(r.text)
                    m = r_json['results'][0]['hits']
                    title = []
                    url = []
                    stock = []
                    with open('galeries/data.json', 'r') as f:
                        data = json.load(f)
                    for i in m:
                        if i['title'] not in data.keys():
                            title.append(i['title'])
                            url.append(i['productUrl'])
                            stock.append(i['stock'])
                        #if 'Tee' not in i.find('p',{'class':'pdt-title'}).text:
                        #    if 'Pant' not in i.find('h2',{'itemprop':'name'}).text:
                        #        if 'Crew' not in i.find('h2',{'itemprop':'name'}).text:
                        #            if 'Sweater' not in i.find('h2',{'itemprop':'name'}).text:
                        #                if 'Slide' not in i.find('h2',{'itemprop':'name'}).text:
                        #                    if 'Belt' not in i.find('h2',{'itemprop':'name'}).text:
                        #                        if 'TEE' not in i.find('h2',{'itemprop':'name'}).text:
                        #                            if 'Sweat' not in i.find('h2',{'itemprop':'name'}).text:
                        #                                if 'Essential' not in i.find('h2',{'itemprop':'name'}).text:
                        #                                    if 'CAMISETA' not in i.find('h2',{'itemprop':'name'}).text:
                        #                                        if 'Chuck' not in i.find('h2',{'itemprop':'name'}).text:
                        #                                            if i['data-id-product'] not in data.keys():
                        #                                                title.append(i.find('h2',{'itemprop':'name'}).text)
                        #                                                url.append(i.find('a')['href'])
                        
                    if not title:
                        self.warn('No new products found, monitoring...')
                        time.sleep(self.delay)
                        continue

                    tot = zip(title,url,stock)
                    self.connect = list(tot)
                    
                    with open('galeries/data.json', 'r') as f:
                        data = json.load(f)

                    for z in title:
                        if z not in data.keys():
                            self.success('New product found!')
                            for b in self.connect:
                                if z == b[0]:
                                    data[b[0]] = b[1]
                                    with open('galeries/data.json', 'w') as f:
                                        json.dump(data, f, indent=4)
                                    f.close()
                                    sito = 'https://www.galerieslafayette.com/'
                                    phoenixqt = f'http://127.0.0.1:5005/phoenixqt?site=galeries&input=https://www.galerieslafayette.com{b[1]}'
                                    webhook = DiscordWebhook(url=self.webhook_url, content = "")
                                    embed = DiscordEmbed(title=f'{b[0]}', url = f'https://www.galerieslafayette.com{b[1]}', description = '`New Product Detected!`', color = 0x715aff)
                                    embed.add_embed_field(name='**Site**', value = f'[Galerieslafayette]({sito})', inline = True)
                                    embed.add_embed_field(name='**Stock**', value = f'`{b[2]}`', inline = True)
                                    embed.add_embed_field(name='**Checkout Link**', value = f'[Checkout (Only use this if you are logged in)](https://www.galerieslafayette.com/deliveries/1)', inline = False)
                                    embed.add_embed_field(name='**Quicktasks**', value = f'[Phoenix]({phoenixqt})', inline = True)
                                    embed.set_footer(text = f" Monitor - Galerieslafayette", icon_url = "")
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