import json, requests, threading, csv, urllib3, sys, random, base64, platform, random, ctypes, logging, os, time, re, urllib, cloudscraper, names, lxml
from mods.logger import info, warn, error
from discord_webhook import DiscordWebhook, DiscordEmbed
from bs4 import BeautifulSoup as bs
from playsound import playsound
from twocaptcha import TwoCaptcha
from card_identifier.card_type import identify_card_type
from hawk_cf_api.hawk_cf import CF_2, Cf_challenge_3
from mods.errorHandler import errorHandler
import traceback

HANDLER = errorHandler(__file__)
urllib3.disable_warnings()
machineOS = platform.system()
sys.dont_write_bytecode = True

threads = {}
ipaddr = None

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

checkoutnum = 0
failed = 0
carted = 0

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

class SNIPES():

    def __init__(self, row, webhook, version, i, DISCORD_ID):
        try:
            if machineOS == "Darwin":
                path = os.path.dirname(__file__).rsplit('/', 1)[0]
                path = os.path.join(os.path.dirname(sys.argv[0]), 'snipes/proxies.txt')
            elif machineOS == "Windows": 
                path = os.path.dirname(__file__).rsplit('\\', 1)[0]
                path = os.path.join(os.path.dirname(sys.argv[0]), "snipes/proxies.txt")
            with open(f'{path}', 'r') as f:
                proxylist = f.read()
                if proxylist == '':
                    self.all_proxies = None
                else:
                    self.all_proxies = proxylist.split('\n')
                f.close()

        except:
            error("FAILED TO READ PROXIES, STARTING LOCAL HOST")
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
            time.sleep(5)
            sys.exit(1)

        self.s = cloudscraper.create_scraper(
            browser= {
                'browser': 'chrome',
                'mobile': False,
                'platform': 'windows'
            },
            captcha=self.captcha,
            doubleDown=False,
            requestPostHook=self.injection
        )

        self.pid = row['PID']

        self.webhook_url = webhook
        self.version = version
        self.threadID = '%03d' % i
        self.delay = int(config['delay'])
        self.discord = DISCORD_ID

        #self.fullpassword = f"{self.username}:{self.password}"

        self.timeout = 120
        self.build_proxy()
        self.balance = balancefunc()
        self.bar()

        self.warn('Task started!') 
        self.getprod()

    def error(self, text):
        if 'exception' in text.lower():
            HANDLER.log_exception(traceback.format_exc())
        message = f'[TASK {self.threadID}] - [SNIPES] [{self.pid}] - {text}'
        error(message)

    def success(self, text):
        message = f'[TASK {self.threadID}] - [SNIPES] [{self.pid}] - {text}'
        info(message)

    def warn(self, text):
        message = f'[TASK {self.threadID}] - [SNIPES] [{self.pid}] - {text}'
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
                f' Monitors {self.version} - Running SNIPES | 2cap Balance: {self.balance} | Carted: {carted} | Checkout: {checkoutnum} | Failed: {failed}')
        else:
            sys.stdout.write(f'\x1b]2; Monitors {self.version} - Running SNIPES | 2cap Balance: {self.balance} | Carted: {carted} | Checkout: {checkoutnum} | Failed: {failed}\x07')


    def injection(self, session, response):
        if session.is_New_IUAM_Challenge(response):
            self.warn('Solving Cloudflare v2 api 2')
            return CF_2(session,response,key="",captcha=False,debug=False).solve() 
        elif session.is_New_Captcha_Challenge(response):
            self.warn('Solving Cloudflare v2 api 2')
            return CF_2(session,response,key="",captcha=True,debug=False).solve() 
        else:
            return response
    
    def getprod(self):
        head = {'Accept': 'application/json, text/plain, /','Accept-Encoding': 'gzip, deflate, br','Accept-Language': 'it-it','User-Agent':'SNIPES/phone'}
        self.warn('Getting product page...')
        while True:
            try:
                r = self.s.get(
                    f'https://www.snipes.it/s/snse-SOUTH/dw/shop/v19_5/products/{self.pid}?c_app=true&client_id=27a186cb-e098-41fe-8409-a62f3a28ac83&locale=it-IT&expand=images,prices,variations,availability&c_var_inv=true&currency=EUR', 
                    headers = head,
                    timeout = self.timeout
                )
                if r.status_code == 200:
                    r_json = json.loads(r.text)
                    print(r_json)
                    self.img = r_json['image_groups'][0]['images'][0]['link']
                    self.title = r_json['image_groups'][0]['images'][0]['title']
                    self.price = r_json['c_list_price']
                    check = r_json['inventory']['orderable']
                    if check == False:
                        self.warn('Product oos, retrying...')
                        time.sleep(self.delay)
                        continue
                    self.success('Succesfully got product page!')
                    p = r_json['variants']
                    variantlist = []
                    sizelist = []
                    for i in p:
                        if i['orderable'] == True:
                            variantlist.append(i['product_id'])
                            sizelist.append(i['variation_values']['size'])
                    if not sizelist:
                        self.warn('Product oos, retrying...')
                        time.sleep(self.delay)
                        continue
                    print('a')
                    tot = zip(variantlist, sizelist)
                    self.connect = list(tot)
                    webhook = DiscordWebhook(url=self.webhook_url, content = "")
                    embed = DiscordEmbed(title=self.title, url = f'https://www.snipes.it/{self.pid}.html', color = 0x715aff)
                    embed.add_embed_field(name='**Site**', value = f'`Snipes`', inline = True)
                    embed.add_embed_field(name='**Price**', value = f'{self.price}', inline = True)
                    emb = []
                    for z in sizelist:
                        for i in self.connect:
                            if z == i[1]:
                                emb.append(f'{i[1]} - [LOAD](https://snipes.it/{i[0]}.html)')
                    sizesToPing = [emb[x:x+4] for x in range(0, len(emb), 4)]
                    z= ""
                    for s in sizesToPing:
                        z= ('\n'.join(str(x) for x in s))
                        embed.add_embed_field(name="**Sizes**", value=z, inline=False)
                    embed.add_embed_field(name='**Checkout Link**', value = f'[Checkout](https://www.snipes.it/checkout)', inline = True)
                    embed.set_thumbnail(url=self.img)
                    embed.set_footer(text = " Monitors - Snipes", icon_url = "https://www.adigeo.com/fileadmin/user_upload/GLOBAL/brand_stores/logos/snipes.png")
                    webhook.add_embed(embed)
                    webhook.execute()
                    break
                elif r.status_code >= 500 and r.status_code <= 600:
                    self.warn('Site dead, retrying...')
                    time.sleep(self.delay)
                    continue   
                elif r.status_code == 403:
                    self.error('Proxy banned, rotating proxies...')
                    self.build_proxy()
                    continue   
                elif r.status_code == 404:
                    self.error('Page not loaded, retrying...')
                    time.sleep(self.delay)
                    continue   
                elif r.status_code == 429:
                    self.error('Rate limit, rotating proxies...')
                    self.build_proxy()
                    continue
                else:
                    self.error(f'Unkown error while getting product page: {r.status_code}, rotating proxies...')
                    self.build_proxy()
                    continue
            except (requests.exceptions.ProxyError, requests.exceptions.ConnectTimeout, requests.exceptions.ReadTimeout, requests.exceptions.ConnectionError):
                self.error('Connection error, retrying...')
                self.build_proxy()
                continue
            except Exception as e: 
                self.error(f'Exception error while getting product page: {e}, restarting...')
                print(traceback.format_exc())
                self.build_proxy()
                time.sleep(25)
                continue