import json, requests, threading, csv, urllib3, sys, random, base64, platform, random, ctypes, logging, os, time, re, urllib, cloudscraper, names, lxml
from mods.logger import info, warn, error
from discord_webhook import DiscordWebhook, DiscordEmbed
from bs4 import BeautifulSoup as bs
from playsound import playsound
from twocaptcha import TwoCaptcha
from card_identifier.card_type import identify_card_type
from hawk_cf_api.hawk_cf import CF_2, Cf_challenge_3
from mods.errorHandler import errorHandler
import traceback, ssl

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

class OQIUM():

    def __init__(self, row, webhook, version, i, DISCORD_ID):
        try:
            if machineOS == "Darwin":
                path = os.path.dirname(__file__).rsplit('/', 1)[0]
                path = os.path.join(os.path.dirname(sys.argv[0]), 'oqium/proxies.txt')
            elif machineOS == "Windows": 
                path = os.path.dirname(__file__).rsplit('\\', 1)[0]
                path = os.path.join(os.path.dirname(sys.argv[0]), "oqium/proxies.txt")
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

        ssl_context = ssl.create_default_context()
        ssl_context.set_ciphers('ECDH-RSA-NULL-SHA:ECDH-RSA-RC4-SHA:ECDH-RSA-DES-CBC3-SHA:ECDH-RSA-AES128-SHA:ECDH-RSA-AES256-SHA:ECDH-ECDSA-NULL-SHA:ECDH-ECDSA-RC4-SHA:ECDH-ECDSA-DES-CBC3-SHA:ECDH-ECDSA-AES128-SHA:ECDH-ECDSA-AES256-SHA:ECDHE-RSA-NULL-SHA:ECDHE-RSA-RC4-SHA:ECDHE-RSA-DES-CBC3-SHA:ECDHE-RSA-AES128-SHA:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-NULL-SHA:ECDHE-ECDSA-RC4-SHA:ECDHE-ECDSA-DES-CBC3-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-ECDSA-AES256-SHA:AECDH-NULL-SHA:AECDH-RC4-SHA:AECDH-DES-CBC3-SHA:AECDH-AES128-SHA:AECDH-AES256-SHA')
        ssl_context.set_ecdh_curve('prime256v1')
        ssl_context.options |= (ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3 | ssl.OP_NO_TLSv1_3 | ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1)
        ssl_context.check_hostname=False

        self.s = cloudscraper.create_scraper(
            browser= {
                'browser': 'chrome',
                'mobile': False,
                'platform': 'windows'
            },
            captcha=self.captcha,
            ssl_context = ssl_context,
            doubleDown=False,
            requestPostHook=self.injection
        )

        self.link = row['LINK']

        self.webhook_url = webhook
        self.version = version
        self.threadID = '%03d' % i
        self.delay = int(config['delay'])
        self.discord = DISCORD_ID

        if ' ' in self.link:
            self.link = self.link.replace(' ', '%20')

        #self.fullpassword = f"{self.username}:{self.password}"

        self.timeout = 120
        self.build_proxy()
        self.balance = balancefunc()
        self.bar()


        self.warn('Task started!') 
        if '-' in self.link:
            self.search2()
        else:
            self.search()

    # Red logging

    def error(self, text):
        if 'exception' in text.lower():
            HANDLER.log_exception(traceback.format_exc())
        message = f'[TASK {self.threadID}] - [OQIUM] [{self.link}] - {text}'
        error(message)

    # Green logging

    def success(self, text):
        message = f'[TASK {self.threadID}] - [OQIUM] [{self.link}] - {text}'
        info(message)

    # Yellow logging

    def warn(self, text):
        message = f'[TASK {self.threadID}] - [OQIUM] [{self.link}] - {text}'
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
                f' Monitors {self.version} - Running OQIUM | 2cap Balance: {self.balance} | Carted: {carted} | Checkout: {checkoutnum} | Failed: {failed}')
        else:
            sys.stdout.write(f'\x1b]2; Monitors {self.version} - Running OQIUM | 2cap Balance: {self.balance} | Carted: {carted} | Checkout: {checkoutnum} | Failed: {failed}\x07')


    def injection(self, session, response):
        self.bar()
        if session.is_New_IUAM_Challenge(response):
            self.warn('Solving Cloudflare v2 api 2')
            return CF_2(session,response,key="",captcha=False,debug=False).solve() 
        elif session.is_New_Captcha_Challenge(response):
            self.warn('Solving Cloudflare v2 api 2')
            return CF_2(session,response,key="",captcha=True,debug=False).solve() 
        else:
            return response
    
    def pidmonitor(self):
        self.warn('Getting product page...')
        while True:
            try:
                r = self.s.get(
                    f'{self.link}.json',
                    timeout = self.timeout
                )
                if r.status_code == 200:
                    
                    if 'outofstock' in r.text:
                        self.warn('Product OOS, retrying...')
                        time.sleep(self.delay)
                        continue
                    r_json = json.loads(r.text)
                    title = r_json['product']['title']
                    image = r_json['product']['image']['src']
                    price = r_json['product']['variants'][0]['price']
                    size = []
                    variants = []
                    for i in r_json['product']['variants']:
                        variants.append(i['id'])
                        size.append(i['title'])
                    tot = zip(variants,size)
                    self.connect2 = list(tot)
                    addre = 'https://oqium.com/checkout'
                    sito = 'https://oqium.com/'
                    webhook = DiscordWebhook(url=self.webhook_url, content = "")
                    embed = DiscordEmbed(title=title, url = self.link, color = 0x715aff)
                    embed.add_embed_field(name='**Site**', value = f'[Oquim]({sito})', inline = True)
                    embed.add_embed_field(name='**Price**', value = f'{price}€', inline = True)
                    emb = []
                    for z in size:
                        for i in self.connect2:
                            if z == i[1]:
                                emb.append(f'[{i[1]}](https://oqium.com/cart/{i[0]}:1)')
                    sizesToPing = [emb[x:x+8] for x in range(0, len(emb), 8)]
                    z= ""
                    for s in sizesToPing:
                        z= ('\n'.join(str(x) for x in s))
                        embed.add_embed_field(name="**Sizes**", value=z, inline=False)
                    embed.add_embed_field(name='**Checkout Link**', value = f'[Checkout]({addre})', inline = False)
                    embed.set_thumbnail(url=image)
                    embed.set_footer(text = f" Monitor - Oqium", icon_url = "")
                    webhook.add_embed(embed)
                    webhook.execute()
                    self.success('Product in stock, webhook sent!')
                    time.sleep(10)
                    continue
                elif r.status_code in (502, 599):
                    self.warn('Site is dead, retrying...')
                    time.sleep(self.delay)
                    continue
                elif r.status_code == 500:
                    self.warn('Internal server error, retrying...')
                    time.sleep(self.delay)
                    continue
                elif r.status_code in [403, 429]:
                    self.warn('Proxy banned, retrying...')
                    self.build_proxy()
                    continue
                else:
                    self.warn(f'Error getting product page: {r.status_code}, retrying...')
                    time.sleep(self.delay)
                    self.build_proxy()
                    continue
            except (requests.exceptions.ProxyError, requests.exceptions.ConnectTimeout, requests.exceptions.ReadTimeout, requests.exceptions.ConnectionError):
                self.error('Connection error, retrying...')
                self.build_proxy()
                continue
            except Exception as e:
                self.error(f'Exception getting search: {e}, retrying...')
                self.build_proxy()
                time.sleep(self.delay)
                continue

    def search(self):
        while True:
            try:
                self.warn('Monitoring search...')
                prod = self.s.get(
                    f'https://svc-0-usf.hotyon.com/instantsearch?q={self.link}&apiKey=d5498f0b-2aa4-4b7d-b7d1-ffd7d8761ec1&locale=en&sort=-date',
                    timeout=self.timeout
                )
                if prod.status_code == 200:
                    r_json = json.loads(prod.text)
                    items = r_json['data']['items']
                    if not items:
                        self.warn('No products found, monitoring...')
                        time.sleep(self.delay)
                        continue
                    images = []
                    titles = []
                    variantlist = []
                    urls = []
                    with open('oqium/data.json', 'r') as f:
                        data = json.load(f)
                    for i in items:
                        if 'Jordan 1' in i['title'] or 'Air Force 1' in i['title']:
                            if 'Jordan 3' not in i['title']:
                                if 'Jordan 11' not in i['title']:
                                    if 'Jordan 5' not in i['title']:
                                        if "'92" not in i['title']:
                                            if 'delta' not in i['title']:
                                                if 'PS' not in i['title']:
                                                    if 'TD' not in i['title']:
                                                        if 'Crib' not in i['title']:
                                                            if 'T-shirt' not in i['title']:
                                                                if 'Hoodie' not in i['title']:
                                                                    if i['title'] not in data.keys():
                                                                        titles.append(i['title'])
                                                                        images.append(f"https:{i['images'][0]['url']}")
                                                                        variantlist.append(i['variants'])
                                                                        urls.append(f"https://oqium.com/products/{i['urlName']}")
                    
                    if not variantlist:
                        self.warn('No products found, monitoring...')
                        time.sleep(self.delay)
                        continue
                    tot = zip(titles,images,urls,variantlist)
                    self.connect = list(tot)
                    var = []
                    qty = []
                    size = []
                    for m in variantlist[0]:
                        var.append(m['id'])
                        qty.append(m['available'])
                        for p in m['metafields']:
                            if p['key'] == 'size-eu':
                                size.append(p['value'])

                    tot2 = zip(var,qty,size)
                    self.connect2 = list(tot2)

                    with open('oqium/data.json', 'r') as f:
                        data = json.load(f)

                    for z in titles:
                        if z not in data.keys():
                            self.success('New product found!')
                            for b in self.connect:
                                if z == b[0]:
                                    data[b[0]] = b[2]
                                    with open('oqium/data.json', 'w') as f:
                                        json.dump(data, f, indent=4)
                                    f.close()
                                    link = b[2]
                                    addre = 'https://oqium.com/checkout'
                                    sito = 'https://oqium.com/'
                                    webhook = DiscordWebhook(url=self.webhook_url, content = "")
                                    embed = DiscordEmbed(title=f'{b[0]}', url = link, description = '`New Product Detected!`', color = 0x715aff)
                                    embed.add_embed_field(name='**Site**', value = f'[Oqium]({sito})', inline = True)
                                    try:
                                        emb = []
                                        for k in size:
                                            for i in self.connect2:
                                                if k == i[2]:
                                                    emb.append(f'[{i[2]}](https://oqium.com/cart/{i[0]}:1) - Stock: {i[1]}')
                                        sizesToPing = [emb[x:x+4] for x in range(0, len(emb), 4)]
                                        z= ""
                                        for s in sizesToPing:
                                            z= ('\n'.join(str(x) for x in s))
                                            embed.add_embed_field(name="**Sizes**", value=z, inline=False)
                                    except:
                                        pass
                                    embed.add_embed_field(name='**Checkout Link**', value = f'[Checkout]({addre})', inline = False)
                                    embed.set_thumbnail(url=f'{b[1]}')
                                    embed.set_footer(text = f" Monitor - Oqium", icon_url = "")
                                    webhook.add_embed(embed)
                                    webhook.execute()
                    time.sleep(self.delay)
                    continue
                    
                elif prod.status_code in (502, 599):
                    self.warn('Site is dead, retrying...')
                    time.sleep(self.delay)
                    continue
                elif prod.status_code == 500:
                    self.warn('Internal server error, retrying...')
                    time.sleep(self.delay)
                    continue
                elif prod.status_code in [403, 429]:
                    self.warn('Proxy banned, retrying...')
                    self.build_proxy()
                    continue
                else:
                    self.warn(f'Error getting product page: {prod.status_code}, retrying...')
                    time.sleep(self.delay)
                    self.build_proxy()
                    continue
            except (requests.exceptions.ProxyError, requests.exceptions.ConnectTimeout, requests.exceptions.ReadTimeout, requests.exceptions.ConnectionError):
                self.error('Connection error, retrying...')
                self.build_proxy()
                continue
            except Exception as e:
                self.error(f'Exception getting search: {e}, retrying...')
                self.build_proxy()
                time.sleep(self.delay)
                continue

    def search2(self):
        self.warn('Getting product page...')
        while True:
            try:
                r = self.s.get(
                    'https://shop-oqium.myshopify.com/products.json',
                    timeout = self.timeout
                )
                if r.status_code == 200:
                    r_json = json.loads(r.text)
                    title = []
                    img = []
                    price = []
                    variant = []
                    size = []
                    handle = []
                    test = {}
                    with open('oqium/data.json', 'r') as f:
                        data = json.load(f)
                    for i in r_json['products']:
                        if i['handle'] not in data.keys():
                            #if 'Jordan 1' in i['title'] or 'Jordan 4' not in i['title'] or 'dunk' not in i['title'] or 'air force 1' not in i['title']:
                            test['title'] = i['title']
                            test['image'] = i['images'][0]['src']
                            test['price'] = i['variants'][0]['price']
                            test['handle'] = i['handle']
                            for x in i['variants']:
                                if x['available'] == True:
                                    test['variant'] = x['id']
                                    test['size'] = x['title']
                    if not variant:
                        self.warn('No products in stock, monitoring...')
                        time.sleep(self.delay)
                        continue
                    tot = zip(title,img,price,variant,size,handle)
                    self.connect = list(tot)
                    with open('oqium/data.json', 'r') as f:
                        data = json.load(f)
                    for z in handle:
                        if z not in data.keys():
                            self.success('New product found!')
                            for b in self.connect:
                                if z == b[5]:
                                    data[b[5]] = b[0]
                                    with open('oqium/data.json', 'w') as f:
                                        json.dump(data, f, indent=4)
                                    f.close()
                                    addre = 'https://oqium.com/checkout'
                                    webhook = DiscordWebhook(url=self.webhook_url, content = "")
                                    embed = DiscordEmbed(title=b[0], url=f'https://oqium.com/products/{b[5]}', color = 0x715aff)
                                    embed.add_embed_field(name='**Price**', value = b[2], inline = True)
                                    embed.add_embed_field(name='**Site**', value = f'[Oqium](https://oqium.com/)', inline = True)
                                    try:
                                        emb = []
                                        for k in size:
                                            for i in self.connect:
                                                if k == i[4]:
                                                    emb.append(f'[{i[4]}](https://oqium.com/cart/{i[3]}:1)')
                                        sizesToPing = [emb[x:x+4] for x in range(0, len(emb), 4)]
                                        z= ""
                                        for s in sizesToPing:
                                            z= ('\n'.join(str(x) for x in s))
                                            embed.add_embed_field(name="**Sizes**", value=z, inline=False)
                                    except:
                                        pass
                                    embed.add_embed_field(name='**Checkout Link**', value = f'[Checkout]({addre})', inline = False)
                                    embed.set_thumbnail(url=b[1])
                                    embed.set_footer(text = f" Monitors - Oqium", icon_url = "")
                                    webhook.add_embed(embed)
                                    webhook.execute()
                                    self.success('Product in stock, webhook sent!')
                                    time.sleep(1)
                    continue
                elif r.status_code in (501, 599):
                    self.warn('Site is dead, retrying...')
                    time.sleep(self.delay)
                    continue
                elif r.status_code == 500:
                    self.warn('Internal server error, retrying...')
                    time.sleep(self.delay)
                    continue
                elif r.status_code in [403, 429]:
                    self.warn('Proxy banned, retrying...')
                    self.build_proxy()
                    continue
                else:
                    self.warn(f'Error getting product page: {r.status_code}, retrying...')
                    time.sleep(self.delay)
                    self.build_proxy()
                    continue
            except (requests.exceptions.ProxyError, requests.exceptions.ConnectTimeout, requests.exceptions.ReadTimeout, requests.exceptions.ConnectionError):
                self.error('Connection error, retrying...')
                self.build_proxy()
                continue
            except Exception as e:
                self.error(f'Exception getting search: {e}, retrying...')
                print(traceback.format_exc())
                self.build_proxy()
                time.sleep(self.delay)
                continue