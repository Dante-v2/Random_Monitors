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
import helheim

helheim.auth('ad377af2-3fde-45ba-b676-b77178d0499f')

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

class MEDIAMARKET():

    def __init__(self, row, webhook, version, i, DISCORD_ID):
        try:
            if machineOS == "Darwin":
                path = os.path.dirname(__file__).rsplit('/', 1)[0]
                path = os.path.join(os.path.dirname(sys.argv[0]), 'mediamarket/proxies.txt')
            elif machineOS == "Windows": 
                path = os.path.dirname(__file__).rsplit('\\', 1)[0]
                path = os.path.join(os.path.dirname(sys.argv[0]), "mediamarket/proxies.txt")
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

        #ssl_context = ssl.create_default_context()
        #ssl_context.set_ciphers('ECDH-RSA-NULL-SHA:ECDH-RSA-RC4-SHA:ECDH-RSA-DES-CBC3-SHA:ECDH-RSA-AES128-SHA:ECDH-RSA-AES256-SHA:ECDH-ECDSA-NULL-SHA:ECDH-ECDSA-RC4-SHA:ECDH-ECDSA-DES-CBC3-SHA:ECDH-ECDSA-AES128-SHA:ECDH-ECDSA-AES256-SHA:ECDHE-RSA-NULL-SHA:ECDHE-RSA-RC4-SHA:ECDHE-RSA-DES-CBC3-SHA:ECDHE-RSA-AES128-SHA:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-NULL-SHA:ECDHE-ECDSA-RC4-SHA:ECDHE-ECDSA-DES-CBC3-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-ECDSA-AES256-SHA:AECDH-NULL-SHA:AECDH-RC4-SHA:AECDH-DES-CBC3-SHA:AECDH-AES128-SHA:AECDH-AES256-SHA')
        #ssl_context.set_ecdh_curve('prime256v1')
        #ssl_context.options |= (ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3 | ssl.OP_NO_TLSv1_3 | ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1)
        #ssl_context.check_hostname=False

        self.s = cloudscraper.create_scraper(
            browser= {
                'browser': 'chrome',
                'mobile': False,
                'platform': 'windows'
            },
            captcha=self.captcha,
            #ssl_context = ssl_context,
            doubleDown=False,
            requestPostHook=self.injection
        )

        self.link = row['LINK']
        self.mode = row['MODE']
        self.pid = row['PID']

        self.webhook_url = webhook
        self.version = version
        self.threadID = '%03d' % i
        self.delay = int(config['delay'])
        self.discord = DISCORD_ID


        self.timeout = 120
        self.build_proxy()
        self.balance = balancefunc()
        self.bar()


        self.warn('Task started!') 
        if self.mode == 'searchstock':
            self.searchstock()
        elif self.mode == 'searchnew':
            self.searchnew()
        else:
            self.direct()

    def error(self, text):
        if 'exception' in text.lower():
            HANDLER.log_exception(traceback.format_exc())
        message = f'[TASK {self.threadID}] - [MEDIAMARKET] [{self.mode}] [{self.link}] - {text}'
        error(message)

    def success(self, text):
        message = f'[TASK {self.threadID}] - [MEDIAMARKET] [{self.mode}] [{self.link}] - {text}'
        info(message)

    def warn(self, text):
        message = f'[TASK {self.threadID}] - [MEDIAMARKET] [{self.mode}] [{self.link}] - {text}'
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
                f' Monitors {self.version} - Running MEDIAMARKET | 2cap Balance: {self.balance} | Carted: {carted} | Checkout: {checkoutnum} | Failed: {failed}')
        else:
            sys.stdout.write(f'\x1b]2; Monitors {self.version} - Running MEDIAMARKET | 2cap Balance: {self.balance} | Carted: {carted} | Checkout: {checkoutnum} | Failed: {failed}\x07')

    def injection(self, session, response):
        self.bar()
        if helheim.isChallenge(session, response):
            self.warn('Solving cloudflare...')
            # solve(session, response, max_tries=5)
            return helheim.solve(session, response)
        else:
            return response
        #if session.is_New_IUAM_Challenge(response):
        #    self.warn('Solving Cloudflare v2 api 2')
        #    return CF_2(session,response,key="",captcha=False,debug=False).solve() 
        #elif session.is_New_Captcha_Challenge(response):
        #    self.warn('Solving Cloudflare v2 api 2')
        #    return CF_2(session,response,key="",captcha=True,debug=False).solve() 
        #else:
        #    return response

    def searchstock(self):
        #headers = {
        #    'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
        #    'accept-encoding': 'gzip, deflate, br',
        #    'accept-language': 'en,it-IT;q=0.9,it;q=0.8,en-US;q=0.7,de;q=0.6,es;q=0.5,fr;q=0.4',
        #    'cache-control': 'no-cache',
        #    'pragma': 'no-cache',
        #    'sec-ch-ua': '"Chromium";v="94", "Google Chrome";v="94", ";Not A Brand";v="99"',
        #    'sec-ch-ua-mobile': '?0',
        #    'sec-ch-ua-platform': '"Windows"',
        #    'sec-fetch-dest': 'document',
        #    'sec-fetch-mode': 'navigate',
        #    'sec-fetch-site': 'none',
        #    'sec-fetch-user': '?1',
        #    'upgrade-insecure-requests':'1',
        #    'User-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/94.0.4606.81 Safari/537.36'
        #}
        #self.s.headers.update(headers)
        if 'mediamarkt' in self.link:
            while True:
                try:
                    self.warn('Monitoring search...')
                    prod = self.s.get(
                        self.link,
                        #headers = headers,
                        timeout=125    
                    )
                    if prod.status_code == 200:
                        jsontext = prod.text.split('window.__PRELOADED_STATE__ = ')[1].strip().split(';</script>')[0]
                        r_json = json.loads(jsontext)
                        items = r_json['apolloState']['ROOT_QUERY']['categoryV4({\"experiment\":\"mp\",\"filters\":[],\"page\":1,\"wcsId\":\"769024\"})'.replace('769024',self.pid)]['resultItems']
                        if not items:
                            self.warn('No products found, monitoring...')
                            time.sleep(4)
                            continue
                        images = []
                        titles = []
                        urls = []
                        pid = []
                        quantity = []
                        price = []
                        for i in items:
                            if i['availability']['delivery({})']['quantity'] > 0:
                                price.append(i['price']['price'])
                                titles.append(i['product']['title'])
                                images.append(f"https://assets.mmsrg.com/isr/166325/c1/-/{i['product']['titleImageId']}/fee_786_587_png")
                                urls.append(f'https://www.mediamarkt.de{i["product"]["url"]}')
                                pid.append(i['productId'])
                                quantity.append(i['availability']['delivery({})']['quantity'])
                        if not pid:
                            self.warn('Nothing new, monitoring...')
                            time.sleep(4)
                            continue
                        tot = zip(titles,images,urls,quantity,pid,price)
                        self.connect = list(tot)
                        with open('mediamarket/data.json', 'r') as f:
                            data = json.load(f)
                        for z in self.connect:
                            self.success('New product found!')
                            for b in self.connect:
                                link = b[2]
                                sito = 'https://www.mediamarkt.de/'
                                webhook = DiscordWebhook(url=self.webhook_url, content = "")
                                embed = DiscordEmbed(title=f'{b[0]}', url = link, description = '`New Product Detected!`', color = 0x715aff)
                                embed.add_embed_field(name='**Site**', value = f'[Mediamarkt]({sito})', inline = True)
                                embed.add_embed_field(name='**Pid**', value = f'`{b[4]}`', inline = True)
                                embed.add_embed_field(name="**Stock**", value=f'{b[3]}', inline=True)
                                embed.add_embed_field(name="**Price**", value=f'{b[5]}', inline=True)
                                embed.set_thumbnail(url=b[1])
                                embed.set_footer(text = f" Monitor - Mediamarkt", icon_url = "")
                                webhook.add_embed(embed)
                                webhook.execute()
                        time.sleep(1500)
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
                    print(traceback.format_exc())
                    self.build_proxy()
                    time.sleep(self.delay)
                    continue
        else:
            while True:
                try:
                    self.warn('Monitoring search...')
                    prod = self.s.get(
                        self.link,
                        #headers = headers,
                        timeout=125    
                    )
                    if prod.status_code == 200:
                        jsontext = prod.text.split('window.__PRELOADED_STATE__ = ')[1].strip().split(';</script>')[0]
                        r_json = json.loads(jsontext)
                        items = r_json['apolloState']['ROOT_QUERY']['categoryV4({\"experiment\":\"mp\",\"filters\":[],\"page\":1,\"wcsId\":\"769024\"})'.replace('769024',self.pid)]['resultItems']
                        if not items:
                            self.warn('No products found, monitoring...')
                            time.sleep(4)
                            continue
                        images = []
                        titles = []
                        urls = []
                        pid = []
                        quantity = []
                        price = []
                        for i in items:
                            if i['availability']['delivery({})']['quantity'] > 0:
                                price.append(i['price']['price'])
                                titles.append(i['product']['title'])
                                images.append(f"https://assets.mmsrg.com/isr/166325/c1/-/{i['product']['titleImageId']}/fee_786_587_png")
                                urls.append(f'https://www.saturn.de{i["product"]["url"]}')
                                pid.append(i['productId'])
                                quantity.append(i['availability']['delivery({})']['quantity'])
                        if not pid:
                            self.warn('Nothing new, monitoring...')
                            time.sleep(4)
                            continue
                        tot = zip(titles,images,urls,quantity,pid,price)
                        self.connect = list(tot)
                        for z in self.connect:
                            self.success('New product found!')
                            for b in self.connect:
                                if z[4] == b[4]:
                                    link = b[2]
                                    sito = 'https://www.saturn.de/'
                                    webhook = DiscordWebhook(url=self.webhook_url, content = "")
                                    embed = DiscordEmbed(title=f'{b[0]}', url = link, description = '`New Product Detected!`', color = 0x715aff)
                                    embed.add_embed_field(name='**Site**', value = f'[Saturn]({sito})', inline = True)
                                    embed.add_embed_field(name='**Pid**', value = f'`{b[4]}`', inline = True)
                                    embed.add_embed_field(name="**Stock**", value=f'{b[3]}', inline=True)
                                    embed.add_embed_field(name="**Price**", value=f'{b[5]}', inline=True)
                                    embed.set_thumbnail(url=b[1])
                                    embed.set_footer(text = f" Monitor - Saturn", icon_url = "")
                                    webhook.add_embed(embed)
                                    webhook.execute()
                        time.sleep(1500)
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
                    print(traceback.format_exc())
                    self.build_proxy()
                    time.sleep(self.delay)
                    continue
    
    def searchnew(self):
        #headers = {
        #    'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
        #    'accept-encoding': 'gzip, deflate, br',
        #    'accept-language': 'en,it-IT;q=0.9,it;q=0.8,en-US;q=0.7,de;q=0.6,es;q=0.5,fr;q=0.4',
        #    'cache-control': 'no-cache',
        #    'pragma': 'no-cache',
        #    'sec-ch-ua': '"Chromium";v="94", "Google Chrome";v="94", ";Not A Brand";v="99"',
        #    'sec-ch-ua-mobile': '?0',
        #    'sec-ch-ua-platform': '"Windows"',
        #    'sec-fetch-dest': 'document',
        #    'sec-fetch-mode': 'navigate',
        #    'sec-fetch-site': 'none',
        #    'sec-fetch-user': '?1',
        #    'upgrade-insecure-requests':'1',
        #    'User-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/94.0.4606.81 Safari/537.36'
        #}
        #self.s.headers.update(headers)
        if 'mediamarkt' in self.link:
            while True:
                try:
                    self.warn('Monitoring search...')
                    prod = self.s.get(
                        self.link,
                        #headers = headers,
                        timeout=125    
                    )
                    if prod.status_code == 200:
                        jsontext = prod.text.split('window.__PRELOADED_STATE__ = ')[1].strip().split(';</script>')[0]
                        r_json = json.loads(jsontext)
                        items = r_json['apolloState']['ROOT_QUERY']['categoryV4({\"experiment\":\"mp\",\"filters\":[],\"page\":1,\"wcsId\":\"769024\"})'.replace('769024',self.pid)]['resultItems']
                        if not items:
                            self.warn('No products found, monitoring...')
                            time.sleep(4)
                            continue
                        images = []
                        titles = []
                        urls = []
                        pid = []
                        quantity = []
                        price = []
                        with open('mediamarket/data.json', 'r') as f:
                            data = json.load(f)
                        for i in items:
                            if i['productId'] not in data.keys():
                                price.append(i['price']['price'])
                                titles.append(i['product']['title'])
                                images.append(f"https://assets.mmsrg.com/isr/166325/c1/-/{i['product']['titleImageId']}/fee_786_587_png")
                                urls.append(f'https://www.mediamarkt.de{i["product"]["url"]}')
                                pid.append(i['productId'])
                                quantity.append(i['availability']['delivery({})']['quantity'])
                        if not pid:
                            self.warn('Nothing new, monitoring...')
                            time.sleep(4)
                            continue
                        tot = zip(titles,images,urls,quantity,pid,price)
                        self.connect = list(tot)
                        with open('mediamarket/data.json', 'r') as f:
                            data = json.load(f)
                        for z in self.connect:
                            if z[4] not in data.keys():
                                self.success('New product found!')
                                for b in self.connect:
                                    if z[4] == b[4]:
                                        data[b[4]] = b[0]
                                        with open('mediamarket/data.json', 'w') as f:
                                            json.dump(data, f, indent=4)
                                        f.close()
                                        link = b[2]
                                        sito = 'https://www.mediamarkt.de/'
                                        webhook = DiscordWebhook(url='https://discord.com/api/webhooks/902290043354349610/4_3okkXneWLZAxN50uhRiItxkSlvwFtf08ApUFxXElgL_Mu7CxcBrm-1j1jREmRipLk6', content = "")
                                        embed = DiscordEmbed(title=f'{b[0]}', url = link, description = '`New Product Detected!`', color = 0x715aff)
                                        embed.add_embed_field(name='**Site**', value = f'[Mediamarkt]({sito})', inline = True)
                                        embed.add_embed_field(name='**Pid**', value = f'`{b[4]}`', inline = True)
                                        embed.add_embed_field(name="**Stock**", value=f'{b[3]}', inline=True)
                                        embed.add_embed_field(name="**Price**", value=f'{b[5]}', inline=True)
                                        embed.set_thumbnail(url=b[1])
                                        embed.set_footer(text = f" Monitor - Mediamarkt", icon_url = "")
                                        webhook.add_embed(embed)
                                        webhook.execute()
                        time.sleep(1500)
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
                    print(traceback.format_exc())
                    self.build_proxy()
                    time.sleep(self.delay)
                    continue
        else:
            while True:
                try:
                    self.warn('Monitoring search...')
                    prod = self.s.get(
                        self.link,
                        #headers = headers,
                        timeout=125    
                    )
                    if prod.status_code == 200:
                        jsontext = prod.text.split('window.__PRELOADED_STATE__ = ')[1].strip().split(';</script>')[0]
                        r_json = json.loads(jsontext)
                        items = r_json['apolloState']['ROOT_QUERY']['categoryV4({\"experiment\":\"mp\",\"filters\":[],\"page\":1,\"wcsId\":\"769024\"})'.replace('769024',self.pid)]['resultItems']
                        if not items:
                            self.warn('No products found, monitoring...')
                            time.sleep(4)
                            continue
                        images = []
                        titles = []
                        urls = []
                        pid = []
                        quantity = []
                        price = []
                        with open('mediamarket/data.json', 'r') as f:
                            data = json.load(f)
                        for i in items:
                            if i['productId'] not in data.keys():
                                price.append(i['price']['price'])
                                titles.append(i['product']['title'])
                                images.append(f"https://assets.mmsrg.com/isr/166325/c1/-/{i['product']['titleImageId']}/fee_786_587_png")
                                urls.append(f'https://www.saturn.de{i["product"]["url"]}')
                                pid.append(i['productId'])
                                quantity.append(i['availability']['delivery({})']['quantity'])
                        if not pid:
                            self.warn('Nothing new, monitoring...')
                            time.sleep(4)
                            continue
                        tot = zip(titles,images,urls,quantity,pid,price)
                        self.connect = list(tot)
                        with open('mediamarket/data.json', 'r') as f:
                            data = json.load(f)
                        for z in self.connect:
                            if z[4] not in data.keys():
                                self.success('New product found!')
                                for b in self.connect:
                                    if z[4] == b[4]:
                                        data[b[4]] = b[0]
                                        with open('mediamarket/data.json', 'w') as f:
                                            json.dump(data, f, indent=4)
                                        f.close()
                                        link = b[2]
                                        sito = 'https://www.saturn.de/'
                                        webhook = DiscordWebhook(url='https://discord.com/api/webhooks/902290512407588924/H3Ec6NVmCY609K5vMZcdN7bBwfhKXnpOnu2W2tkqBnTZ2vg5JM6GJ3pjuPYURn6i3M5U', content = "")
                                        embed = DiscordEmbed(title=f'{b[0]}', url = link, description = '`New Product Detected!`', color = 0x715aff)
                                        embed.add_embed_field(name='**Site**', value = f'[Saturn]({sito})', inline = True)
                                        embed.add_embed_field(name='**Pid**', value = f'`{b[4]}`', inline = True)
                                        embed.add_embed_field(name="**Stock**", value=f'{b[3]}', inline=True)
                                        embed.add_embed_field(name="**Price**", value=f'{b[5]}', inline=True)
                                        embed.set_thumbnail(url=b[1])
                                        embed.set_footer(text = f" Monitor - Saturn", icon_url = "")
                                        webhook.add_embed(embed)
                                        webhook.execute()
                        time.sleep(1500)
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
                    print(traceback.format_exc())
                    self.build_proxy()
                    time.sleep(self.delay)
                    continue

    def direct(self):
        headers = {
            'sec-ch-ua':'"Chromium";v="92", " Not A;Brand";v="99", "Google Chrome";v="92"',
            'sec-ch-ua-mobile':'?0',
            'upgrade-insecure-requests':'1',
            'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.159 Safari/537.36',
            'Accept':'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
            'sec-fetch-site':'none',
            'sec-fetch-mode':'navigate',
            'sec-fetch-user':'?1',
            'sec-fetch-dest':'document',
            'Accept-Encoding':'gzip, deflate, br',
            'Accept-Language':'en'
        }
        self.s.headers.update(headers)
        while True:
            try:
                self.warn('Monitoring search...')
                prod = self.s.get(
                    self.link,
                    #headers = headers,
                    allow_redirects = False,
                    timeout=125    
                )
                if prod.status_code == 200: 
                    print(prod.text)
                    if '>in den ware' not in prod.text:
                        self.warn('Product oos, retrying...')
                        time.sleep(self.delay)
                        continue
                    else:
                        soup = bs(prod.text, features='lxml')
                        l = soup.find('div',{'data-test':'mms-select-details-header'})
                        print(l)
                        break
                        #webhook = DiscordWebhook(url=self.webhook_url, content = "")
                        #embed = DiscordEmbed(title=f'', url = self.link, description = '`Product In Stock!`', color = 0x715aff)
                        #embed.add_embed_field(name='**Site**', value = f'[Luisaviaroma]({sito})', inline = True)
                        #embed.add_embed_field(name='**Pid**', value = f'`{b[4]}`', inline = True)
                        #embed.add_embed_field(name="**Sizes**", value=f'{b[3]}', inline=False)
                        #embed.add_embed_field(name='**Checkout Link**', value = f'[Checkout]({addre})', inline = False)
                        #embed.set_thumbnail(url=f'http://proxy.hawkaio.com/{b[1]}')
                        #embed.set_footer(text = f" Monitor - Luisaviaroma", icon_url = "")
                        #webhook.add_embed(embed)
                        #webhook.execute()
                        #time.sleep(1500)
                        #continue
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
                print(traceback.format_exc())
                self.build_proxy()
                time.sleep(self.delay)
                continue