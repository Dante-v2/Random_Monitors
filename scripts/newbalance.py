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

class NEWBALANCE():

    def __init__(self, row, webhook, version, i, DISCORD_ID):
        try:
            if machineOS == "Darwin":
                path = os.path.dirname(__file__).rsplit('/', 1)[0]
                path = os.path.join(os.path.dirname(sys.argv[0]), 'newbalance/proxies.txt')
            elif machineOS == "Windows": 
                path = os.path.dirname(__file__).rsplit('\\', 1)[0]
                path = os.path.join(os.path.dirname(sys.argv[0]), "newbalance/proxies.txt")
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
            doubleDown=False,
            ssl_context = ssl_context,
            requestPostHook=self.injection
        )

        self.link = row['LINK']
        self.style = row['STYLE']
        self.type = row['TYPE']

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
        if self.type == 'DIRECT':
            self.pidmonitor()
        else:
            self.search()

    # Red logging

    def error(self, text):
        if 'exception' in text.lower():
            HANDLER.log_exception(traceback.format_exc())
        message = f'[TASK {self.threadID}] - [NEW BALANCE] [{self.link}] [{self.type}] - {text}'
        error(message)
    # Green logging
    def success(self, text):
        message = f'[TASK {self.threadID}] - [NEW BALANCE] [{self.link}] [{self.type}] - {text}'
        info(message)
    # Yellow logging

    def warn(self, text):
        message = f'[TASK {self.threadID}] - [NEW BALANCE] [{self.link}] [{self.type}] - {text}'
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
                f' Monitors {self.version} - Running NEW BALANCE | 2cap Balance: {self.balance} | Carted: {carted} | Checkout: {checkoutnum} | Failed: {failed}')
        else:
            sys.stdout.write(f'\x1b]2; Monitors {self.version} - Running NEW BALANCE | 2cap Balance: {self.balance} | Carted: {carted} | Checkout: {checkoutnum} | Failed: {failed}\x07')

    def injection(self, session, response):
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
                    f'https://www.newbalance.it/{self.link}.html?dwvar_{self.link}_style={self.style}',
                    timeout = self.timeout
                )
                if r.status_code == 200:
                    if 'Spiacente, questo articolo' in r.text:
                        self.warn('Product oos, monitoring...')
                        time.sleep(self.delay)
                        continue
                    soup = bs(r.text, features='lxml')
                    title = soup.find('h1',{'class':'product-name hidden-sm-down'}).text
                    price = soup.find('div',{'class':'prices'}).text.strip()
                    img = soup.find('div',{'class':'carousel-item zoom-image-js active'}).find('picture').find('img',{'class':'tile-image img-fluid lazyload lazypreload'})['data-src']
                    de = 'https://www.newbalance.de'
                    uk = 'https://www.newbalance.co.uk'
                    belgio = 'https://www.newbalance.be'
                    es = 'https://www.newbalance.es'
                    fr = 'https://www.newbalance.fr'
                    it = 'https://www.newbalance.it'
                    nl = 'https://nl.newbalance.eu'
                    pt = 'https://www.newbalance.pt'
                    ch = 'https://www.newbalance.ch'
                    pl = 'https://www.newbalance.pl'
                    link = f'{de}/{self.link}.html?dwvar_{self.link}_style={self.style}'
                    comp = f'/{self.link}.html?dwvar_{self.link}_style={self.style}'
                    checkout = '/on/demandware.store/Sites-NBEU-Site/it_IT/Checkout-Begin'
                    webhook = DiscordWebhook(url=self.webhook_url, content = "")
                    embed = DiscordEmbed(title=title, url = link, description = '`Product in stock!`', color = 0x715aff)
                    embed.add_embed_field(name='**Site**', value = f'[New Balance]({de})', inline = True)
                    embed.add_embed_field(name='**Pid**', value = self.link, inline = True)
                    embed.add_embed_field(name='**Price**', value = price, inline = True)
                    embed.add_embed_field(name='**Product Page**', value = f'[:flag_de:]({de}{comp}) - [:flag_gb:]({uk}{comp}) - [:flag_be:]({belgio}{comp}) - [:flag_es:]({es}{comp}) - [:flag_fr:]({fr}{comp}) - [:flag_it:]({it}{comp}) - [:flag_pt:]({pt}{comp}) - [:flag_ch:]({ch}{comp}) - [:flag_pl:]({pl}{comp})', inline = True)
                    try:
                        embed.set_thumbnail(url=img)
                    except:
                        pass
                    embed.set_footer(text = f" Monitor - New Balance", icon_url = "")
                    webhook.add_embed(embed)
                    webhook.execute()
                    self.success('Product in stock!')
                    time.sleep(600)
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
                elif r.status_code == 410:
                    self.warn('Page not loaded, retrying...')
                    self.build_proxy()
                    self.s.cookies.clear()
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
                    f'https://www.newbalance.it/it/search?q={self.link}&search-button=&lang=it_IT', 
                    timeout=self.timeout
                )
                if prod.status_code == 200:
                    soup = bs(prod.text, features='lxml')
                    x = soup.find('div',{'class':'row product-grid'})
                    l = soup.find_all('div',{'class':'pgptiles col-6 col-lg-4 px-1 px-lg-2'})
                    pid = []
                    href = []
                    img = []
                    color = []
                    title = []
                    with open('newbalance/data.json', 'r') as f:
                        data = json.load(f)
                    for i in l:
                        #pid.append(i.find('div',{'class':'product w-100'})['data-pid'])
                        po = i.find('div',{'class':'product-tile w-100'}).find('div',{'class':'tile-body'}).find('div',{'class':'color-swatches'}).find_all('a',{'class':'sildes p-1'})#.find('img',{'class':'swatch swatch-circle rounded-0 h-100 m-0 lazyload'}))#['href'])#.find('div',{'class':'swatches row mx-auto'}))#.find_all('div',{'role':'group'}))
                        im = i.find('div',{'class':'product-tile w-100'}).find('div',{'class':'tile-body'}).find('div',{'class':'color-swatches'}).find_all('img',{'class':'swatch swatch-circle rounded-0 h-100 m-0 lazyload'})
                        for m in po:
                            href.append(m['href'])
                            pid.append(m['href'].split('dwvar_')[1].split('_')[0])
                            color.append(m['href'].split('style=')[1])
                            title.append(m['href'].split('/pd/')[1].split('/')[0])
                        for s in im:
                            img.append(s['data-src'].split(' 1x')[0])
                    tot = zip(pid,href,img,color,title)
                    self.connect = list(tot)
                    for z in color:
                        if z not in data.keys():
                            self.success('New product found!')
                            for b in self.connect:
                                if z == b[3]:
                                    data[b[3]] = b[1]
                                    with open('newbalance/data.json', 'w') as f:
                                        json.dump(data, f, indent=4)
                                    f.close()
                                    de = 'https://www.newbalance.de'
                                    uk = 'https://www.newbalance.co.uk'
                                    belgio = 'https://www.newbalance.be'
                                    es = 'https://www.newbalance.es'
                                    fr = 'https://www.newbalance.fr'
                                    it = 'https://www.newbalance.it'
                                    nl = 'https://nl.newbalance.eu'
                                    pt = 'https://www.newbalance.pt'
                                    ch = 'https://www.newbalance.ch'
                                    pl = 'https://www.newbalance.pl'
                                    #sito = 'https://www.newbalance.de/de'
                                    link = f'{de}{b[1]}'
                                    #checkout = '/on/demandware.store/Sites-NBEU-Site/it_IT/Checkout-Begin'
                                    webhook = DiscordWebhook(url=self.webhook_url, content = "")
                                    embed = DiscordEmbed(title=f'{b[4]}', url = link, description = '`New Product Detected!`', color = 0x715aff)
                                    embed.add_embed_field(name='**Site**', value = f'[New Balance]({de})', inline = True)
                                    embed.add_embed_field(name='**Pid**', value = f'{b[0]}', inline = True)
                                    embed.add_embed_field(name='**Style**', value = f'{b[3]}', inline = True)
                                    #embed.add_embed_field(name='**Checkout Link**', value = f'[:flag_de:]({de}{checkout}) - [:flag_gb:]({uk}{checkout}) - [:flag_be:]({belgio}{checkout})\n[:flag_es:]({es}{checkout}) - [:flag_fr:]({fr}{checkout}) - [:flag_it:]({it}{checkout})\n[:flag_pt:]({pt}{checkout}) - [:flag_ch:]({ch}{checkout}) - [:flag_pl:]({pl}{checkout})', inline = True)
                                    embed.add_embed_field(name='**Product Page**', value = f'[:flag_de:]({de}{b[1]}) - [:flag_gb:]({uk}{b[1]}) - [:flag_be:]({belgio}{b[1]}) - [:flag_es:]({es}{b[1]}) - [:flag_fr:]({fr}{b[1]}) - [:flag_it:]({it}{b[1]}) - [:flag_pt:]({pt}{b[1]}) - [:flag_ch:]({ch}{b[1]}) - [:flag_pl:]({pl}{b[1]})', inline = True)
                                    embed.set_thumbnail(url=f'{b[2]}')
                                    embed.set_footer(text = f" Monitor - New Balance", icon_url = "")
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
                print(traceback.format_exc())
                self.build_proxy()
                time.sleep(self.delay)
                continue