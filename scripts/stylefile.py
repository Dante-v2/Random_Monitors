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

class STYLEFILE():

    def __init__(self, row, webhook, version, i, DISCORD_ID):
        try:
            if machineOS == "Darwin":
                path = os.path.dirname(__file__).rsplit('/', 1)[0]
                path = os.path.join(os.path.dirname(sys.argv[0]), 'stylefile/proxies.txt')
            elif machineOS == "Windows": 
                path = os.path.dirname(__file__).rsplit('\\', 1)[0]
                path = os.path.join(os.path.dirname(sys.argv[0]), "stylefile/proxies.txt")
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
        self.country = row['COUNTRY']
        self.type = row['TYPE']

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
        if 'P.' in self.link:
            self.pidmonitor()
        else:
            if self.type == 'M':
                self.searchm()
            elif self.type:
                self.searchw()

    # Red logging

    def error(self, text):
        if 'exception' in text.lower():
            HANDLER.log_exception(traceback.format_exc())
        message = f'[TASK {self.threadID}] - [STYLEFILE] [{self.link}] [{self.country}] [{self.type}] - {text}'
        error(message)

    # Green logging

    def success(self, text):
        message = f'[TASK {self.threadID}] - [STYLEFILE] [{self.link}] [{self.country}] [{self.type}] - {text}'
        info(message)

    # Yellow logging

    def warn(self, text):
        message = f'[TASK {self.threadID}] - [STYLEFILE] [{self.link}] [{self.country}] [{self.type}] - {text}'
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
                f' Monitors {self.version} - Running STYLEFILE | 2cap Balance: {self.balance} | Carted: {carted} | Checkout: {checkoutnum} | Failed: {failed}')
        else:
            sys.stdout.write(f'\x1b]2; Monitors {self.version} - Running STYLEFILE | 2cap Balance: {self.balance} | Carted: {carted} | Checkout: {checkoutnum} | Failed: {failed}\x07')


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
        if self.country == 'COM':
            linknaz = f'https://www.stylefile.com//{self.link}.html'
        elif self.country == 'DE':
            linknaz = f'https://www.stylefile.de//{self.link}.html'
        self.warn('Getting product page...')
        self.x = ''
        t = 0
        while True:
            try:
                r = self.s.get(
                    linknaz,
                    timeout = self.timeout
                )
                if r.status_code == 200:
                    soup = bs(r.text, features='lxml')
                    menu = soup.find('div',{'class':'swiper-box'}).find('ul',{'class':'product-variations_list'}).find_all('li',{'class':'product-variations_list-item selectable variation-group-value'})
                    
                    if not menu:
                        self.warn('Product oos, monitoring...')
                        time.sleep(self.delay)
                        continue
                    title = r.text.split('<title>')[1].split('</title>')[0]
                    image = r.text.split('<img class="primary-image" src="')[1].split('"')[0]
                    size = []
                    href = []
                    for i in menu:
                        href.append(i.find('a')['href'])
                        size.append(i.text.replace('\n',''))
                    tot = zip(href,size)
                    self.connect2 = list(tot)
                    if t == 1:
                        if self.x == self.connect2:
                            time.sleep(900)
                    if '.de' in linknaz:
                        sito = 'https://www.stylefile.de/'
                        addre = 'https://www.stylefile.de/adressen'
                        ci = ':flag_de:'
                    if '.com' in linknaz:
                        ci = ':flag_eu:'
                        sito = 'https://www.stylefile.com/'
                        addre = 'https://www.stylefile.com/shipping/'
                    webhook = DiscordWebhook(url=self.webhook_url, content = "")
                    embed = DiscordEmbed(title=title, url = linknaz, color = 0x715aff)
                    embed.add_embed_field(name='**Site**', value = f'[Stylefile {ci}]({sito})', inline = True)
                    emb = []
                    for z in size:
                        for i in self.connect2:
                            if z == i[1]:
                                emb.append(f'[{i[1]}]({i[0]})')
                    sizesToPing = [emb[x:x+4] for x in range(0, len(emb), 4)]
                    z= ""
                    for s in sizesToPing:
                        z= ('\n'.join(str(x) for x in s))
                        embed.add_embed_field(name="**Sizes**", value=z, inline=False)
                    embed.add_embed_field(name='**Checkout Link**', value = f'[Address]({addre})', inline = False)
                    embed.set_thumbnail(url=image)
                    embed.set_footer(text = f" Monitor - Stylefile", icon_url = "")
                    webhook.add_embed(embed)
                    webhook.execute()
                    self.success('Product in stock, webhook sent!')
                    time.sleep(100)
                    if t == 0:
                        self.x = self.connect2
                    if t == 1:
                        if self.x == self.connect2:
                            break
                        else:
                            t = 0
                            self.x = self.connect2
                    t = 1
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

    def searchm(self):
        if self.country == 'COM':
            linknaz = f'https://www.stylefile.com/men/shoes/?q={self.link}'
        elif self.country == 'DE':
            linknaz = f'https://www.stylefile.de/men/schuhe/?q={self.link}'
        else:
            self.error('Enter an existing country')
            sys.exit()
        while True:
            try:
                self.warn('Monitoring search...')
                prod = self.s.get(
                    linknaz, 
                    timeout=self.timeout
                )
                if prod.status_code == 200:
                    soup = bs(prod.text, features='lxml')
                    if self.country == 'DE':
                        searchresult = soup.find('div',{'class':'search-result-content'})
                        title = soup.find_all('div',{'class':'product-tile'})
                        images = []
                        pid = []
                        titles = []
                        if self.link == 'jordan+1':
                            for i in title:
                                f = i.find('div',{'class':'product-name'}).find('span',{'class':'name-product-tile'}).text
                                if '1' in f and '11' not in f:
                                    pid.append(i['data-itemid'])
                                    images.append(i.find('div',{'class':'product-image'}).find('img')['src'])
                                    titles.append(i.find('div',{'class':'product-name'}).find('span',{'class':'name-product-tile'}).text)
                                    tot = zip(pid,images,titles)
                                    self.connect = list(tot)
                        elif self.link == 'dunk':
                            for i in title:
                                f = i.find('div',{'class':'product-name'}).find('span',{'class':'name-product-tile'}).text
                                if 'converse' not in f and 'all star' not in f:
                                    pid.append(i['data-itemid'])
                                    images.append(i.find('div',{'class':'product-image'}).find('img')['src'])
                                    titles.append(i.find('div',{'class':'product-name'}).find('span',{'class':'name-product-tile'}).text)
                                    tot = zip(pid,images,titles)
                                    self.connect = list(tot)
                        else:
                            for i in title:
                                f = i.find('div',{'class':'product-name'}).find('span',{'class':'name-product-tile'}).text
                                pid.append(i['data-itemid'])
                                images.append(i.find('div',{'class':'product-image'}).find('img')['src'])
                                titles.append(i.find('div',{'class':'product-name'}).find('span',{'class':'name-product-tile'}).text)
                                tot = zip(pid,images,titles)
                                self.connect = list(tot)
                        with open('stylefile/data.json', 'r') as f:
                            data = json.load(f)
                        for z in pid:
                            if z not in data.keys():
                                self.success('New product found!')
                                for b in self.connect:
                                    if z == b[0]:
                                        data[b[0]] = b[2]
                                        with open('stylefile/data.json', 'w') as f:
                                            json.dump(data, f, indent=4)
                                        f.close()
                                        link = 'https://www.stylefile.de//{}.html'.format(b[0])
                                        sito = 'https://www.stylefile.de/'
                                        addre = 'https://www.stylefile.de/adressen'
                                        webhook = DiscordWebhook(url=self.webhook_url, content = "")
                                        embed = DiscordEmbed(title=f'{b[2]}', url = link, description = '`New Product Detected!`', color = 0x715aff)
                                        embed.add_embed_field(name='**Site**', value = f'[Stylefile :flag_de:]({sito})', inline = True)
                                        embed.add_embed_field(name='**Checkout Link**', value = f'[Address]({addre})', inline = False)
                                        embed.set_thumbnail(url=f'{b[1]}')
                                        embed.set_footer(text = f" Monitor - Stylefile", icon_url = "")
                                        webhook.add_embed(embed)
                                        webhook.execute()
                                        self.lonk = link
                                        self.prodaft()
                        time.sleep(self.delay)
                        continue
                    elif self.country == 'COM':
                        searchresult = soup.find('div',{'class':'search-result-content'})
                        title = soup.find_all('div',{'class':'product-tile'})
                        images = []
                        pid = []
                        titles = []
                        if self.link == 'jordan+1':
                            for i in title:
                                f = i.find('div',{'class':'product-name'}).find('span',{'class':'name-product-tile'}).text
                                if '1' in f and '11' not in f:
                                    pid.append(i['data-itemid'])
                                    images.append(i.find('div',{'class':'product-image'}).find('img')['src'])
                                    titles.append(i.find('div',{'class':'product-name'}).find('span',{'class':'name-product-tile'}).text)
                                    tot = zip(pid,images,titles)
                                    self.connect = list(tot)
                        elif self.link == 'dunk':
                            for i in title:
                                f = i.find('div',{'class':'product-name'}).find('span',{'class':'name-product-tile'}).text
                                if 'converse' not in f and 'all star' not in f:
                                    pid.append(i['data-itemid'])
                                    images.append(i.find('div',{'class':'product-image'}).find('img')['src'])
                                    titles.append(i.find('div',{'class':'product-name'}).find('span',{'class':'name-product-tile'}).text)
                                    tot = zip(pid,images,titles)
                                    self.connect = list(tot)
                        else:
                            for i in title:
                                f = i.find('div',{'class':'product-name'}).find('span',{'class':'name-product-tile'}).text
                                pid.append(i['data-itemid'])
                                images.append(i.find('div',{'class':'product-image'}).find('img')['src'])
                                titles.append(i.find('div',{'class':'product-name'}).find('span',{'class':'name-product-tile'}).text)
                                tot = zip(pid,images,titles)
                                self.connect = list(tot)
                        with open('stylefile/comdata.json', 'r') as f:
                            data = json.load(f)
                        for z in pid:
                            if z not in data.keys():
                                self.success('New product found!')
                                for b in self.connect:
                                    if z == b[0]:
                                        data[b[0]] = b[2]
                                        with open('stylefile/comdata.json', 'w') as f:
                                            json.dump(data, f, indent=4)
                                        f.close()
                                        link = 'https://www.stylefile.com//{}.html'.format(b[0])
                                        sito = 'https://www.stylefile.com/'
                                        addre = 'https://www.stylefile.com/shipping/'
                                        webhook = DiscordWebhook(url=self.webhook_url, content = "")
                                        embed = DiscordEmbed(title=f'{b[2]}', url = link, description = '`New Product Detected!`', color = 0x715aff)
                                        embed.add_embed_field(name='**Site**', value = f'[Stylefile :flag_eu:]({sito})', inline = True)
                                        embed.add_embed_field(name='**Checkout Link**', value = f'[Address]({addre})', inline = False)
                                        embed.set_thumbnail(url=f'{b[1]}')
                                        embed.set_footer(text = f" Monitor - Stylefile", icon_url = "")
                                        webhook.add_embed(embed)
                                        webhook.execute()
                                        self.lonk = link
                                        self.prodaft()
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
    
    def searchw(self):
        if self.country == 'COM':
            linknaz = f'https://www.stylefile.com/women/shoes/?q={self.link}'
        elif self.country == 'DE':
            linknaz = f'https://www.stylefile.de/women/schuhe/?q={self.link}'
        else:
            self.error('Enter an existing country')
            sys.exit()
        while True:
            try:
                self.warn('Monitoring search...')
                prod = self.s.get(
                    linknaz, 
                    timeout=self.timeout
                )
                if prod.status_code == 200:
                    if 'returned no results' in prod.text:
                        self.warn('No product found...')
                        time.sleep(self.delay)
                        continue
                    if 'ergab keine Ergebnisse' in prod.text:
                        self.warn('No product found...')
                        time.sleep(self.delay)
                        continue
                    soup = bs(prod.text, features='lxml')
                    if self.country == 'DE':
                        searchresult = soup.find('div',{'class':'search-result-content'})
                        title = soup.find_all('div',{'class':'product-tile'})
                        images = []
                        pid = []
                        titles = []
                        if self.link == 'jordan+1':
                            for i in title:
                                f = i.find('div',{'class':'product-name'}).find('span',{'class':'name-product-tile'}).text
                                if '1' in f and '11' not in f:
                                    pid.append(i['data-itemid'])
                                    images.append(i.find('div',{'class':'product-image'}).find('img')['src'])
                                    titles.append(i.find('div',{'class':'product-name'}).find('span',{'class':'name-product-tile'}).text)
                                    tot = zip(pid,images,titles)
                                    self.connect = list(tot)
                        elif self.link == 'dunk':
                            for i in title:
                                f = i.find('div',{'class':'product-name'}).find('span',{'class':'name-product-tile'}).text
                                if 'converse' not in f and 'all star' not in f:
                                    pid.append(i['data-itemid'])
                                    images.append(i.find('div',{'class':'product-image'}).find('img')['src'])
                                    titles.append(i.find('div',{'class':'product-name'}).find('span',{'class':'name-product-tile'}).text)
                                    tot = zip(pid,images,titles)
                                    self.connect = list(tot)
                        else:
                            for i in title:
                                f = i.find('div',{'class':'product-name'}).find('span',{'class':'name-product-tile'}).text
                                pid.append(i['data-itemid'])
                                images.append(i.find('div',{'class':'product-image'}).find('img')['src'])
                                titles.append(i.find('div',{'class':'product-name'}).find('span',{'class':'name-product-tile'}).text)
                                tot = zip(pid,images,titles)
                                self.connect = list(tot)
                        with open('stylefile/data.json', 'r') as f:
                            data = json.load(f)
                        for z in pid:
                            if z not in data.keys():
                                self.success('New product found!')
                                for b in self.connect:
                                    if z == b[0]:
                                        data[b[0]] = b[2]
                                        with open('stylefile/data.json', 'w') as f:
                                            json.dump(data, f, indent=4)
                                        f.close()
                                        link = 'https://www.stylefile.de//{}.html'.format(b[0])
                                        sito = 'https://www.stylefile.de/'
                                        addre = 'https://www.stylefile.de/adressen'
                                        webhook = DiscordWebhook(url=self.webhook_url, content = "")
                                        embed = DiscordEmbed(title=f'{b[2]}', url = link, description = '`New Product Detected!`', color = 0x715aff)
                                        embed.add_embed_field(name='**Site**', value = f'[Stylefile :flag_de:]({sito})', inline = True)
                                        embed.add_embed_field(name='**Checkout Link**', value = f'[Address]({addre})', inline = False)
                                        embed.set_thumbnail(url=f'{b[1]}')
                                        embed.set_footer(text = f" Monitor - Stylefile", icon_url = "")
                                        webhook.add_embed(embed)
                                        webhook.execute()
                                        self.lonk = link
                                        self.prodaft()
                        time.sleep(self.delay)
                        continue
                    elif self.country == 'COM':
                        searchresult = soup.find('div',{'class':'search-result-content'})
                        title = soup.find_all('div',{'class':'product-tile'})
                        images = []
                        pid = []
                        titles = []
                        if self.link == 'jordan+1':
                            for i in title:
                                f = i.find('div',{'class':'product-name'}).find('span',{'class':'name-product-tile'}).text
                                if '1' in f and '11' not in f:
                                    pid.append(i['data-itemid'])
                                    images.append(i.find('div',{'class':'product-image'}).find('img')['src'])
                                    titles.append(i.find('div',{'class':'product-name'}).find('span',{'class':'name-product-tile'}).text)
                                    tot = zip(pid,images,titles)
                                    self.connect = list(tot)
                        elif self.link == 'dunk':
                            for i in title:
                                f = i.find('div',{'class':'product-name'}).find('span',{'class':'name-product-tile'}).text
                                if 'converse' not in f and 'all star' not in f:
                                    pid.append(i['data-itemid'])
                                    images.append(i.find('div',{'class':'product-image'}).find('img')['src'])
                                    titles.append(i.find('div',{'class':'product-name'}).find('span',{'class':'name-product-tile'}).text)
                                    tot = zip(pid,images,titles)
                                    self.connect = list(tot)
                        else:
                            for i in title:
                                f = i.find('div',{'class':'product-name'}).find('span',{'class':'name-product-tile'}).text
                                pid.append(i['data-itemid'])
                                images.append(i.find('div',{'class':'product-image'}).find('img')['src'])
                                titles.append(i.find('div',{'class':'product-name'}).find('span',{'class':'name-product-tile'}).text)
                                tot = zip(pid,images,titles)
                                self.connect = list(tot)
                        with open('stylefile/comdata.json', 'r') as f:
                            data = json.load(f)
                        for z in pid:
                            if z not in data.keys():
                                self.success('New product found!')
                                for b in self.connect:
                                    if z == b[0]:
                                        data[b[0]] = b[2]
                                        with open('stylefile/comdata.json', 'w') as f:
                                            json.dump(data, f, indent=4)
                                        f.close()
                                        link = 'https://www.stylefile.com//{}.html'.format(b[0])
                                        sito = 'https://www.stylefile.com/'
                                        addre = 'https://www.stylefile.com/shipping/'
                                        webhook = DiscordWebhook(url=self.webhook_url, content = "")
                                        embed = DiscordEmbed(title=f'{b[2]}', url = link, description = '`New Product Detected!`', color = 0x715aff)
                                        embed.add_embed_field(name='**Site**', value = f'[Stylefile :flag_eu:]({sito})', inline = True)
                                        embed.add_embed_field(name='**Checkout Link**', value = f'[Address]({addre})', inline = False)
                                        embed.set_thumbnail(url=f'{b[1]}')
                                        embed.set_footer(text = f" Monitor - Stylefile", icon_url = "")
                                        webhook.add_embed(embed)
                                        webhook.execute()
                                        self.lonk = link
                                        self.prodaft()
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

    def prodaft(self):
        self.warn('Getting product page...')
        while True:
            try:
                r = self.s.get(
                    self.lonk,
                    timeout = self.timeout
                )
                if r.status_code == 200:
                    soup = bs(r.text, features='lxml')
                    menu = soup.find('div',{'class':'swiper-box'}).find('ul',{'class':'product-variations_list'}).find_all('li',{'class':'product-variations_list-item selectable variation-group-value'})
                    title = r.text.split('<title>')[1].split('</title>')[0]
                    image = r.text.split('<img class="primary-image" src="')[1].split('"')[0]
                    size = []
                    href = []
                    for i in menu:
                        href.append(i.find('a')['href'])
                        size.append(i.text.replace('\n',''))
                    tot = zip(href,size)
                    self.connect2 = list(tot)
                    if '.de' in self.lonk:
                        sito = 'https://www.stylefile.de/'
                        addre = 'https://www.stylefile.de/adressen'
                        ci = '.de'
                    if '.com' in self.lonk:
                        ci = '.com'
                        sito = 'https://www.stylefile.com/'
                        addre = 'https://www.stylefile.com/shipping/'
                    webhook = DiscordWebhook(url=self.webhook_url, content = "")
                    embed = DiscordEmbed(title=title, url = self.lonk, color = 0x715aff)
                    embed.add_embed_field(name='**Site**', value = f'[Stylefile{ci}]({sito})', inline = True)
                    emb = []
                    for z in size:
                        for i in self.connect2:
                            if z == i[1]:
                                emb.append(f'[{i[1]}]({i[0]})')
                    sizesToPing = [emb[x:x+4] for x in range(0, len(emb), 4)]
                    z= ""
                    for s in sizesToPing:
                        z= ('\n'.join(str(x) for x in s))
                        embed.add_embed_field(name="**Sizes**", value=z, inline=False)
                    embed.add_embed_field(name='**Checkout Link**', value = f'[Address]({addre})', inline = False)
                    embed.set_thumbnail(url=image)
                    embed.set_footer(text = f" Monitor - Stylefile", icon_url = "")
                    webhook.add_embed(embed)
                    webhook.execute()
                    break
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
        return self.success('Succesfully got product!')