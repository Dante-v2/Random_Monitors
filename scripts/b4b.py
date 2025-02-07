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
import ssl
from datetime import datetime

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

class ChallengeSolver():
    def __init__(self, s):
        self.s = s

    def getCookieByName(self, name):
        for c in self.s.cookies:
            if c.name == name:
                return c.value
        return None

    def addCookie(self, name, value, domain):
        cookie_obj = requests.cookies.create_cookie(domain = domain, name = name, value = value)
        self.s.cookies.set_cookie(cookie_obj)

    def xorKeyValueASeparator(self, keyStr, sourceStr):
        keyLength = len(keyStr)
        sourceLen = len(sourceStr)
        targetStr = ""
        for i in range(sourceLen):
            rPos = i % keyLength
            a = ord(sourceStr[i])
            b = ord(keyStr[rPos])
            c = a ^ b
            d = str(c) + "a"
            targetStr += d
        return targetStr

    def solve_normal_challenge(self, r):
        in1 = r.text.split('"vii="+m2vr("')[1].split('"')[0]
        sbtsckCookie = r.text.split('document.cookie="sbtsck=')[1].split(';')[0]
        self.addCookie("sbtsck", sbtsckCookie, "www.basket4ballers.com")

        sp = r.text.split('function genPid() {return String.fromCharCode(')[1]
        prid = chr(int(sp.split(')')[0])) + chr(int(sp.split(')+String.fromCharCode(')[1].split(')')[0]))
        gprid = prid
        
        prlst = self.getCookieByName("PRLST")
        if (prlst == None or (not (prid in prlst) and len(prlst.split('/')) < 5)):
            if prlst and prlst != '':
                prlst += "/"
            elif not prlst:
                prlst = ''
            self.addCookie("PRLST", prlst + prid, "www.basket4ballers.com"    )

        cookieUTGv2 = self.getCookieByName("UTGv2")
        cookieUTGv2Splitted = cookieUTGv2
        if cookieUTGv2 != None and "-" in cookieUTGv2Splitted:
            cookieUTGv2Splitted = cookieUTGv2Splitted.split("-")[1]
        if cookieUTGv2 == None or cookieUTGv2 != cookieUTGv2Splitted:
            if(cookieUTGv2 == None):
                cookieUTGv2 = r.text.split('this.sbbsv("')[1].split('"')[0]
                self.addCookie("UTGv2", cookieUTGv2, "www.basket4ballers.com")
            else:
                cookieUTGv2 = cookieUTGv2Splitted
                self.s.cookies.set('UTGv2', cookieUTGv2, domain='www.basket4ballers.com', path='/')

        ts = int(time.time()) - int(r.text.split('/1000)-')[1].split(")")[0])
        r2 = self.s.get(f'https://basket4ballers.com/sbbi/?sbbpg=sbbShell&gprid={gprid}&sbbgs={cookieUTGv2}&ddl={ts}')
        
        if "sbrmpIO=start()" in r2.text:
            return 3

        if not "D-" in cookieUTGv2:
            cookieUTGv2 = "D-" + cookieUTGv2
            self.s.cookies.set('UTGv2', cookieUTGv2, domain='www.basket4ballers.com', path='/')

        trstr = r2.text.split('{sbbdep("')[1].split('"')[0].strip()
        trstrup = trstr.upper()
        data = {
            "cdmsg": self.xorKeyValueASeparator(trstrup, "v0phj7cahz-41-zezw4iqrr-w7mccahwofo-egdctq9g4nf-noieo-90.3095389639745667"),
            "femsg": 1,
            "bhvmsg": self.xorKeyValueASeparator(trstrup, "0pvc0b7oa39j-iws9o"),
            "futgs": "",
            "jsdk": trstr,
            "glv": self.xorKeyValueASeparator(trstrup, "N"),
            "lext": self.xorKeyValueASeparator(trstrup, "[0,0]"),
            "sdrv": 0
        }
        r3 = self.s.post(f'https://basket4ballers.com/sbbi/?sbbpg=sbbShell&gprid={gprid}&sbbgs={cookieUTGv2}&ddl={ts}', data = data)
        if 'smbtFrm()' in r3.text:
            return 2
        else:
            return 0

    def solve_captcha_challenge(self, r):
        html = r.text.split("data:image/png;base64,")[1].split('"')[0]
        captchaID = r.text.split('SBM.captchaInput.id="')[1].split('"')[0]
        sbtsckCookie = r.text.split('doc.cookie="sbtsck=')[1].split(';')[0]
        self.addCookie('sbtsck', sbtsckCookie, 'www.basket4ballers.com')
        captchaIDlen = len(captchaID)
        totalTime = 0
        output = ""
        for i in range(3):
            t = random.randint(0,2)
            if i == 0:
                t += random.randint(5,15)
            c = t if t < captchaIDlen else captchaIDlen - 1
            output += captchaID[c]
            totalTime += t
        output = str(totalTime) + "/" + output
        pvstr = output
        solver = TwoCaptcha(config['2captcha'])
        result = solver.normal(html, caseSensitive=1)
        self.addCookie('pvstr', pvstr, 'www.basket4ballers.com')
        self.addCookie('cnfc', result['code'], 'www.basket4ballers.com')
        return 1

class B4B():

    def __init__(self, row, webhook, version, i, DISCORD_ID):
        try:
            if machineOS == "Darwin":
                path = os.path.dirname(__file__).rsplit('/', 1)[0]
                path = os.path.join(os.path.dirname(sys.argv[0]), 'b4b/proxies.txt')
            elif machineOS == "Windows": 
                path = os.path.dirname(__file__).rsplit('\\', 1)[0]
                path = os.path.join(os.path.dirname(sys.argv[0]), "b4b/proxies.txt")
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
            browser={
                'browser': 'chrome',
                'mobile': False,
                'platform': 'windows'
            },
            captcha=self.captcha,
            doubleDown=False,
            ssl_context=ssl_context,
            requestPostHook=self.injection
        )

        self.link = row['LINK'] 

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
        if 'http' in self.link:
            self.getprod()
        else:
            self.search()

    # Red logging

    def error(self, text):
        if 'exception' in text.lower():
            HANDLER.log_exception(traceback.format_exc())
        message = f'[TASK {self.threadID}] - [B4B] - {text}'
        error(message)

    # Green logging

    def success(self, text):
        message = f'[TASK {self.threadID}] - [B4B] - {text}'
        info(message)

    # Yellow logging

    def warn(self, text):
        message = f'[TASK {self.threadID}] - [B4B] - {text}'
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
                f' Monitors {self.version} - Running B4B | 2cap Balance: {self.balance} | Carted: {carted} | Checkout: {checkoutnum} | Failed: {failed}')
        else:
            sys.stdout.write(f'\x1b]2; Monitors {self.version} - Running B4B | 2cap Balance: {self.balance} | Carted: {carted} | Checkout: {checkoutnum} | Failed: {failed}\x07')


    def injection(self, session, response):
        if session.is_New_IUAM_Challenge(response):
            self.warn('Solving Cloudflare v2 api 2')
            return CF_2(session,response,key="",captcha=False,debug=False).solve() 
        elif session.is_New_Captcha_Challenge(response):
            self.warn('Solving Cloudflare v2 api 2')
            return CF_2(session,response,key="",captcha=True,debug=False).solve() 
        else:
            return response
    
    def handle_challenge(self, r):
        challenge_solver = ChallengeSolver(self.s)
        if '"vii="' in r.text:
            self.warn('Solving challenge...')
            try:
                result = challenge_solver.solve_normal_challenge(r)
                if result in [1,2]:
                    self.success(f'Successfully solved challenge! [{result}]')
                    return True
                elif result == 3:
                    self.success(f'Successfully solved challenge! [1]')
                    return False
                else:
                    self.error('Error solving challenge...')
                    return False
            except Exception as e:
                self.error(f'Exception solving challenge: {e.__class__.__name__}')
                return False
        elif 'captchaImageInline' in r.text:
            self.warn('Solving captcha challenge...')
            try:
                result = challenge_solver.solve_captcha_challenge(r)
                if result in [1,2]:
                    self.success(f'Successfully solved challenge! [{result}]')
                    return True
                elif result == 3:
                    return False
                else:
                    self.error('Error solving challenge...')
                    return False
            except Exception as e:
                self.error(f'Exception solving challenge: {e.__class__.__name__}')
                return False

    def getprod(self):
        self.warn('Getting product page...')
        t = 0
        self.x = ''
        while True:
            try:
                now = datetime.now()
                timestamp = str(datetime.timestamp(now)).split('.')[0]
                r = self.s.get(
                    f'{self.link}?timestamp={timestamp}', 
                    timeout = self.timeout
                )
                if 'stackpath' in r.text and any([x in r.text for x in ['captchaImageInline', '"vii="']]):
                    self.handle_challenge(r)
                    continue
                if 'This product is no longer available.' in r.text:
                    self.warn('Product OOS, retrying...')
                    time.sleep(self.delay)
                    continue
                if '<em class="caps">sold out</em>' in r.text.lower():
                    self.warn('Prodcut OOS, monitoring...')
                    time.sleep(self.delay)
                    continue
                if 'countdown' in r.text:
                    self.warn('Product not released yet, monitoring...')
                    time.sleep(self.delay)
                    continue
                if r.status_code == 200:
                    self.check = r.text
                    soup = bs(r.text, features='lxml')
                    self.title = soup.find("span", {"itemprop": "name"}).text
                    self.price = soup.find("span", {"itemprop": "price"}).text
                    self.tokennn = r.text.split("static_token='")[1].split("';")[0]
                    try:
                        self.img = r.text.split('rel="gal1" href="')[1].split('"')[0]
                    except:
                        self.img = "https://cdn2.basket4ballers.com/img/logo.jpg"
                    var = r.text.split("var combinations=")[1].split("var combinationsFromController")[0]
                    var2 = var[:-1]
                    self.prodid = var.split('"reference":"IDP')[1].split('--')[0]                      
                    r_json = json.loads(var2)
                    variant = list(r_json.keys())
                    quantity = []
                    size = []
                    for i in variant:
                        quant = r_json[i]
                        if quant['quantity'] > 0:
                            quantity.append(quant['quantity'])
                            sizee = quant['attributes_values']
                            size.append(sizee['15'])
                    connect = zip(variant, size, quantity)
                    self.connect = list(connect)
                    if "Disponible dans" in r.text:
                        self.warn(f'{self.title} not dropped yet, monitoring...')
                        time.sleep(self.delay)
                        continue
                    if len(size) < 1:
                        self.warn(f'{self.title} OOS, monitoring...')
                        time.sleep(self.delay)
                        continue
                    else:
                        if t == 1:
                            if self.x == self.connect:
                                time.sleep(900)
                        self.success(f'{self.title} is in stock...')
                        webhook = DiscordWebhook(url=self.webhook_url, content = "")
                        embed = DiscordEmbed(title=self.title, url = self.link, color = 0x715aff)
                        embed.add_embed_field(name='**Site**', value = f'Basket4Ballers', inline = True)
                        embed.add_embed_field(name='**Price**', value = f'`{self.price}`', inline = True)
                        emb = []
                        for z in size:
                            for i in self.connect:
                                if i[2] > 0:
                                    if z == i[1]:
                                        emb.append(f'{i[1]} [{i[2]}] - [ATC](https://www.basket4ballers.com/en/commande?controller=cart&add=1&hunt=true&id_product={self.prodid}&ipa={i[0]})')
                        sizesToPing = [emb[x:x+4] for x in range(0, len(emb), 4)]
                        z= ""
                        for s in sizesToPing:
                            z= ('\n'.join(str(x) for x in s))
                            embed.add_embed_field(name="**Sizes**", value=z, inline=False)
                        embed.add_embed_field(name='**Checkout Link**', value = f'[Checkout](https://www.basket4ballers.com/en/commande?step=1)', inline = True)
                        embed.add_embed_field(name='**Quicktasks**', value = f'[Phoenix](http://127.0.0.1:5005/phoenixqt?site=b4b&input={self.link})', inline = True)
                        embed.set_thumbnail(url=self.img)
                        embed.set_footer(text = f" Monitor - B4B", icon_url = "")
                        webhook.add_embed(embed)
                        webhook.execute()
                        time.sleep(100)
                        if t == 0:
                            self.x = self.connect
                        if t == 1:
                            if self.x == self.connect:
                                break
                            else:
                                t = 0
                                self.x = self.connect
                        t = 1
                        continue            
                elif r.status_code == 403:
                    self.error('Proxy banned, retrying...')
                    self.build_proxy()
                    time.sleep(self.delay)
                    continue
                elif r.status_code == 404:
                    self.warn('Product page not loaded, retrying...')
                    time.sleep(self.delay)
                    continue
                elif r.status_code == 429:
                    self.error('Rate limit, retryng...')
                    self.build_proxy()
                    time.sleep(self.delay)
                    continue
                elif r.status_code >= 500 and r.status_code <= 600:
                    self.warn('Site dead, retrying...')
                    time.sleep(self.delay)
                    continue
                else:
                    self.error(f'Error while getting product page: {r.status_code}, retrying...')
                    time.sleep(self.delay)
                    self.build_proxy()
                    continue
            except (requests.exceptions.ProxyError, requests.exceptions.ConnectTimeout, requests.exceptions.ReadTimeout, requests.exceptions.ConnectionError):
                self.error('Connection error, retrying...')
                self.build_proxy()
                continue
            except Exception as e: 
                self.error(f'Exception while getting product page: {e}, retrying...')
                self.s.cookies.clear()
                self.build_proxy()
                continue

    def search(self):
        while True:
            try:
                now = datetime.now()
                timestamp = str(datetime.timestamp(now)).split('.')[0]
                r = self.s.get(
                    f'https://www.basket4ballers.com/fr/recherche?q={self.link}&ajaxSearch=1&timestamp={timestamp}',
                    timeout = self.timeout
                )
                if 'stackpath' in r.text and any([x in r.text for x in ['captchaImageInline', '"vii="']]):
                    self.handle_challenge(r)
                    continue
                if r.status_code == 200:
                    with open('b4b/data.json', 'r') as f:
                        data = json.load(f)
                    r_json = json.loads(r.text)
                    for i in r_json:
                        if 'Jordan 1' in i['pname'] or 'Jordan 4' in i['pname']:
                            if i['pname'] not in data.keys():
                                data[i['pname']] = i['product_link']
                                with open('b4b/data.json', 'w') as f:
                                    json.dump(data, f, indent=4)
                                webhook = DiscordWebhook(url=self.webhook_url, content = "")
                                embed = DiscordEmbed(title=i['pname'], url = i['product_link'], color = 0x715aff)
                                embed.add_embed_field(name='**Site**', value = f'Basket4Ballers', inline = False)
                                embed.add_embed_field(name='**Checkout Link**', value = f'[Checkout](https://www.basket4ballers.com/en/commande?step=1)', inline = True)
                                embed.add_embed_field(name='**Quicktasks**', value = f'[Phoenix](http://127.0.0.1:5005/phoenixqt?site=b4b&input={self.link})', inline = True)
                                #embed.set_thumbnail(url=i['cover'].replace('\\',''))
                                embed.set_footer(text = f" Monitor - B4B", icon_url = "")
                                webhook.add_embed(embed)
                                webhook.execute()
                                self.success('Webhook sent!')

                    self.warn('No products found, retrying...')
                    time.sleep(self.delay)
                    continue
                elif r.status_code == 403:
                    self.error('Proxy banned, retrying...')
                    self.build_proxy()
                    time.sleep(self.delay)
                    continue
                elif r.status_code == 404:
                    self.warn('Product page not loaded, retrying...')
                    time.sleep(self.delay)
                    continue
                elif r.status_code == 429:
                    self.error('Rate limit, retryng...')
                    self.build_proxy()
                    time.sleep(self.delay)
                    continue
                elif r.status_code >= 500 and r.status_code <= 600:
                    self.warn('Site dead, retrying...')
                    time.sleep(self.delay)
                    continue
                else:
                    self.error(f'Error while getting search: {r.status_code}, retrying...')
                    time.sleep(self.delay)
                    self.build_proxy()
                    continue
            except (requests.exceptions.ProxyError, requests.exceptions.ConnectTimeout, requests.exceptions.ReadTimeout, requests.exceptions.ConnectionError):
                self.error('Connection error, retrying...')
                self.build_proxy()
                continue
            except Exception as e:
                self.error(f'Exception while getting search: {e}, retrying...')
                self.s.cookies.clear()
                self.build_proxy()
                continue