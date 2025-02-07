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

class SLAMJAM():

    def __init__(self, row, webhook, version, i, DISCORD_ID):

        self.logs_path = os.path.join(os.path.dirname(sys.argv[0]), 'slamjam/exceptions.log')
        try:
            if machineOS == "Darwin":
                path = os.path.dirname(__file__).rsplit('/', 1)[0]
                path = os.path.join(os.path.dirname(sys.argv[0]), 'slamjam/proxies.txt')
            elif machineOS == "Windows": 
                path = os.path.dirname(__file__).rsplit('\\', 1)[0]
                path = os.path.join(os.path.dirname(sys.argv[0]), "slamjam/proxies.txt")
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
                ssl_context=ssl_context,
                requestPostHook=self.injection
        )

        self.pidmonitor = row['SKU']

        self.discord = DISCORD_ID
    
        self.twoCaptcha = str(config['2captcha'])
        
        self.delay = int(config['delay'])
        self.timeout = 120
          
        self.balance = balancefunc()
        self.threadID = '%03d' % i
        #self.webhook_url = ''
        self.webhook_url = webhook
        self.version = version
        self.build_proxy()
        self.monster = config['capmonster']

        self.bar()

        self.warn('Task started!')
        self.monitor()

    def error(self, text):
        message = f'[TASK {self.threadID}] - [SLAMJAM] [{self.pidmonitor}] - {text}'
        error(message)

    def success(self, text):
        message = f'[TASK {self.threadID}] - [SLAMJAM] [{self.pidmonitor}] - {text}'
        info(message)

    def warn(self, text):
        message = f'[TASK {self.threadID}] - [SLAMJAM] [{self.pidmonitor}] - {text}'
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

    def get_ddCaptchaChallenge(self):

        try:

            self.warn('Parsing challenge...')

            js_script = """
            const navigator = {
                userAgent: 'user_agent',
                language: 'singleLangHere',
                languages: 'langListHere'
            }

            ddExecuteCaptchaChallenge = function(r, t) {
                function e(r, t, e) {
                    this.seed = r, this.currentNumber = r % t, this.offsetParameter = t, this.multiplier = e, this.currentNumber <= 0 && (this.currentNumber += t)
                }
                e.prototype.getNext = function() {
                    return this.currentNumber = this.multiplier * this.currentNumber % this.offsetParameter, this.currentNumber
                };
                for (var n = [function(r, t) {
                        var e = 26157,
                            n = 0;
                        if (s = "VEc5dmEybHVaeUJtYjNJZ1lTQnFiMkkvSUVOdmJuUmhZM1FnZFhNZ1lYUWdZWEJ3YkhsQVpHRjBZV1J2YldVdVkyOGdkMmwwYUNCMGFHVWdabTlzYkc5M2FXNW5JR052WkdVNklERTJOMlJ6YUdSb01ITnVhSE0", navigator.userAgent) {
                            for (var a = 0; a < s.length; a += 1 % Math.ceil(1 + 3.1425172 / navigator.userAgent.length)) n += s.charCodeAt(a).toString(2) | e ^ t;
                            return n
                        }
                        return s ^ t
                    }, function(r, t) {
                        for (var e = (navigator.userAgent.length << Math.max(r, 3)).toString(2), n = -42, a = 0; a < e.length; a++) n += e.charCodeAt(a) ^ t << a % 3;
                        return n
                    }, function(r, t) {
                        for (var e = 0, n = (navigator.language ? navigator.language.substr(0, 2) : void 0 !== navigator.languages ? navigator.languages[0].substr(0, 2) : "default").toLocaleLowerCase() + t, a = 0; a < n.length; a++) e = ((e = ((e += n.charCodeAt(a) << Math.min((a + t) % (1 + r), 2)) << 3) - e + n.charCodeAt(a)) & e) >> a;
                        return e
                    }], a = new e(function(r) {
                        for (var t = 126 ^ r.charCodeAt(0), e = 1; e < r.length; e++) t += (r.charCodeAt(e) * e ^ r.charCodeAt(e - 1)) >> e % 2;
                        return t
                    }(r), 1723, 7532), o = a.seed, u = 0; u < t; u++) {
                    o ^= (0, n[a.getNext() % n.length])(u, a.seed)
                }
                ddCaptchaChallenge = o
                return ddCaptchaChallenge
            }
            ddExecuteCaptchaChallenge("putCidHere", 10);
            """.replace("putCidHere",self.cid).replace("user_agent","Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.198 Safari/537.36") \
                .replace("singleLangHere", "en-US").replace("langListHere", "en-US,en;q=0.9,sr;q=0.8")

            self.result = js2py.eval_js(js_script)
            self.warn('Got challenge...')
            return self.result

        except Exception as e:
            print(e)

    def connection2(self):
        try:
            captchalink = f"https://geo.captcha-delivery.com/captcha/?initialCid={self.initialcid}&hash={self.hsh}&cid={self.cid}&t=fe&referer=https://www.slamjam.com/on/demandware.store/Sites-slamjam-Site&s={self.sss}"
            headers = {
                'accept-encoding': 'gzip, deflate, br',
                'pragma': 'no-cache',
                'upgrade-insecure-requests': '1',
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.66 Safari/537.36',
                'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,/;q=0.8,application/signed-exchange;v=b3;q=0.9',
                'sec-fetch-site': 'none',
                'sec-fetch-mode': 'navigate',
                'sec-fetch-user': '?1',
                'sec-fetch-dest': 'document',
                'accept-language': 'en-US,en;q=0.9,sr;q=0.8'
            }
            s = requests.Session()
            r = s.get(captchalink, proxies = self.s.proxies, headers = headers)   
            if r.status_code == 200:
                ciao = r.text
                self.challenge = ciao.split("challenge: '")[1].split("',")[0]
                self.gt = ciao.split("gt: '")[1].split("',")[0]
                self.ip = ciao.split("'&x-forwarded-for=' + encodeURIComponent('")[1].split("'")[0]
                self.initialcid = ciao.split("&icid=' + encodeURIComponent('")[1].split("'")[0]
                self.hsh = ciao.split("&hash=' + encodeURIComponent('")[1].split("'")[0]
                self.ip = ciao.split("(IP ")[1].split(")")[0]
                headers2 = {
                    'Accept':'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
                    'Connection': 'keep-alive',
                    'Accept-Language': 'en-US,en;q=0.9,sr;q=0.8',
                    'Cache-Control': 'no-cache',
                    'Sec-Fetch-Dest': 'iframe',
                    'Pragma': 'no-cache',
                    'Referer': 'https://www.slamjam.com/',
                    'Sec-Fetch-Mode': 'navigate',
                    'Sec-Fetch-Site': 'cross-site',
                    'Upgrade-Insecure-Requests': '1',
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.66 Safari/537.36'
                }
                server = ["http://45.83.105.7:4200/api/geetest", "http://45.83.105.7:4500/api/geetest","http://45.83.105.7:5500/api/geetest", "http://45.83.105.7:4900/api/geetest"]
                data = {
                    "gt": self.gt,
                    "challenge": self.challenge,
                    "userID": '',
                    "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.66 Safari/537.36"
                }
                r = s.post(random.choice(server), json=data)
                print(r.text)
                jsonresp = json.loads(r.text)
                self.geetest_challenge = self.challenge
                self.geetest_validate = jsonresp['Result'][0]
                self.geetest_seccode = jsonresp['Result'][1]
                headers = {
                    'Accept': '*/*',
                    'Connection': 'keep-alive',
                    'Accept-Language': 'en-US,en;q=0.9,zh-CN;q=0.8,zh;q=0.7',
                    'Cache-Control': 'no-cache',
                    'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
                    'Referer': 'https://geo.captcha-delivery.com/',
                    'Pragma': 'no-cache',
                    'Sec-Fetch-Dest': 'empty',
                    'Sec-Fetch-Mode': 'cors',
                    'Sec-Fetch-Site': 'same-origin',
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.66 Safari/537.36'
                }
                dd_url = 'https://geo.captcha-delivery.com/captcha/check?cid=' + self.cid + '&icid=' + self.initialcid +'&ccid=' + 'null' +'&geetest-response-challenge=' + str(jsonresp['Result'][1]) +'&geetest-response-validate=' + str(jsonresp['Result'][0])  +'&geetest-response-seccode=' + f"{jsonresp['Result'][0]}|jordan" +'&hash=' + self.hsh +'&ua=' + 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.66 Safari/537.36' +'&referer=' + self.dataurl +'&parent_url=' + f'https://www.slamjam.com/' + '&s=' + str(self.sss)
                r = self.s.get(dd_url, headers=headers)
                if r.status_code == 200:
                    jsondd = json.loads(r.text)
                    dd = jsondd['cookie']
                    dd = dd.split('datadome=')[1].split(';')[0]
                    self.cookie_obj = requests.cookies.create_cookie(domain='.slamjam.com',name='datadome',value=dd)
                    self.s.cookies.set_cookie(self.cookie_obj)
                    return self.success('Datadome done, proceding...')
                else:
                    self.s.cookies.clear()
                    self.build_proxy()
                    return self.error('Datadome failed, retrying...')
            else:
                self.s.cookies.clear()
                self.build_proxy()
                return self.error('Datadome failed, restarting...')
        except Exception as e:
            print(traceback.format_exc())
            self.build_proxy()
            return self.error('Datadome failed, restarting...')
            
    def random_char(self, y):
        return ''.join(random.choice(string.ascii_letters) for x in range(y))

    def bar(self):
        if machineOS.lower() == 'windows':
            ctypes.windll.kernel32.SetConsoleTitleW(
                f' Monitors {self.version} - Running SJS | 2cap Balance: {self.balance} | Carted: {carted} | Checkout: {checkoutnum} | Failed: {failed}')
        else:
            sys.stdout.write(f'\x1b]2; Monitors {self.version} - Running SJS | 2cap Balance: {self.balance} | Carted: {carted} | Checkout: {checkoutnum} | Failed: {failed}\x07')

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
        self.warn('Getting product page...')
        headers = {
            'accept': '*/*',
            'accept-encoding': 'gzip, deflate, br',
            'accept-language': 'it-IT,it;q=0.9,en-US;q=0.8,en;q=0.7',
            'dnt': '1',
            'referer': f'https://www.slamjam.com/en_IT/{self.pidmonitor}.html',
            'sec-fetch-dest': 'empty',
            'sec-fetch-mode': 'cors',
            'sec-fetch-site': 'same-origin',
            'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.88 Safari/537.36',
            'x-requested-with': 'XMLHttpRequest'
        }
        i = 0
        while True:
            try:
                r = self.s.get(
                    f'https://www.slamjam.com/on/demandware.store/Sites-slamjam-Site/en_IT/Product-Variation?dwvar_{self.pidmonitor}_color=&dwvar_{self.pidmonitor}_size=&pid={self.pidmonitor}&quantity=1', 
                    headers = headers,
                    timeout = 120
                )
                if 'Please enable JS' in r.text:
                    self.dataurl = r.url                    
                    resp = r.text
                    self.initialcid = resp.split("'cid':'")[1].split("','")[0]
                    self.hsh = resp.split("hsh':'")[1].split("','")[0]
                    self.sss = resp.split("'s':")[1].split(',')[0]
                    self.ttt = resp.split("'t':'")[1].split("',")[0]
                    if self.ttt == "bv" or i > 1:
                        self.error('Proxy banned, retrying...')
                        self.build_proxy()
                        i = 0
                        continue
                    self.warn('Datadome found, proceding...')
                    cid = []
                    cookies = [{'name': c.name, 'value': c.value, 'domain': c.domain, 'path': c.path, 'url': ''} for c in self.s.cookies]
                    for cookie in cookies:
                        if cookie['name'] == "datadome":
                            cid.append(cookie)
                    ciddo = cid[-1]
                    self.cid = ciddo["value"]
                    self.connection2()
                    i = i + 1
                    continue
                if r.status_code == 200:
                    r_json = json.loads(r.text)
                    try:
                        if r_json['error'] == True:
                            self.warn('Product page not loaded, retrying...')
                            time.sleep(self.delay)
                            continue
                    except:
                        pass
                    self.title2 = r_json['product']['productName']
                    img = r_json['product']['images']['hi-res'][0]['url']
                    self.immagine = f'https://www.slamjam.com{img}'
                    try:
                        raffle = r_json['product']['isRaffle']
                    except:
                        raffle = False
                    if raffle == True:
                        self.warn('Raffle product, monitoring...')
                        time.sleep(self.delay)
                        continue
                    else:
                        self.available = r_json['product']['available']
                        if self.available == True:
                            availability = r_json['product']['availability']['messages'][0]
                            if availability == 'In Stock':
                                values = r_json['product']['variationAttributes'][1]['values']
                                self.sizeprint = []
                                self.variantid = []
                                self.oneleft = []
                                for x in values:
                                    if x['selectable'] == True:
                                        self.sizeprint.append(x['displayValue'])
                                        self.variantid.append(x['productID'])
                                        self.oneleft.append(x['oneLeft'])
                                tot = zip(self.sizeprint, self.variantid,self.oneleft)
                                connect = list(tot)
                                webhook = DiscordWebhook(url=self.webhook_url, content = "")
                                embed = DiscordEmbed(title=self.title2, url = f'https://www.slamjam.com/en_IT//{self.pidmonitor}.html', color = 0x715aff)
                                embed.add_embed_field(name='**Site**', value = f'Slam Jam', inline = True)
                                embed.add_embed_field(name='**Pid**', value = f'`{self.pidmonitor}`', inline = True)
                                emb = []
                                for z in self.sizeprint:
                                    for i in connect:
                                        if z == i[0]:
                                            if i[2] == True:
                                                emb.append(f'{i[0]} [1] - [Orbit](http://localhost:5080/quicktask?site=SlamJam&method=checkout-pid&input={i[1]}) - [Phoenix](http://127.0.0.1:5005/phoenixqt?site=slamjam&input={i[1]})')
                                            else:
                                                emb.append(f'{i[0]} - [Orbit](http://localhost:5080/quicktask?site=SlamJam&method=checkout-pid&input={i[1]}) - [Phoenix](http://127.0.0.1:5005/phoenixqt?site=slamjam&input={i[1]})')
                                sizesToPing = [emb[x:x+4] for x in range(0, len(emb), 4)]
                                z= ""
                                for s in sizesToPing:
                                    z= ('\n'.join(str(x) for x in s))
                                    embed.add_embed_field(name="**Sizes**", value=z, inline=False)
                                embed.add_embed_field(name='**Checkout Link**', value = f'[Address :truck:](https://www.slamjam.com/en_IT/checkout-begin?stage=shipping#shipping)\n[Payment :dollar:](https://www.slamjam.com/en_IT/checkout-begin?stage=payment#payment)', inline = True)
                                embed.add_embed_field(name='**Quicktasks**', value = f'[Orbit](http://localhost:5080/quicktask?site=slamjam&method=PID&input={self.pidmonitor})\n[Phoenix](http://127.0.0.1:5005/phoenixqt?site=slamjam&input={self.pidmonitor})\n[Thunder](https://dashboard.thunder-io.com/quicktask?site=SlamJam___DE&url={self.pidmonitor}&size=random)', inline = True)
                                embed.add_embed_field(name='**Regions**', value = f'[DE](https://www.slamjam.com/en_DE//{self.pidmonitor}.html) - [GB](https://www.slamjam.com/en_GB//{self.pidmonitor}.html) - [ES](https://www.slamjam.com/en_ES//{self.pidmonitor}.html) - [FR](https://www.slamjam.com/en_FR//{self.pidmonitor}.html) - [NL](https://www.slamjam.com/en_NL//{self.pidmonitor}.html) - [RU](https://www.slamjam.com/en_RU//{self.pidmonitor}.html)', inline = False)
                                embed.set_thumbnail(url=self.immagine)
                                embed.set_footer(text = f" Monitor - Slamjam", icon_url = "")
                                webhook.add_embed(embed)
                                webhook.execute()
                                self.success('Product in stock!')
                                time.sleep(90)
                                continue
                            else:
                                self.warn('Product OOS, monitoring...')
                                time.sleep(self.delay)
                                continue
                        else:
                            self.warn('Product OOS, monitoring...')
                            time.sleep(self.delay)
                            continue
                elif r.status_code == 403:
                    self.error('Proxy banned, rotating...')
                    self.build_proxy()
                    time.sleep(self.delay)
                    continue
        
                elif r.status_code == 404:
                    self.warn('Page not loaded, retrying...')
                    time.sleep(self.delay)
                    continue

                elif r.status_code == 429:
                    self.error('Rate limit, rotating...')
                    self.build_proxy()
                    time.sleep(self.delay)
                    continue

                else:
                    self.error(f'Error status {r.status_code}, retrying...')
                    self.build_proxy()
                    time.sleep(self.delay)
                    continue
            except (requests.exceptions.ProxyError, requests.exceptions.ConnectTimeout, requests.exceptions.ReadTimeout, requests.exceptions.ConnectionError):
                self.error('Connection error, retrying...')
                self.s.cookies.clear()
                self.build_proxy()
                continue
            except Exception as e:
                open(self.logs_path, 'a+').write(f'{e}\n')
                self.error(f'Unable to get product: {e}, retrying...')
                self.build_proxy()
                continue

    def monitor(self):
        headers = {
            'authority': 'www.slamjam.com',
            'sec-ch-ua': '^\\^Chromium^\\^;v=^\\^92^\\^, ^\\^',
            'accept': 'application/json, text/javascript, */*; q=0.01',
            'dnt': '1',
            'x-requested-with': 'XMLHttpRequest',
            'sec-ch-ua-mobile': '?0',
            'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.131 Safari/537.36',
            'sec-fetch-site': 'same-origin',
            'sec-fetch-mode': 'cors',
            'sec-fetch-dest': 'empty',
            'referer': 'https://www.slamjam.com/en_IT/search?q=J229918',
            'accept-language': 'de,en;q=0.9,de-DE;q=0.8,en-US;q=0.7',
        }
        params = (
            ('pid', 'J220120'),
        )
        response = self.s.get('https://www.slamjam.com/on/demandware.store/Sites-slamjam-Site/en_IT/Product-ShowQuickView', headers=headers, params=params)
        jsonR = response.json()
        print(jsonR)