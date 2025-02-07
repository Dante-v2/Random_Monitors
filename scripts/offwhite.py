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
# monkey patch the method in
cloudscraper.CloudScraper.perform_request = perform_request

@staticmethod
def is_New_Captcha_Challenge(resp):
    try:
        return (
                resp.headers.get('Server', '').startswith('cloudflare')
                and resp.status_code == 403
                and re.search(
                    r'cpo.src\s*=\s*"/cdn-cgi/challenge-platform/?\w?/?\w?/orchestrate/.*/v1',
                    resp.text,
                    re.M | re.S
                )
                and re.search(r'window._cf_chl_opt', resp.text, re.M | re.S)
        )
    except AttributeError:
        pass

    return False
cloudscraper.CloudScraper.is_New_Captcha_Challenge = is_New_Captcha_Challenge

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

QUEUE_DATA = {
    'passed': False,
    'cookie': None,
    'time': 0
}

def queueHandler(cookie):
    try:
        if cookie:
            QUEUE_DATA['passed'] = True
            QUEUE_DATA['cookie'] = cookie
            QUEUE_DATA['time'] = int(time.time())
            return True
        else:
            if cookie == None:
                if QUEUE_DATA['passed']:
                    if QUEUE_DATA['time'] + 300 > int(time.time()):
                        return QUEUE_DATA['cookie']
                    else:
                        QUEUE_DATA['passed'] = False
                        return False
                else:
                    return False
            elif cookie == False:
                QUEUE_DATA['passed'] = False
                return False
    except Exception as e:
        error(e)


class OFFWHITE():

    def __init__(self, row, webhook, version, i, DISCORD_ID):
        try:
            if machineOS == "Darwin":
                path = os.path.dirname(__file__).rsplit('/', 1)[0]
                path = os.path.join(os.path.dirname(sys.argv[0]), 'offwhite/proxies.txt')
            elif machineOS == "Windows":
                path = os.path.dirname(__file__).rsplit('\\', 1)[0]
                path = os.path.join(os.path.dirname(sys.argv[0]), "offwhite/proxies.txt")
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
            self.captcha = {
                'provider': '2captcha',
                'api_key': config['2captcha']
            }

        else:
            error('2Captcha or AntiCaptcha needed. Stopping task.')
            time.sleep(5)
            sys.exit(1)

        ssl_context = ssl.create_default_context()
        ssl_context.set_ciphers('ECDH-RSA-NULL-SHA:ECDH-RSA-RC4-SHA:ECDH-RSA-DES-CBC3-SHA:ECDH-RSA-AES128-SHA:ECDH-RSA-AES256-SHA:ECDH-ECDSA-NULL-SHA:ECDH-ECDSA-RC4-SHA:ECDH-ECDSA-DES-CBC3-SHA:ECDH-ECDSA-AES128-SHA:ECDH-ECDSA-AES256-SHA:ECDHE-RSA-NULL-SHA:ECDHE-RSA-RC4-SHA:ECDHE-RSA-DES-CBC3-SHA:ECDHE-RSA-AES128-SHA:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-NULL-SHA:ECDHE-ECDSA-RC4-SHA:ECDHE-ECDSA-DES-CBC3-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-ECDSA-AES256-SHA:AECDH-NULL-SHA:AECDH-RC4-SHA:AECDH-DES-CBC3-SHA:AECDH-AES128-SHA:AECDH-AES256-SHA')
        ssl_context.set_ecdh_curve('prime256v1')
        ssl_context.options |= (
        ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3 | ssl.OP_NO_TLSv1_3 | ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1)
        ssl_context.check_hostname = False

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

        self.pid = row['PID']

        self.webhook_url = webhook
        self.version = version
        self.threadID = '%03d' % i
        self.delay = int(config['delay'])
        self.discord = DISCORD_ID

        # self.fullpassword = f"{self.username}:{self.password}"

        self.timeout = 120
        self.build_proxy()
        self.balance = balancefunc()
        self.bar()

        self.warn('Task started!')

        self.dropsprod()

    # Red logging

    def error(self, text):
        if 'exception' in text.lower():
            HANDLER.log_exception(traceback.format_exc())
        message = f'[TASK {self.threadID}] - [OFFWHITE] [{self.pid}] - {text}'
        error(message)

    # Green logging

    def success(self, text):
        message = f'[TASK {self.threadID}] - [OFFWHITE] [{self.pid}] - {text}'
        info(message)

    # Yellow logging

    def warn(self, text):
        message = f'[TASK {self.threadID}] - [OFFWHITE] [{self.pid}] - {text}'
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
                f' Monitors {self.version} - Running OFFWHITE | 2cap Balance: {self.balance} | Carted: {carted} | Checkout: {checkoutnum} | Failed: {failed}')
        else:
            sys.stdout.write(
                f'\x1b]2; Monitors {self.version} - Running OFFWHITE | 2cap Balance: {self.balance} | Carted: {carted} | Checkout: {checkoutnum} | Failed: {failed}\x07')

    def injection(self, session, response):
        try:
            if helheim.isChallenge(session, response):
                self.warn('Solving Cloudflare v2')
                return helheim.solve(session, response)
            else:
                return response
        except Exception as e:
            print(e)
            #if session.is_New_IUAM_Challenge(response):
            #    self.warn('Solving Cloudflare v2 x1')
            #    return CF_2(session, response, key="", captcha=False,debug=False).solve()
            #elif session.is_New_Captcha_Challenge(response):
            #    self.warn('Solving Cloudflare v2 x2')
            #    return CF_2(session, response, key="", captcha=True,debug=True).solve()
            #elif is_fingerprint_challenge(response):
            #    self.warn('Solving Cloudflare v2 x3')
            #    return Cf_challenge_3(session,response,key="",debug=True).solve()
            #else:
            #    return response

    def dropsprod(self):
        self.warn('Getting product page...')
        while True:
            try:
                qData = queueHandler(None)
                if qData:
                    if self.s.cookies.get('__cfwaitingroom'):
                        cookie = \
                            [{'name': c.name, 'value': c.value, 'domain': c.domain, 'path': c.path} for c in
                             self.s.cookies
                             if c.name == '__cfwaitingroom'][0]
                        self.s.cookies.set('__cfwaitingroom', qData, domain=cookie['domain'], path=cookie['path'])
                    else:
                        self.s.cookies.set('__cfwaitingroom', qData, domain='drops.off---white.com', path='/')
                r = self.s.get(
                    f'https://drops.off---white.com/products/{self.pid}?subfolder=it-it',
                    timeout=self.timeout
                )
                if 'estimated wait time' in r.text:
                    if qData:
                        queueHandler(False)
                    self.warn('Waiting in queue...')
                    continue
                if r.status_code == 200:
                    js = r.text.split('__FLAREACT_DATA" type="application/json">')[1].split('</script><script')[0]
                    r_json = json.loads(js)
                    if r_json['props']['comingSoon'] == True:
                        self.warn('Product coming soon, retrying...')
                        time.sleep(self.delay)
                        continue
                    else:
                        pass
                    jsonprod = r_json['props']['productDetails']
                    try:
                        self.productName = jsonprod['breadCrumbs'][4]['text'].replace('â¢','').replace('™️','')
                    except:
                        self.productName = jsonprod['breadCrumbs'][3]['text'].replace('â¢','').replace('™️','')
                    
                    try:
                        self.productImage = jsonprod['images'][0]['1000'].replace('\\','/').replace('u002F','')
                    except:
                        self.productImage = ""
                    
                    quantity = []
                    size_id = []
                    scale = []
                    merchantID = []
                    sizereal = []

                    try:
                        sizegenerale = jsonprod['sizes']
                    except KeyError:
                        self.warn('No sizes, retrying...')
                        time.sleep(self.delay)
                        continue
                    
                    for m in sizegenerale:
                        quantity.append(str(m['quantity']))
                        size_id.append(str(m['id']))
                        sizereal.append(m['name'])
                    
                    self.element = zip(quantity, size_id, sizereal)
                    self.all_sizes = list(self.element)
                    self.instock = []
                    self.sizeinstock = []
                    for element in self.all_sizes:
                        if element[0] != "0":
                            self.instock.append(element)
                    self.element = zip(quantity, size_id, sizereal)
                    self.all_sizes = list(self.element)
                    webhook = DiscordWebhook(url='https://discord.com/api/webhooks/908433754882736138/uf8WeNujRKPhUJ-qLVEtxSCx8Dlp7s-wX29p50urupeUumiQvBOJEg9u5CV_6sRiCyM8', content="")
                    embed = DiscordEmbed(title=self.productName, url=f'https://drops.off---white.com/products/{self.pid}?subfolder=en-it', color=0x715aff)
                    embed.add_embed_field(name='**Site**', value=f'[Drops.Off-White](https://drops.off---white.com/products)', inline=True)
                    emb = []
                    for z in sizereal:
                        for i in self.all_sizes:
                            if i[0] > "0":
                                if z == i[2]:
                                    emb.append(
                                        f'{i[2]} [{i[0]}] - [ATC](https://drops.off---white.com/_flareact/props/checkout/{self.pid}.json?size={i[1]}&subfolder=en-it)')
                    sizesToPing = [emb[x:x + 4] for x in range(0, len(emb), 4)]
                    z = ""
                    for s in sizesToPing:
                        z = ('\n'.join(str(x) for x in s))
                        embed.add_embed_field(name="**Sizes**", value=z, inline=False)
                    embed.set_thumbnail(url=self.productImage)
                    embed.set_footer(text=f" Monitor - Off-White",icon_url="")
                    webhook.add_embed(embed)
                    webhook.execute()
                    time.sleep(60)
                    break
                elif r.status_code >= 500 and r.status_code <= 600:
                    self.warn('Site dead, retrying...')
                    time.sleep(self.delay)
                    continue
                elif r.status_code == 403:
                    if 'Back Soon' in r.text:
                        self.error('Back soon page up, retrying...')
                        self.build_proxy()
                        time.sleep(self.delay)
                        continue
                    else:
                        self.error('Proxy banned, retrying...')
                        self.build_proxy()
                        time.sleep(self.delay)
                        continue
                elif r.status_code == 429:
                    self.error('Rate limit, retrying...')
                    self.build_proxy()
                    time.sleep(self.delay)
                    continue
                else:
                    self.error(f'Error while getting product page (drops.): {r.status_code}, retrying...')
                    self.build_proxy()
                    time.sleep(self.delay)
                    continue
            except (requests.exceptions.ProxyError, requests.exceptions.ConnectTimeout, requests.exceptions.ReadTimeout,
                    requests.exceptions.ConnectionError):
                self.error('Connection error, retrying...')
                self.build_proxy()
                continue
            except Exception as e:
                self.error(f'Exception while getting product page (drops.): {e}, retrying...')
                print(traceback.format_exc())
                time.sleep(self.delay)
                continue