#!/usr/bin/env python3
"""自动识别并处理宝塔 WAF 插件的五种行为验证。"""

import base64
import hashlib
import io
import os
import re
import sys
import time

import requests


SLIDER_TEXT = "".join(map(chr, (0x6ED1, 0x52A8, 0x9A8C, 0x8BC1)))
HUMAN_CHECK_TEXT = "".join(map(chr, (0x4EBA, 0x673A, 0x9A8C, 0x8BC1)))
CAPTCHA_TEXT = "".join(map(chr, (0x9A8C, 0x8BC1, 0x7801)))
VERIFICATION_TEXT = "".join(map(chr, (0x9A8C, 0x8BC1)))

if len(sys.argv) != 2:
    print("用法：python auto_verify.py http://target.example/")
    sys.exit(1)

BASE = sys.argv[1].rstrip("/")
CAPTCHA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "captcha")

session = requests.Session()
session.headers["User-Agent"] = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36"
)


def match_captcha(remote_b64):
    """在本地参考图中查找像素完全一致的图片，并从文件名返回验证码答案。"""
    if not os.path.isdir(CAPTCHA_DIR):
        return None
    from PIL import Image

    remote_img = Image.open(io.BytesIO(base64.b64decode(remote_b64)))
    remote_data = list(remote_img.get_flattened_data())
    for filename in os.listdir(CAPTCHA_DIR):
        if not filename.endswith(".png"):
            continue
        local_img = Image.open(os.path.join(CAPTCHA_DIR, filename))
        if local_img.size != remote_img.size:
            continue
        if remote_data == list(local_img.get_flattened_data()):
            return filename.split("_")[1].replace(".png", "")
    return None


def handle_js_challenge(response, challenge_name):
    """提取验证参数并提交计算结果。"""
    search_name = "renji" if challenge_name == "browser" else challenge_name
    script = re.search(rf'src="(/{search_name}_[^"]+\.js\?[^"]+)"', response.text)
    if not script:
        print(f"找不到 {search_name} 验证脚本。")
        return False

    script_response = session.get(f"{BASE}{script.group(1)}", timeout=15)
    key_match = re.search(r'key\s*=\s*"([^"]+)"', script_response.text)
    value_match = re.search(r'value\s*=\s*"([^"]+)"', script_response.text)
    if not key_match or not value_match:
        print("无法提取验证参数。")
        return False

    key = key_match.group(1)
    value = value_match.group(1)
    ascii_type = 0 if challenge_name == "renji" else 1
    computed = hashlib.md5(
        "".join(str(ord(char) + ascii_type) for char in value).encode()
    ).hexdigest()

    if challenge_name == "huadong":
        verification_url = (
            f"{BASE}/a20be899_96a6_40b2_88ba_32f1f75f1552_yanzheng_huadong.php"
            f"?type=ad82060c2e67cc7e2cc47552a4fc1242&key={key}&value={computed}"
        )
    elif challenge_name == "browser":
        computed = "".join(chr(ord(char) + 1) for char in value)
        fingerprint = hashlib.md5(str(time.time()).encode()).hexdigest()
        verification_url = (
            f"{BASE}/Rxizm32rm3CPpyyW_yanzheng_ip.php"
            f"?type=96c4e20a0e951f471d32dae103e83881"
            f"&key={key}&value={computed}&fingerprint={fingerprint}"
        )
    else:
        verification_url = (
            f"{BASE}/a20be899_96a6_40b2_88ba_32f1f75f1552_yanzheng_ip.php"
            f"?type=96c4e20a0e951f471d32dae103e83881&key={key}&value={computed}"
        )

    if challenge_name == "browser":
        verification = session.post(verification_url, timeout=15)
    else:
        verification = session.get(verification_url, timeout=15)
    print(f"验证响应：{verification.text.strip()}")
    print(f"验证状态：HTTP {verification.status_code}")
    return True


first = session.get(BASE, timeout=15)
print(f"初始响应：HTTP {first.status_code}")

if SLIDER_TEXT in first.text or "huadong" in first.text:
    print("检测到滑动验证。")
    handle_js_challenge(first, "huadong")
elif HUMAN_CHECK_TEXT in first.text or "renji" in first.text:
    print("检测到人机验证。")
    handle_js_challenge(first, "renji")
elif CAPTCHA_TEXT in first.text or "captcha" in first.text:
    print("检测到图片验证码。")
    response = session.get(
        f"{BASE}/get_btwaf_captcha_base64?captcha={int(time.time() * 1000)}",
        timeout=15,
    )
    data = response.json()
    if not data.get("status"):
        print("无法获取图片验证码。")
        sys.exit(1)

    code = match_captcha(data["msg"])
    if not code:
        print(f"在 {CAPTCHA_DIR} 中找不到匹配的参考图片。")
        sys.exit(1)

    verification = session.get(
        f"{BASE}/Verification_auth_btwaf?captcha={code}", timeout=15
    )
    print(f"验证响应：{verification.text.strip()}")
elif "fingerprint" in first.text or "Fingerprint2" in first.text or "Rxizm32" in first.text:
    print("检测到浏览器验证。")
    key_match = re.search(r"key\s*=\s*'([^']+)'", first.text)
    value_match = re.search(r"value\s*=\s*'([^']+)'", first.text)
    if not key_match or not value_match:
        print("无法提取浏览器验证参数。")
        sys.exit(1)
    key = key_match.group(1)
    value = value_match.group(1)
    transformed = "".join(chr(ord(char) + 1) for char in value)
    fingerprint = hashlib.md5(str(time.time()).encode()).hexdigest()
    verification_url = (
        f"{BASE}/Rxizm32rm3CPpyyW_yanzheng_ip.php"
        f"?type=96c4e20a0e951f471d32dae103e83881"
        f"&key={key}&value={transformed}&fingerprint={fingerprint}"
    )
    verification = session.post(verification_url, timeout=15)
    print(f"验证响应：{verification.text.strip()}")
elif "btwaf=" in first.text or "window.location.href" in first.text:
    print("检测到 JavaScript 跳转验证。")
    match = re.search(r'btwaf=(\d+)"', first.text)
    if match:
        session.get(f"{BASE}/?btwaf={match.group(1)}", timeout=15)
    else:
        session.get(BASE, timeout=15)
else:
    print("未检测到支持的验证类型。")
    sys.exit(0)

final = session.get(BASE, timeout=15)
print(f"最终响应：HTTP {final.status_code}")
if final.status_code == 200 and VERIFICATION_TEXT not in final.text and "captcha" not in final.text.lower():
    print("最终页面可以访问。")
else:
    print("无法确认验证结果。")
    print(final.text[:800])
