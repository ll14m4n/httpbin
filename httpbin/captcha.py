# -*- coding: utf-8 -*-

"""
httpbin.captcha
~~~~~~~~~~~~~~~

This module provides captcha helper functions for httpbin.
"""

import os
import random
import string
import time
import uuid

import requests
from captcha.image import ImageCaptcha

# reCAPTCHA test keys (from Google's FAQ - always pass)
RECAPTCHA_V2_TEST_SITEKEY = "6LeIxAcTAAAAAJcZVRqyHh71UMIEGNQ_MXjiZKhI"
RECAPTCHA_V2_TEST_SECRET = "6LeIxAcTAAAAAGG-vFI1TnRWxMZNFuojJ4WifJWe"

# hCaptcha test keys (from hCaptcha docs - always pass)
HCAPTCHA_TEST_SITEKEY = "10000000-ffff-ffff-ffff-000000000001"
HCAPTCHA_TEST_SECRET = "0x0000000000000000000000000000000000000000"

# Configuration from environment (falls back to test keys)
RECAPTCHA_V2_SITEKEY = os.environ.get("RECAPTCHA_V2_SITEKEY", RECAPTCHA_V2_TEST_SITEKEY)
RECAPTCHA_V2_SECRET = os.environ.get("RECAPTCHA_V2_SECRET", RECAPTCHA_V2_TEST_SECRET)

RECAPTCHA_V3_SITEKEY = os.environ.get("RECAPTCHA_V3_SITEKEY", RECAPTCHA_V2_TEST_SITEKEY)
RECAPTCHA_V3_SECRET = os.environ.get("RECAPTCHA_V3_SECRET", RECAPTCHA_V2_TEST_SECRET)

HCAPTCHA_SITEKEY = os.environ.get("HCAPTCHA_SITEKEY", HCAPTCHA_TEST_SITEKEY)
HCAPTCHA_SECRET = os.environ.get("HCAPTCHA_SECRET", HCAPTCHA_TEST_SECRET)

# Simple in-memory store for local captcha challenges
# Key: token, Value: {"text": "ABC123", "created": timestamp}
CAPTCHA_STORE = {}
CAPTCHA_EXPIRY = 300  # 5 minutes


def generate_simple_captcha():
    """Generate a simple image captcha and return (token, text)."""
    # Generate random text (6 characters)
    text = ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))

    # Generate unique token
    token = str(uuid.uuid4())

    # Store the challenge
    CAPTCHA_STORE[token] = {
        "text": text,
        "created": time.time()
    }

    # Clean expired entries
    _cleanup_expired_captchas()

    return token, text


def get_captcha_image(token):
    """Generate captcha image bytes for the given token."""
    if token not in CAPTCHA_STORE:
        return None

    challenge = CAPTCHA_STORE[token]
    if time.time() - challenge["created"] > CAPTCHA_EXPIRY:
        return None

    # Generate image
    image = ImageCaptcha(width=280, height=90)
    data = image.generate(challenge["text"])
    return data.read()


def verify_simple_captcha(token, response):
    """Verify a simple captcha response. Returns (success, message)."""
    _cleanup_expired_captchas()

    if token not in CAPTCHA_STORE:
        return False, "Invalid or expired captcha token"

    challenge = CAPTCHA_STORE.pop(token)  # One-time use

    if time.time() - challenge["created"] > CAPTCHA_EXPIRY:
        return False, "Captcha expired"

    if response.upper() == challenge["text"]:
        return True, "Captcha verified successfully"

    return False, "Incorrect captcha response"


def _cleanup_expired_captchas():
    """Remove expired captcha entries from store."""
    current_time = time.time()
    expired = [k for k, v in CAPTCHA_STORE.items()
               if current_time - v["created"] > CAPTCHA_EXPIRY]
    for k in expired:
        CAPTCHA_STORE.pop(k, None)


def verify_recaptcha(response_token, secret=None, version="v2"):
    """
    Verify a reCAPTCHA response with Google's API.
    Returns dict with success status and details.
    """
    if secret is None:
        secret = RECAPTCHA_V3_SECRET if version == "v3" else RECAPTCHA_V2_SECRET

    verify_url = "https://www.google.com/recaptcha/api/siteverify"

    try:
        resp = requests.post(verify_url, data={
            "secret": secret,
            "response": response_token
        }, timeout=10)
        result = resp.json()
    except Exception as e:
        return {
            "success": False,
            "error-codes": ["request-failed"],
            "error_message": str(e)
        }

    return {
        "success": result.get("success", False),
        "challenge_ts": result.get("challenge_ts"),
        "hostname": result.get("hostname"),
        "score": result.get("score"),  # v3 only
        "action": result.get("action"),  # v3 only
        "error-codes": result.get("error-codes", [])
    }


def verify_hcaptcha(response_token, secret=None):
    """
    Verify an hCaptcha response with hCaptcha's API.
    Returns dict with success status and details.
    """
    if secret is None:
        secret = HCAPTCHA_SECRET

    verify_url = "https://hcaptcha.com/siteverify"

    try:
        resp = requests.post(verify_url, data={
            "secret": secret,
            "response": response_token
        }, timeout=10)
        result = resp.json()
    except Exception as e:
        return {
            "success": False,
            "error-codes": ["request-failed"],
            "error_message": str(e)
        }

    return {
        "success": result.get("success", False),
        "challenge_ts": result.get("challenge_ts"),
        "hostname": result.get("hostname"),
        "credit": result.get("credit"),
        "error-codes": result.get("error-codes", [])
    }
