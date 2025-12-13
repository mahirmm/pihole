#!/usr/bin/env python3

import requests
import re
import sys

# ---------------- CONFIG ----------------

PIHOLE_URL_base = "http://192.168.10.134:8080/api"
PIHOLE_URL = "http://192.168.10.134:8080/api/domains/allow/regex"
payload_creds = {"password": "shaolin"}  # your password

DOMAINS_URL = "https://raw.githubusercontent.com/mahirmm/pihole/refs/heads/main/whitelists/master-whitelist.txt"
COMMENTS_URL = "https://raw.githubusercontent.com/mahirmm/pihole/refs/heads/main/whitelists/master-whitelist-comments.txt"

GROUPS = [0, 1]

pihole_sid = None

# ----------------------------------------

def refresh_sid():
    global pihole_sid

    try:
        response = requests.post(
            f"{PIHOLE_URL_base}/auth/",
            json=payload_creds,
            timeout=5,
            verify=False
        )
        data = response.json()
        new_sid = data.get("session", {}).get("sid")
    except Exception as e:
        return pihole_sid

    if new_sid:
        pihole_sid = new_sid

    return pihole_sid


def normalize(domain):
    """
    Canonicalize domain / regex from GitHub files
    """
    # Remove BOM
    domain = domain.replace("\ufeff", "")

    # Normalize whitespace
    domain = domain.strip()
    domain = domain.replace("\r", "")
    domain = domain.replace("\t", " ")

    # Collapse spaces
    domain = re.sub(r"\s+", " ", domain)

    return domain




def download_file(url):
    r = requests.get(url, timeout=15)
    r.raise_for_status()
    return r.text.splitlines()


def is_regex(domain):
    """
    Detect Pi-hole regex safely.
    Excludes exact domains like google.com
    """
    regex_indicators = ["^", "$", "(", ")", "[", "]", "\\", "*", "+", "?", "{", "}", "|"]

    if not any(c in domain for c in regex_indicators):
        return False

    try:
        re.compile(domain)
        return True
    except re.error:
        return False


def parse_comments(lines):
    comments = {}

    for line in lines:
        line = normalize(line)
        if not line or " | " not in line:
            continue

        domain, comment = line.split(" | ", 1)
        domain = normalize(domain)
        comment = comment.strip()

        if is_regex(domain):
            comments[domain] = comment

    return comments




def add_regex(domain, comment):
    refresh_sid()
    headers = {
        "accept": "application/json",
        "content-type": "application/json",
        "sid": pihole_sid
    }

    payload = {
        "domain": domain,
        "comment": comment,
        "groups": GROUPS,
        "enabled": True
    }

    r = requests.post(PIHOLE_URL, headers=headers, json=payload)

    if r.ok:
        print(f"✔ Added regex: {domain}  →  {comment}")
    else:
        print(f"✖ Failed: {domain}\n{r.text}")


def main():
    print("Downloading domain lists...")

    domains = download_file(DOMAINS_URL)
    comments_lines = download_file(COMMENTS_URL)

    comment_map = parse_comments(comments_lines)

    regex_domains = []

    for domain in domains:
        domain = normalize(domain)
        if is_regex(domain):
            regex_domains.append(domain)

    print(f"Found {len(regex_domains)} regex entries")

    for domain in regex_domains:
        comment = comment_map.get(domain, "Synced from GitHub")
        if domain not in comment_map:
            print(f"⚠ No comment match for: [{domain}]")

        add_regex(domain, comment)


if __name__ == "__main__":
    main()
