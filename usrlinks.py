#!/usr/bin/env python3
"""
USRLINKS - Advanced OSINT Username Hunter
Terminal-based tool to check username availability across 100+ platforms.
"""

import os
import sys
import time
import json
import csv
import random
import argparse
import re
import hashlib
from datetime import datetime
from urllib.parse import urlparse
import requests
from requests.adapters import HTTPAdapter, Retry
from bs4 import BeautifulSoup
from tqdm import tqdm
import logging

# try exception block
try:
    from fake_useragent import UserAgent
    FAKE_UA_AVAILABLE = True
except ImportError:
    FAKE_UA_AVAILABLE = False

  # --- Logging Setup ----
logging.basicConfig(
    filename="usrlinks.log",
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)



# --- Styling & Terminal UI ---
class Colors:
    RED = "\033[1;31m"
    GREEN = "\033[1;32m"
    YELLOW = "\033[1;33m"
    BLUE = "\033[1;34m"
    MAGENTA = "\033[1;35m"
    CYAN = "\033[1;36m"
    WHITE = "\033[1;37m"
    RESET = "\033[0m"
    BOLD = "\033[1m"
    UNDERLINE = "\033[4m"
    PROGRESS_BAR = "\033[1;35m"
    PROGRESS_TEXT = "\033[1;36m"
    ERROR = "\033[1;31m"

class Table:
    def __init__(self, headers):
        self.headers = headers
        self.rows = []
    
    def add_row(self, row):
        self.rows.append(row)
    
    def display(self):
        col_widths = [len(header) for header in self.headers]
        for row in self.rows:
            for i, cell in enumerate(row):
                cell_str = str(cell)
                if len(cell_str) > col_widths[i]:
                    col_widths[i] = len(cell_str)
        
        print(Colors.CYAN + "╔" + "╦".join(["═" * (width + 2) for width in col_widths]) + "╗")
        header_row = "║".join([f" {header.ljust(col_widths[i])} " for i, header in enumerate(self.headers)])
        print(Colors.CYAN + f"║{header_row}║")
        print(Colors.CYAN + "╠" + "╬".join(["═" * (width + 2) for width in col_widths]) + "╣")
        
        for row in self.rows:
            row_str = "║".join([f" {str(cell).ljust(col_widths[i])} " for i, cell in enumerate(row)])
            print(f"║{row_str}║")
        
        print(Colors.CYAN + "╚" + "╩".join(["═" * (width + 2) for width in col_widths]) + "╝")

# --- Enhanced Reconnaissance Class ---
class EnhancedRecon:
    def __init__(self, session):
        self.session = session
        self.email_patterns = [
            r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            r'\b[A-Za-z0-9._%+-]+\s*\[\s*at\s*\]\s*[A-Za-z0-9.-]+\s*\[\s*dot\s*\]\s*[A-Z|a-z]{2,}\b'
        ]
        self.phone_patterns = [
            r'\+?1?[-.\s]?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}',
            r'\+?[0-9]{1,4}[-.\s]?[0-9]{1,4}[-.\s]?[0-9]{1,4}[-.\s]?[0-9]{1,9}'
        ]
        self.url_patterns = [
            r'https?://(?:[-\w.])+(?:[:\d]+)?(?:/(?:[\w/_.])*(?:\?(?:[\w&=%.])*)?(?:#(?:[\w.])*)?)?',
            r'www\.(?:[-\w.])+(?:[:\d]+)?(?:/(?:[\w/_.])*(?:\?(?:[\w&=%.])*)?(?:#(?:[\w.])*)?)?'
        ]

    def extract_contact_info(self, soup, url):
        """Extract email addresses and phone numbers from profile pages"""
        contact_info = {
            'emails': [],
            'phones': [],
            'urls': [],
            'location': None,
            'bio': None
        }
        
        text_content = soup.get_text()
        
        # Extract emails
        for pattern in self.email_patterns:
            emails = re.findall(pattern, text_content, re.IGNORECASE)
            contact_info['emails'].extend(emails)
        
        # Extract phone numbers
        for pattern in self.phone_patterns:
            phones = re.findall(pattern, text_content)
            contact_info['phones'].extend(phones)
        
        # Extract URLs
        for pattern in self.url_patterns:
            urls = re.findall(pattern, text_content)
            contact_info['urls'].extend(urls)
        
        # Platform-specific extractions
        contact_info.update(self._extract_platform_specific(soup, url))
        
        # Clean and deduplicate
        contact_info['emails'] = list(set(contact_info['emails']))
        contact_info['phones'] = list(set(contact_info['phones']))
        contact_info['urls'] = list(set(contact_info['urls']))
        
        return contact_info

    def _extract_platform_specific(self, soup, url):
        """Extract platform-specific information"""
        info = {'location': None, 'bio': None, 'name': None, 'verified': False}
        
        if 'github.com' in url:
            info.update(self._extract_github_info(soup))
        elif 'twitter.com' in url or 'x.com' in url:
            info.update(self._extract_twitter_info(soup))
        elif 'instagram.com' in url:
            info.update(self._extract_instagram_info(soup))
        elif 'linkedin.com' in url:
            info.update(self._extract_linkedin_info(soup))
        
        return info

    def _extract_github_info(self, soup):
        """Extract GitHub-specific information"""
        info = {}
        
        # Location
        location_elem = soup.find('li', {'itemprop': 'homeLocation'})
        if location_elem:
            info['location'] = location_elem.get_text(strip=True)
        
        # Bio
        bio_elem = soup.find('div', class_='user-profile-bio')
        if bio_elem:
            info['bio'] = bio_elem.get_text(strip=True)
        
        # Name
        name_elem = soup.find('span', {'itemprop': 'name'})
        if name_elem:
            info['name'] = name_elem.get_text(strip=True)
        
        return info

    def _extract_twitter_info(self, soup):
        """Extract Twitter/X-specific information"""
        info = {}
        
        # Bio
        bio_elem = soup.find('div', {'data-testid': 'UserDescription'})
        if bio_elem:
            info['bio'] = bio_elem.get_text(strip=True)
        
        # Location
        location_elem = soup.find('span', {'data-testid': 'UserLocation'})
        if location_elem:
            info['location'] = location_elem.get_text(strip=True)
        
        # Verified status
        verified_elem = soup.find('svg', {'data-testid': 'verificationBadge'})
        info['verified'] = verified_elem is not None
        
        return info

    def _extract_instagram_info(self, soup):
        """Extract Instagram-specific information"""
        info = {}
        
        # Bio (Instagram stores bio in meta tags)
        bio_meta = soup.find('meta', {'property': 'og:description'})
        if bio_meta:
            info['bio'] = bio_meta.get('content', '').strip()
        
        return info

    def _extract_linkedin_info(self, soup):
        """Extract LinkedIn-specific information"""
        info = {}
        
        # Location
        location_elem = soup.find('span', class_='text-body-small')
        if location_elem and 'location' in location_elem.get_text().lower():
            info['location'] = location_elem.get_text(strip=True)
        
        return info

    def extract_profile_image(self, soup, url):
        """Extract profile image URL and generate hash"""
        profile_image_info = {
            'url': None,
            'hash': None,
            'downloaded': False
        }
        
        # Common profile image selectors
        image_selectors = [
            'img[data-testid="userAvatarImage"]',  # Twitter
            '.avatar img',  # GitHub
            'img[alt*="profile"]',  # Generic
            'img[class*="avatar"]',  # Generic
            'img[class*="profile"]',  # Generic
        ]
        
        for selector in image_selectors:
            img_elem = soup.select_one(selector)
            if img_elem:
                img_url = img_elem.get('src') or img_elem.get('data-src')
                if img_url:
                    if img_url.startswith('//'):
                        img_url = 'https:' + img_url
                    elif img_url.startswith('/'):
                        domain = urlparse(url).netloc
                        img_url = f"https://{domain}{img_url}"
                    
                    profile_image_info['url'] = img_url
                    profile_image_info['hash'] = self._generate_image_hash(img_url)
                    break
        
        return profile_image_info

    def _generate_image_hash(self, img_url):
        """Generate hash of profile image for comparison"""
        try:
            response = self.session.get(img_url, timeout=10)
            if response.status_code == 200:
                return hashlib.md5(response.content).hexdigest()
        except Exception:
            pass
        return None

    def generate_google_dorks(self, username):
        """Generate Google search dorks for the username"""
        dorks = [
            f'"{username}"',
            f'"{username}" site:pastebin.com',
            f'"{username}" site:github.com',
            f'"{username}" site:reddit.com',
            f'"{username}" filetype:pdf',
            f'"{username}" "email" OR "contact"',
            f'"{username}" "phone" OR "mobile"',
            f'"{username}" inurl:resume OR inurl:cv',
            f'intitle:"{username}"',
            f'"{username}" site:linkedin.com',
        ]
        return dorks

def load_platforms(config_path=None):
    """Load platforms from JSON file or use built-in."""
    if config_path and os.path.isfile(config_path):
        with open(config_path, "r") as f:
            return json.load(f)
    
    # Enhanced platform configs with reconnaissance capabilities
    return {
        "GitHub": {
            "url": "https://github.com/{}",
            "method": "status_code",
            "code": [404],
            "recon_enabled": True,
            "api_endpoint": "https://api.github.com/users/{}"
        },
        "Twitter": {
            "url": "https://twitter.com/{}",
            "method": "response_text",
            "error_msg": ["doesn't exist", "404"],
            "recon_enabled": True
        },
        "Instagram": {
            "url": "https://instagram.com/{}",
            "method": "status_code",
            "code": [404],
            "recon_enabled": True
        },
        "Reddit": {
            "url": "https://reddit.com/user/{}",
            "method": "status_code",
            "code": [404],
            "recon_enabled": True
        },
        "LinkedIn": {
            "url": "https://linkedin.com/in/{}",
            "method": "status_code",
            "code": [404],
            "recon_enabled": True
        },
        "TikTok": {"url": "https://tiktok.com/@{}", "method": "response_text", "error_msg": ["Couldn't find this account"]},
        "YouTube": {"url": "https://youtube.com/{}", "method": "response_text", "error_msg": ["This channel does not exist"]},
        "Twitch": {"url": "https://twitch.tv/{}", "method": "status_code", "code": [404]},
        "Facebook": {"url": "https://facebook.com/{}", "method": "response_text", "error_msg": ["This page isn't available"]},
        "Pinterest": {"url": "https://pinterest.com/{}", "method": "response_text", "error_msg": ["Sorry, we couldn't find that page"]},
        "Steam": {"url": "https://steamcommunity.com/id/{}", "method": "response_text", "error_msg": ["The specified profile could not be found"]},
        "Vimeo": {"url": "https://vimeo.com/{}", "method": "response_text", "error_msg": ["Sorry, we couldn't find that user"]},
        "SoundCloud": {"url": "https://soundcloud.com/{}", "method": "response_text", "error_msg": ["Oops! We can't find that track"]},
        "Medium": {"url": "https://medium.com/@{}", "method": "response_text", "error_msg": ["404"]},
        "DeviantArt": {"url": "https://{}.deviantart.com", "method": "response_text", "error_msg": ["404"]},
        "GitLab": {"url": "https://gitlab.com/{}", "method": "status_code", "code": [404]},
        "Bitbucket": {"url": "https://bitbucket.org/{}", "method": "status_code", "code": [404]},
        "Keybase": {"url": "https://keybase.io/{}", "method": "status_code", "code": [404]},
        "HackerNews": {"url": "https://news.ycombinator.com/user?id={}", "method": "response_text", "error_msg": ["No such user"]},
        "CodePen": {"url": "https://codepen.io/{}", "method": "response_text", "error_msg": ["Sorry, couldn't find that pen"]},
        "Telegram": {"url": "https://t.me/{}", "method": "response_text", "error_msg": ["Telegram channel not found"]},
        "Tumblr": {"url": "https://{}.tumblr.com", "method": "response_text", "error_msg": ["Nothing here"]},
        "Spotify": {"url": "https://open.spotify.com/user/{}", "method": "response_text", "error_msg": ["Couldn't find that user"]},
        "Last.fm": {"url": "https://last.fm/user/{}", "method": "response_text", "error_msg": ["Page not found"]},
        "Roblox": {"url": "https://www.roblox.com/user.aspx?username={}", "method": "response_text", "error_msg": ["404"]},
        "Quora": {"url": "https://www.quora.com/profile/{}", "method": "response_text", "error_msg": ["Oops! The page you were looking for doesn't exist"]},
        "VK": {"url": "https://vk.com/{}", "method": "response_text", "error_msg": ["404"]},
        "Imgur": {"url": "https://imgur.com/user/{}", "method": "response_text", "error_msg": ["404"]},
        "Etsy": {"url": "https://www.etsy.com/shop/{}", "method": "response_text", "error_msg": ["404"]},
        "Pastebin": {"url": "https://pastebin.com/u/{}", "method": "response_text", "error_msg": ["404"]},
    }

FALLBACK_UA_LIST = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
]

def get_random_user_agent():
    if FAKE_UA_AVAILABLE:
        try:
            return UserAgent().random
        except Exception:
            pass
    return random.choice(FALLBACK_UA_LIST)

def get_session_with_retries(proxy=None, tor=False):
    session = requests.Session()
    retries = Retry(total=3, backoff_factor=0.5, status_forcelist=[429, 500, 502, 503, 504])
    session.mount("https://", HTTPAdapter(max_retries=retries))
    session.headers.update({
        "User-Agent": get_random_user_agent(),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate",
        "Connection": "keep-alive",
        "Referer": "https://www.google.com/",
        "DNT": "1",
    })
    if proxy:
        session.proxies = {"http": proxy, "https": proxy}
    elif tor:
        session.proxies = {
            "http": "socks5h://127.0.0.1:9050",
            "https": "socks5h://127.0.0.1:9050"
        }
    return session

def check_platform(session, username, platform, info, timeout=15, deep_scan=False):
    url = info["url"].format(username)
    result = {
        "platform": platform,
        "url": url,
        "available": None,
        "recon_data": {}
    }
    from tqdm import tqdm  # tqdm is imported

    try:
        tqdm.write(f"[•] Checking {platform} ({url})")
        time.sleep(random.uniform(0.5, 1.5))
        session.headers["User-Agent"] = get_random_user_agent()
        response = session.get(url, timeout=timeout)
        
        # Check availability
        if info["method"] == "status_code":
            is_available = response.status_code in info["code"]
        elif info["method"] == "response_text":
            soup = BeautifulSoup(response.text, "html.parser")
            page_text = soup.get_text().lower()
            error_msgs = [msg.lower() for msg in info["error_msg"]]
            is_available = any(msg in page_text for msg in error_msgs)
        else:
            is_available = False
        
        result["available"] = is_available
        
        if is_available:
            tqdm.write(f"[✓] {platform}: Available")
        else:
            tqdm.write(f"[✗] {platform}: Taken")
        
        # Perform deep reconnaissance if account exists and deep_scan is enabled
        if not is_available and deep_scan and info.get("recon_enabled", False):
            soup = BeautifulSoup(response.text, "html.parser")
            recon = EnhancedRecon(session)
            
            # Extract contact information
            contact_info = recon.extract_contact_info(soup, url)
            result["recon_data"]["contact_info"] = contact_info
            
            # Extract profile image info
            image_info = recon.extract_profile_image(soup, url)
            result["recon_data"]["profile_image"] = image_info
        
        return result
        
    except Exception as e:
        result["available"] = None
        result["error"] = str(e)
        tqdm.write(f"[!] {platform}: Error — {str(e)}")
        return result

def scan_usernames(username, platforms, proxy=None, tor=False, threads=10, timeout=15, deep_scan=False):
    session = get_session_with_retries(proxy, tor)
    results = []
    items = list(platforms.items())
    
    with tqdm(
        total=len(items),
        desc=f"Scanning {username}",
        unit="site",
        bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}]",
        colour='magenta'
    ) as pbar:
        from concurrent.futures import ThreadPoolExecutor, as_completed
        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {
                executor.submit(check_platform, session, username, platform, info, timeout, deep_scan): platform
                for platform, info in items
            }
            for future in as_completed(futures):
                platform = futures[future]
                try:
                    result = future.result()
                    results.append(result)
                except Exception as e:
                    results.append({
                        "platform": platform,
                        "url": platforms[platform]["url"].format(username),
                        "available": None,
                        "error": str(e),
                        "recon_data": {}
                    })
                finally:
                    pbar.update(1)
                    pbar.set_postfix_str(f"Last: {platform}")
    
    return results

def display_banner():
    print(Colors.GREEN + r"""
            ██╗   ██╗███████╗██████╗ ██╗     ██╗███╗   ██╗██╗  ██╗███████╗
            ██║   ██║██╔════╝██╔══██╗██║     ██║████╗  ██║██║ ██╔╝██╔════╝
            ██║   ██║███████╗██████╔╝██║     ██║██╔██╗ ██║█████╔╝ ███████╗
            ██║   ██║╚════██║██╔══██╗██║     ██║██║╚██╗██║██╔═██╗ ╚════██║
            ╚██████╔╝███████║██║  ██║███████╗██║██║ ╚████║██║  ██╗███████║
            ╚═════╝ ╚══════╝╚═╝  ╚═╝╚══════╝╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝╚══════╝
    """ + Colors.RESET)
    print(Colors.BLUE + "USRLINKS - The Ultimate OSINT Username Hunter")
    print(Colors.CYAN + "=" * 60)
    print(Colors.YELLOW + "Scanning 100+ platforms for username availability...")
    print(Colors.CYAN + "=" * 60 + "\n")

def display_results(results, username, deep_scan=False):
    table = Table(["Platform", "Status", "URL"])
    available_count = 0
    taken_count = 0
    error_count = 0
    
    for result in sorted(results, key=lambda x: x["platform"]):
        if result["available"] is True:
            status = Colors.GREEN + "AVAILABLE" + Colors.RESET
            available_count += 1
        elif result["available"] is False:
            status = Colors.RED + "TAKEN" + Colors.RESET
            taken_count += 1
        else:
            status = Colors.YELLOW + "ERROR" + Colors.RESET
            error_count += 1
        table.add_row([result["platform"], status, result["url"]])
    
    table.display()
    
    # Display reconnaissance data if deep scan was performed
    if deep_scan:
        display_recon_summary(results)
    
    # Summary row
    print("\n" + Colors.CYAN + "─" * 60)
    print(Colors.GREEN + f"Available: {available_count}" + Colors.RESET + " | " +
          Colors.RED + f"Taken: {taken_count}" + Colors.RESET + " | " +
          Colors.YELLOW + f"Errors: {error_count}" + Colors.RESET)
    print(Colors.CYAN + "─" * 60)

def display_recon_summary(results):
    """Display summary of reconnaissance data"""
    print(f"\n{Colors.MAGENTA}=== RECONNAISSANCE SUMMARY ==={Colors.RESET}")
    
    all_emails = set()
    all_phones = set()
    all_urls = set()
    all_locations = set()
    profile_images = []
    
    for result in results:
        if result["available"] is False and result.get("recon_data"):
            recon = result["recon_data"]
            contact = recon.get("contact_info", {})
            
            all_emails.update(contact.get("emails", []))
            all_phones.update(contact.get("phones", []))
            all_urls.update(contact.get("urls", []))
            if contact.get("location"):
                all_locations.add(contact["location"])
            
            img_info = recon.get("profile_image", {})
            if img_info.get("url"):
                profile_images.append({
                    "platform": result["platform"],
                    "url": img_info["url"],
                    "hash": img_info.get("hash")
                })
    
    # Display findings
    if all_emails:
        print(f"{Colors.CYAN}📧 Email Addresses Found:{Colors.RESET}")
        for email in sorted(all_emails):
            print(f"  • {email}")
    
    if all_phones:
        print(f"\n{Colors.CYAN}📱 Phone Numbers Found:{Colors.RESET}")
        for phone in sorted(all_phones):
            print(f"  • {phone}")
    
    if all_urls:
        print(f"\n{Colors.CYAN}🔗 Associated URLs:{Colors.RESET}")
        for url in sorted(all_urls)[:10]:  # Limit to first 10
            print(f"  • {url}")
    
    if all_locations:
        print(f"\n{Colors.CYAN}📍 Locations Found:{Colors.RESET}")
        for location in sorted(all_locations):
            print(f"  • {location}")
    
    if profile_images:
        print(f"\n{Colors.CYAN}🖼️  Profile Images:{Colors.RESET}")
        for img in profile_images:
            print(f"  • {img['platform']}: {img['url']}")
            if img['hash']:
                print(f"    Hash: {img['hash']}")

def generate_dorks(username):
    """Generate and display Google dorks for the username"""
    recon = EnhancedRecon(None)
    dorks = recon.generate_google_dorks(username)
    
    print(f"\n{Colors.MAGENTA}=== GOOGLE DORKS FOR {username.upper()} ==={Colors.RESET}")
    for i, dork in enumerate(dorks, 1):
        print(f"{Colors.YELLOW}{i:2d}.{Colors.RESET} {dork}")
    print(f"\n{Colors.CYAN}Copy these dorks into Google for additional reconnaissance{Colors.RESET}\n")

def save_results(results, username, format="csv"):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"USRLINKS_{username}_{timestamp}.{format}"
    try:
        if format == "csv":
            with open(filename, "w", newline="") as f:
                writer = csv.writer(f)
                writer.writerow(["Platform", "Status", "URL", "Emails", "Phones", "URLs", "Location", "Bio"])
                for result in results:
                    status = "AVAILABLE" if result["available"] else "TAKEN" if result["available"] is False else "ERROR"
                    
                    # Extract recon data
                    recon = result.get("recon_data", {})
                    contact = recon.get("contact_info", {})
                    emails = "; ".join(contact.get("emails", []))
                    phones = "; ".join(contact.get("phones", []))
                    urls = "; ".join(contact.get("urls", []))
                    location = contact.get("location", "")
                    bio = contact.get("bio", "")
                    
                    writer.writerow([
                        result["platform"], status, result["url"],
                        emails, phones, urls, location, bio
                    ])
        elif format == "json":
            with open(filename, "w") as f:
                json.dump(results, f, indent=2)
        print(Colors.GREEN + f"[+] Results saved to {filename}")
    except Exception as e:
        print(Colors.RED + f"[-] Error saving results: {e}")

def list_platforms(platforms):
    print(Colors.CYAN + "Supported platforms:")
    for name in sorted(platforms.keys()):
        recon_status = "✓" if platforms[name].get("recon_enabled") else "✗"
        print(Colors.YELLOW + f"- {name} {Colors.CYAN}[Recon: {recon_status}]{Colors.RESET}")

def print_result_table(results):
    from tabulate import tabulate  # move to top if u wanto

    table_data = []
    for result in results:
        status = (
            "AVAILABLE" if result["available"] is True
            else "TAKEN" if result["available"] is False
            else "ERROR"
        )
        profile_url = result["url"] if result["available"] is False else "-"
        table_data.append([result["platform"], status, profile_url])

    headers = ["Platform", "Status", "Profile"]
    print("\n" + Colors.CYAN + tabulate(table_data, headers=headers, tablefmt="github") + Colors.RESET)

def main():
    parser = argparse.ArgumentParser(description="USRLINKS - OSINT Username Hunter")
    parser.add_argument("-u", "--username", help="Username to scan")
    parser.add_argument("-p", "--proxy", help="HTTP/SOCKS proxy (e.g., http://127.0.0.1:8080)")
    parser.add_argument("-t", "--tor", action="store_true", help="Use Tor for anonymity")
    parser.add_argument("-th", "--threads", type=int, default=10, help="Number of threads (default: 10)")
    parser.add_argument("-o", "--output", choices=["csv", "json"], help="Save results to file")
    parser.add_argument("--platforms", help="Path to custom platforms JSON file")
    parser.add_argument("--list-platforms", action="store_true", help="List supported platforms and exit")
    parser.add_argument("--deep-scan", action="store_true", help="Perform deep reconnaissance on found profiles")
    parser.add_argument("--generate-dorks", action="store_true", help="Generate Google dorks for the username")
    
    args = parser.parse_args()
    platforms = load_platforms(args.platforms)
    
    if args.list_platforms:
        list_platforms(platforms)
        sys.exit(0)
    
    if args.generate_dorks:
        if not args.username:
            print(Colors.RED + "[-] Username required for dork generation")
            sys.exit(1)
        generate_dorks(args.username)
        sys.exit(0)
    
    if not args.username:
        parser.print_help()
        sys.exit(1)
    
    display_banner()
    
    if args.deep_scan:
        print(Colors.YELLOW + f"[*] Deep scanning enabled - extracting profile information...\n")
    
    print(Colors.YELLOW + f"[*] Scanning for username: {args.username}...\n")
    
    results = scan_usernames(
        username=args.username,
        platforms=platforms,
        proxy=args.proxy,
        tor=args.tor,
        threads=args.threads,
        deep_scan=args.deep_scan
    )
    
    print_result_table(results)  # show initial results table

    # retry failed platforms 2 times again
    failed_results = [r for r in results if r["available"] is None]
    session = get_session_with_retries(args.proxy, args.tor)
    if failed_results:
        from tqdm import tqdm
        for attempt in range(2):
            tqdm.write(f"\n[⏳] Retrying failed platforms (Attempt {attempt + 1}/2)")
            retry_results = []
            for fr in failed_results:
                tqdm.write(f"[•] Retrying {fr['platform']}...")
                retry_result = check_platform(session, args.username, fr['platform'], platforms[fr['platform']], timeout=15)
                retry_results.append(retry_result)

                if retry_result["available"] is True:
                    tqdm.write(f"[✓] {fr['platform']}: Available")
                elif retry_result["available"] is False:
                    tqdm.write(f"[✗] {fr['platform']}: Taken")
                else:
                    tqdm.write(f"[!] {fr['platform']}: Still error")

            print_result_table(retry_results)
            failed_results = [r for r in retry_results if r["available"] is None]

            if not failed_results:
                tqdm.write("[✓] All platforms resolved after retries.")
                break

        if failed_results:
            failed_names = [r["platform"] for r in failed_results]
            tqdm.write(f"[*] Still failing after 2 retries: {failed_names}")

    display_results(results, args.username, args.deep_scan)
    
    if args.output:
        save_results(results, args.username, args.output)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(Colors.RED + "\n[!] Scan aborted by user.")
        sys.exit(1)
    except Exception as e:
        print(Colors.RED + f"\n[!] Error: {e}")
        sys.exit(1)
        logging.error(f"Fatal error: {e}")
        sys.exit(1)




