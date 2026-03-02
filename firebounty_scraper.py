#!/usr/bin/env python3
"""
FireBounty Domain Extractor
Extracts all domains with security policies listed on https://firebounty.com/
Rate-limit bypass: rotating User-Agents, per-thread sessions, jitter delays,
explicit 429/503 back-off, shuffled page order.
"""

import os
import re
import time
import random
import argparse
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from bs4 import BeautifulSoup
from tqdm import tqdm

# ── Configuration ─────────────────────────────────────────────────────────────
BASE_URL      = "https://firebounty.com/"
TOTAL_PAGES   = 3534
OUTPUT_FILE   = "domains.txt"
PROGRESS_FILE = "scraper_progress.txt"

# Rotating User-Agents – avoids a static browser fingerprint
USER_AGENTS = [
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:122.0) Gecko/20100101 Firefox/122.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 Edg/122.0.0.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 OPR/105.0.0.0",
]

ACCEPT_LANGUAGES = [
    "en-US,en;q=0.9",
    "en-GB,en;q=0.9",
    "en-US,en;q=0.8,fr;q=0.6",
    "en-US,en;q=0.9,de;q=0.7",
]

# Thread-safe locks
_write_lock    = threading.Lock()
_progress_lock = threading.Lock()

# Per-thread session storage
_thread_local = threading.local()


# ── Session Factory ───────────────────────────────────────────────────────────

def make_session() -> requests.Session:
    """Create a requests session with a connection-pool adapter."""
    session = requests.Session()
    adapter = HTTPAdapter(pool_connections=10, pool_maxsize=20)
    session.mount("https://", adapter)
    session.mount("http://",  adapter)
    return session


def get_session() -> requests.Session:
    """Return a per-thread session (created on first use)."""
    if not hasattr(_thread_local, "session"):
        _thread_local.session = make_session()
    return _thread_local.session


def random_headers() -> dict:
    """Build a browser-like header dict with randomised UA / Accept-Language."""
    return {
        "User-Agent":               random.choice(USER_AGENTS),
        "Accept-Language":          random.choice(ACCEPT_LANGUAGES),
        "Accept":                   "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Encoding":          "gzip, deflate, br",
        "Connection":               "keep-alive",
        "DNT":                      "1",
        "Upgrade-Insecure-Requests":"1",
        "Referer":                  "https://firebounty.com/",
        "Cache-Control":            "max-age=0",
        "Sec-Fetch-Dest":           "document",
        "Sec-Fetch-Mode":           "navigate",
        "Sec-Fetch-Site":           "same-origin",
        "Sec-Fetch-User":           "?1",
    }


# ── Helpers ───────────────────────────────────────────────────────────────────

def get_total_pages(session: requests.Session) -> int:
    """Fetch page 1 and detect the real total page count from pagination."""
    try:
        resp = session.get(BASE_URL, headers=random_headers(), timeout=30)
        resp.raise_for_status()
        soup = BeautifulSoup(resp.text, "lxml")
        pag = soup.select("ul.pagination li a, .pagination a")
        numbers = [int(a.get_text(strip=True)) for a in pag if a.get_text(strip=True).isdigit()]
        if numbers:
            return max(numbers)
    except Exception:
        pass
    return TOTAL_PAGES


def scrape_page(page: int, base_delay: float, retries: int = 6) -> list[str]:
    """
    Scrape a single page using a per-thread session.
    Rate-limit bypass:
      - Randomised User-Agent + headers on every request
      - Jittered delay: base_delay * U(0.5, 1.5)
      - Explicit 429 / 50x back-off before retrying
    Always returns list[str].
    """
    session = get_session()
    url = BASE_URL if page == 1 else f"{BASE_URL}?page={page}"
    last_exc: Exception = Exception("no attempts made")

    for attempt in range(1, retries + 1):
        # Jittered sleep on every attempt (not just retries)
        time.sleep(base_delay * random.uniform(0.5, 1.5))

        try:
            resp = session.get(url, headers=random_headers(), timeout=30)

            # ── Rate-limited ──────────────────────────────────────────────────
            if resp.status_code == 429:
                retry_after = int(resp.headers.get("Retry-After", 10 * attempt))
                wait = retry_after + random.uniform(2, 5)
                tqdm.write(f"[~] 429 on page {page} – sleeping {wait:.1f}s (attempt {attempt})")
                time.sleep(wait)
                last_exc = Exception(f"HTTP 429")
                continue

            # ── Server-side errors ────────────────────────────────────────────
            if resp.status_code in (500, 502, 503, 504):
                wait = (2 ** attempt) + random.uniform(1, 5)
                tqdm.write(f"[~] {resp.status_code} on page {page} – sleeping {wait:.1f}s (attempt {attempt})")
                time.sleep(wait)
                last_exc = Exception(f"HTTP {resp.status_code}")
                continue

            resp.raise_for_status()

            soup = BeautifulSoup(resp.text, "lxml")
            domains: list[str] = []
            for a in soup.find_all("a", href=re.compile(r"^/\d+")):
                name = a.get_text(strip=True)
                if name and "." in name and " " not in name:
                    domains.append(name.lower())
            return list(dict.fromkeys(domains))  # deduplicated, ordered

        except requests.RequestException as exc:
            last_exc = exc
            wait = (2 ** attempt) + random.uniform(0, 3)
            if attempt < retries:
                tqdm.write(f"[~] Page {page}: {exc} – retry {attempt}/{retries} in {wait:.1f}s")
                time.sleep(wait)

    tqdm.write(f"[!] Page {page} permanently failed: {last_exc}")
    return []


def load_progress() -> int:
    """Return the last successfully scraped page number (0 if none)."""
    if os.path.exists(PROGRESS_FILE):
        try:
            return int(open(PROGRESS_FILE).read().strip())
        except ValueError:
            pass
    return 0


def save_progress(page: int) -> None:
    with _progress_lock:
        with open(PROGRESS_FILE, "w") as f:
            f.write(str(page))


def append_domains(domains: list[str]) -> None:
    with _write_lock:
        with open(OUTPUT_FILE, "a") as f:
            for d in domains:
                f.write(d + "\n")


# ── Main ──────────────────────────────────────────────────────────────────────

def run(start_page: int, end_page: int, workers: int, delay: float) -> None:
    print(f"[*] Scraping pages {start_page}–{end_page}  |  workers={workers}  |  base_delay={delay}s")
    print(f"[*] Output → {OUTPUT_FILE}")
    if start_page > 1 and os.path.exists(OUTPUT_FILE):
        print(f"[*] Resuming – appending to existing file")
    else:
        open(OUTPUT_FILE, "w").close()

    pages = list(range(start_page, end_page + 1))
    # Shuffle so concurrent workers don't hit consecutive pages together
    random.shuffle(pages)

    total_domains = 0

    with tqdm(total=len(pages), desc="Pages", unit="pg", dynamic_ncols=True) as bar:
        with ThreadPoolExecutor(max_workers=workers) as pool:
            future_map = {pool.submit(scrape_page, p, delay): p for p in pages}

            for future in as_completed(future_map):
                page    = future_map[future]
                domains = future.result()

                # Write immediately – no ordering dependency
                if domains:
                    append_domains(domains)
                    total_domains += len(domains)
                save_progress(page)
                bar.update(1)
                bar.set_postfix(domains=f"{total_domains:,}")

    print(f"\n[+] Done! {total_domains:,} raw entries written to '{OUTPUT_FILE}'")

    print("[*] Deduplicating…")
    with open(OUTPUT_FILE) as f:
        seen = dict.fromkeys(ln.strip() for ln in f if ln.strip())
    with open(OUTPUT_FILE, "w") as f:
        f.write("\n".join(seen) + "\n")
    print(f"[+] Unique domains: {len(seen):,}")

    if os.path.exists(PROGRESS_FILE):
        os.remove(PROGRESS_FILE)


# ── CLI ───────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Extract all domains with security policies from firebounty.com"
    )
    parser.add_argument("--start",     type=int,   default=None,
                        help="First page (default: auto-resume or 1)")
    parser.add_argument("--end",       type=int,   default=None,
                        help=f"Last page (default: auto-detected, ~{TOTAL_PAGES})")
    parser.add_argument("--workers",   type=int,   default=15,
                        help="Concurrent threads (default: 15)")
    parser.add_argument("--delay",     type=float, default=0.3,
                        help="Base delay per request in seconds with ±50%% jitter (default: 0.3)")
    parser.add_argument("--no-resume", action="store_true",
                        help="Ignore saved progress and restart from page 1")
    args = parser.parse_args()

    if args.no_resume:
        # Wipe all old artefacts
        for f in (OUTPUT_FILE, PROGRESS_FILE):
            if os.path.exists(f):
                os.remove(f)
        print("[*] Old progress cleared – starting fresh")
        start = args.start or 1
    else:
        saved = load_progress()
        start = args.start or (saved + 1 if saved else 1)

    if args.end:
        end = args.end
    else:
        print("[*] Auto-detecting total pages…")
        end = get_total_pages(make_session())
        print(f"[*] Total pages: {end}")

    if start > end:
        print("[!] Nothing to do (start > end).")
        return

    run(start, end, args.workers, args.delay)


if __name__ == "__main__":
    main()
