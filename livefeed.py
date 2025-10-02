#!/usr/bin/env python3
import io
import os
import re
import sys
import time
import urllib.request
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse, parse_qsl

# ---------- Config ----------
AUTH_LOG = "/var/log/auth.log"
FEEDS = [
    ("jamesbrine_csv", "https://jamesbrine.com.au/csv"),
    ("threatview_high_conf", "https://threatview.io/Downloads/IP-High-Confidence-Feed.txt"),
    ("cybercure_ips_csv", "https://api.cybercure.ai/feed/get_ips?type=csv"),
    ("dataplane_proto41", "https://dataplane.org/proto41.txt"),
    ("snort_block_list", "https://snort.org/downloads/ip-block-list"),
    ("ipsum_level1", "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/1.txt"),
    ("alienvault", "https://reputation.alienvault.com/reputation.generic"),
    ("ipsum_level2", "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/2.txt"),
    ("tor_node", "https://www.dan.me.uk/torlist/")
]
USER_AGENT = "python-ip-tail-matcher/1.2"
DOWNLOAD_TIMEOUT = 30
SLEEP_NO_DATA_SEC = 0.25
RECHECK_INODE_EVERY_SEC = 2.0

# Strict IPv4 (0–255 per octet)
IPV4_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"
)

# ---------- Helpers ----------
def derive_filename(name: str, url: str) -> str:
    """Create a stable, readable filename for a feed in the script's folder."""
    p = urlparse(url)
    base = os.path.basename(p.path) or p.netloc.replace(".", "_")
    if p.query:
        q = "_".join(f"{k}-{v}" for k, v in parse_qsl(p.query))
        base = f"{base}_{q}"
    # Ensure it has an extension for convenience
    if not os.path.splitext(base)[1]:
        base += ".txt"
    return f"{name}__{base}"

def fetch_bytes(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=DOWNLOAD_TIMEOUT) as r:
        return r.read()

def download_feeds(dest_dir: Path) -> list[tuple[str, Path]]:
    """Download all feeds to dest_dir. Returns list of (name, filepath)."""
    saved = []
    dest_dir.mkdir(parents=True, exist_ok=True)
    for name, url in FEEDS:
        fname = derive_filename(name, url)
        fpath = dest_dir / fname
        try:
            data = fetch_bytes(url)
            fpath.write_bytes(data)
            print(f"[INFO] Saved {name} -> {fpath}", file=sys.stderr)
            saved.append((name, fpath))
        except Exception as e:
            print(f"[WARN] Could not download {name} ({url}): {e}", file=sys.stderr)
    return saved

def load_ip_sources(saved_files: list[tuple[str, Path]]) -> dict[str, set]:
    """Build dict: ip -> set(list_names) from saved feed files."""
    ip_sources: dict[str, set] = {}
    for name, path in saved_files:
        try:
            with io.open(path, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    for ip in IPV4_RE.findall(line):
                        ip_sources.setdefault(ip, set()).add(name)
        except Exception as e:
            print(f"[WARN] Could not parse {path}: {e}", file=sys.stderr)
    print(f"[INFO] Loaded {len(ip_sources)} unique IPs from feeds.", file=sys.stderr)
    return ip_sources

def iso_now() -> str:
    return datetime.now().isoformat(timespec="seconds")

def print_match(ip: str, lists: set[str], line: str):
    # Emit: timestamp, IP, lists, and (optional) a short snippet of the line
    lists_str = ",".join(sorted(lists))
    print(f"{iso_now()} MATCH {ip} lists=[{lists_str}]")

def follow_file(path: str):
    """
    Tail -F like follower that handles log rotation.
    Yields new lines as they are written.
    """
    def open_follow(p):
        f = io.open(p, "r", encoding="utf-8", errors="replace")
        f.seek(0, os.SEEK_END)
        return f, os.fstat(f.fileno()).st_ino

    last_check = 0.0
    f, inode = open_follow(path)
    try:
        while True:
            line = f.readline()
            if line:
                yield line
                continue

            # No data; periodically check for rotation/truncation
            now = time.time()
            if now - last_check >= RECHECK_INODE_EVERY_SEC:
                last_check = now
                try:
                    st = os.stat(path)
                    # rotated (inode changed) or truncated (file size < current pos)
                    if st.st_ino != inode or st.st_size < f.tell():
                        try:
                            f.close()
                        except Exception:
                            pass
                        f, inode = open_follow(path)
                        continue
                except FileNotFoundError:
                    # File temporarily missing during rotation; wait and retry
                    pass

            time.sleep(SLEEP_NO_DATA_SEC)
    finally:
        try:
            f.close()
        except Exception:
            pass

# ---------- Main ----------
def main():
    script_dir = Path(__file__).resolve().parent

    # 1) Download feeds to the same folder as the script
    saved = download_feeds(script_dir)
    if not saved:
        print("[ERROR] No feeds were saved; exiting.", file=sys.stderr)
        sys.exit(1)

    # 2) Build IP → lists mapping from saved files
    ip_sources = load_ip_sources(saved)
    if not ip_sources:
        print("[ERROR] No IPs loaded from feeds; exiting.", file=sys.stderr)
        sys.exit(1)

    # 3) Tail the auth log and print a line whenever an IP matches any feed
    print(f"[INFO] Following {AUTH_LOG} for matches...", file=sys.stderr)
    try:
        for line in follow_file(AUTH_LOG):
            # Avoid double prints if multiple same IPs in line
            for ip in set(IPV4_RE.findall(line)):
                lists = ip_sources.get(ip)
                if lists:
                    print_match(ip, lists, line)
    except KeyboardInterrupt:
        print("\n[INFO] Stopped.", file=sys.stderr)

if __name__ == "__main__":
    main()
