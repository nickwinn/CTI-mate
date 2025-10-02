#!/usr/bin/env python3
import json
import socket
import threading
import subprocess
import sys
import time
import requests
import argparse
import os
import logging
import signal
import struct
import ipaddress
import curses
import queue

# Global variable to indicate if we are running in daemon mode
IS_DAEMON = False

# Global configuration dictionary (loaded from JSON)
CONFIG = {}

# Global bind address
bind_addr = ""

# Global queue for log messages in interactive mode
log_queue = queue.Queue()

def is_ipv6(ip):
    """Check if IPv6."""
    try:
        return ipaddress.ip_address(ip).version == 6
    except Exception:
        return False

def log_msg(msg):
    """If running as a daemon, write to logging; in interactive mode, push messages to the queue for the UI to display."""
    if IS_DAEMON:
        logging.info(msg)
    else:
        log_queue.put(msg)

def flush_all_rules():
    """Flush (-F) all rules in iptables and ip6tables (filter table)."""
    for table in ["iptables", "ip6tables"]:
        try:
            subprocess.run([table, "-F"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
            log_msg(f"Rules in {table} have been flushed.")
        except Exception as e:
            log_msg(f"Error flushing rules in {table}: {e}")

def clear_scandetect_rules():
    """
    Remove all rules in the INPUT and OUTPUT chains that contain 'scandetect'.
    List the rules with 'iptables -S' and remove them.
    """
    for table in ["iptables", "ip6tables"]:
        for chain in ["INPUT", "OUTPUT"]:
            try:
                result = subprocess.run([table, "-S", chain], stdout=subprocess.PIPE, text=True)
                for line in result.stdout.splitlines():
                    if "scandetect" in line:
                        delete_rule = line.replace("-A", "-D", 1)
                        subprocess.run(delete_rule.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                log_msg(f"Previous 'scandetect' rules cleared in {table} (chain {chain}).")
            except Exception as e:
                log_msg(f"Error clearing rules in {table} (chain {chain}): {e}")

def create_ipset():
    """Create the ipset 'blacklist'. Destroy it if it already exists."""
    timeout = CONFIG.get("blacklist_timeout", 0)  # 0 means permanent
    subprocess.run(["ipset", "destroy", "blacklist"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    cmd = ["ipset", "create", "blacklist", "hash:ip"]
    if timeout:
        cmd.extend(["timeout", str(timeout)])
    try:
        subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
        log_msg("IpSet 'blacklist' created.")
    except Exception as e:
        log_msg(f"Error creating ipset 'blacklist': {e}")

def configure_whitelist():
    """
    Create an ipset named 'whitelist' with IPs defined in CONFIG and
    insert an early rule in INPUT to accept traffic from those IPs.
    """
    ips = CONFIG.get("whitelist", [])
    if not ips:
        log_msg("Whitelist was not configured.")
        return
    subprocess.run(["ipset", "destroy", "whitelist"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        subprocess.run(["ipset", "create", "whitelist", "hash:ip"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
        for ip in ips:
            subprocess.run(["ipset", "add", "whitelist", ip], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
        subprocess.run(["iptables", "-I", "INPUT", "1", "-m", "set", "--match-set", "whitelist", "src", "-j", "ACCEPT"],
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
        subprocess.run(["ip6tables", "-I", "INPUT", "1", "-m", "set", "--match-set", "whitelist", "src", "-j", "ACCEPT"],
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
        log_msg("IpSet 'whitelist' created and accept rule inserted.")
    except Exception as e:
        log_msg(f"Error configuring whitelist: {e}")

def load_config(config_file):
    """Load configuration from a JSON file."""
    try:
        with open(config_file) as f:
            return json.load(f)
    except Exception as e:
        log_msg(f"Error loading configuration: {e}")
        sys.exit(1)

def send_telegram_notification(telegram_config, message):
    """Send a notification via Telegram."""
    token = telegram_config.get("token")
    chat_id = telegram_config.get("chat_id")
    if token and chat_id:
        url = f"https://api.telegram.org/bot{token}/sendMessage"
        data = {"chat_id": chat_id, "text": message}
        try:
            response = requests.post(url, data=data, timeout=5)
            if response.status_code != 200:
                log_msg(f"Error bus Telegram: {response.text}")
        except Exception as e:
            log_msg(f"Exception when sending Telegram: {e}")

def block_ip(ip):
    """
        Add rules in INPUT and OUTPUT with the comment 'scandetect'.
    """
    if is_ipv6(ip):
        try:
            subprocess.run(["ip6tables", "-A", "INPUT", "-s", ip, "-j", "DROP", "-m", "comment", "--comment", "scandetect"],
                           check=True)
        except Exception as e:
            log_msg(f"Error blocking IPv6 in INPUT for {ip}: {e}")
        try:
            subprocess.run(["ip6tables", "-A", "OUTPUT", "-d", ip, "-j", "DROP", "-m", "comment", "--comment", "scandetect"],
                           check=True)
        except Exception as e:
            log_msg(f"Error blocking IPv6 in OUTPUT for {ip}: {e}")
    else:
        try:
            subprocess.run(["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP", "-m", "comment", "--comment", "scandetect"],
                           check=True)
        except Exception as e:
            log_msg(f"Error blocking IPv4 in INPUT for {ip}: {e}")
        try:
            subprocess.run(["iptables", "-A", "OUTPUT", "-d", ip, "-j", "DROP", "-m", "comment", "--comment", "scandetect"],
                           check=True)
        except Exception as e:
            log_msg(f"Error blocking IPv4 in OUTPUT for {ip}: {e}")
    log_msg(f"IP bloqueada: {ip}")

def emergency_unblock(ip, telegram_config):
    """
    Unblock the IP by removing 'scandetect' rules from the corresponding address family.
    """
    if is_ipv6(ip):
        try:
            subprocess.run(["ip6tables", "-D", "INPUT", "-s", ip, "-j", "DROP", "-m", "comment", "--comment", "scandetect"],
                           check=True)
        except Exception as e:
            log_msg(f"Error unblocking IPv6 in INPUT for {ip}: {e}")
        try:
            subprocess.run(["ip6tables", "-D", "OUTPUT", "-d", ip, "-j", "DROP", "-m", "comment", "--comment", "scandetect"],
                           check=True)
        except Exception as e:
            log_msg(f"Error unblocking IPv6 in OUTPUT for {ip}: {e}")
    else:
        try:
            subprocess.run(["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP", "-m", "comment", "--comment", "scandetect"],
                           check=True)
        except Exception as e:
            log_msg(f"Error unblocking IPv4 in INPUT for {ip}: {e}")
        try:
            subprocess.run(["iptables", "-D", "OUTPUT", "-d", ip, "-j", "DROP", "-m", "comment", "--comment", "scandetect"],
                           check=True)
        except Exception as e:
            log_msg(f"Error unblocking IPv4 in OUTPUT for {ip}: {e}")
    log_msg(f"IP {ip} has been unblocked via emergency.")
    if telegram_config:
        send_telegram_notification(telegram_config, f"IP sequence triggered: {ip}")

def emergency_handle(ip, port, telegram_config):
    """Handle the emergency sequence to unblock an IP address."""
    now = time.time()
    progress, last_time = CONFIG.get("emergency_progress", {}).get(ip, (0, now))
    if now - last_time > CONFIG.get("emergency_delay", 30):
        progress = 0
    expected_port = emergency_sequence[progress] if progress < len(emergency_sequence) else None
    if port == expected_port:
        progress += 1
        log_msg(f"IP {ip} progressed in the emergency sequence to index {progress} (port {port}).")
        if progress == len(emergency_sequence):
            log_msg(f"Sequence complete for IP {ip}. Proceeding to unblock.")
            CONFIG.setdefault("emergency_progress", {})[ip] = (0, now)
            emergency_unblock(ip, telegram_config)
        else:
            CONFIG.setdefault("emergency_progress", {})[ip] = (progress, now)
    else:
        log_msg(f"IP {ip} sent port {port} in the wrong order (expected {expected_port}). Resetting sequence.")
        CONFIG.setdefault("emergency_progress", {})[ip] = (0, now)

def register_connection_attempt(ip):
    """
    Record a connection attempt for the IP and return True if the threshold is exceeded.
    CONNECTION_TIME_WINDOW
    """
    now = time.time()
    timestamps = [t for t in CONFIG.get("connection_attempts", {}).get(ip, []) if now - t <= CONNECTION_TIME_WINDOW]
    timestamps.append(now)
    CONFIG.setdefault("connection_attempts", {})[ip] = timestamps
    if len(timestamps) >= CONFIG.get("connection_threshold", 2):
        CONFIG["connection_attempts"][ip] = []
        return True
    return False

def tcp_listener(port, telegram_config):
    """TCP listener to detect connections on monitored ports."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(10)
    try:
        s.bind((bind_addr, port))
    except OSError as e:
        log_msg(f"Error binding TCP on {bind_addr}:{port}: {e}. Skipping this port.")
        return
    s.listen(5)
    log_msg(f"Escuchando TCP en {bind_addr}:{port}")
    while True:
        try:
            conn, addr = s.accept()
            ip = addr[0]
            log_msg(f"TCP connection detected from {ip} on port {port}")
            if ip in CONFIG.get("whitelist", []):
                log_msg(f"IP {ip} is on the whitelist. It will not be blocked.")
            else:
                if register_connection_attempt(ip):
                    block_ip(ip)
                    if telegram_config:
                        send_telegram_notification(telegram_config, f"IP block (TCP): {ip}")
            conn.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', 1, 0))
            conn.close()
        except socket.timeout:
            continue
        except Exception as e:
            log_msg(f"Error in TCP listener on port {port}: {e}")

def udp_listener(port, telegram_config):
    """UDP listener to detect packets on monitored ports."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(10)
    try:
        s.bind((bind_addr, port))
    except OSError as e:
        log_msg(f"Error binding UDP on {bind_addr}:{port}: {e}. Skipping this port.")
        return
    log_msg(f"UDP {bind_addr}:{port}")
    while True:
        try:
            data, addr = s.recvfrom(1024)
            ip = addr[0]
            log_msg(f"UDP packet detected from {ip} on port {port}")
            if ip in CONFIG.get("whitelist", []):
                log_msg(f"IP {ip} is on the whitelist. It will not be blocked.")
            else:
                if register_connection_attempt(ip):
                    block_ip(ip)
                    if telegram_config:
                        send_telegram_notification(telegram_config, f"IP blocked port (UDP): {ip}")
        except socket.timeout:
            continue
        except Exception as e:
            log_msg(f"Error in UDP listener on port {port}: {e}")

def emergency_listener(port, telegram_config):
    """Listener for each emergency port that checks the sequence to unblock."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(10)
    try:
        s.bind((bind_addr, port))
    except OSError as e:
        log_msg(f"Error binding emergency UDP port on {bind_addr}:{port}: {e}. Skipping this port.")
        return
    log_msg(f"Listening on emergency UDP port at {bind_addr}:{port}")
    while True:
        try:
            data, addr = s.recvfrom(1024)
            ip = addr[0]
            log_msg(f"Emergency access detected from {ip} on port {port}")
            emergency_handle(ip, port, telegram_config)
        except socket.timeout:
            continue
        except Exception as e:
            log_msg(f"Error in emergency listener for port {port}: {e}")

def curses_console(stdscr):
    """
        Display log messages in a dedicated area (above the prompt)
    """
    curses.curs_set(1)
    stdscr.nodelay(True)
    stdscr.clear()
    max_y, max_x = stdscr.getmaxyx()
    log_height = max_y - 3
    input_height = 3
    log_win = curses.newwin(log_height, max_x, 0, 0)
    input_win = curses.newwin(input_height, max_x, log_height, 0)
    input_win.keypad(True)
    log_win.scrollok(True)
    current_input = ""
    while True:
        while not log_queue.empty():
            try:
                msg = log_queue.get_nowait()
                log_win.addstr(msg + "\n")
                log_win.refresh()
            except Exception:
                break
        input_win.clear()
        input_win.addstr(0, 0, ">> " + current_input)
        input_win.refresh()
        ch = input_win.getch()
        if ch == curses.KEY_BACKSPACE or ch == 127:
            current_input = current_input[:-1]
        elif ch in [10, 13]:
            command = current_input.strip().lower()
            current_input = ""
            if command == "":
                continue
            elif command == "help":
                help_text = (
                    "\nAvailable commands:\n"
                    "  rules      - Show iptables and ip6tables rules\n"
                    "  ips        - Show blocked IPs (ipset blacklist)\n"
                    "  whitelist  - Show IPs in the whitelist (ipset whitelist)\n"
                    "  exit       - Exit the interactive console (cleans rules and stops the service)\n"
                )
                log_queue.put(help_text)
            elif command == "rules":
                try:
                    rules_v4 = subprocess.check_output(["iptables", "-L", "-v"], universal_newlines=True)
                except Exception as e:
                    rules_v4 = f"Error retrieving iptables rules: {e}"
                try:
                    rules_v6 = subprocess.check_output(["ip6tables", "-L", "-v"], universal_newlines=True)
                except Exception as e:
                    rules_v6 = f"Error retrieving ip6tables rules: {e}"
                log_queue.put("\niptables rules (IPv4):\n" + rules_v4)
                log_queue.put("\nip6tables rules (IPv6):\n" + rules_v6)
            elif command == "ips":
                try:
                    ips = subprocess.check_output(["ipset", "list", "blacklist"], universal_newlines=True)
                except Exception as e:
                    ips = f"Error retrieving blacklist: {e}"
                log_queue.put("\nIPs blocked (ipset blacklist):\n" + ips)
            elif command == "whitelist":
                try:
                    wlist = subprocess.check_output(["ipset", "list", "whitelist"], universal_newlines=True)
                except Exception as e:
                    wlist = f"Error retrieving whitelist: {e}"
                log_queue.put("\nIPs whitelist (ipset whitelist):\n" + wlist)
            elif command == "exit":
                log_queue.put("Command 'exit' detected. Cleaning rules and exiting...")
                flush_all_rules()
                sys.exit(0)
            else:
                log_queue.put("\nUnrecognized command. Type 'help' for help.\n")
        elif ch == -1:
            time.sleep(0.1)
        else:
            try:
                current_input += chr(ch)
            except Exception:
                pass

def interactive_console():
    """Start the curses-based interactive console."""
    curses.wrapper(curses_console)

def heartbeat():
    """Thread that periodically indicates the service is alive."""
    while True:
        log_msg("Heartbeat: service is running.")
        time.sleep(60)

def graceful_shutdown(signum, frame):
    log_msg("Signal received to terminate. Shutting down the service safely.")
    sys.exit(0)

def daemonize_process():
    """Perform the daemonization process."""
    try:
        pid = os.fork()
        if pid > 0:
            sys.exit(0)
    except OSError as e:
        sys.stderr.write(f"Error en fork #1: {e}\n")
        sys.exit(1)
    os.chdir("/")
    os.setsid()
    os.umask(0)
    try:
        pid = os.fork()
        if pid > 0:
            sys.exit(0)
    except OSError as e:
        sys.stderr.write(f"Error in fork #2: {e}\n")
        sys.exit(1)
    sys.stdout.flush()
    sys.stderr.flush()
    with open("/dev/null", 'r') as si, open("/dev/null", 'a+') as so, open("/dev/null", 'a+') as se:
        os.dup2(si.fileno(), sys.stdin.fileno())
        os.dup2(so.fileno(), sys.stdout.fileno())
        os.dup2(se.fileno(), sys.stderr.fileno())

def write_pid_file(pid_file):
    """Write the current PID to the specified file."""
    try:
        with open(pid_file, "w") as f:
            f.write(str(os.getpid()))
    except Exception as e:
        log_msg(f"Error PID: {e}")

def monitor_ipset(telegram_config):
    """Monitors the 'blacklist' every 5 seconds until notification of new blocked IPs."""
    notified = set()
    while True:
        try:
            result = subprocess.run(["ipset", "list", "blacklist"], stdout=subprocess.PIPE, text=True)
            ips = set()
            for line in result.stdout.splitlines():
                line = line.strip()
                try:
                    ipaddress.ip_address(line)
                    ips.add(line)
                except ValueError:
                    continue
            for ip in ips:
                if ip not in notified:
                    log_msg(f"IP blocked: {ip}")
                    if telegram_config:
                        send_telegram_notification(telegram_config, f"IP blocked firewall: {ip}")
                    notified.add(ip)
        except Exception as e:
            log_msg(f"Error monitoring ipset: {e}")
        time.sleep(5)

def main():
    global IS_DAEMON, bind_addr, CONFIG, emergency_sequence
    parser = argparse.ArgumentParser(description='Scan detection and blocking with iptables+ipset')
    group = parser.add_mutually_exclusive_group()
    group.add_argument('--daemon', action='store_true', help='Run in daemon mode (no interactive console)')
    group.add_argument('--interactive', action='store_true', help='Run in interactive mode')
    parser.add_argument('--config', default='config.json', help='Path to the JSON configuration file')
    args = parser.parse_args()

    start_dir = os.getcwd()
    config_path = os.path.join(start_dir, args.config)
    print(f"Loading configuration from: {config_path}")
    CONFIG = load_config(config_path)

    pid_file = CONFIG.get("pid_file", os.path.join(start_dir, "scandetect.pid"))
    log_file = CONFIG.get("log_file", os.path.join(start_dir, "scandetect.log"))

    bind_ip_conf = CONFIG.get("bind_ip", "*")
    bind_addr = "" if bind_ip_conf in ["*", "0.0.0.0"] else bind_ip_conf

    # Read rate limiting parameters: connection_time_window is provided in milliseconds and converted to seconds.
    CONNECTION_THRESHOLD = CONFIG.get("connection_threshold", 2)
    CONNECTION_TIME_WINDOW = CONFIG.get("connection_time_window", 1000) / 1000.0

    if CONFIG.get("block_immediately", False):
        CONNECTION_THRESHOLD = 1

    IS_DAEMON = args.daemon

    if IS_DAEMON:
        daemonize_process()
        write_pid_file(pid_file)
        logging.basicConfig(filename=log_file, level=logging.INFO,
                            format="%(asctime)s %(levelname)s: %(message)s")
        log_msg("Daemon started.")
    else:
        logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s: %(message)s")

    flush_all_rules()
    clear_scandetect_rules()
    create_ipset()
    configure_whitelist()

    tcp_ports = CONFIG.get("tcp_ports", [])
    if tcp_ports:
        log_msg("Configuring firewall rules for monitored TCP ports...")
        for port in tcp_ports:
            try:
                subprocess.run(["iptables", "-A", "INPUT", "-p", "tcp", "--dport", str(port),
                                "-m", "recent", "--name", f"SCAN_{port}", "--set"],
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
                subprocess.run(["iptables", "-A", "INPUT", "-p", "tcp", "--dport", str(port),
                                "-m", "recent", "--name", f"SCAN_{port}", "--update",
                                "--seconds", "1", "--hitcount", str(CONNECTION_THRESHOLD),
                                "-j", "SET", "--add-set", "blacklist", "src"],
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
            except Exception as e:
                log_msg(f"Error setting up rules for TCP port {port}: {e}")
        try:
            subprocess.run(["iptables", "-A", "INPUT", "-m", "set", "--match-set", "blacklist", "src", "-j", "DROP"],
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
            log_msg("Global rule to block IPs on blacklist added (TCP).")
        except Exception as e:
            log_msg(f"Error adding global rule for blacklist (TCP): {e}")
    else:
        log_msg("No TCP ports were configured in settings.")

    udp_ports = CONFIG.get("udp_ports", [])
    if udp_ports:
        log_msg("Configuring firewall rules for monitored UDP ports...")
        for port in udp_ports:
            try:
                subprocess.run(["iptables", "-A", "INPUT", "-p", "udp", "--dport", str(port),
                                "-m", "recent", "--name", f"UDP_SCAN_{port}", "--set"],
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
                subprocess.run(["iptables", "-A", "INPUT", "-p", "udp", "--dport", str(port),
                                "-m", "recent", "--name", f"UDP_SCAN_{port}", "--update",
                                "--seconds", "1", "--hitcount", str(CONNECTION_THRESHOLD),
                                "-j", "SET", "--add-set", "blacklist", "src"],
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
            except Exception as e:
                log_msg(f"Error setting up rules for UDP port {port}: {e}")
        try:
            subprocess.run(["iptables", "-A", "INPUT", "-m", "set", "--match-set", "blacklist", "src", "-j", "DROP"],
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
            log_msg("Global rule to block IPs on blacklist added (UDP).")
        except Exception as e:
            log_msg(f"Error adding global rule for blacklist (UDP): {e}")
    else:
        log_msg("No UDP ports were configured in settings.")

    emergency_sequence = CONFIG.get("emergency_ports", [])
    if emergency_sequence:
        log_msg(f"Emergency sequence configured: {emergency_sequence}")
        for port in emergency_sequence:
            try:
                subprocess.run(["iptables", "-I", "INPUT", "-p", "udp", "--dport", str(port),
                                "-j", "ACCEPT", "-m", "comment", "--comment", "scandetect"],
                               check=True)
            except Exception as e:
                log_msg(f"Error inserting emergency rule for port {port} (IPv4 INPUT): {e}")
            try:
                subprocess.run(["iptables", "-I", "OUTPUT", "-p", "udp", "--sport", str(port),
                                "-j", "ACCEPT", "-m", "comment", "--comment", "scandetect"],
                               check=True)
            except Exception as e:
                log_msg(f"Error inserting emergency rule for port {port} (IPv4 OUTPUT): {e}")
            try:
                subprocess.run(["ip6tables", "-I", "INPUT", "-p", "udp", "--dport", str(port),
                                "-j", "ACCEPT", "-m", "comment", "--comment", "scandetect"],
                               check=True)
            except Exception as e:
                log_msg(f"Error inserting emergency rule for port {port} (IPv6 INPUT): {e}")
            try:
                subprocess.run(["ip6tables", "-I", "OUTPUT", "-p", "udp", "--sport", str(port),
                                "-j", "ACCEPT", "-m", "comment", "--comment", "scandetect"],
                               check=True)
            except Exception as e:
                log_msg(f"Error inserting emergency rule for port {port} (IPv6 OUTPUT): {e}")
            t = threading.Thread(target=emergency_listener, args=(port, CONFIG.get("telegram", None)), daemon=True)
            t.start()
    else:
        log_msg("'emergency_ports' was not configured.")

    monitor_thread = threading.Thread(target=monitor_ipset, args=(CONFIG.get("telegram", None),), daemon=True)
    monitor_thread.start()

    if not IS_DAEMON:
        log_msg("Running in interactive mode.")
        interactive_console()

    while True:
        time.sleep(1)

if __name__ == "__main__":
    signal.signal(signal.SIGTERM, graceful_shutdown)
    signal.signal(signal.SIGINT, graceful_shutdown)
    # Start the interface (or daemon)
    main()

