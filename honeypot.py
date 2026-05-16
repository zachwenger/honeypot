import socket
import threading
import logging
import os
from datetime import datetime
from colorama import init, Fore, Style

init(autoreset=True)

# ------------------------------------------------
# ZW Honeypot — by Zach Wenger
# listens on common ports and logs whoever shows up
# ------------------------------------------------

# where logs get saved
LOG_DIR = "logs"
os.makedirs(LOG_DIR, exist_ok=True)

# set up the log file
logging.basicConfig(
    filename=f"{LOG_DIR}/honeypot_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log",
    level=logging.INFO,
    format="%(asctime)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)

# ports we're pretending to be
PORTS = {
    21:  "FTP",
    22:  "SSH",
    23:  "Telnet",
    80:  "HTTP",
    443: "HTTPS",
    3389: "RDP",
}

# keep track of how many hits we get
hit_count = 0
hit_lock = threading.Lock()


def log_hit(port, service, ip, data=None):
    # every time someone connects, we log it and print it
    global hit_count
    with hit_lock:
        hit_count += 1
        count = hit_count

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    data_str = f" | data: {data[:100]}" if data else ""
    msg = f"[HIT #{count}] {service} (port {port}) | IP: {ip}{data_str}"

    logging.info(msg)
    print(f"[{timestamp}] {msg}")


def handle_connection(conn, addr, port, service):
    # this runs every time someone actually connects to a port
    ip = addr[0]
    data = None

    try:
        conn.settimeout(3)
        raw = conn.recv(1024)
        if raw:
            # try to decode whatever they sent us
            data = raw.decode("utf-8", errors="ignore").strip()
    except:
        pass
    finally:
        conn.close()

    log_hit(port, service, ip, data)


def listen_on_port(port, service):
    # spins up a listener on a single port
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("0.0.0.0", port))
        s.listen(5)
        print(f"  listening on port {port} ({service})")

        while True:
            try:
                conn, addr = s.accept()
                # handle each connection in its own thread so nothing blocks
                t = threading.Thread(
                    target=handle_connection,
                    args=(conn, addr, port, service),
                    daemon=True
                )
                t.start()
            except:
                break
    except PermissionError:
        print(f"  couldn't bind port {port} ({service}) — try running as admin")
    except Exception as e:
        print(f"  port {port} error: {e}")


def print_banner():
    print()
    print("=" * 55)
    print("   ZW Honeypot — by Zach Wenger")
    print("   logging connection attempts in real time")
    print("=" * 55)
    print()


def main():
    print_banner()
    print("starting listeners...\n")

    threads = []
    for port, service in PORTS.items():
        t = threading.Thread(
            target=listen_on_port,
            args=(port, service),
            daemon=True
        )
        t.start()
        threads.append(t)

    print(f"\nhoneypot is live. waiting for connections...")
    print(f"logs saving to: {LOG_DIR}/")
    print(f"press Ctrl+C to stop\n")
    print("-" * 55)

    try:
        while True:
            threading.Event().wait(1)
    except KeyboardInterrupt:
        print(f"\n\nhoneypot stopped.")
        print(f"total hits this session: {hit_count}")
        print(f"check your logs folder for the full report.")
        print()


if __name__ == "__main__":
    main()