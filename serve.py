import subprocess
import threading
import sys
import time
import socket

def get_local_ip():
    """Get the local IPv4 address (non-loopback)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    except Exception:
        ip = "127.0.0.1"
    finally:
        s.close()
    return ip

def run_process(command, name):
    """Run a process and print its output."""
    print(f"[{name}] Starting...")
    process = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        universal_newlines=True
    )

    for line in process.stdout:
        print(f"[{name}] {line.strip()}")

    process.wait()
    print(f"[{name}] exited with code {process.returncode}")

def main():
    ip = get_local_ip()
    port = 3000

    print("\n" + "="*50)
    print(f"Access the app at: http://{ip}:{port}")
    print("="*50 + "\n")

    commands = [
        {"cmd": ["python/python.exe", "server.py"], "name": "Python Server"},
        {"cmd": ["python/python.exe", "db_server.py"], "name": "Python Server"}
    ]

    threads = []
    for cmd_info in commands:
        t = threading.Thread(
            target=run_process,
            args=(cmd_info["cmd"], cmd_info["name"]),
            daemon=True
        )
        threads.append(t)

    print("[Main] Starting all servers...")
    for t in threads:
        t.start()

    try:
        for t in threads:
            t.join()
    except KeyboardInterrupt:
        print("\n[Main] Interrupted by user. Exiting...")
        sys.exit(0)

if __name__ == "__main__":
    main()
