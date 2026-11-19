"""HTTP-сервер стенда с запуском проверок сигнатур на контрольной записи."""

import argparse
import functools
import http.server
import ipaddress
from pathlib import Path
import signal
import subprocess
import tempfile
import threading


class LabHandler(http.server.SimpleHTTPRequestHandler):
    replay_rules = {"/lab/ssh": "ssh.rules", "/lab/postgres": "postgres.rules"}
    replay_lock = threading.Lock()

    def __init__(self, *args, replay_socket, replay_peer, **kwargs):
        self.replay_socket = replay_socket
        self.replay_peer = replay_peer
        super().__init__(*args, **kwargs)

    def do_POST(self):
        rule = self.replay_rules.get(self.path)
        if self.replay_socket is None or rule is None:
            self.send_error(404)
            return
        if self.client_address[0] != str(self.replay_peer):
            self.send_error(403)
            return
        if not self.replay_lock.acquire(blocking=False):
            self.send_error(409)
            return
        try:
            subprocess.run(
                [
                    "./bin/absolert",
                    "--pcap", "internal/sensor/testdata/et-tcp-scan.pcap",
                    "--rules", str(self.replay_socket.with_name(rule)),
                    "--home-net", "192.0.2.2/32",
                    "--api-socket", str(self.replay_socket),
                ],
                cwd=Path(__file__).resolve().parents[1],
                check=True,
                timeout=2,
            )
        except (OSError, subprocess.SubprocessError):
            self.send_error(500, "PCAP replay failed")
            return
        finally:
            self.replay_lock.release()
        self.send_response(200)
        self.end_headers()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bind", type=ipaddress.IPv4Address, default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8088)
    parser.add_argument("--replay-socket", type=Path)
    parser.add_argument("--replay-peer", type=ipaddress.IPv4Address)
    args = parser.parse_args()
    if not 1 <= args.port <= 65535:
        parser.error("порт должен быть в диапазоне 1–65535")
    if (args.replay_socket is None) != (args.replay_peer is None):
        parser.error("--replay-socket и --replay-peer задаются вместе")

    signal.signal(signal.SIGTERM, signal.default_int_handler)
    try:
        # Временный пустой каталог исключает случайную раздачу исходников и секретов.
        with tempfile.TemporaryDirectory(prefix="absolert-lab-") as directory:
            handler = functools.partial(
                LabHandler,
                directory=directory,
                replay_socket=args.replay_socket,
                replay_peer=args.replay_peer,
            )
            with http.server.ThreadingHTTPServer((str(args.bind), args.port), handler) as server:
                print(f"Стенд: http://{args.bind}:{args.port}/ — Ctrl+C для остановки", flush=True)
                server.serve_forever(poll_interval=0.2)
    except KeyboardInterrupt:
        print("\nСервер остановлен.")
    except OSError as error:
        parser.exit(1, f"Не удалось запустить сервер: {error}\n")


if __name__ == "__main__":
    main()
