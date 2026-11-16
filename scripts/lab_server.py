"""Пустой HTTP-сервер стенда без доступа к файлам проекта и изменений сети."""

import argparse
import functools
import http.server
import ipaddress
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bind", type=ipaddress.IPv4Address, default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8088)
    args = parser.parse_args()
    if not 1 <= args.port <= 65535:
        parser.error("порт должен быть в диапазоне 1–65535")

    try:
        # Временный пустой каталог исключает случайную раздачу исходников и секретов.
        with tempfile.TemporaryDirectory(prefix="absolert-lab-") as directory:
            handler = functools.partial(
                http.server.SimpleHTTPRequestHandler, directory=directory
            )
            with http.server.ThreadingHTTPServer((str(args.bind), args.port), handler) as server:
                print(f"Стенд: http://{args.bind}:{args.port}/ — Ctrl+C для остановки", flush=True)
                try:
                    server.serve_forever(poll_interval=0.2)
                except KeyboardInterrupt:
                    print("\nСервер остановлен.")
    except OSError as error:
        parser.exit(1, f"Не удалось запустить сервер: {error}\n")


if __name__ == "__main__":
    main()
