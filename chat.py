#!/usr/bin/env python3

import argparse
import socket
import sys
import threading

try:
    import paramiko
except ImportError:
    paramiko = None


def chat_loop(sock, peer_label: str) -> None:
    """Dwukierunkowy czat na danym gniezdzie (socket/Channel)."""
    stop_event = threading.Event()

    def reader() -> None:
        try:
            while not stop_event.is_set():
                data = sock.recv(4096)
                if not data:
                    print("\n[Połączenie zostało zamknięte]", flush=True)
                    stop_event.set()
                    break
                text = data.decode("utf-8", errors="replace")
                # Nowa linia, żeby nie mieszać z tym, co wpisuje użytkownik
                print(f"\n[{peer_label}] {text}", end="", flush=True)
        except Exception as e:  # noqa: BLE001
            print(f"\n[Błąd odbioru: {e}]", flush=True)
            stop_event.set()

    t = threading.Thread(target=reader, daemon=True)
    t.start()

    print(
        "Możesz pisać wiadomości. Zakończ czat wpisując /quit lub używając Ctrl+C.",
        flush=True,
    )

    try:
        for line in sys.stdin:
            if stop_event.is_set():
                break
            if line.strip() == "/quit":
                stop_event.set()
                break
            try:
                sock.sendall(line.encode("utf-8"))
            except Exception as e:  # noqa: BLE001
                print(f"[Błąd wysyłki: {e}]", flush=True)
                stop_event.set()
                break
    except KeyboardInterrupt:
        print("\n[Przerwano przez użytkownika]", flush=True)
    finally:
        stop_event.set()
        try:
            sock.close()
        except Exception:  # noqa: BLE001
            pass


def run_listen(port: int) -> None:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("127.0.0.1", port))
    srv.listen(1)
    print(f"Nasłuchiwanie lokalne na 127.0.0.1:{port} (czat tunelowany przez SSH).")
    print("Oczekiwanie na połączenie z klienta...", flush=True)

    conn, addr = srv.accept()
    print(f"Połączono z lokalnym klientem z {addr} (tunel SSH zestawiony).", flush=True)
    srv.close()

    chat_loop(conn, "ZDALNY")


def run_connect(host: str, user: str, chat_port: int, ssh_port: int) -> None:
    if paramiko is None:
        print(
            "Ten tryb wymaga biblioteki paramiko. "
            "Zainstaluj ją poleceniem: pip install paramiko"
        )
        sys.exit(1)

    client = paramiko.SSHClient()
    client.load_system_host_keys()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    print(f"Łączenie przez SSH z {user}@{host}:{ssh_port}...", flush=True)
    try:
        client.connect(hostname=host, port=ssh_port, username=user)
    except Exception as e:  # noqa: BLE001
        print(f"Nie udało się połączyć przez SSH: {e}")
        sys.exit(1)

    transport = client.get_transport()
    if transport is None:
        print("Brak aktywnego transportu SSH.")
        sys.exit(1)

    try:
        chan = transport.open_channel(
            "direct-tcpip",
            ("127.0.0.1", chat_port),  # cel po stronie serwera
            ("127.0.0.1", 0),          # adres źródłowy (nieistotny)
        )
    except Exception as e:  # noqa: BLE001
        print(f"Nie udało się otworzyć kanału direct-tcpip: {e}")
        sys.exit(1)

    print(
        f"Połączono. Czat tunelowany do 127.0.0.1:{chat_port} po stronie serwera.",
        flush=True,
    )

    class ChannelWrapper:
        def __init__(self, channel: "paramiko.Channel") -> None:  # type: ignore[name-defined]
            self.channel = channel

        def recv(self, n: int) -> bytes:
            return self.channel.recv(n)

        def sendall(self, data: bytes) -> None:
            self.channel.sendall(data)

        def close(self) -> None:
            self.channel.close()

    sock = ChannelWrapper(chan)

    try:
        chat_loop(sock, "ZDALNY")
    finally:
        client.close()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Prosty czat tekstowy tunelowany przez SSH (Windows/Linux)."
    )
    parser.add_argument(
        "--mode",
        choices=["listen", "connect"],
        required=True,
        help="listen - nasłuch na serwerze, connect - łączenie się z serwerem przez SSH",
    )
    parser.add_argument(
        "--host",
        help="adres IP lub nazwa hosta serwera (dla mode=connect)",
    )
    parser.add_argument(
        "--user",
        help="nazwa użytkownika na serwerze (dla mode=connect)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=6000,
        help="port lokalny czatu (domyślnie 6000)",
    )
    parser.add_argument(
        "--ssh-port",
        type=int,
        default=22,
        help="port SSH serwera (domyślnie 22)",
    )

    args = parser.parse_args()

    if args.mode == "listen":
        run_listen(args.port)
    elif args.mode == "connect":
        if not args.host or not args.user:
            print("Dla mode=connect musisz podać --host i --user.")
            sys.exit(1)
        run_connect(args.host, args.user, args.port, args.ssh_port)


if __name__ == "__main__":
    main()
