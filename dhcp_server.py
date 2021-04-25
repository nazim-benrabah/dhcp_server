# import sys
from scapy.all import *
from socket import *

import scapy

from dhcp_parameters import parametrisation
import random
import binascii
from getmac import get_mac_address as gma


def listen(param_data):

    srv_ip = "127.0.0.1"
    gateway = param_data["gateway"]
    netmask = param_data["subnet_mask"]
    broadcast = param_data["net_broadcast_add"]
    dns1 = param_data["dns_primary"]
    dns2 = param_data["dns_secondary"]
    timeout = param_data["timeout"]
    pool = param_data["pool"]
    ip_offered = random.choice(pool)

    serverPort = 67

    serverSocket = socket(AF_INET, SOCK_DGRAM)
    serverSocket.bind(("", serverPort))
    print("Server ready !")

    while True:

        message, clientAddress = serverSocket.recvfrom(1024)
        # print(hexdump(message))
        m = binascii.hexlify((message)).decode("utf-8")

        mac_addr = m[56:68]
        t = iter(mac_addr)
        mac_addr = ":".join(a + b for a, b in zip(t, t))

        transaction_id = "0x" + m[8:16]
        transaction_id = int("0x" + m[8:16], 16)

        print(transaction_id)
        print(mac_addr)

        msgtype = m[484] + m[485]

        if msgtype == "01":
            print("\nDHCP Discover arrived from %s \nSending DHCP Offer..." % mac_addr)
            send_offer(
                srv_ip,
                ip_offered,
                mac_addr,
                broadcast,
                gateway,
                netmask,
                dns1,
                dns2,
                timeout,
                transaction_id,
            )
        elif msgtype == "03":
            print("\nDHCP request arrived from %s \nSending DHCP ACK..." % mac_addr)
            send_ack(
                srv_ip,
                ip_offered,
                mac_addr,
                broadcast,
                gateway,
                netmask,
                dns1,
                dns2,
                timeout,
                transaction_id,
            )


def send_offer(
    srv_ip,
    ip_offered,
    client_mac,
    broadcast,
    gateway,
    netmask,
    dns1,
    dns2,
    timeout,
    transaction_id,
):
    ethernet = Ether(dst="FF:FF:FF:FF:FF:FF", src=gma(), type=0x800)
    ip = IP(dst="255.255.255.255", src=srv_ip)
    udp = UDP(sport=67, dport=68)
    bootp = BOOTP(
        op=2,
        ciaddr="0.0.0.0",
        yiaddr=ip_offered,
        siaddr=srv_ip,
        chaddr=binascii.unhexlify(client_mac.replace(":", "")),
        xid=transaction_id,
    )
    dhcp = DHCP(
        options=[
            ("message-type", "offer"),
            ("server_id", srv_ip),
            ("broadcast_address", broadcast),
            ("router", gateway),
            ("subnet_mask", netmask),
            ("name_server", dns1, dns2),
            ("lease_time", timeout),
            ("end"),
        ]
    )
    paquet = ethernet / ip / udp / bootp / dhcp
    sendp(paquet)


def send_ack(
    srv_ip,
    ip_offered,
    client_mac,
    broadcast,
    gateway,
    netmask,
    dns1,
    dns2,
    timeout,
    transaction_id,
):
    ethernet = Ether(dst="FF:FF:FF:FF:FF:FF", src=gma(), type=0x800)
    ip = IP(dst="255.255.255.255", src=srv_ip)
    udp = UDP(sport=67, dport=68)
    bootp = BOOTP(
        op=2,
        ciaddr="0.0.0.0",
        yiaddr=ip_offered,
        siaddr=srv_ip,
        chaddr=binascii.unhexlify(client_mac.replace(":", "")),
        xid=transaction_id,
    )
    dhcp = DHCP(
        options=[
            ("message-type", "ack"),
            ("server_id", srv_ip),
            ("broadcast_address", broadcast),
            ("router", gateway),
            ("subnet_mask", netmask),
            ("name_server", dns1, dns2),
            ("lease_time", timeout),
            ("end"),
        ]
    )
    paquet = ethernet / ip / udp / bootp / dhcp
    sendp(paquet)


# srv_ip = "127.0.0.1"
# client_mac = "AB:FA:BF:06:FF:FF"
# broadcast = "192.168.255.255"
# gateway = "192.168.3.1"
# netmask = "255.0.0.0"
# dns1 = "8.8.8.8"
# dns2 = "8.8.4.4"
# timeout = 100
# pool = ["192.168.0.8", "192.168.0.3", "192.168.0.45", "192.168.0.19", "192.168.0.9"]
# ip_offered = random.choice(pool)


def run_server():

    param_data = parametrisation()

    listen(param_data)


if __name__ == "__main__":

    run_server()

# sudo nmap --script broadcast dhcp-discover     to send DHCP Discover
# sudo netwox 171 -d lo		to send DHCP DISCOVER
# sudo dhcping -s 255.255.255.255 -h fa:fa:fa:fa:fa:fa   to send dhcprequest with a specifif client mac to a specific server ip
