from ipaddress import IPv4Network
from socket import *
import ipcalc
import os
from netaddr import IPNetwork


def get_subnet(IpAdress, mask):

    addr = ipcalc.IP(IpAdress, mask=mask)
    network_with_cidr = str(addr.guess_network())
    subnet_add = network_with_cidr.split("/")[0]

    return network_with_cidr


def clean_pool(pool):

    already_taken = []

    with os.popen("arp -a") as f:
        data = f.read()

    import re

    for line in re.findall("([(.0-9)]+)\s", data):
        line = line.replace("(", "").replace(")", "")
        if len(line) > 6:
            already_taken.append(line)

    matched = list(set(pool) & set(already_taken))

    for m in matched:
        for p in pool:
            if m == p:
                pool.remove(p)

    return pool


def parametrisation():

    print("---------------------- Configuration du server DHCP ----------------------")

    net_add = str(input("Adresse du réseau : "))
    subnet_mask = str(input("Masque : "))

    net_add = get_subnet(net_add, subnet_mask)

    net_broadcast_add = str(IPNetwork(str(net_add))[-1])

    x = False
    while x == False:

        gateway = str(input("Adresse de la passerelle par défaut: "))

        subnet_add_gateway = get_subnet(gateway, subnet_mask)

        if (
            subnet_add_gateway.split("/")[0] == net_add.split("/")[0]
            and gateway != net_broadcast_add
            and gateway != net_add.split("/")[0]
        ):
            x = True
        else:
            x = False
            print(
                "ERREUR : l'adresse doit appartenir au meme réseau et ne doit pas etre identique à "
                + net_add.split("/")[0]
                + " ||"
                + net_broadcast_add
                + " ||"
            )

    dns_primaire = str(input("DNS primaire : "))
    dns_secondaire = str(input("DNS secondaire : "))

    print("--------")

    print("Plage d'adresses")

    x = False
    while x == False:

        start_ip_address = str(input("Enter first ip address : "))
        subnet_add_start = get_subnet(start_ip_address, subnet_mask)

        if (
            subnet_add_start.split("/")[0] == net_add.split("/")[0]
            and start_ip_address != net_broadcast_add
            and start_ip_address != net_add.split("/")[0]
        ):
            x = True
        else:
            x = False
            print(
                "ERREUR : l'adresse doit appartenir au meme réseau que vous avez introduit, et ne doit pas etre identique à "
                + net_add.split("/")[0]
                + " ||"
                + net_broadcast_add
                + " ||"
            )

    x = False
    while x == False:

        last_ip_address = str(input("Enter last ip address : "))

        subnet_add_last = get_subnet(last_ip_address, subnet_mask)

        if (
            subnet_add_last.split("/")[0] == net_add.split("/")[0]
            and last_ip_address != net_broadcast_add
            and last_ip_address != net_add.split("/")[0]
        ):
            x = True
        else:
            x = False
            print(
                "ERREUR : l'adresse doit appartenir au meme réseau que que vous avez introduit, et ne doit pas etre identique à "
                + net_add.split("/")[0]
                + " ||"
                + net_broadcast_add
                + " ||"
            )

    pool = []

    for ip in IPNetwork(str(subnet_add_start)):
        pool.append("%s" % ip)
        if str(ip) == last_ip_address:
            break

    target_ibdex = pool.index(start_ip_address)
    pool = pool[target_ibdex:]

    y = False
    for p in pool:
        if p == gateway:
            y = True

    if y == True:
        pool.remove(gateway)

    print("--------")

    pool = clean_pool(pool)

    timeout = int(input("Durée du bail en secondes : "))

    # print("--------configuration sauvgardée-------")
    # print("Adresse du réseau : ", net_add)
    # print("Adresse broadcast : ", net_broadcast_add)
    # print("Adresse de la gateway : ", gateway)
    # print("DNS primaire : ", dns_primaire)
    # print("DNS secondaire : ", dns_secondaire)
    # print("Plage d'adresses allouée : ", pool)
    # print("Durée du bail (s): ", timeout)
    # print("--------")

    param_data = {
        "net_add": net_add,
        "subnet_mask": subnet_mask,
        "net_broadcast_add": net_broadcast_add,
        "gateway": gateway,
        "dns_primary": dns_primaire,
        "dns_secondary": dns_secondaire,
        "pool": pool,
        "timeout": timeout,
    }
    return param_data


if __name__ == "__main__":
    param_data = parametrisation()
