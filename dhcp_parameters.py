from ipaddress import IPv4Network
from socket import *
import ipcalc
import os
from netaddr import IPNetwork
import json
import re


def ip_hex2dec(ip):
    ip1=str(int(ip[0:2],16))
    ip2=str(int(ip[2:4],16))
    ip3=str(int(ip[4:6],16))
    ip4=str(int(ip[6:8],16))
    ipConverted=ip1+'.'+ip2+'.'+ip3+'.'+ip4
    return ipConverted

def get_subnet(IpAdress, mask):

    addr = ipcalc.IP(IpAdress, mask=mask)
    network_with_cidr = str(addr.guess_network())
    # subnet_add = network_with_cidr.split("/")[0]

    return network_with_cidr


def clean_pool(pool):

    already_taken = []

    with os.popen("arp -a") as f:
        data = f.read()

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

    while True:

        gateway = str(input("Adresse de la passerelle par défaut: "))

        subnet_add_gateway = get_subnet(gateway, subnet_mask)

        if (
            subnet_add_gateway.split("/")[0] == net_add.split("/")[0]
            and gateway != net_broadcast_add
            and gateway != net_add.split("/")[0]
        ):
            break
        else:

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


    while True:

        start_ip_address = str(input("Enter first ip address : "))
        subnet_add_start = get_subnet(start_ip_address, subnet_mask)

        if (
            subnet_add_start.split("/")[0] == net_add.split("/")[0]
            and start_ip_address != net_broadcast_add
            and start_ip_address != net_add.split("/")[0]
        ):
            break
        else:

            print(
                "ERREUR : l'adresse doit appartenir au meme réseau que vous avez introduit, et ne doit pas etre identique à "
                + net_add.split("/")[0]
                + " ||"
                + net_broadcast_add
                + " ||"
            )

    while True:

        last_ip_address = str(input("Enter last ip address : "))

        subnet_add_last = get_subnet(last_ip_address, subnet_mask)

        if (
            subnet_add_last.split("/")[0] == net_add.split("/")[0]
            and last_ip_address != net_broadcast_add
            and last_ip_address != net_add.split("/")[0]
        ):
            break
        else:
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

    
    for p in pool:
        if p == gateway:
            pool.remove(gateway)

    print("--------")

    #pool = clean_pool(pool)

    timeout = int(input("Durée du bail en secondes : "))

    print("--------")

    while 1:
        address_filtering_input = input(
            "Do you want to enable address filtering (y/n) : "
        )

        if address_filtering_input == "y":
            address_filtering = True
            break
        elif address_filtering_input == "n":
            address_filtering = False
            break
        else:
            print("Please answer by typing y/n...")

    action = "deny"
    filter_list = []

    if address_filtering == True:

        while 1:
            action_input = input("Specify filtering action (deny/enable) : ")

            if action_input.lower() == "deny":
                action = "deny"
                break

            elif action_input.lower() == "enable":
                action = "enable"
                break

            else:
                print("Please answer by typing deny/enable...")

        p = re.compile(r"(?:[0-9a-fA-F]:?){12}")

        while 1:
            mac_input = input("Enter @mac to filter (q to quit) : ")

            mac_format_check = re.match(p, mac_input.lower())

            if mac_format_check == None and mac_input.lower() != "q":
                print("Wrong mac address format (aa:aa:aa:aa:aa:aa)...")

            elif mac_format_check != None:
                filter_list.append(mac_input.lower())

            elif mac_input.lower() == "q":
                break


    print('--------')
    dos_protection=str(input('Do you want to secure your server against denial of service attacks ? (y/n) : '))

    if dos_protection.lower()=='y':
        dos_protection=True
        print('You must specify how many DHCP messages you will accept to recieve and in how long ')
        max_requests=int(input("Maximum messages : "))
        delay=int(input("Delay (s) : "))
        
    elif dos_protection.lower()=='n':
        dos_protection=False
        max_requests=''
        delay=''
    


    param_data = {
        "net_add": net_add,
        "subnet_mask": subnet_mask,
        "net_broadcast_add": net_broadcast_add,
        "gateway": gateway,
        "dns_primary": dns_primaire,
        "dns_secondary": dns_secondaire,
        "pool": pool,
        "timeout": timeout,

        "address_filtering": address_filtering,
        "action": action,
        "filter_pool": filter_list,

        'dos_protection':dos_protection,
        'max_requests':max_requests,
        'delay':delay
    }
    return param_data


def read_param_data():
    with open("dhcp_config.json") as file:
        param_data = json.load(file)
    print("Retrieved configuration from dhcp_config.json")
    return param_data


def write_param_data(param_data):
    with open("dhcp_config.json", "w") as file:
        json.dump(param_data, file, indent=2)
    print("\n-------------------------------\nSaved configuration in dhcp_config.json\n-------------------------------\n")


def get_parameters():

    while 1:
        default = input("Use previous configuration ? (y/n) : ")

        if default.lower() == "y":

            if not os.path.isfile("dhcp_config.json"):
                print(
                    "Could not find previous configuration file, please enter a new configuration."
                )

                param_data = parametrisation()
                write_param_data(param_data)

            else:
                param_data = read_param_data()
            break

        elif default.lower() == "n":
            param_data = parametrisation()
            write_param_data(param_data)
            break

        else:
            print("Please answer with (y/n)")

    return param_data


if __name__ == "__main__":

    param_data = get_parameters()
    print(param_data)
