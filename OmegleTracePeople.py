#!/usr/bin/python3
from scapy.all import *
import ipinfo
import sys
import socket

__author__ = "fb.com/yasser.janah"


def getLocalIP():
    """ Get Local IP , ex : 192.168.1.* """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    return s.getsockname()[0]
    s.close()

my_ip = getLocalIP()

db = ipinfo.getHandler("< Go to https://ipinfo.io/signup and get your API Key >")

print("[!] listening on [any] Omegle packet ... coded by y4ss3r_j4n4ah")


def GetIPLocation(ip, saved):
    info = db.getDetails(ip)
    data2save = saved if (saved is not None) else False
    try:
        country = info.all['country_name']
        if country is None:
            c = x
    except:
        country = "Unknown Country"
    try:
        region = info.all['region']
    except:
        region = "Unknown Region"
    try:
        city = info.all['city']
    except:
        city = "Unknown City"
    try:
        postal = info.all['postal']
    except:
        postal = "Unknown Postal"

    if data2save != False:
        f = open(data2save, mode="a")
        f.write(f"{ip} →  {country}, {region}, {city}, {postal}\n")
        f.close()

    print(f"[+] {ip} →  {country}, {region}, {city}, {postal}")


def show_info(src_ip, saved):
    try:
        GetIPLocation(src_ip, saved)
    except Exception as err:
        print(err)


def pkt_callback(packet):
    #packet.show()
    global current_ip
    global previous_ip
    if packet.haslayer(UDP):
        if not (str(packet[IP].dst).startswith("192.168.") or str(packet[IP].dst).startswith("239.255.255.") or str(packet[IP].dst).startswith('52.87.201.4') or str(packet[IP].dst).startswith("54.172.47.69")):
            current_ip = packet[IP].dst
            if current_ip != previous_ip: # mean that we work with new ip
                show_info(packet[IP].dst, args.save)
            else:
                    show_info(packet[IP].dst, None)

            previous_ip = current_ip

def getArgs():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('-s', '--save', help='Saving People IP with location into a file ...')
    return parser.parse_args()

def main():
    global args
    global current_ip
    global previous_ip
    current_ip = ''
    previous_ip = ''
    args = getArgs()
    sniff(prn=pkt_callback, filter=f"udp and host {my_ip}", store=0)

try:
    main()

except KeyboardInterrupt:
    exit("CTRL+C detected , exiting")
