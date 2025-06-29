import struct
import socket
from enum import IntEnum
from collections import namedtuple

ARP_PACKET_FORMAT = "!HHBBH6s4s6s4s"
ARP_FORMAT_SIZE = struct.calcsize(ARP_PACKET_FORMAT)
# Assemble header attributes into a structure
ArpHeader = namedtuple('ArpHeader', [
    'hardware_type', 'protocol_type', 'hardware_len', 'protocol_len',
    'op', 'sender_mac', 'sender_ip', 'target_mac', 'target_ip'
])
# Ethernet
ETHERNET_TYPE_ARP = 0x0806
ETHERNET_BROADCAST_MAC = b'\xff' * 6
ETHERNET_EMPTY_MAC = b'\00' * 6
# ARP
ARP_HW_TYPE_ETHERNET = 1
ARP_PROTO_TYPE_IPV4 = 0x0800
ARP_HW_LEN = 6
ARP_PROTO_LEN = 4

class ArpOp(IntEnum):
    REQUEST = 1
    REPLY = 2

def bytes_to_ip(bytes):
    return socket.inet_ntoa(bytes)

def ip_to_bytes(ip_str):
    return socket.inet_aton(ip_str)

def bytes_to_mac(bytes_form):
    return ':'.join(f'{b:02x}' for b in bytes_form)

# Decode bytes into ArpHeader format
def parse_arp_header(payload):
    try:
        arp_parameters = struct.unpack(ARP_PACKET_FORMAT, payload[:ARP_FORMAT_SIZE])
        return ArpHeader(*arp_parameters)
    except struct.error as e:
        print(f"Failed to unpack ARP header: {e}")
        return None

def handle_arp_request(arp_parameters, my_ip, arp_cache):
    sender_ip = arp_parameters.sender_ip
    sender_mac = arp_parameters.sender_mac
    target_ip = arp_parameters.target_ip

    print(f"ARP request from: {bytes_to_ip(sender_ip)}|{bytes_to_mac(sender_mac)} for {bytes_to_ip(target_ip)}'s MAC")

    if target_ip != my_ip:
        print("Requested IP is not my IP, dropping")
        return None
    target_mac = arp_cache.get(target_ip)

    # Switch receiver and sender
    response = build_arp_reply(
        arp_parameters.hardware_type,
        arp_parameters.protocol_type,
        arp_parameters.hardware_len,
        arp_parameters.protocol_len,
        target_mac,
        target_ip,
        sender_mac,
        sender_ip,
    )

    print(f"Sending ARP response to {bytes_to_ip(sender_ip)}")
    return response

def handle_arp_reply(arp_parameters, arp_cache):
    sender_ip = arp_parameters.sender_ip
    sender_mac = arp_parameters.sender_mac

    print(f"ARP reply: {bytes_to_ip(sender_ip)} is at {bytes_to_mac(sender_mac)}")

    if sender_ip not in arp_cache:
        print("Storing in cache...")
        arp_cache[sender_ip] = sender_mac
    else:
        print(f"MAC address: {bytes_to_ip(sender_ip)} is already in ARP cache")


def build_arp_packet(op, sender_mac, sender_ip, target_mac, target_ip):
    return struct.pack(
        ARP_PACKET_FORMAT,
        ARP_HW_TYPE_ETHERNET,
        ARP_PROTO_TYPE_IPV4,
        ARP_HW_LEN,
        ARP_PROTO_LEN,
        op,
        sender_mac,
        sender_ip,
        target_mac,
        target_ip
    )
def build_arp_reply(sender_mac, sender_ip, target_mac, target_ip):
    return build_arp_packet(ArpOp.REPLY, sender_mac, sender_ip, target_mac, target_ip)
def build_arp_request(src_mac, src_ip, target_ip):
    return build_arp_packet(ArpOp.REQUEST, src_mac, src_ip, ETHERNET_EMPTY_MAC, target_ip)

def parse_arp(payload, arp_cache):
    my_ip = list(arp_cache.keys())[0]
    print("Payload length:", len(payload))
    print("Payload hex:", payload.hex())

    if len(payload) < ARP_FORMAT_SIZE:
        print(f"ARP packet too short! length={len(payload)}, expected length={ARP_FORMAT_SIZE}")
        return None

    arp_parameters = parse_arp_header(payload)
    if arp_parameters is None:
        return None

    if arp_parameters.op == ArpOp.REQUEST:
        return handle_arp_request(arp_parameters, my_ip, arp_cache)
    elif arp_parameters.op == ArpOp.REPLY:
        handle_arp_reply(arp_parameters, arp_cache)
    else:
        print("Unknown ARP OP code")
    return None
