import struct
import socket
from enum import IntEnum

PACKET_FORMAT = "!HHBBH6s4s6s4s"
PACKET_FORMAT_SIZE = struct.calcsize(PACKET_FORMAT)
MY_IP = b""
ARP_CACHE = {}

class ArpOp(IntEnum):
    REQUEST = 1
    REPLY = 2

def bytes_to_ip(bytes):
    return socket.inet_ntoa(bytes)

def bytes_to_mac(bytes_form):
    hexed_bytes = bytes_form.hex()
    pretty_mac = ""
    index = 0
    while index < len(hexed_bytes):
        pretty_mac += hexed_bytes[index]
        pretty_mac += hexed_bytes[index + 1]
        pretty_mac += ":"
        index += 2
    return pretty_mac[:len(pretty_mac) - 1]

def parse_arp(payload):
    print("Payload length:", len(payload))
    print("Payload hex:", payload.hex())
    if len(payload) < 28:
        print(f"ARP packet too short! length={len(payload)}")
        return None
    global ARP_CACHE, MY_IP
    (hardware_type, protocol_type, hardware_len, protocol_len,
     op, sender_mac, sender_ip, target_mac, target_ip) = struct.unpack(PACKET_FORMAT, payload[:PACKET_FORMAT_SIZE])
    if op == ArpOp.REQUEST:
        print(f"ARP request from: {bytes_to_ip(sender_ip)}|{bytes_to_mac(sender_mac)} for {bytes_to_ip(target_ip)}'s mac")
        # Only answer if the target address belong to own device
        if target_ip != MY_IP:
            print("Requested IP is not my IP, dropping")
            return None
        # Get target mac from cache:
        target_mac = ARP_CACHE[target_ip]
        # Construct the pack back to sender (switch between sender and target)
        response = build_arp_reply(hardware_type, protocol_type, hardware_len, protocol_len,
                                   target_mac, target_ip, sender_mac, sender_ip)

        print(f"Sending ARP response to {bytes_to_ip(sender_ip)}")
        return response

    elif op == ArpOp.REPLY:
        print(f"ARP reply: {bytes_to_ip(sender_ip)} is at {bytes_to_mac(sender_mac.hex)}")
        # Cache the addresses of requesting device
        if sender_ip not in ARP_CACHE:
            # TODO - Implement arp poisoning detection
            ARP_CACHE[sender_ip] = sender_mac
        else:
            print(f"{sender_ip.hex()} is already in arp cache")
    else:
        print("Unknown op code")
    return None

def build_arp_reply(hardware_type, protocol_type, hardware_len,
                    protocol_len, sender_mac, sender_ip, target_mac, target_ip):
    packet = struct.pack(PACKET_FORMAT, hardware_type, protocol_type, hardware_len,
                       protocol_len, ArpOp.REPLY, sender_mac, sender_ip, target_mac, target_ip)
    return packet
