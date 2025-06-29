import struct
import socket
from enum import IntEnum

ARP_PACKET_FORMAT = "!HHBBH6s4s6s4s"
ARP_FORMAT_SIZE = struct.calcsize(ARP_PACKET_FORMAT)

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
        pretty_mac += hexed_bytes[index: index + 2] + ":"
        index += 2
    return pretty_mac[:len(pretty_mac) - 1]

def parse_arp_header(payload):
    try:
        (hardware_type, protocol_type, hardware_len, protocol_len,
         op, sender_mac, sender_ip, target_mac, target_ip) = struct.unpack(
            ARP_PACKET_FORMAT, payload[:ARP_FORMAT_SIZE]
        )
        return {
            "hardware_type": hardware_type,
            "protocol_type": protocol_type,
            "hardware_len": hardware_len,
            "protocol_len": protocol_len,
            "op": op,
            "sender_mac": sender_mac,
            "sender_ip": sender_ip,
            "target_mac": target_mac,
            "target_ip": target_ip,
        }
    except struct.error as e:
        print(f"Failed to unpack ARP header: {e}")
        return None

def handle_arp_request(fields, my_ip, arp_cache):
    sender_ip = fields["sender_ip"]
    sender_mac = fields["sender_mac"]
    target_ip = fields["target_ip"]

    print(f"ARP request from: {bytes_to_ip(sender_ip)}|{bytes_to_mac(sender_mac)} for {bytes_to_ip(target_ip)}'s MAC")

    if target_ip != my_ip:
        print("Requested IP is not my IP, dropping")
        return None
    print("That's my mac!")
    target_mac = arp_cache.get(target_ip)

    # Switch receiver and sender
    response = build_arp_reply(
        fields["hardware_type"],
        fields["protocol_type"],
        fields["hardware_len"],
        fields["protocol_len"],
        target_mac,
        target_ip,
        sender_mac,
        sender_ip,
    )

    print(f"Sending ARP response to {bytes_to_ip(sender_ip)}")
    return response

def handle_arp_reply(fields, arp_cache):
    sender_ip = fields["sender_ip"]
    sender_mac = fields["sender_mac"]

    print(f"ARP reply: {bytes_to_ip(sender_ip)} is at {bytes_to_mac(sender_mac)}")

    if sender_ip not in arp_cache:
        print("Storing in cache...")
        arp_cache[sender_ip] = sender_mac
    else:
        print(f"MAC address: {bytes_to_ip(sender_ip)} is already in ARP cache")

def build_arp_reply(hardware_type, protocol_type, hardware_len,
                    protocol_len, sender_mac, sender_ip, target_mac, target_ip):
    packet = struct.pack(ARP_PACKET_FORMAT, hardware_type, protocol_type, hardware_len,
                       protocol_len, ArpOp.REPLY, sender_mac, sender_ip, target_mac, target_ip)
    return packet

def parse_arp(payload, arp_cache):
    my_ip = list(arp_cache.keys())[0]
    print("Payload length:", len(payload))
    print("Payload hex:", payload.hex())

    if len(payload) < ARP_FORMAT_SIZE:
        print(f"ARP packet too short! length={len(payload)}, expected length={ARP_FORMAT_SIZE}")
        return None

    fields = parse_arp_header(payload)
    if fields is None:
        return None

    op = fields["op"]
    if op == ArpOp.REQUEST:
        return handle_arp_request(fields, my_ip, arp_cache)
    elif op == ArpOp.REPLY:
        handle_arp_reply(fields, arp_cache)
    else:
        print("Unknown op code")
    return None
