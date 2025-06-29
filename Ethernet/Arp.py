import struct
import socket

PACKET_FORMAT = "!HHBBH6s4s6s4s"
# Own device, DG
ARP_CACHE = { socket.inet_aton("192.168.1.16") : bytes.fromhex("1c1b0d9529ae"),
              socket.inet_aton("192.168.1.1") : bytes.fromhex("5cb13e589a1c")
}

ARP_REQUEST = 1
ARP_REPLY = 2

def parse_arp(payload):
    (hardware_type, protocol_type, hardware_len, protocol_len,
     op, sender_mac, sender_ip, target_mac, target_ip) = struct.unpack(PACKET_FORMAT, payload)

    # Cache the addresses of requesting device
    if sender_ip not in ARP_CACHE:
        ARP_CACHE[sender_ip] = sender_mac


    if op == ARP_REQUEST:
        print(f"ARP request from: {sender_ip.hex()}| {sender_mac.hex()} for {target_ip.hex()}'s mac")
        if target_ip not in ARP_CACHE:
            print("Requested IP not in ARP cache, dropping")
            return None

        # Get target mac from cache:
        target_mac = ARP_CACHE[target_ip]
        # Construct the pack back to sender (switch between sender and target)
        response = build_arp_reply(hardware_type, protocol_type, hardware_len, protocol_len,
                                   target_mac, target_ip, sender_mac, sender_ip)

        print(f"Sending ARP response to {sender_ip.hex()}")
        return response

    elif op == ARP_REPLY:
        print(f"ARP reply: {sender_ip.hex()} is at {sender_mac.hex()}")
        if sender_ip not in ARP_CACHE:
            ARP_CACHE[sender_ip] = sender_mac
        else:
            print(f"{sender_ip.hex()} is already in arp cache")
    else:
        print("Unknown op code")
    return None



def build_arp_reply(hardware_type, protocol_type, hardware_len,
                    protocol_len, sender_mac, sender_ip, target_mac, target_ip):

    packet = struct.pack(PACKET_FORMAT, hardware_type, protocol_type, hardware_len,
                       protocol_len, ARP_REPLY, sender_mac, sender_ip, target_mac, target_ip)
    return packet