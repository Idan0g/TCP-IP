import socket
from scapy.all import conf

import Arp
from IP import parse_ip
from Arp import parse_arp
from Ipv6 import parse_ipv6
from Vlan import parse_vlan
import struct

# Ethernet Frame Format: 6 bytes dest, 6 bytes src, 2 bytes ethertype
ETHERNET_FRAME_FORMAT = "!6s6sH"
ETH_HEADER_LEN = struct.calcsize(ETHERNET_FRAME_FORMAT)
BROADCAST_MAC = b'\xff\xff\xff\xff\xff\xff'

ETHERTYPE_PROTOCOL = {
    0x0800: ("IPv4", parse_ip),
    0x0806: ("ARP", parse_arp),
    0x86DD: ("IPv6", parse_ipv6),
    0x8100: ("VLAN", parse_vlan),
}

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

def parse_ether_payload(ether_type, payload):
    response = None
    if ether_type in ETHERTYPE_PROTOCOL:
        name, parser = ETHERTYPE_PROTOCOL[ether_type]
        print(f"{name} packet!")
        response = parser(payload)
    else:
        print(f"Unknown Ether type: {hex(ether_type)}")
    return response

def send_response(sock, src_mac, dst_mac, ether_type, response):
    reply = struct.pack(ETHERNET_FRAME_FORMAT, dst_mac, src_mac, ether_type) + response
    sock.send(reply)

def listen(read_sock, write_sock, device_mac):
    while True:
        packet = read_sock.recv_raw()  # Receive raw frame
        # If received an empty packet, Extract the raw frame from packet tuple
        if not packet or not (raw_frame := packet[1]):
            continue
        if len(raw_frame) < ETH_HEADER_LEN:
            continue
        dst_mac, src_mac, ether_type = struct.unpack(ETHERNET_FRAME_FORMAT, raw_frame[:ETH_HEADER_LEN])
        payload = raw_frame[ETH_HEADER_LEN:]
        # If packet wasn't meant for device, drop it
        # TODO - implement unicast
        if dst_mac != device_mac and dst_mac != BROADCAST_MAC:
            continue
        print(f"Frame received: \nDestination address: {bytes_to_mac(dst_mac)}, Source address: {bytes_to_mac(src_mac)},"
              f" Ether type: {hex(ether_type)}, Payload: {payload.hex()}")
        response = parse_ether_payload(ether_type, payload)
        if response:
            # Switch the src and dst addresses
            send_response(write_sock, dst_mac, src_mac, ether_type, response)

def init_device_info():
    iface = conf.iface
    if not iface:
        raise RuntimeError("Could not find default interface")
    my_ip = iface.ip
    my_mac = iface.mac

    if not my_ip or not my_mac:
        raise RuntimeError("Interface missing IP or MAC")
    my_ip_bytes = socket.inet_aton(my_ip)
    my_mac_bytes = bytes.fromhex(my_mac.replace(":", ""))

    return my_ip_bytes, my_mac_bytes, iface.name

def main():
    try:
        my_ip_bytes, my_mac_bytes, iface_name = init_device_info()
    except  RuntimeError as e:
        print(f"Network device initialization error: {e}")
        return
    Arp.MY_IP = my_ip_bytes
    Arp.ARP_CACHE = {my_ip_bytes: my_mac_bytes}
    read_socket = conf.L2listen(iface=iface_name, promisc=True)
    write_socket = conf.L2socket(iface=iface_name)
    listen(read_socket, write_socket, my_mac_bytes)

if __name__ == "__main__":
    main()
