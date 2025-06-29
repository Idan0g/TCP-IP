import socket
from scapy.all import conf, IFACES

import Arp
import IP
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
        pretty_mac += hexed_bytes[index: index + 2] + ":"
        index += 2
    return pretty_mac[:len(pretty_mac) - 1]

def parse_ether_payload(ether_type, payload, arp_cache):
    response = None
    if ether_type in ETHERTYPE_PROTOCOL:
        name, parser = ETHERTYPE_PROTOCOL[ether_type]
        print(f"{name} packet!")
        # Handle special needs
        if name == "ARP":
            response = parser(payload, arp_cache)
        # Save interface ip
        elif name == "IPv4":
            response = parser(payload, list(arp_cache.keys())[0])
        else:
            response = parser(payload)
    else:
        print(f"Unknown Ether type: {hex(ether_type)}")
    return response

def send_response(sock, src_mac, dst_mac, ether_type, response):
    reply = struct.pack(ETHERNET_FRAME_FORMAT, dst_mac, src_mac, ether_type) + response
    sock.send(reply)

def listen(socket, device_mac, arp_cache):
    while True:
        # Receive raw frame
        packet = socket.recv_raw()
        # If received an empty packet drop it, Extract the raw frame from packet tuple
        if not packet or not (raw_frame := packet[1]):
            continue
        if len(raw_frame) < ETH_HEADER_LEN:
            continue

        # Extract different fields according to Ethernet frame structure
        dst_mac, src_mac, ether_type = struct.unpack(ETHERNET_FRAME_FORMAT, raw_frame[:ETH_HEADER_LEN])
        payload = raw_frame[ETH_HEADER_LEN:]

        # If packet wasn't meant for device, drop it
        if dst_mac != device_mac and dst_mac != BROADCAST_MAC:
            continue

        print(f"Frame received: \nDestination address: {bytes_to_mac(dst_mac)}, Source address: {bytes_to_mac(src_mac)},"
              f" Ether type: {hex(ether_type)}, Payload: {payload.hex()}")

        # Parse the payload, check if got response
        response = parse_ether_payload(ether_type, payload, arp_cache)
        if response:
            # Switch the src and dst addresses
            send_response(socket, dst_mac, src_mac, ether_type, response)

def init_device_info(iface):
    if not iface.ip or not iface.mac:
        raise RuntimeError("Interface missing IP or MAC")

    my_ip_bytes = socket.inet_aton(iface.ip)
    my_mac_bytes = bytes.fromhex(iface.mac.replace(":", ""))

    return my_ip_bytes, my_mac_bytes, iface.name

def list_interfaces():
    print("Available interfaces:")
    index = 1
    for iface in IFACES.values():
        name = iface.name or "(no name)"
        ip = iface.ip or "no IP"
        mac = iface.mac or "no MAC"
        print(f"Index {index}: {name} | IP: {ip} | MAC: {mac}")
        index += 1
    return list(IFACES.values())

def choose_interface():
    interfaces = list_interfaces()
    while True:
        try:
            index = int(input("Choose interface index: "))
            if index >= 1 and index <= len(interfaces):
                return interfaces[index - 1]
            print("Invalid index.")
        except ValueError:
            print("Please enter a valid number.")

def main():
    try:
        iface = choose_interface()
        my_ip_bytes, my_mac_bytes, iface_name = init_device_info(iface)
    except RuntimeError as e:
        print(f"Network device initialization error: {e}")
        return

    arp_cache = {my_ip_bytes: my_mac_bytes}
    socket = conf.L2socket(iface=iface_name, promisc=True)
    listen(socket, my_mac_bytes, arp_cache)

if __name__ == "__main__":
    main()
