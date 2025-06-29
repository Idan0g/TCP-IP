import socket
from scapy.all import conf, IFACES

import Arp
from IP import parse_ip
from Arp import parse_arp
from Ipv6 import parse_ipv6
from Vlan import parse_vlan
import struct
import time

# Ethernet Frame Format: 6 bytes dest, 6 bytes src, 2 bytes ethertype
ETHERNET_FRAME_FORMAT = "!6s6sH"
ETH_HEADER_LEN = struct.calcsize(ETHERNET_FRAME_FORMAT)
BROADCAST_MAC = b'\xff\xff\xff\xff\xff\xff'

# ARP
ETHERNET_TYPE_ARP = 0x0806
ARP_TIMEOUT = 5

ETHERTYPE_PROTOCOL = {
    0x0800: ("IPv4", parse_ip),
    0x0806: ("ARP", parse_arp),
    0x86DD: ("IPv6", parse_ipv6),
    0x8100: ("VLAN", parse_vlan),
}

def bytes_to_mac(bytes_form):
    return ':'.join(f'{b:02x}' for b in bytes_form)

def bytes_to_ip(bytes):
    return socket.inet_ntoa(bytes)

def ip_to_bytes(ip_str):
    return socket.inet_aton(ip_str)

# Process Ethernet frame payload
def parse_ether_payload(ether_type, payload, arp_cache, my_ip_bytes):
    response = None

    if ether_type in ETHERTYPE_PROTOCOL:
        name, parser = ETHERTYPE_PROTOCOL[ether_type]
        print(f"{name} packet!")
        # Handle special needs
        if name == "ARP":
            response = parser(payload, arp_cache)
        # Save interface ip
        elif name == "IPv4":
            response = parser(payload, my_ip_bytes)
        else:
            response = parser(payload)

    else:
        print(f"Unknown Ether type: {hex(ether_type)}")

    return response

# General- ethernet response
def send_response(sock, src_mac, dst_mac, ether_type, response):
    reply = struct.pack(ETHERNET_FRAME_FORMAT, dst_mac, src_mac, ether_type) + response
    sock.send(reply)

# General- ethernet request
def send_ethernet_frame(sock, dst_mac, src_mac, ether_type, payload):
    frame = struct.pack(ETHERNET_FRAME_FORMAT, dst_mac, src_mac, ether_type) + payload
    sock.send(frame)


def send_arp_request(sock, src_mac, src_ip, target_ip_str, arp_cache):
    target_ip = ip_to_bytes(target_ip_str)

    # Use build_arp_request function - returns a constructed arp payload
    request = Arp.build_arp_request(src_mac, src_ip, target_ip)
    # Construct the header, destination = broadcast
    ethernet_frame = struct.pack(ETHERNET_FRAME_FORMAT,
                                 BROADCAST_MAC, src_mac, ETHERNET_TYPE_ARP) + request
    sock.send(ethernet_frame)
    print(f"Sent ARP request for {target_ip_str}")

    # Run until timeout
    start = time.time()
    while time.time() - start < ARP_TIMEOUT:
        # Examine each received packet
        unpacked = receive_and_unpack(sock)
        if unpacked is None:
            continue

        dst_mac, src_mac, ether_type, payload = unpacked

        if ether_type != ETHERNET_TYPE_ARP:
            continue

        # Parse arp payload - create variable to store the different attributes
        arp = Arp.parse_arp_header(payload)
        if not arp:
            continue

        # If got a matching answer to specific ip
        if arp.op == Arp.ArpOp.REPLY and arp.sender_ip == target_ip:
            mac = bytes_to_mac(arp.sender_mac)
            # If new, store in arp cache
            if arp.sender_ip not in arp_cache:
                print("Storing in ARP cache...")
                arp_cache[arp.sender_ip] = arp.sender_mac
            return mac

    print("No ARP reply received.")
    return None

def send_ip_request(sock):
    pass

def receive_and_unpack(sock):
    # Receive frame, and unpack it's content
    packet = sock.recv_raw()
    # If received an empty packet drop it, Extract the raw frame from packet tuple
    if not packet or not (raw_frame := packet[1]):
        return None
    # If frame length is invalid
    if len(raw_frame) < ETH_HEADER_LEN:
        return None
    #Unpack into variables
    dst_mac, src_mac, ether_type = struct.unpack(ETHERNET_FRAME_FORMAT, raw_frame[:ETH_HEADER_LEN])
    payload = raw_frame[ETH_HEADER_LEN:]
    return dst_mac, src_mac, ether_type, payload

def listen(sock, device_mac, arp_cache, my_ip_bytes):
    while True:
        unpacked = receive_and_unpack(sock)
        if unpacked is None:
            continue

        # Extract different fields according to Ethernet frame structure
        dst_mac, src_mac, ether_type, payload = unpacked

        # If packet wasn't meant for device, drop it
        if dst_mac != device_mac and dst_mac != BROADCAST_MAC:
            continue

        print(f"Frame received: \nDestination address: {bytes_to_mac(dst_mac)}, Source address: {bytes_to_mac(src_mac)},"
              f" Ether type: {hex(ether_type)}")

        # Parse the payload, check if got response
        response = parse_ether_payload(ether_type, payload, arp_cache, my_ip_bytes)
        if response:
            # Switch the src and dst addresses
            send_response(sock, dst_mac, src_mac, ether_type, response)
        print()

def init_device_info(iface):
    missing = []
    if not iface.ip:
        missing.append("IP address")
    if not iface.mac:
        missing.append("MAC address")
    if missing:
        raise RuntimeError(f"Interface missing {", ".join(missing)}")

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
            print("Please enter a valid choice number.")

def init_menu(sock, my_mac_bytes, arp_cache, my_ip_bytes):
    while True:
        print("\n--- Main Menu ---")
        print("1. Listen")
        print("2. Send ARP request")
        print("3. Send Ping (ICMP Echo)")
        print("4. Show ARP cache")
        print("5. Exit")
        choice = input("Enter your choice: ")

        if choice == '1':
            listen(sock, my_mac_bytes, arp_cache, my_ip_bytes)

        elif choice == '2':
            target_ip_str = input("Enter IP to resolve: ")
            mac_answer = send_arp_request(sock, my_mac_bytes, my_ip_bytes, target_ip_str, arp_cache)
            if mac_answer:
                print(f"{target_ip_str} is at: {mac_answer}")
            else:
                print("Failed to resolve MAC.")

        elif choice == '3':
            target_ip_str = input("Enter IP to ping: ")
            send_ip_request(sock, my_ip_bytes, my_mac_bytes, target_ip_str, arp_cache)

        elif choice == '4':
            print("--- ARP Cache ---")
            for ip, mac in arp_cache.items():
                print(f"{bytes_to_ip(ip)} -> {bytes_to_mac(mac)}")

        elif choice == '5':
            break
        else:
            print("Invalid choice")

def main():
    try:
        iface = choose_interface()
        my_ip_bytes, my_mac_bytes, iface_name = init_device_info(iface)
    except RuntimeError as e:
        print(f"Network device initialization error: {e}")
        return

    arp_cache = {my_ip_bytes: my_mac_bytes}
    sock = conf.L2socket(iface=iface_name, promisc=True)
    init_menu(sock, my_mac_bytes, arp_cache, my_ip_bytes)

if __name__ == "__main__":
    main()
