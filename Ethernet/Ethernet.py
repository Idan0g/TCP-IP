from scapy.all import conf, IFACES
from IP import parse_ip
from Arp import parse_arp
from Ipv6 import parse_ipv6
from Vlan import parse_vlan
import struct

DEVICE_NAME = "Intel(R) Ethernet Connection (2) I219-V"
IFACE = IFACES.dev_from_name(DEVICE_NAME)
DEVICE_MAC_STR = IFACE.mac.lower()
DEVICE_MAC = bytes.fromhex(DEVICE_MAC_STR.replace(":", ""))
INTERFACE_NAME = IFACE.name
BROADCAST_MAC = b'\xff\xff\xff\xff\xff\xff'

# Frame Format: 6 bytes dest, 6 bytes src, 2 bytes ethertype
ETHERNET_FRAME_FORMAT = "!6s6sH"
ETH_HEADER_LEN = 14

ETHERTYPE_PROTOCOL = {
    0x0800: ("IPv4", parse_ip),
    0x0806: ("ARP", parse_arp),
    0x86DD: ("IPv6", parse_ipv6),
    0x8100: ("VLAN", parse_vlan),
}

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
def listen(sock):
    while True:
        packet = sock.recv_raw()  # Receive raw frame
        # If received an empty packet
        if not packet or not packet[1]:
            continue
        # Extract the raw frame from packet tuple
        raw_frame = packet[1]
        if len(raw_frame) < ETH_HEADER_LEN:
            continue
        dst_mac, src_mac, ether_type = struct.unpack(ETHERNET_FRAME_FORMAT, raw_frame[:ETH_HEADER_LEN])
        payload = raw_frame[ETH_HEADER_LEN:]
        # If packet wasn't meant for device, drop it
        if dst_mac != DEVICE_MAC and dst_mac != BROADCAST_MAC:
            continue
        print(f"Frame received: \n Destination address: {dst_mac.hex()}, Source address: {src_mac.hex()},"
              f" Ether type: {hex(ether_type)}, Payload: {payload.hex()}")
        response = parse_ether_payload(ether_type, payload)

        if response:
            # Switch the src and dst addresses
            send_response(sock, dst_mac, src_mac, ether_type, response)

def create_socket():
    if not INTERFACE_NAME:
        return
    sock = conf.L2listen(iface=INTERFACE_NAME, promisc=True) # Create the socket
    return sock


def main():
    socket = create_socket()
    if not socket:
        print("Interface not found... exiting")
        return
    listen(socket)

if __name__ == "__main__":
    main()