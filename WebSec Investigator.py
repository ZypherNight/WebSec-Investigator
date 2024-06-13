#!/usr/bin/env python

import scapy.all as scapy
import argparse
import socket
import nmap
from scapy.layers.inet import IP, TCP, UDP, ICMP
import networkx as nx
import matplotlib.pyplot as plt
from tabulate import tabulate  # Import tabulate
import threading
from queue import Queue
import p0f  # You'll need to install p0f: pip install p0f

def scan(ip):
    """
    Performs an ARP scan on the specified IP address or range,
    presenting the results in a visually appealing table.

    Args:
        ip (str): The IP address or range to scan.
    """

    try:
        arp_request = scapy.ARP(pdst=ip)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast/arp_request
        answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
 
        print("\n===== Active Devices =====")
        table_data = []
        for element in answered_list:
            table_data.append([element[1].psrc, element[1].hwsrc])

        print(tabulate(table_data, headers=["IP Address", "MAC Address"], tablefmt="grid"))

    except Exception as e:
        print(f"Error during ARP scan: {e}")

def port_scan_worker(queue, results):
    """
    Worker function for threaded port scanning.

    Args:
        queue (Queue): Queue of (target, port) tuples to scan.
        results (list): List to store scan results.
    """
    while not queue.empty():
        target, port = queue.get()
        try:
            scanner = nmap.PortScanner()
            scanner.scan(target, str(port))
            for host in scanner.all_hosts():
                for proto in scanner[host].all_protocols():
                    for p in scanner[host][proto].keys():
                        state = scanner[host][proto][p]['state']
                        service = scanner[host][proto][p]['name']
                        results.append([p, state, service])
        except Exception as e:
            results.append([port, "error", str(e)])
        queue.task_done()

def port_scan(target, ports):
    """
    Performs a port scan on the specified target and ports,
    including service detection. Presents the results in a well-formatted table.

    Args:
        target (str): The target hostname or IP address.
        ports (str): The ports to scan (e.g., "22,80,443" or "1-1024").
    """

    port_list = []
    if '-' in ports:
        start, end = map(int, ports.split('-'))
        port_list = range(start, end + 1)
    else:
        port_list = map(int, ports.split(','))

    print(f"\n===== Scanning {target} for open ports =====")
    queue = Queue()
    results = []

    for port in port_list:
        queue.put((target, port))

    threads = []
    num_threads = 10  # Adjust this for performance
    for _ in range(num_threads):
        t = threading.Thread(target=port_scan_worker, args=(queue, results))
        t.start()
        threads.append(t)

    queue.join()

    for t in threads:
        t.join()

    if results:
        print(tabulate(results, headers=["Port", "State", "Service"], tablefmt="grid"))
    else:
        print("No open ports found.")

def get_hostname(ip):
    """
    Resolves the hostname from an IP address.

    Args:
        ip (str): The IP address to resolve.

    Returns:
        str: The resolved hostname, or the original IP if resolution fails.
    """

    try:
        hostname = socket.gethostbyaddr(ip)[0]
        return hostname
    except socket.herror:
        return ip

def os_detection(target):
    """
    Attempts to identify the operating system of the target using multiple techniques.

    Args:
        target (str): The target IP address or hostname.
    """

    print(f"\n===== Identifying Operating System of {target} =====")
    scanner = nmap.PortScanner()

    try:
        ip_address = socket.gethostbyname(target)  # Resolve domain
        scanner.scan(hosts=ip_address, arguments="-O")  # Use Nmap's OS detection

        if 'osmatch' in scanner[ip_address]:
            osmatches = scanner[ip_address]['osmatch']
            if osmatches:
                for osmatch in osmatches:
                    print(f"   Name: {osmatch['name']}")
                    print(f"   Accuracy: {osmatch['accuracy']}%")
                    if 'osclass' in osmatch:
                        for osclass in osmatch['osclass']:
                            print(f"   OS Class: {osclass['type']}")
                            print(f"   OS Family: {osclass['osfamily']}")
                    print("-" * 30)
            else:
                print("   No OS matches found.")
        else:
            print("   OS detection failed.")
    except Exception as e:
        print(f"   Error during OS detection: {e}")

def protocol_identification(target, port):
    """
    Identifies the protocol used on a specific port using Scapy.

    Args:
        target (str): The target hostname or IP address.
        port (int): The port to identify.
    """

    print(f"\n===== Identifying protocol on {target}:{port} =====")
    try:
        # Send a SYN packet (TCP)
        tcp_packet = IP(dst=target)/TCP(dport=port, flags="S")
        tcp_response = scapy.sr1(tcp_packet, timeout=2, verbose=0)

        if tcp_response:
            if tcp_response.haslayer(TCP):
                if tcp_response[TCP].flags == "SA":
                    print("     Protocol: TCP (Open)")
                elif tcp_response[TCP].flags == "RA":
                    print("     Protocol: TCP (Closed)")
            elif tcp_response.haslayer(UDP):
                print("     Protocol: UDP (Open)")
        else:
            # Send a UDP packet
            udp_packet = IP(dst=target)/UDP(dport=port)
            udp_response = scapy.sr1(udp_packet, timeout=2, verbose=0)
            if udp_response:
                if udp_response.haslayer(ICMP) and udp_response[ICMP].type == 3 and udp_response[ICMP].code == 3:
                    print("     Protocol: UDP (Closed)")
                else:
                    print("     Protocol: UDP (Open)")
            else:
                print("     No response received. The port might be filtered or blocked.")

    except Exception as e:
        print(f"     Error: {e}")

def topology_discovery(ip_range):
    """
    Performs basic topology discovery using ARP responses.

    Args:
        ip_range (str): The IP address range to scan.
    """

    print("\n===== Discovering Network Topology =====")
    ans, unans = scapy.srp(
        scapy.Ether(dst="ff:ff:ff:ff:ff:ff")/scapy.ARP(pdst=ip_range),
        timeout=2,
        verbose=0,
    )

    connections = [(rcv.sprintf(r"%ARP.psrc%"), rcv.sprintf(r"%ARP.pdst%")) for snd, rcv in ans]

    print("\n[+] Connections:")
    for src, dst in connections:
        print(f"  {src} -> {dst}")

    return connections

def visualize_topology(connections):
    """
    Creates a 2D network visualization using NetworkX and Matplotlib.

    Args:
        connections (list): A list of tuples representing connections
                          (e.g., [('192.168.1.1', '192.168.1.2'), ...]).
    """

    graph = nx.Graph()
    graph.add_edges_from(connections)

    pos = nx.spring_layout(graph)  # Layout algorithm (you can explore others)
    nx.draw(graph, pos, with_labels=True, node_size=1500, node_color="skyblue", font_size=10, font_weight="bold", edge_color="gray")
    plt.title("Network Topology")
    plt.show()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Network Scanner: A tool for analyzing network devices and connections.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("target", help="Target IP address, range, or hostname (e.g., 192.168.1.0/24, example.com)")
    parser.add_argument("-p", "--ports", help="Ports to scan (e.g., 22,80,443 or 1-1024). Default: 1-1000", default="1-1000")
    parser.add_argument("--os", action="store_true", help="Enable OS detection")
    parser.add_argument("--topology", action="store_true", help="Enable topology discovery and generate a 2D network map")
    parser.add_argument("--protocol", help="Identify the protocol on a specific port (e.g., 80)")

    args = parser.parse_args()

    scan(args.target)
    port_scan(args.target, args.ports)

    if args.os:
        os_detection(args.target)

    if args.protocol:
        protocol_identification(args.target, int(args.protocol))

    if args.topology:
        connections = topology_discovery(args.target)
        visualize_topology(connections)