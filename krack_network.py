from scapy.all import sniff, Dot11
from rich.console import Console
import subprocess
import sys
import time
from loguru import logger
from .krack_core import parse_signal_strength

console = Console()

def get_interfaces():
    """Gets a list of available network interfaces, handling OS differences."""
    if sys.platform == 'darwin':  # macOS
        try:
            # Use the 'networksetup' command to get Wi-Fi interfaces
            output = subprocess.check_output(["networksetup", "-listallhardwareports"]).decode("utf-8")
            interfaces = []
            for line in output.splitlines():
                if "Wi-Fi" in line:  # Look for Wi-Fi interfaces
                    parts = line.split()
                    for i in range(len(parts)):
                        if parts[i].startswith("en") and parts[i][2:].isdigit():
                            interfaces.append(parts[i])
            return interfaces
        except subprocess.CalledProcessError:
            console.print("[bold red]Error:[/] Could not get interface list using 'networksetup'.")
            return []
    else:  # Linux and other systems
        from scapy.all import get_if_list
        return get_if_list()

def select_interface():
    """Allows the user to select a network interface."""
    interfaces = get_interfaces()
    if not interfaces:
        console.print("[bold red]Error:[/] No network interfaces found.")
        return None

    console.print("[bold blue]Available Network Interfaces:[/bold blue]")
    for i, iface in enumerate(interfaces, 1):
        console.print(f"{i}. {iface}")

    while True:
        try:
            choice = int(console.input("Enter the number of the interface to use: "))
            if 1 <= choice <= len(interfaces):
                return interfaces[choice - 1]
            else:
                console.print("[bold yellow]Invalid choice.[/bold yellow]")
        except ValueError:
            console.print("[bold yellow]Invalid choice.[/bold yellow]")

def scan_networks_linux(interface):
    """Scans for nearby Wi-Fi networks on Linux."""
    console.print(f"[bold green]Scanning for networks on interface '{interface}'...[/bold green]")
    try:
        # Scan for networks using the 'iwlist' command
        result = subprocess.run(['iwlist', interface, 'scan'], capture_output=True, text=True, check=True)
        output = result.stdout
        networks = []
        current_network = {}
        for line in output.splitlines():
            line = line.strip()
            if line.startswith('Cell '):
                if current_network:
                    networks.append(current_network)
                current_network = {}
                current_network['Address'] = line.split('Address: ')[1]
            elif line.startswith('ESSID:'):
                current_network['ESSID'] = line.split('ESSID:')[1].strip('"')
            elif line.startswith('Channel:'):
                current_network['Channel'] = line.split('Channel:')[1]
            elif 'Quality' in line and 'Signal level' in line:
                current_network['Quality'] = line.split('Quality=')[1].split(' ')[0]
                current_network['Signal'] = line.split('Signal level=')[1]
        if current_network:
            networks.append(current_network)

        return networks
    except subprocess.CalledProcessError as e:
        console.print(f"[bold red]Error during network scan:[/] {e}")
        return None

def scan_networks_macos(interface):
    """Scans for nearby Wi-Fi networks on macOS."""
    console.print(f"[bold green]Scanning for networks on interface '{interface}'...[/bold green]")
    try:
        # Scan for networks using the 'airport' command
        result = subprocess.run(['/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport', '-s'], capture_output=True, text=True, check=True)
        output = result.stdout
        networks = []
        for line in output.splitlines()[1:]:  # Skip header line
            parts = line.split()
            if len(parts) >= 8:
                network = {}
                network['ESSID'] = parts[0]
                network['Address'] = parts[1]
                network['Channel'] = parts[-1].split(',')[0]
                # Signal strength/quality is a bit more complex to parse
                network['Quality'] = 'N/A'
                network['Signal'] = parts[2] + ' dBm'
                networks.append(network)
        return networks
    except subprocess.CalledProcessError as e:
        console.print(f"[bold red]Error during network scan:[/] {e}")
        return None

def scan_networks(interface):
    """Scans for nearby Wi-Fi networks, handling OS differences."""
    if sys.platform == 'darwin':  # macOS
        return scan_networks_macos(interface)
    else:  # Linux and other systems
        return scan_networks_linux(interface)

def detect_clients(interface, ap_mac, timeout=30):
    """
    Detect clients connected to a specific access point.
    
    Args:
        interface (str): Network interface to use
        ap_mac (str): MAC address of the access point
        timeout (int): How long to scan for clients (in seconds)
    
    Returns:
        list: List of client MAC addresses
    """
    logger.info(f"Detecting clients for AP {ap_mac}...")
    
    clients = set()
    start_time = time.time()
    
    def packet_filter(pkt):
        """Filter packets to find client addresses."""
        if not pkt.haslayer(Dot11):
            return False
            
        # Verify addresses exist and are valid
        if not hasattr(pkt, 'addr1') or not hasattr(pkt, 'addr2'):
            return False
            
        # Check if packet is to/from our target AP
        if pkt.addr1 != ap_mac and pkt.addr2 != ap_mac:
            return False
            
        # Exclude broadcast/multicast addresses
        client_addr = pkt.addr2 if pkt.addr1 == ap_mac else pkt.addr1
        if (not client_addr or 
            client_addr == "ff:ff:ff:ff:ff:ff" or 
            client_addr.startswith("01:00:5e") or 
            client_addr.startswith("33:33")):
            return False
            
        return True
    
    try:
        # Sniff for packets
        packets = sniff(
            iface=interface,
            timeout=timeout,
            lfilter=packet_filter
        )
        
        # Extract unique client addresses
        for pkt in packets:
            client_addr = pkt.addr2 if pkt.addr1 == ap_mac else pkt.addr1
            if client_addr not in clients:
                clients.add(client_addr)
                logger.info(f"Found client: {client_addr}")
    
    except Exception as e:
        logger.error(f"Error during client detection: {str(e)}")
    
    return list(clients)

def sort_networks_by_strength(networks):
    """Sort networks by signal strength, strongest first."""
    return sorted(networks, 
                 key=lambda x: parse_signal_strength(x.get('Signal', '-100')), 
                 reverse=True) 