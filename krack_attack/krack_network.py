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

def detect_clients(interface, target_ap_mac, timeout=30):
    """
    Detect clients connected to a specific access point.
    
    Args:
        interface (str): Network interface to use
        target_ap_mac (str): MAC address of the target AP
        timeout (int): Time to sniff for clients in seconds
        
    Returns:
        list: List of client MAC addresses
    """
    logger.info(f"Detecting clients for AP {target_ap_mac}...")
    
    def is_valid_client_mac(mac):
        """Check if MAC address is valid (not broadcast/multicast)."""
        # Convert MAC to bytes for comparison
        mac_bytes = bytes.fromhex(mac.replace(':', ''))
        # Check if it's a broadcast address
        if mac_bytes == b'\xff\xff\xff\xff\xff\xff':
            return False
        # Check if it's a multicast address (first byte LSB is 1)
        if mac_bytes[0] & 0x01:
            return False
        # Check if it's all zeros
        if mac_bytes == b'\x00\x00\x00\x00\x00\x00':
            return False
        return True
    
    def packet_filter(pkt):
        """Filter packets for client detection."""
        if not pkt.haslayer(Dot11):
            return False
            
        # Check if packet is to/from our target AP
        if pkt.addr1 != target_ap_mac and pkt.addr2 != target_ap_mac:
            return False
            
        # Get the client address (the other end of the communication)
        client_addr = pkt.addr2 if pkt.addr1 == target_ap_mac else pkt.addr1
        
        # Validate client address
        if not is_valid_client_mac(client_addr):
            return False
            
        return True
    
    try:
        # Sniff for client packets
        packets = sniff(iface=interface, lfilter=packet_filter, timeout=timeout)
        
        # Extract unique client addresses
        clients = set()
        for pkt in packets:
            client_addr = pkt.addr2 if pkt.addr1 == target_ap_mac else pkt.addr1
            if is_valid_client_mac(client_addr):
                clients.add(client_addr)
                logger.info(f"Found client: {client_addr}")
        
        return list(clients)
        
    except Exception as e:
        logger.error(f"Error detecting clients: {str(e)}")
        return []

def sort_networks_by_strength(networks):
    """Sort networks by signal strength, strongest first."""
    return sorted(networks, 
                 key=lambda x: parse_signal_strength(x.get('Signal', '-100')), 
                 reverse=True) 