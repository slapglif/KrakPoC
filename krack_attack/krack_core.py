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
import contextlib

console = Console()

# Configure loguru logger
logger.remove()  # Remove default handler
logger.add(sys.stderr, level="INFO")

class TimeoutError(Exception):
    """Raised when an operation times out."""
    pass

@contextlib.contextmanager
def timeout(seconds):
    """Context manager for timeouts."""
    def signal_handler(signum, frame):
        raise TimeoutError("Operation timed out")
    
    # Set the signal handler and a timeout
    import signal
    signal.signal(signal.SIGALRM, signal_handler)
    signal.alarm(seconds)
    
    try:
        yield
    finally:
        # Disable the alarm
        signal.alarm(0)

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

def parse_signal_strength(signal_str):
    """Parse signal strength from different formats to a comparable number."""
    try:
        if 'dBm' in signal_str:
            return float(signal_str.split('dBm')[0])
        elif '/' in signal_str:  # Format like 70/100
            num, den = signal_str.split('/')
            return float(num) / float(den) * 100
        else:
            return float(signal_str)
    except (ValueError, TypeError):
        return -100  # Return a very low value for unparseable signals 