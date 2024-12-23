# KRACK Attack Tool

![ezgif-1-4a9174721e](https://github.com/user-attachments/assets/bce56522-7a00-49be-926d-a4c9fb6cb3f1)

An implementation of the Key Reinstallation Attack (KRACK) against WPA2 as described in the paper "Key Reinstallation Attacks: Forcing Nonce Reuse in WPA2" by Mathy Vanhoef and Frank Piessens.

## Features

- Implementation of all major KRACK attack variants:
  - 4-way handshake attack (plaintext and encrypted retransmission)
  - Group key handshake attack (immediate and delayed installation)
  - Fast BSS Transition (FT) handshake attack
- User-friendly CLI interface with:
  - Network scanning and target selection
  - MAC address validation
  - Progress indicators and colored output
  - Detailed error reporting
- Cross-platform support (Linux and macOS)
- Comprehensive test suite

## Requirements

- Python 3.7+
- Root/sudo privileges (for network interface access)
- Linux or macOS operating system
- Wireless network interface that supports monitor mode

## Installation

1. Clone the repository:
```bash
git clone https://github.com/slapglif/KrakPoC
cd krack-attack
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Make sure your wireless interface supports monitor mode:
```bash
sudo airmon-ng
```

## Usage

Basic usage:
```bash
sudo python3 krack_cli.py
```

With specific options:
```bash
sudo python3 krack_cli.py --interface wlan0 --ap-mac 00:11:22:33:44:55 --client-mac aa:bb:cc:dd:ee:ff
```

Options:
- `-i, --interface`: Network interface to use
- `--ap-mac`: Target AP MAC address
- `--client-mac`: Target client MAC address
- `--scan/--no-scan`: Enable/disable network scanning

## Attack Types

1. **4-Way Handshake (Plaintext)**: Exploits plaintext retransmissions of message 3
2. **4-Way Handshake (Encrypted)**: Exploits encrypted retransmissions of message 3
3. **Group Key (Immediate)**: Attacks APs that install group keys immediately
4. **Group Key (Delayed)**: Attacks APs that delay group key installation
5. **Fast BSS Transition**: Attacks the Fast BSS Transition (FT) handshake

## Testing

Run the test suite:
```bash
python3 -m pytest test_krack_attack.py -v
```
all tests passing
![image](https://github.com/user-attachments/assets/e65b73f7-c62d-4bbf-b219-36ff16811e25)

## Disclaimer

This tool is for educational and research purposes only. Do not use it against networks you don't own or have explicit permission to test. The authors are not responsible for any misuse or damage caused by this tool.

## References

- [Original KRACK Attack Paper](https://papers.mathyvanhoef.com/ccs2017.pdf)
- [CVE-2017-13077](https://nvd.nist.gov/vuln/detail/CVE-2017-13077)
- [CVE-2017-13078](https://nvd.nist.gov/vuln/detail/CVE-2017-13078)

## License

This project is licensed under the MIT License - see the LICENSE file for details. 
