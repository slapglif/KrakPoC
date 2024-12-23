import unittest
from unittest.mock import MagicMock, patch, ANY
from scapy.all import Dot11
from krack_attack.krack_network import detect_clients, scan_networks
from krack_attack.krack_core import parse_signal_strength
from krack_attack.krack_network import sort_networks_by_strength

class TestNetwork(unittest.TestCase):
    def setUp(self):
        self.interface = "wlan0"
        self.target_ap_mac = "00:11:22:33:44:55"
        
        # Create mock for scapy functions
        self.mock_sniff = patch('krack_attack.krack_network.sniff').start()
        
    def tearDown(self):
        patch.stopall()

    def test_detect_clients(self):
        """Test client detection functionality."""
        # Create mock packets for client detection
        mock_client1_packet = MagicMock()
        mock_client1_packet.haslayer.side_effect = lambda x: x == Dot11
        mock_client1_packet.addr1 = self.target_ap_mac
        mock_client1_packet.addr2 = "CC:DD:EE:FF:00:11"
        
        mock_client2_packet = MagicMock()
        mock_client2_packet.haslayer.side_effect = lambda x: x == Dot11
        mock_client2_packet.addr1 = self.target_ap_mac
        mock_client2_packet.addr2 = "CC:DD:EE:FF:00:22"
        
        # Create noise packets that should be filtered out
        mock_noise_packet1 = MagicMock()
        mock_noise_packet1.haslayer.side_effect = lambda x: x == Dot11
        mock_noise_packet1.addr1 = "00:00:00:00:00:00"
        mock_noise_packet1.addr2 = "11:11:11:11:11:11"
        
        mock_broadcast_packet = MagicMock()
        mock_broadcast_packet.haslayer.side_effect = lambda x: x == Dot11
        mock_broadcast_packet.addr1 = self.target_ap_mac
        mock_broadcast_packet.addr2 = "ff:ff:ff:ff:ff:ff"
        
        # Mock sniff to return our test packets
        self.mock_sniff.return_value = [
            mock_client1_packet,
            mock_client2_packet,
            mock_noise_packet1,
            mock_broadcast_packet
        ]
        
        clients = detect_clients(self.interface, self.target_ap_mac, timeout=5)
        
        # Verify we found both valid clients and filtered out noise
        self.assertEqual(len(clients), 2)
        self.assertIn("CC:DD:EE:FF:00:11", clients)
        self.assertIn("CC:DD:EE:FF:00:22", clients)
        
        # Verify sniff was called with correct parameters
        self.mock_sniff.assert_called_once_with(
            iface=self.interface,
            timeout=5,
            lfilter=ANY
        )

    def test_parse_signal_strength(self):
        """Test signal strength parsing from different formats."""
        # Test dBm format
        self.assertEqual(parse_signal_strength("-65dBm"), -65)
        self.assertEqual(parse_signal_strength("-90dBm"), -90)
        
        # Test percentage format (70/100)
        self.assertEqual(parse_signal_strength("70/100"), 70)
        self.assertEqual(parse_signal_strength("45/100"), 45)
        
        # Test raw number format
        self.assertEqual(parse_signal_strength("-75"), -75)
        self.assertEqual(parse_signal_strength("60"), 60)
        
        # Test invalid formats
        self.assertEqual(parse_signal_strength("invalid"), -100)
        self.assertEqual(parse_signal_strength(None), -100)

    def test_sort_networks_by_strength(self):
        """Test network sorting by signal strength."""
        networks = [
            {'ESSID': 'Network1', 'Signal': '-65dBm'},
            {'ESSID': 'Network2', 'Signal': '-90dBm'},
            {'ESSID': 'Network3', 'Signal': '-75dBm'},
            {'ESSID': 'Network4', 'Signal': '80/100'},
            {'ESSID': 'Network5', 'Signal': 'invalid'},
        ]
        
        sorted_networks = sort_networks_by_strength(networks)
        
        # Verify order: Network4 (80) > Network1 (-65) > Network3 (-75) > Network2 (-90) > Network5 (invalid/-100)
        self.assertEqual(sorted_networks[0]['ESSID'], 'Network4')
        self.assertEqual(sorted_networks[1]['ESSID'], 'Network1')
        self.assertEqual(sorted_networks[2]['ESSID'], 'Network3')
        self.assertEqual(sorted_networks[3]['ESSID'], 'Network2')
        self.assertEqual(sorted_networks[4]['ESSID'], 'Network5') 