import unittest
from unittest.mock import MagicMock, patch, call, ANY
from krack_attack import *

class TestKrackAttack(unittest.TestCase):
    def setUp(self):
        self.interface = "wlan0"
        self.target_ap_mac = "00:11:22:33:44:55"
        self.target_client_mac = "AA:BB:CC:DD:EE:FF"
        
        # Create mock for scapy functions
        self.mock_sniff = patch('krack_attack.sniff').start()
        self.mock_sendp = patch('krack_attack.sendp').start()
        
        # Mock the interface check
        self.mock_conf = patch('krack_attack.conf').start()
        self.mock_conf.ifaces = MagicMock()
        self.mock_conf.ifaces.dev_from_name.return_value = MagicMock()
        
    def tearDown(self):
        patch.stopall()

    def test_block_message_4(self):
        # Test the message 4 blocking filter
        mock_msg4 = MagicMock()
        mock_msg4.haslayer.side_effect = lambda x: x == EAPOL
        mock_msg4.getlayer.return_value.type = 3
        mock_msg4.addr1 = self.target_ap_mac
        mock_msg4.addr2 = self.target_client_mac
        
        # Mock sniff to return our test packet
        self.mock_sniff.return_value = [mock_msg4]
        
        # Get the block filter function
        block_filter = block_message_4(
            self.interface,
            self.target_ap_mac,
            self.target_client_mac
        )
        
        # Verify the filter works correctly
        self.assertTrue(block_filter(mock_msg4))
        # Verify sniff was called with correct timeout
        self.mock_sniff.assert_called_with(
            iface=self.interface,
            lfilter=block_filter,
            count=1,
            timeout=5
        )

    def test_block_group_key_message_2(self):
        # Test the group message 2 blocking filter
        mock_msg2 = MagicMock()
        mock_msg2.haslayer.side_effect = lambda x: x == EAPOL
        mock_msg2.getlayer.return_value.type = 3
        mock_msg2.getlayer.return_value.key_info = 0x2000  # Group Key bit set (bit 13)
        mock_msg2.addr1 = self.target_client_mac
        
        # Mock sniff to return our test packet
        self.mock_sniff.return_value = [mock_msg2]
        
        # Get the block filter function
        block_filter = block_group_key_message_2(
            self.interface,
            self.target_ap_mac
        )
        
        # Verify the filter works correctly
        self.assertTrue(block_filter(mock_msg2))
        # Verify sniff was called with correct timeout
        self.mock_sniff.assert_called_with(
            iface=self.interface,
            lfilter=block_filter,
            count=1,
            timeout=5
        )

    def test_four_way_handshake_plaintext(self):
        # Test plaintext four-way handshake attack
        # Create mock packets for the complete 4-way handshake
        mock_msg1 = MagicMock()
        mock_msg1.haslayer.side_effect = lambda x: x == EAPOL
        mock_msg1.getlayer.return_value.type = 3
        mock_msg1.getlayer.return_value.key_info = 0x008a  # Message 1 flags
        mock_msg1.addr1 = self.target_client_mac
        mock_msg1.addr2 = self.target_ap_mac

        mock_msg2 = MagicMock()
        mock_msg2.haslayer.side_effect = lambda x: x == EAPOL
        mock_msg2.getlayer.return_value.type = 3
        mock_msg2.getlayer.return_value.key_info = 0x010a  # Message 2 flags
        mock_msg2.addr1 = self.target_ap_mac
        mock_msg2.addr2 = self.target_client_mac

        mock_msg3 = MagicMock()
        mock_msg3.haslayer.side_effect = lambda x: x == EAPOL
        mock_msg3.getlayer.return_value.type = 3
        mock_msg3.getlayer.return_value.key_info = 0x13ca  # Message 3 flags
        mock_msg3.addr1 = self.target_client_mac
        mock_msg3.addr2 = self.target_ap_mac

        mock_msg4 = MagicMock()
        mock_msg4.haslayer.side_effect = lambda x: x == EAPOL
        mock_msg4.getlayer.return_value.type = 3
        mock_msg4.getlayer.return_value.key_info = 0x030a  # Message 4 flags
        mock_msg4.addr1 = self.target_ap_mac
        mock_msg4.addr2 = self.target_client_mac
        
        # Mock sniff to return our test packets in sequence
        self.mock_sniff.side_effect = [
            [mock_msg1, mock_msg2, mock_msg3, mock_msg4],  # Initial handshake
            [],  # Block message 4 (no packets)
            [mock_msg3],  # Retransmitted message 3
        ]
        
        with patch('krack_attack.time.sleep'):
            four_way_handshake_plaintext_retransmission(
                self.interface,
                self.target_ap_mac,
                self.target_client_mac
            )
            
        self.mock_sendp.assert_called_with(mock_msg3, iface=self.interface, verbose=False)

    def test_four_way_handshake_encrypted(self):
        # Test encrypted four-way handshake attack
        # Create mock packets for the complete 4-way handshake
        mock_msg1 = MagicMock()
        mock_msg1.haslayer.side_effect = lambda x: x == EAPOL
        mock_msg1.getlayer.return_value.type = 3
        mock_msg1.getlayer.return_value.key_info = 0x008a  # Message 1 flags
        mock_msg1.addr1 = self.target_client_mac
        mock_msg1.addr2 = self.target_ap_mac

        mock_msg2 = MagicMock()
        mock_msg2.haslayer.side_effect = lambda x: x == EAPOL
        mock_msg2.getlayer.return_value.type = 3
        mock_msg2.getlayer.return_value.key_info = 0x010a  # Message 2 flags
        mock_msg2.addr1 = self.target_ap_mac
        mock_msg2.addr2 = self.target_client_mac

        mock_msg3 = MagicMock()
        mock_msg3.haslayer.side_effect = lambda x: x == EAPOL
        mock_msg3.getlayer.return_value.type = 3
        mock_msg3.getlayer.return_value.key_info = 0x13ca  # Message 3 flags
        mock_msg3.addr1 = self.target_client_mac
        mock_msg3.addr2 = self.target_ap_mac

        mock_msg4 = MagicMock()
        mock_msg4.haslayer.side_effect = lambda x: x == EAPOL
        mock_msg4.getlayer.return_value.type = 3
        mock_msg4.getlayer.return_value.key_info = 0x030a  # Message 4 flags
        mock_msg4.addr1 = self.target_ap_mac
        mock_msg4.addr2 = self.target_client_mac
        
        # Mock sniff to return our test packets in sequence
        self.mock_sniff.side_effect = [
            [mock_msg1, mock_msg2, mock_msg3, mock_msg4],  # Initial handshake
            [],  # Block message 4 (no packets)
            [mock_msg3],  # Retransmitted message 3
            [mock_msg3],  # Encrypted retransmitted message 3
        ]
        
        with patch('krack_attack.time.sleep'):
            four_way_handshake_encrypted_retransmission(
                self.interface,
                self.target_ap_mac,
                self.target_client_mac
            )
            
        self.mock_sendp.assert_has_calls([
            call(mock_msg3, iface=self.interface, verbose=False),
            call(mock_msg3, iface=self.interface, verbose=False)
        ])

    def test_group_key_handshake_immediate(self):
        # Test immediate group key handshake attack
        # Create mock packets for group key handshake
        mock_msg1 = MagicMock()
        mock_msg1.haslayer.side_effect = lambda x: x == EAPOL
        mock_msg1.getlayer.return_value.type = 3
        mock_msg1.getlayer.return_value.key_info = 0x2080  # Group Key and ACK bits set
        mock_msg1.addr1 = self.target_client_mac
        mock_msg1.addr2 = self.target_ap_mac

        mock_msg2 = MagicMock()
        mock_msg2.haslayer.side_effect = lambda x: x == EAPOL
        mock_msg2.getlayer.return_value.type = 3
        mock_msg2.getlayer.return_value.key_info = 0x2000  # Group Key bit set
        mock_msg2.addr1 = self.target_ap_mac
        mock_msg2.addr2 = self.target_client_mac

        mock_broadcast = MagicMock()
        mock_broadcast.haslayer.side_effect = lambda x: x == Dot11
        mock_broadcast.addr2 = self.target_ap_mac
        mock_broadcast.dst = "ff:ff:ff:ff:ff:ff"
        
        # Mock sniff to return our test packets in sequence
        self.mock_sniff.side_effect = [
            [mock_msg1, mock_msg2],  # Initial group key handshake
            [],  # Block message 2 (no packets)
            [mock_msg1],  # Retransmitted message 1
            [mock_broadcast],  # Broadcast frame
        ]
        
        with patch('krack_attack.time.sleep'):
            group_key_handshake_immediate_install(
                self.interface,
                self.target_ap_mac
            )
            
        self.mock_sendp.assert_has_calls([
            call(mock_msg1, iface=self.interface, verbose=False),
            call(mock_broadcast, iface=self.interface, verbose=False)
        ])

    def test_group_key_handshake_delayed(self):
        # Test delayed group key handshake attack
        # Create mock packets for group key handshake
        mock_msg1 = MagicMock()
        mock_msg1.haslayer.side_effect = lambda x: x == EAPOL
        mock_msg1.getlayer.return_value.type = 3
        mock_msg1.getlayer.return_value.key_info = 0x2080  # Group Key and ACK bits set
        mock_msg1.addr1 = self.target_client_mac
        mock_msg1.addr2 = self.target_ap_mac

        mock_msg2 = MagicMock()
        mock_msg2.haslayer.side_effect = lambda x: x == EAPOL
        mock_msg2.getlayer.return_value.type = 3
        mock_msg2.getlayer.return_value.key_info = 0x2000  # Group Key bit set
        mock_msg2.addr1 = self.target_ap_mac
        mock_msg2.addr2 = self.target_client_mac

        mock_broadcast = MagicMock()
        mock_broadcast.haslayer.side_effect = lambda x: x == Dot11
        mock_broadcast.addr2 = self.target_ap_mac
        mock_broadcast.dst = "ff:ff:ff:ff:ff:ff"
        
        # Mock sniff to return our test packets in sequence
        self.mock_sniff.side_effect = [
            [mock_msg1, mock_msg2],  # Initial group key handshake
            [],  # Block message 2 (no packets)
            [mock_msg1],  # Retransmitted message 1
            [mock_msg2],  # Message 2 to modify
            [mock_broadcast],  # Broadcast frame
        ]
        
        with patch('krack_attack.time.sleep'):
            group_key_handshake_delayed_install(
                self.interface,
                self.target_ap_mac
            )
            
        self.mock_sendp.assert_has_calls([
            call(mock_msg2, iface=self.interface, verbose=False),
            call(mock_msg1, iface=self.interface, verbose=False),
            call(mock_broadcast, iface=self.interface, verbose=False)
        ])

    def test_fast_bss_transition(self):
        # Test Fast BSS Transition attack
        # Create mock packets for FT handshake
        mock_auth_req = MagicMock()
        mock_auth_req.haslayer.side_effect = lambda x: x in [Dot11, Dot11Auth, Dot11Elt]
        mock_auth_req.getlayer.side_effect = lambda x: MagicMock(
            algo=2,  # FT Authentication
            info=b'\x00' * 32 + b'\x11' * 32,  # SNonce
            ID=55  # Mobility Domain IE
        )
        mock_auth_req.addr1 = self.target_ap_mac
        mock_auth_req.addr2 = self.target_client_mac

        mock_auth_resp = MagicMock()
        mock_auth_resp.haslayer.side_effect = lambda x: x in [Dot11, Dot11Auth, Dot11Elt]
        mock_auth_resp.getlayer.side_effect = lambda x: MagicMock(
            algo=2,  # FT Authentication
            info=b'\x00' * 32 + b'\x22' * 32,  # ANonce
            ID=55  # Mobility Domain IE
        )
        mock_auth_resp.addr1 = self.target_client_mac
        mock_auth_resp.addr2 = self.target_ap_mac

        mock_reasso_req = MagicMock()
        mock_reasso_req.haslayer.side_effect = lambda x: x in [Dot11, Dot11ReassoReq, Dot11Elt]
        mock_reasso_req.getlayer.side_effect = lambda x: MagicMock(
            ID=55,  # Mobility Domain IE
            info=b'\x00' * 64 + b'\x00\x00\x00\x00\x00\x00\x00\x00'  # Replay counter
        )
        mock_reasso_req.addr1 = self.target_ap_mac
        mock_reasso_req.addr2 = self.target_client_mac
        mock_reasso_req.copy.return_value = mock_reasso_req  # Return self on copy

        mock_reasso_resp = MagicMock()
        mock_reasso_resp.haslayer.side_effect = lambda x: x in [Dot11, Dot11ReassoResp, Dot11Elt]
        mock_reasso_resp.getlayer.side_effect = lambda x: MagicMock(ID=55)  # Mobility Domain IE
        mock_reasso_resp.addr1 = self.target_client_mac
        mock_reasso_resp.addr2 = self.target_ap_mac
        
        # Mock sniff to return our test packets in sequence
        self.mock_sniff.side_effect = [
            [mock_auth_req, mock_auth_resp, mock_reasso_req, mock_reasso_resp],  # Complete FT handshake
            [mock_reasso_req],  # Encrypted frame
        ]
        
        with patch('krack_attack.time.sleep'):
            fast_bss_transition_attack(
                self.interface,
                self.target_ap_mac,
                self.target_client_mac
            )
            
        # Verify that sendp was called with the modified reassociation request
        self.mock_sendp.assert_called_with(mock_reasso_req, iface=self.interface, verbose=False)

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
        self.mock_sniff.side_effect = [
            [mock_client1_packet, mock_noise_packet1],  # First scan
            [mock_client2_packet, mock_broadcast_packet],  # Second scan
            []  # Empty scan to trigger timeout
        ]
        
        with patch('krack_attack.time.time') as mock_time:
            # Simulate time progression
            mock_time.side_effect = [0, 10, 20, 30]
            
            clients = detect_clients(self.interface, self.target_ap_mac, timeout=5)
            
            # Verify we found both valid clients and filtered out noise
            self.assertEqual(len(clients), 2)
            self.assertIn("CC:DD:EE:FF:00:11", clients)
            self.assertIn("CC:DD:EE:FF:00:22", clients)

    def test_auto_attack(self):
        """Test auto attack functionality."""
        # Create mock networks with different signal strengths
        mock_networks = [
            {'ESSID': 'StrongNetwork', 'Address': '00:11:22:33:44:55', 'Signal': '-60dBm'},
            {'ESSID': 'WeakNetwork', 'Address': '66:77:88:99:AA:BB', 'Signal': '-85dBm'},
            {'ESSID': 'MediumNetwork', 'Address': 'CC:DD:EE:FF:00:11', 'Signal': '-75dBm'}
        ]
        
        # Create mock clients for the strong network
        mock_client1 = "AA:BB:CC:DD:EE:FF"
        
        # Mock the attack functions
        mock_attacks = {
            'four_way_handshake_plaintext_retransmission': MagicMock(return_value=True),
            'four_way_handshake_encrypted_retransmission': MagicMock(return_value=True),
            'group_key_handshake_immediate_install': MagicMock(return_value=True),
            'group_key_handshake_delayed_install': MagicMock(return_value=True),
            'fast_bss_transition_attack': MagicMock(return_value=True)
        }
        
        # Mock network scanning
        with patch('krack_attack.scan_networks', return_value=mock_networks) as mock_scan:
            # Mock client detection
            with patch('krack_attack.detect_clients', return_value=[mock_client1]) as mock_detect:
                # Mock all attack functions
                with patch.multiple('krack_attack', **mock_attacks):
                    # Mock time functions
                    with patch('krack_attack.time.sleep'):
                        # Run auto attack in single run mode
                        results = auto_attack(
                            self.interface,
                            min_signal=-70,  # Only strongest network should qualify
                            attack_timeout=60,
                            scan_interval=30,
                            single_run=True
                        )
        
        # Verify network scanning was called
        mock_scan.assert_called_once()
        
        # Verify client detection was called for strong network
        mock_detect.assert_called_once_with(self.interface, mock_networks[0]['Address'], timeout=60)
        
        # Verify that the strong network was attacked
        self.assertIn(mock_networks[0]['Address'], results)
        self.assertEqual(len(results[mock_networks[0]['Address']]), 5)  # All attacks should succeed
        
        # Verify each attack type was attempted with correct parameters
        mock_attacks['four_way_handshake_plaintext_retransmission'].assert_called_once_with(
            self.interface, mock_networks[0]['Address'], mock_client1)
        mock_attacks['four_way_handshake_encrypted_retransmission'].assert_called_once_with(
            self.interface, mock_networks[0]['Address'], mock_client1)
        mock_attacks['group_key_handshake_immediate_install'].assert_called_once_with(
            self.interface, mock_networks[0]['Address'])
        mock_attacks['group_key_handshake_delayed_install'].assert_called_once_with(
            self.interface, mock_networks[0]['Address'])
        mock_attacks['fast_bss_transition_attack'].assert_called_once_with(
            self.interface, mock_networks[0]['Address'], mock_client1)
        
        # Verify that weak networks were not attacked
        self.assertNotIn(mock_networks[1]['Address'], results)  # Weak network
        self.assertNotIn(mock_networks[2]['Address'], results)  # Medium network

    def test_auto_attack_error_handling(self):
        """Test auto attack error handling and recovery."""
        # Create mock networks
        mock_networks = [
            {'ESSID': 'TestNetwork1', 'Address': '00:11:22:33:44:55', 'Signal': '-65dBm'},
            {'ESSID': 'TestNetwork2', 'Address': '66:77:88:99:AA:BB', 'Signal': '-70dBm'}
        ]
        
        # Create sequence of scan results to simulate network disappearing and reappearing
        scan_results = [
            mock_networks,  # First scan: both networks
            [],  # Second scan: no networks (simulating temporary failure)
            [mock_networks[0]],  # Third scan: one network returns
            mock_networks  # Fourth scan: both networks
        ]
        
        # Create sequence of client detection results
        client_results = [
            [],  # First attempt: no clients
            ["AA:BB:CC:DD:EE:FF"],  # Second attempt: one client
            Exception("Network error"),  # Third attempt: error
            ["AA:BB:CC:DD:EE:FF"]  # Fourth attempt: recovery
        ]
        
        # Mock network scanning
        with patch('krack_attack.scan_networks', side_effect=scan_results) as mock_scan:
            # Mock client detection
            with patch('krack_attack.detect_clients', side_effect=client_results) as mock_detect:
                # Mock time functions
                with patch('krack_attack.time.sleep') as mock_sleep:
                    # Set up mock_sleep to raise KeyboardInterrupt after processing all results
                    mock_sleep.side_effect = [None] * 10 + [KeyboardInterrupt()]
                    
                    auto_attack(
                        self.interface,
                        min_signal=-75,
                        attack_timeout=30,
                        scan_interval=15
                    )
        
        # Verify scanning continued after failures
        self.assertEqual(mock_scan.call_count, 4)
        
        # Verify client detection was attempted multiple times
        self.assertEqual(mock_detect.call_count, 4)

    def test_auto_attack_timeout_handling(self):
        """Test auto attack timeout handling for individual attacks."""
        # Create mock network
        mock_network = {
            'ESSID': 'TestNetwork',
            'Address': '00:11:22:33:44:55',
            'Signal': '-65dBm'
        }
        
        # Create mock client
        mock_client = "AA:BB:CC:DD:EE:FF"
        
        # Mock the attack functions with different behaviors
        mock_attacks = {
            'four_way_handshake_plaintext_retransmission': MagicMock(side_effect=TimeoutError()),
            'four_way_handshake_encrypted_retransmission': MagicMock(return_value=True),
            'group_key_handshake_immediate_install': MagicMock(side_effect=TimeoutError()),
            'group_key_handshake_delayed_install': MagicMock(return_value=True),
            'fast_bss_transition_attack': MagicMock(side_effect=TimeoutError())
        }
        
        # Mock network scanning
        with patch('krack_attack.scan_networks', return_value=[mock_network]) as mock_scan:
            # Mock client detection
            with patch('krack_attack.detect_clients', return_value=[mock_client]) as mock_detect:
                # Mock all attack functions
                with patch.multiple('krack_attack', **mock_attacks):
                    # Mock time functions
                    with patch('krack_attack.time.sleep') as mock_sleep:
                        # Set up mock_sleep to raise KeyboardInterrupt after processing all attacks
                        mock_sleep.side_effect = [None] * 5 + [KeyboardInterrupt()]
                        
                        auto_attack(
                            self.interface,
                            min_signal=-70,
                            attack_timeout=30,
                            scan_interval=15
                        )
        
        # Verify that all attacks were attempted
        for mock_attack in mock_attacks.values():
            self.assertTrue(mock_attack.called)
        
        # Verify that successful attacks were recorded (check the ones that didn't timeout)
        self.assertTrue(mock_attacks['four_way_handshake_encrypted_retransmission'].called)
        self.assertTrue(mock_attacks['group_key_handshake_delayed_install'].called)

if __name__ == '__main__':
    unittest.main() 