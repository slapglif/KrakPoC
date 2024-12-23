import unittest
from unittest.mock import MagicMock, patch, call
from krack_attack.krack_auto import auto_attack
from krack_attack.krack_core import TimeoutError

class TestAutoAttack(unittest.TestCase):
    def setUp(self):
        self.interface = "wlan0"
        self.target_ap_mac = "00:11:22:33:44:55"
        self.target_client_mac = "AA:BB:CC:DD:EE:FF"
        
        # Create mock for network functions
        self.mock_scan = patch('krack_attack.krack_auto.scan_networks').start()
        self.mock_detect = patch('krack_attack.krack_auto.detect_clients').start()
        
        # Create mock for attack functions
        self.mock_attacks = {
            'four_way_handshake_plaintext_retransmission': patch('krack_attack.krack_auto.four_way_handshake_plaintext_retransmission').start(),
            'four_way_handshake_encrypted_retransmission': patch('krack_attack.krack_auto.four_way_handshake_encrypted_retransmission').start(),
            'group_key_handshake_immediate_install': patch('krack_attack.krack_auto.group_key_handshake_immediate_install').start(),
            'group_key_handshake_delayed_install': patch('krack_attack.krack_auto.group_key_handshake_delayed_install').start(),
            'fast_bss_transition_attack': patch('krack_attack.krack_auto.fast_bss_transition_attack').start()
        }
        
    def tearDown(self):
        patch.stopall()

    def test_auto_attack_success(self):
        """Test successful auto attack on strong network."""
        # Create mock networks with different signal strengths
        mock_networks = [
            {'ESSID': 'StrongNetwork', 'Address': '00:11:22:33:44:55', 'Signal': '-60dBm'},
            {'ESSID': 'WeakNetwork', 'Address': '66:77:88:99:AA:BB', 'Signal': '-85dBm'},
            {'ESSID': 'MediumNetwork', 'Address': 'CC:DD:EE:FF:00:11', 'Signal': '-75dBm'}
        ]
        
        # Create mock clients for the strong network
        mock_client1 = "AA:BB:CC:DD:EE:FF"
        
        # Set up mock returns
        self.mock_scan.return_value = mock_networks
        self.mock_detect.return_value = [mock_client1]
        
        # Set all attacks to succeed
        for mock_attack in self.mock_attacks.values():
            mock_attack.return_value = True
        
        # Run auto attack in single run mode
        results = auto_attack(
            self.interface,
            min_signal=-70,  # Only strongest network should qualify
            attack_timeout=60,
            scan_interval=30,
            single_run=True
        )
        
        # Verify network scanning was called
        self.mock_scan.assert_called_once()
        
        # Verify client detection was called for strong network
        self.mock_detect.assert_called_once_with(self.interface, mock_networks[0]['Address'], timeout=60)
        
        # Verify that the strong network was attacked
        self.assertIn(mock_networks[0]['Address'], results)
        self.assertEqual(len(results[mock_networks[0]['Address']]), 5)  # All attacks should succeed
        
        # Verify each attack type was attempted with correct parameters
        self.mock_attacks['four_way_handshake_plaintext_retransmission'].assert_called_once_with(
            self.interface, mock_networks[0]['Address'], mock_client1)
        self.mock_attacks['four_way_handshake_encrypted_retransmission'].assert_called_once_with(
            self.interface, mock_networks[0]['Address'], mock_client1)
        self.mock_attacks['group_key_handshake_immediate_install'].assert_called_once_with(
            self.interface, mock_networks[0]['Address'])
        self.mock_attacks['group_key_handshake_delayed_install'].assert_called_once_with(
            self.interface, mock_networks[0]['Address'])
        self.mock_attacks['fast_bss_transition_attack'].assert_called_once_with(
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
            ["AA:BB:CC:DD:EE:FF"],  # First attempt: one client
            [],  # Second attempt: no clients
            ["AA:BB:CC:DD:EE:FF"],  # Third attempt: one client
            ["AA:BB:CC:DD:EE:FF"]  # Fourth attempt: one client
        ]

        # Set up mock returns
        self.mock_scan.side_effect = scan_results
        self.mock_detect.side_effect = client_results

        # Set some attacks to fail
        self.mock_attacks['four_way_handshake_plaintext_retransmission'].side_effect = TimeoutError()
        self.mock_attacks['group_key_handshake_immediate_install'].side_effect = Exception("Attack failed")
        self.mock_attacks['fast_bss_transition_attack'].return_value = False

        # Set other attacks to succeed
        self.mock_attacks['four_way_handshake_encrypted_retransmission'].return_value = True
        self.mock_attacks['group_key_handshake_delayed_install'].return_value = True

        # Run auto attack with error handling
        with patch('krack_attack.krack_auto.time.sleep') as mock_sleep:
            # Set up mock_sleep to raise KeyboardInterrupt after processing all results
            mock_sleep.side_effect = [None] * 3 + [KeyboardInterrupt()]

            results = auto_attack(
                self.interface,
                min_signal=-75,
                attack_timeout=30,
                scan_interval=15,
                single_run=False  # Allow multiple scan cycles
            )

        # Verify scanning continued after failures
        self.assertEqual(self.mock_scan.call_count, 4)

        # Verify successful attacks were recorded
        self.assertIn('00:11:22:33:44:55', results)
        self.assertIn('four_way_handshake_encrypted', results['00:11:22:33:44:55'])
        self.assertIn('group_key_handshake_delayed', results['00:11:22:33:44:55'])

        # Verify that failed attacks were not recorded
        self.assertNotIn('four_way_handshake_plaintext', results['00:11:22:33:44:55'])
        self.assertNotIn('group_key_handshake_immediate', results['00:11:22:33:44:55'])
        self.assertNotIn('fast_bss', results['00:11:22:33:44:55'])

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

        # Set up mock returns
        self.mock_scan.return_value = [mock_network]  # Return the same network for each scan
        self.mock_detect.return_value = [mock_client]  # Return the same client for each scan

        # Set some attacks to timeout
        self.mock_attacks['four_way_handshake_plaintext_retransmission'].side_effect = TimeoutError()
        self.mock_attacks['group_key_handshake_immediate_install'].side_effect = TimeoutError()
        self.mock_attacks['fast_bss_transition_attack'].side_effect = TimeoutError()

        # Set other attacks to succeed
        self.mock_attacks['four_way_handshake_encrypted_retransmission'].return_value = True
        self.mock_attacks['group_key_handshake_delayed_install'].return_value = True

        # Run auto attack with timeout handling
        with patch('krack_attack.krack_auto.time.sleep') as mock_sleep:
            # Set up mock_sleep to raise KeyboardInterrupt after processing all results
            mock_sleep.side_effect = [None] * 3 + [KeyboardInterrupt()]

            results = auto_attack(
                self.interface,
                min_signal=-70,
                attack_timeout=30,
                scan_interval=15,
                single_run=True  # Run only one scan cycle
            )

        # Verify that all attacks were attempted
        for attack_name, mock_attack in self.mock_attacks.items():
            self.assertTrue(mock_attack.called, f"Attack {attack_name} was not called")

        # Verify that only successful attacks were recorded
        self.assertIn('00:11:22:33:44:55', results)
        self.assertIn('four_way_handshake_encrypted', results['00:11:22:33:44:55'])
        self.assertIn('group_key_handshake_delayed', results['00:11:22:33:44:55'])

        # Verify that timed out attacks were not recorded
        self.assertNotIn('four_way_handshake_plaintext', results['00:11:22:33:44:55'])
        self.assertNotIn('group_key_handshake_immediate', results['00:11:22:33:44:55'])
        self.assertNotIn('fast_bss', results['00:11:22:33:44:55']) 