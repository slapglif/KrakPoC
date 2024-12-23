import unittest
from unittest.mock import MagicMock, patch, call
from scapy.all import Dot11, EAPOL
from scapy.layers.dot11 import Dot11Auth, Dot11AssoReq, Dot11ReassoReq, Dot11AssoResp, Dot11ReassoResp, Dot11Elt, RadioTap
from krack_attack.krack_attacks import (
    four_way_handshake_plaintext_retransmission,
    four_way_handshake_encrypted_retransmission,
    group_key_handshake_immediate_install,
    group_key_handshake_delayed_install,
    fast_bss_transition_attack,
    block_message_4,
    block_group_key_message_2
)

class TestAttacks(unittest.TestCase):
    def setUp(self):
        self.interface = "wlan0"
        self.target_ap_mac = "00:11:22:33:44:55"
        self.target_client_mac = "AA:BB:CC:DD:EE:FF"
        
        # Create mock for scapy functions
        self.mock_sniff = patch('krack_attack.krack_attacks.sniff').start()
        self.mock_sendp = patch('krack_attack.krack_attacks.send_packet').start()
        
    def tearDown(self):
        patch.stopall()

    def test_block_message_4(self):
        """Test the message 4 blocking filter."""
        # Create mock packet
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
        """Test the group message 2 blocking filter."""
        # Create mock packet
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
        """Test plaintext four-way handshake attack."""
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
        
        with patch('krack_attack.krack_attacks.time.sleep'):
            result = four_way_handshake_plaintext_retransmission(
                self.interface,
                self.target_ap_mac,
                self.target_client_mac
            )
            
        self.assertTrue(result)
        self.mock_sendp.assert_called_with(mock_msg3, self.interface)

    def test_four_way_handshake_encrypted(self):
        """Test encrypted four-way handshake attack."""
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
        
        with patch('krack_attack.krack_attacks.time.sleep'):
            result = four_way_handshake_encrypted_retransmission(
                self.interface,
                self.target_ap_mac,
                self.target_client_mac
            )
            
        self.assertTrue(result)
        self.mock_sendp.assert_has_calls([
            call(mock_msg3, self.interface),
            call(mock_msg3, self.interface)
        ])

    def test_group_key_handshake_immediate(self):
        """Test immediate group key handshake attack."""
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
        
        with patch('krack_attack.krack_attacks.time.sleep'):
            result = group_key_handshake_immediate_install(
                self.interface,
                self.target_ap_mac
            )
            
        self.assertTrue(result)
        self.mock_sendp.assert_has_calls([
            call(mock_msg1, self.interface),
            call(mock_broadcast, self.interface)
        ])

    def test_group_key_handshake_delayed(self):
        """Test delayed group key handshake attack."""
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
        
        with patch('krack_attack.krack_attacks.time.sleep'):
            result = group_key_handshake_delayed_install(
                self.interface,
                self.target_ap_mac
            )
            
        self.assertTrue(result)
        self.mock_sendp.assert_has_calls([
            call(mock_msg2, self.interface),
            call(mock_msg1, self.interface),
            call(mock_broadcast, self.interface)
        ])

    def test_fast_bss_transition(self):
        """Test Fast BSS Transition attack."""
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
        
        with patch('krack_attack.krack_attacks.time.sleep'):
            result = fast_bss_transition_attack(
                self.interface,
                self.target_ap_mac,
                self.target_client_mac
            )
            
        self.assertTrue(result)
        self.mock_sendp.assert_called_with(mock_reasso_req, self.interface) 