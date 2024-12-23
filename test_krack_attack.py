import unittest
from unittest.mock import patch, MagicMock
import scapy.all as scapy
from krack_attack import (
    four_way_handshake_plaintext_retransmission,
    four_way_handshake_encrypted_retransmission,
    group_key_handshake_immediate_install,
    group_key_handshake_delayed_install,
    fast_bss_transition_attack,
    block_message_4,
    block_group_key_message_2
)

class TestKrackAttack(unittest.TestCase):
    def setUp(self):
        self.interface = "wlan0"
        self.target_ap_mac = "00:11:22:33:44:55"
        self.target_client_mac = "aa:bb:cc:dd:ee:ff"
        
        # Create mock EAPOL packets
        self.mock_eapol_msg1 = MagicMock()
        self.mock_eapol_msg1.haslayer.return_value = True
        self.mock_eapol_msg1.getlayer.return_value.type = 3
        self.mock_eapol_msg1.addr1 = self.target_client_mac
        self.mock_eapol_msg1.addr2 = self.target_ap_mac
        
        self.mock_eapol_msg2 = MagicMock()
        self.mock_eapol_msg2.haslayer.return_value = True
        self.mock_eapol_msg2.getlayer.return_value.type = 3
        self.mock_eapol_msg2.addr1 = self.target_ap_mac
        self.mock_eapol_msg2.addr2 = self.target_client_mac

    @patch('scapy.sniff')
    @patch('scapy.sendp')
    def test_four_way_handshake_plaintext(self, mock_sendp, mock_sniff):
        # Mock capturing initial handshake
        mock_sniff.side_effect = [
            [self.mock_eapol_msg1, self.mock_eapol_msg2] * 2,  # 4 messages
            [self.mock_eapol_msg1],  # Retransmitted message 3
        ]
        
        result = four_way_handshake_plaintext_retransmission(
            self.interface,
            self.target_ap_mac,
            self.target_client_mac
        )
        
        self.assertTrue(result)
        mock_sendp.assert_called()

    @patch('scapy.sniff')
    @patch('scapy.sendp')
    def test_four_way_handshake_encrypted(self, mock_sendp, mock_sniff):
        # Mock capturing initial handshake
        mock_sniff.side_effect = [
            [self.mock_eapol_msg1, self.mock_eapol_msg2] * 2,  # 4 messages
            [self.mock_eapol_msg1],  # Retransmitted message 3
            [self.mock_eapol_msg1],  # Encrypted retransmitted message 3
        ]
        
        result = four_way_handshake_encrypted_retransmission(
            self.interface,
            self.target_ap_mac,
            self.target_client_mac
        )
        
        self.assertTrue(result)
        self.assertEqual(mock_sendp.call_count, 2)  # Should send message 3 twice

    @patch('scapy.sniff')
    @patch('scapy.sendp')
    def test_group_key_handshake_immediate(self, mock_sendp, mock_sniff):
        # Create mock broadcast frame
        mock_broadcast = MagicMock()
        mock_broadcast.haslayer.return_value = True
        mock_broadcast.addr2 = self.target_ap_mac
        mock_broadcast.dst = "ff:ff:ff:ff:ff:ff"
        
        # Mock packet captures
        mock_sniff.side_effect = [
            [self.mock_eapol_msg1, self.mock_eapol_msg2],  # Group key handshake
            [self.mock_eapol_msg1],  # Retransmitted message 1
            [mock_broadcast],  # Broadcast frame
        ]
        
        result = group_key_handshake_immediate_install(
            self.interface,
            self.target_ap_mac
        )
        
        self.assertTrue(result)
        self.assertEqual(mock_sendp.call_count, 2)  # Message 1 and broadcast frame

    @patch('scapy.sniff')
    @patch('scapy.sendp')
    def test_group_key_handshake_delayed(self, mock_sendp, mock_sniff):
        # Create mock broadcast frame
        mock_broadcast = MagicMock()
        mock_broadcast.haslayer.return_value = True
        mock_broadcast.addr2 = self.target_ap_mac
        mock_broadcast.dst = "ff:ff:ff:ff:ff:ff"
        
        # Mock packet captures
        mock_sniff.side_effect = [
            [self.mock_eapol_msg1, self.mock_eapol_msg2],  # Group key handshake
            [self.mock_eapol_msg1],  # Retransmitted message 1
            [self.mock_eapol_msg2],  # Message 2 to modify
            [mock_broadcast],  # Broadcast frame
        ]
        
        result = group_key_handshake_delayed_install(
            self.interface,
            self.target_ap_mac
        )
        
        self.assertTrue(result)
        self.assertEqual(mock_sendp.call_count, 3)  # Modified msg2, msg1, broadcast

    @patch('scapy.sniff')
    @patch('scapy.sendp')
    def test_fast_bss_transition(self, mock_sendp, mock_sniff):
        # Create mock reassociation request
        mock_reasso_req = MagicMock()
        mock_reasso_req.haslayer.side_effect = lambda x: x == scapy.Dot11ReassoReq
        mock_reasso_req.addr1 = self.target_ap_mac
        mock_reasso_req.addr2 = self.target_client_mac
        
        # Mock packet captures
        mock_sniff.side_effect = [
            [mock_reasso_req] * 4,  # FT handshake packets
        ]
        
        result = fast_bss_transition_attack(
            self.interface,
            self.target_ap_mac,
            self.target_client_mac
        )
        
        self.assertTrue(result)
        mock_sendp.assert_called()

    def test_block_message_4(self):
        # Test the message 4 blocking filter
        mock_msg4 = MagicMock()
        mock_msg4.haslayer.return_value = True
        mock_msg4.getlayer.return_value.type = 3
        mock_msg4.addr1 = self.target_ap_mac
        mock_msg4.addr2 = self.target_client_mac
        
        block_filter = block_message_4(
            self.interface,
            self.target_ap_mac,
            self.target_client_mac
        )
        
        self.assertTrue(block_filter(mock_msg4))

    def test_block_group_key_message_2(self):
        # Test the group message 2 blocking filter
        mock_msg2 = MagicMock()
        mock_msg2.haslayer.return_value = True
        mock_msg2.getlayer.return_value.type = 3
        mock_msg2.getlayer.return_value.key_info = 0x10  # Bit 4 set
        mock_msg2.addr1 = self.target_client_mac  # Not AP
        
        block_filter = block_group_key_message_2(
            self.interface,
            self.target_ap_mac
        )
        
        self.assertTrue(block_filter(mock_msg2))

if __name__ == '__main__':
    unittest.main() 