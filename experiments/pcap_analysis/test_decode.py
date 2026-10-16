"""Parser tests for partial payloads, extension bounds and nested IP selection."""
import struct,unittest
from scapy.layers.inet import IP,TCP
from scapy.contrib.gtp import GTP_U_Header,GTPPDUSessionContainer
from decode_inner import decode

def sample():
    inner=bytes(IP(src='12.1.1.133',dst='192.0.2.1')/TCP(sport=15000,dport=443,flags='PA')/bytes(100))
    gtp=bytes(GTP_U_Header(E=1,gtp_type=255,teid=41,next_ex=0x85)/GTPPDUSessionContainer(type=1,QFI=1)/inner)
    udp=struct.pack('!HHHH',2152,2152,len(gtp)+8,0)+gtp
    outer=bytes(IP(src='192.168.70.129',dst='192.168.70.134',proto=17)/udp)
    return bytes(14)+b'\x08\x00'+outer

class DecoderTests(unittest.TestCase):
    def test_complete_inner_header(self):
        r,_,_=decode(sample())
        self.assertEqual((r['inner_src'],r['destination_port'],r['direction']),('12.1.1.133',443,1))
        self.assertEqual(r['inner_missing_bytes'],0)
    def test_partial_body_preserves_header_and_missing_count(self):
        full=sample();r,_,_=decode(full[:-24])
        self.assertEqual(r['inner_missing_bytes'],24)
        self.assertEqual(r['gtp_missing_bytes'],24)
        self.assertEqual(r['destination_port'],443)
    def test_truncated_transport_header_is_rejected(self):
        with self.assertRaises(ValueError):decode(sample()[:16+20+8+16+20+10])
    def test_invalid_extension_length_is_rejected(self):
        data=bytearray(sample());data[16+20+8+12]=255
        with self.assertRaises(ValueError):decode(bytes(data))
    def test_non_initial_outer_fragment_is_not_decoded(self):
        data=bytearray(sample());data[16+6:16+8]=struct.pack('!H',1)
        self.assertIsNone(decode(bytes(data)))

if __name__=='__main__':unittest.main()
