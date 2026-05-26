import struct

import rdp_check as rdp


def test_build_x224_cr_ssl_only():
    pkt = rdp.build_x224_cr(rdp.PROTOCOL_SSL)
    assert pkt[:2] == b"\x03\x00"                        # TPKT version/reserved
    assert struct.unpack("!H", pkt[2:4])[0] == len(pkt)  # TPKT length == total
    assert pkt[4] == len(pkt) - 5                        # X.224 LI
    assert pkt[5] == 0xE0                                # CR + CDT
    assert pkt[-8:] == struct.pack("<BBHI", 0x01, 0x00, 0x0008, rdp.PROTOCOL_SSL)


def test_build_x224_cr_hybrid_protocols_field():
    pkt = rdp.build_x224_cr(rdp.PROTOCOL_HYBRID | rdp.PROTOCOL_SSL)
    assert struct.unpack("<I", pkt[-4:])[0] == 0x03
