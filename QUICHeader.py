


from scapy.fields import *
from scapy.packet import Packet
from utils.string_to_ascii import string_to_ascii

class QUICHeader(Packet):
    """
    The header for the QUIC CH packet
    Taken from Wireshark capture example
    """
    name = "QUIC"
    fields_desc = [
        XByteField("Public_Flags", 0xc1),
        StrFixedLenField("Version", string_to_ascii("00000001"),4),
        ByteField("DCID_Length", 8),
        StrFixedLenField("DCID",string_to_ascii("6bafa3cda6256d3c"),8),
        ByteField("SCID_Length", 8),
        StrFixedLenField("SCID",string_to_ascii("2d35022d62b561f2"),8),
        ByteField("Token_length", 0),
        StrFixedLenField("Length",bytes.fromhex("4496"),2),
        LEShortField("Packet_Number",0),
    ]













