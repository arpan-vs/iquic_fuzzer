


from scapy.fields import *
from scapy.packet import Packet
from utils.string_to_ascii import string_to_ascii

class new_connection_id(Packet) :

    name = "new_connection_id"
    fields_desc = [
        XByteField("Frame_Type", 0x18),
        ByteField("Sequence", 1),
        ByteField("Retire_Prior_To",0 ),
        ByteField("CID_Length", 8),
        StrFixedLenField("CID",string_to_ascii("6bafa3cda6256d3c"),8),
        StrFixedLenField("Stateless_Reset_Token",string_to_ascii("6bafa3cda6256d3c"),16),
    ]

class quic_stream(Packet) :

    name = "quic_stream"
    fields_desc = [
        XByteField("Frame_Type", 0x0a),
        ByteField("stream_id", 1),
        StrFixedLenField("Length",bytes.fromhex("4001"),2),
        XStrLenField("Data", None, length_from = lambda pkt: pkt.Length),
    ]

class quic_offset_stream(Packet) :

    name = "quic_stream"
    fields_desc = [
        XByteField("Frame_Type", 0x0e),
        ByteField("stream_id", 1),
        ByteField("offset", 1),
        StrFixedLenField("Length",bytes.fromhex("4001"),2),
        XStrLenField("Data", None, length_from = lambda pkt: pkt.Length),
    ]

class quic_connection_closed(Packet) :
    name = "connection_closed"
    fields_desc = [
        XByteField("Frame_Type", 0x1d),
        StrFixedLenField("Length",bytes.fromhex("4100"),2),
        ByteField("Reason_phrase_length", 0),
        StrFixedLenField("Reason_phrase",None,length_from = lambda pkt: pkt.Reason_phrase_length),
    ]