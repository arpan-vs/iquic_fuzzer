import secrets

from scapy.compat import Any, Optional, Union
from scapy.fields import *
from scapy.packet import Packet
from scapy.layers.tls.handshake import TLSClientHello
from scapy.layers.tls.extensions import (
    TLS_Ext_SupportedGroups,
    TLS_Ext_SupportedVersion_CH,
    TLS_Ext_SignatureAlgorithms,
    TLS_Ext_ServerName,
    ServerName,
    TLS_Ext_PSKKeyExchangeModes,
    TLS_Ext_ALPN,
    ProtocolName,
    TLS_Ext_Unknown,
    _tls_ext
)
from scapy.layers.tls.keyexchange_tls13 import (
    TLS_Ext_KeyShare_CH,
    KeyShareEntry,
    TLS_Ext_KeyShare_HRR,
    TLS_Ext_PreSharedKey_CH
)
from utils.SessionInstance import SessionInstance
from utils.string_to_ascii import string_to_ascii
from donna25519 import PrivateKey, PublicKey


import certifi
import service_identity
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac, serialization
from cryptography.hazmat.primitives.asymmetric import (
    dsa,
    ec,
    ed448,
    ed25519,
    padding,
    rsa,
    x448,
    x25519,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from aioquic.quic.packet import QuicTransportParameters




class CryptoFrame(Packet) :
    """
    The Crypto Frame 
    """
    name = "QUIC"
    
    fields_desc =[
        XByteField("Frame_Type", 0x06),
        ByteField("Offset", 0),
        StrFixedLenField("Length",bytes.fromhex("4179"),2),
    ]
    
    # Client Hello handshake messages 
    def TLSObject(self):
        _random_bytes = secrets.token_bytes(32)
        SessionInstance.get_instance().randome_value = _random_bytes
        return TLSClientHello(
                msglen = 373,
                version = 0x0303,
                sidlen=0,
                sid = None,
                random_bytes=  _random_bytes,
                cipherslen= 6,
                ciphers=[0x1302, 0x1301, 0x1303],
                complen = 1,
                comp = [0],
                extlen = 326,
                ext= [TLS_Ext_KeyShare_CH(client_shares=[KeyShareEntry(group = "x25519", kxlen = 32,
                                                                       key_exchange = SessionInstance.get_instance().public_values_bytes) ,
                                                                       KeyShareEntry(group = "secp256r1"),KeyShareEntry(group = "x448") ],
                                                                       len= 167,client_shares_len=165 ),
                      TLS_Ext_SupportedVersion_CH(versions=["TLS 1.3"],len = 3,versionslen = 2),
                      TLS_Ext_SignatureAlgorithms(sig_algs=[0x0804, 0x0403,0x0401,0x0201,0x0807,0x0808],len = 14 ,sig_algs_len= 12),
                      TLS_Ext_SupportedGroups(groups = ["secp256r1", "x25519", "x448"] , len = 8, groupslen = 6),
                      TLS_Ext_PSKKeyExchangeModes(kxmodes= 1 ,len= 2,kxmodeslen= 1),
                      TLS_Ext_ServerName(servernames=[ServerName(servername= "localhost")],len = 14,servernameslen= 12),
                      TLS_Ext_ALPN(protocols = [ProtocolName(len = 2 , protocol = "h3") , ProtocolName(len = 5 , protocol = "h3-32" ),
                                                ProtocolName(len = 5 , protocol = "h3-31"),ProtocolName(len = 5 , protocol = "h3-30"),
                                                ProtocolName(len = 5 , protocol = "h3-29")], len = 29, protocolslen = 27),
                      QUIC_Ext_Transport_parameters(type = 0x39,Parameters=[
                                                        Parameter(Type= 0x01,len= 4 , value = bytes.fromhex("8000ea60")),
                                                        Parameter(Type= 0x04,len= 4 , value = bytes.fromhex("80100000")),
                                                        Parameter(Type= 0x05,len= 4 , value = bytes.fromhex("80100000")),
                                                        Parameter(Type= 0x06,len= 4 , value = bytes.fromhex("80100000")),          
                                                        Parameter(Type= 0x07,len= 4 , value = bytes.fromhex("80100000")),
                                                        Parameter(Type= 0x08,len= 2 , value = bytes.fromhex("4080")),
                                                        Parameter(Type= 0x09,len= 2 , value = bytes.fromhex("4080")),
                                                        Parameter(Type= 0x0a,len= 1 , value = bytes.fromhex("03")),
                                                        Parameter(Type= 0x0b,len= 1 , value = bytes.fromhex("19")),
                                                        Parameter(Type= 0x0e,len= 1, value = bytes.fromhex("08")),
                                                        Parameter(Type= 0x0f,len= 8 , 
                                                                  value = string_to_ascii(SessionInstance.get_instance().initial_source_connection_id)),
                                                        ],len = 57)
                    ]
                ) 

    def TLSObjectOnline() :
        _random_bytes = secrets.token_bytes(32)
        SessionInstance.get_instance().randome_value = _random_bytes
        return TLSClientHello(
                msglen = 379,
                version = 0x0303,
                sidlen=0,
                sid = None,
                random_bytes=  _random_bytes,
                cipherslen= 6,
                ciphers=[0x1302, 0x1301, 0x1303],
                complen = 1,
                comp = [0],
                extlen = 332,
                ext= [TLS_Ext_KeyShare_CH(client_shares=[KeyShareEntry(group = "x25519", kxlen = 32,
                                                                       key_exchange = SessionInstance.get_instance().public_values_bytes) ,
                                                                       KeyShareEntry(group = "secp256r1"),KeyShareEntry(group = "x448") ],
                                                                       len= 167,client_shares_len=165 ),
                      TLS_Ext_SupportedVersion_CH(versions=["TLS 1.3"],len = 3,versionslen = 2),
                      TLS_Ext_SignatureAlgorithms(sig_algs=[0x0804, 0x0403,0x0401,0x0201,0x0807,0x0808],len = 14 ,sig_algs_len= 12),
                      TLS_Ext_SupportedGroups(groups = ["secp256r1", "x25519", "x448"] , len = 8, groupslen = 6),
                      TLS_Ext_PSKKeyExchangeModes(kxmodes= 1 ,len= 2,kxmodeslen= 1),
                      TLS_Ext_ServerName(servernames=[ServerName(servername= "quic.aiortc.org")],len = 20,servernameslen= 18),
                      TLS_Ext_ALPN(protocols = [ProtocolName(len = 2 , protocol = "h3") , ProtocolName(len = 5 , protocol = "h3-32" ),
                                                ProtocolName(len = 5 , protocol = "h3-31"),ProtocolName(len = 5 , protocol = "h3-30"),
                                                ProtocolName(len = 5 , protocol = "h3-29")], len = 29, protocolslen = 27),
                      QUIC_Ext_Transport_parameters(type = 0x39,Parameters=[
                                                        Parameter(Type= 0x01,len= 4 , value = bytes.fromhex("8000ea60")),
                                                        Parameter(Type= 0x04,len= 4 , value = bytes.fromhex("80100000")),
                                                        Parameter(Type= 0x05,len= 4 , value = bytes.fromhex("80100000")),
                                                        Parameter(Type= 0x06,len= 4 , value = bytes.fromhex("80100000")),          
                                                        Parameter(Type= 0x07,len= 4 , value = bytes.fromhex("80100000")),
                                                        Parameter(Type= 0x08,len= 2 , value = bytes.fromhex("4080")),
                                                        Parameter(Type= 0x09,len= 2 , value = bytes.fromhex("4080")),
                                                        Parameter(Type= 0x0a,len= 1 , value = bytes.fromhex("03")),
                                                        Parameter(Type= 0x0b,len= 1 , value = bytes.fromhex("19")),
                                                        Parameter(Type= 0x0e,len= 1, value = bytes.fromhex("08")),
                                                        Parameter(Type= 0x0f,len= 8 , 
                                                                  value = string_to_ascii(SessionInstance.get_instance().initial_source_connection_id)),
                                                        ],len = 57)
                    ]
                ) 



class Parameter(Packet):
        name = "Parameter"
        fields_desc = [
                    XByteField("Type",None),
                    ByteField("len",None),
                    XStrLenField("value", None,
                                    length_from = lambda pkt: pkt.len) ]
    
    
class QUIC_Ext_Transport_parameters(TLS_Ext_Unknown) :
        name = "QUIC Extension - Transport parameters"
        fields_desc = [
                    ShortEnumField("type", None, _tls_ext),
                    ShortField("len", None),
                    PacketListField("Parameters", [], Parameter,
                                    length_from=lambda pkt: pkt.len)] 
        




class ACKFrame(Packet) :
      name = "ACK"
      fields_desc =[
        XByteField("Frame_Type", 0x02),
        ByteField("Largest_Acknowledged", 0),
        StrFixedLenField("ACK_delay",bytes.fromhex("4496"),2),
        ByteField("ACK_Range_Count",0),
        ByteField("First_ACK_Range",0)
    ]
      

class ACKFrameModify(Packet) :
      name = "ACK"
      fields_desc =[
        XByteField("Frame_Type", 0x02),
        ByteField("Largest_Acknowledged", 0),
        StrFixedLenField("ACK_delay",bytes.fromhex("4496"),1),
        ByteField("ACK_Range_Count",0),
        ByteField("First_ACK_Range",0)
    ]