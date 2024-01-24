
import QUICHeader
import socket
from utils.string_to_ascii import string_to_ascii
from utils.packet_to_hex import extract_from_packet, extract_from_packet_as_bytestring
import random
from events.Events import SendInitialCHLOEvent, SendGETRequestEvent, CloseConnectionEvent, SendFullCHLOEvent, ZeroRTTCHLOEvent, ResetEvent
from utils.SessionInstance import SessionInstance
from aioquic.quic.crypto import hkdf_extract, hkdf_expand_label ,cipher_suite_hash , CipherSuite, AEAD, CryptoError, HeaderProtection ,CryptoContext,CryptoPair
from crypto.Secret import secret_all
from CryptoFrame import CryptoFrame
from donna25519 import PrivateKey, PublicKey
from cryptography.hazmat.primitives import hashes

from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

import binascii
from aioquic.tls import Group

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



DPORT = 4433
class QUIC : 

    def __init__(self) -> None:

        # set Destination conncetion id 
        destination_id = random.getrandbits(64)
        SessionInstance.get_instance().initial_destination_connection_id = str(format(destination_id, 'x').zfill(16))

        # set source conncetion id 
        source_id = random.getrandbits(64)
        SessionInstance.get_instance().initial_source_connection_id = str(format(source_id, 'x').zfill(16))

        self.UDPClientSocket = socket.socket(family = socket.AF_INET, type =socket.SOCK_DGRAM)

        #PUB and Privete key generet
        _x25519_private_key = x25519.X25519PrivateKey.generate()
        SessionInstance.get_instance().public_values_bytes = _x25519_private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        SessionInstance.get_instance().private_value = _x25519_private_key

        # self.UDPClientSocket.settimeout(0.1)


    def send_initial_chlo(self, only_reset):

        # Long Header
        chlo = QUICHeader.QUICHeader() 

        # set destination and source id in header
        chlo.setfieldval("DCID",  string_to_ascii(SessionInstance.get_instance().initial_destination_connection_id)) 
        chlo.setfieldval("SCID",  string_to_ascii(SessionInstance.get_instance().initial_source_connection_id))


        header = bytes.fromhex(extract_from_packet_as_bytestring(chlo)) 
        cryptoFrame = CryptoFrame() 
        tlsObjct = extract_from_packet_as_bytestring(CryptoFrame.TLSObject())
        SessionInstance.get_instance().tlschlo = bytes.fromhex(tlsObjct)
        # padding
        padding = "00" * (775)
    
        crypto_frame = extract_from_packet_as_bytestring(cryptoFrame)

        # client initial packet
        initial_frame = bytes.fromhex(crypto_frame + tlsObjct + padding)

        #client initial encrypted 
        crypto_context = CryptoPair()
        crypto_context.setup_initial(string_to_ascii(SessionInstance.get_instance().initial_destination_connection_id),True,1)
        data = crypto_context.encrypt_packet(header,initial_frame,0)
        
        self.UDPClientSocket.sendto(data, ("127.0.0.1", DPORT))

        datarev_1 = self.UDPClientSocket.recv(1200) # recive frist packet
        datarev_2 = self.UDPClientSocket.recv(1200) # recive second packet
        appliction_data = self.UDPClientSocket.recv(1200) # recive third packet
        
        server_initial = datarev_1[:144]
        server_handshake = datarev_1[144:]

        # server initial packet decrypated
        crypto_context_decode = CryptoPair()
        crypto_context_decode.setup_initial(string_to_ascii(SessionInstance.get_instance().initial_destination_connection_id),True,1)
        plain_header, payload, packet_number = crypto_context.decrypt_packet(server_initial,26,0)

        sever_public_key = payload[-32:]
        random_bytes = payload[16:48]
        packet_number = packet_number
        server_hello_data = payload[10:]
        DCID = plain_header[6:14]
        SCID = plain_header[15:23]

        SessionInstance.get_instance().tlsshalo = server_hello_data

        private_key = SessionInstance.get_instance().private_value
        shared_key = private_key.exchange(x25519.X25519PublicKey.from_public_bytes(sever_public_key))
        sever_handshak_secret = secret_all.nth_secret(cipher_suite = 0x1302,shared_key = shared_key)
    
        crypto_context_sever = CryptoContext()
        crypto_context_sever.setup(cipher_suite = 0x1302,secret =  sever_handshak_secret ,version = 1)
        plain_header, payload, packet_number , hj = crypto_context_sever.decrypt_packet(server_handshake,25,0)
        plain_header_fr, payload_fr, packet_number_fr, hj_fr = crypto_context_sever.decrypt_packet(datarev_2,25,0)

        SessionInstance.get_instance().crypto_extensions = payload[4:114]
        SessionInstance.get_instance().crypto_cert = payload[114:] + payload_fr[:644]
        SessionInstance.get_instance().crypto_certverify = payload_fr[644:1036]
        SessionInstance.get_instance().crypto_finished = payload_fr[1036:]
        
        sever_ap_secret = secret_all.ap_secret(cipher_suite = 0x1302,handshake_secret = bytes.fromhex("2f82be0cd5999ef45ecdd2e2d8c3d8d093875a9a303432c75fcf2a15d90d8161ff207bc3f80ba04792afca9522e82527"))
        print(bytes.hex(sever_ap_secret))
        crypto_context_sever.setup(cipher_suite = 0x1302,secret =  sever_ap_secret ,version = 1)
        plain_header_ap, payload_ap, packet_number_ap, hj_ap = crypto_context_sever.decrypt_packet(appliction_data,9,0)

        print(packet_number_ap)


       
        


  


s = QUIC()
s.send_initial_chlo(True)

