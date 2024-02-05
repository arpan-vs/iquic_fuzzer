
import QUICHeader
import socket
from utils.string_to_ascii import string_to_ascii
from utils.packet_to_hex import extract_from_packet, extract_from_packet_as_bytestring
import random
from events.Events import SendInitialCHLOEvent, SendGETRequestEvent, CloseConnectionEvent, SendFullCHLOEvent, ZeroRTTCHLOEvent, ResetEvent
from utils.SessionInstance import SessionInstance
from aioquic.quic.crypto import hkdf_extract, hkdf_expand_label ,cipher_suite_hash , CipherSuite, AEAD, CryptoError, HeaderProtection ,CryptoContext,CryptoPair
from crypto.Secret import secret_all
from CryptoFrame import CryptoFrame ,ACKFrame
from donna25519 import PrivateKey, PublicKey
from cryptography.hazmat.primitives import hashes

from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from scapy.layers.tls.handshake import TLSClientHello,TLSFinished
import binascii
from aioquic.tls import ClientHello
from aioquic.quic.crypto import CIPHER_SUITES,derive_key_iv_hp

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
        SessionInstance.get_instance().client_initial_destination_connection_id =   SessionInstance.get_instance().initial_destination_connection_id
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
        SessionInstance.get_instance().initial_destination_connection_id = bytes.hex(SCID)

        SessionInstance.get_instance().tlsshalo = server_hello_data
        private_key = SessionInstance.get_instance().private_value
        shared_key = private_key.exchange(x25519.X25519PublicKey.from_public_bytes(sever_public_key))
        SessionInstance.get_instance().shared_key = shared_key
        sever_handshak_secret = secret_all.nth_secret(cipher_suite = 0x1302,shared_key = shared_key, lable = b"s hs traffic")
    
        crypto_context_sever = CryptoContext()
        crypto_context_sever.setup(cipher_suite = 0x1302,secret =  sever_handshak_secret ,version = 1)
        plain_header, payload, packet_number , hj = crypto_context_sever.decrypt_packet(server_handshake,25,0)
        plain_header_fr, payload_fr, packet_number_fr, hj_fr = crypto_context_sever.decrypt_packet(datarev_2,25,0)

        SessionInstance.get_instance().crypto_extensions = payload[4:114]
        SessionInstance.get_instance().crypto_cert = payload[114:] + payload_fr[5:644]
        SessionInstance.get_instance().crypto_certverify = payload_fr[644:1036]
        SessionInstance.get_instance().crypto_finished = payload_fr[1036:]
        
       
        sever_ap_secret = secret_all.ap_secret(cipher_suite = 0x1302, handshake_secret = SessionInstance.get_instance().handshake_secret)
        crypto_context_sever.setup(cipher_suite = 0x1302,secret =  sever_ap_secret ,version = 1)
        plain_header_ap, payload_ap, packet_number_ap, hj_ap = crypto_context_sever.decrypt_packet(appliction_data,9,0)


    def send_ACK(self, only_reset):

    #initial ACK packet             
        # Long Header
        initial_client_ACK_header = QUICHeader.QUICHeader()
        # set destination and source id in header
        initial_client_ACK_header.setfieldval("Public_Flags", 0xc1)
        initial_client_ACK_header.setfieldval("DCID",  string_to_ascii(SessionInstance.get_instance().initial_destination_connection_id)) 
        initial_client_ACK_header.setfieldval("SCID",  string_to_ascii(SessionInstance.get_instance().initial_source_connection_id))
        initial_client_ACK_header.setfieldval("Length",bytes.fromhex("4018"))
        initial_client_ACK_header.setfieldval("Packet_Number",1)
        ackFrame = ACKFrame()
        ackFrame.setfieldval("Largest_Acknowledged",0)
        ackFrame.setfieldval("ACK_delay",bytes.fromhex("42d3"))

        initial_header = bytes.fromhex(extract_from_packet_as_bytestring(initial_client_ACK_header)) 
        ACK_frame = extract_from_packet_as_bytestring(ackFrame)
        
        initial_clinet_ACK = bytes.fromhex(ACK_frame)

        crypto_context = CryptoPair()
        crypto_context.setup_initial(string_to_ascii(SessionInstance.get_instance().client_initial_destination_connection_id),True,1)
        initial_clinet_data = crypto_context.encrypt_packet(initial_header,initial_clinet_ACK,1)

    #handshake ACK packet
        
        handshake_client_ACK_header = QUICHeader.QUICHandshakeHeader()
        # set destination and source id in header
        handshake_client_ACK_header.setfieldval("Public_Flags", 0xe1)
        handshake_client_ACK_header.setfieldval("DCID",  string_to_ascii(SessionInstance.get_instance().initial_destination_connection_id)) 
        handshake_client_ACK_header.setfieldval("SCID",  string_to_ascii(SessionInstance.get_instance().initial_source_connection_id))
        handshake_client_ACK_header.setfieldval("Length",bytes.fromhex("4018"))
        handshake_client_ACK_header.setfieldval("Packet_Number",2)

        ackFrame_handshake = ACKFrame()
        ackFrame_handshake.setfieldval("Largest_Acknowledged",1)
        ackFrame_handshake.setfieldval("ACK_delay",bytes.fromhex("42d3"))
        
        handshake_header = extract_from_packet_as_bytestring(handshake_client_ACK_header)
        ACK_frame = extract_from_packet_as_bytestring(ackFrame_handshake)

        
        handshake_clinet_ACK = bytes.fromhex(ACK_frame)
        handshake_header = bytes.fromhex(handshake_header)
        clinet_handshak_secret = secret_all.nth_secret(cipher_suite = 0x1302,shared_key = SessionInstance.get_instance().shared_key, lable = b"c hs traffic")
       
        crypto_context_sever = CryptoContext()
        crypto_context_sever.setup(cipher_suite = 0x1302,secret =  clinet_handshak_secret ,version = 1)
    
        handshake_clinet_data = crypto_context_sever.encrypt_packet(handshake_header,handshake_clinet_ACK,2)
        print("handshake_clinet_data",len(handshake_clinet_data))
        print("handshake_header",len(handshake_header))
        print("handshake_clinet_ACK",len(handshake_clinet_ACK))
        print("handshake_header",handshake_header)
        print("ACK_frame",ACK_frame )

    
    #send data from client to server 
         
        print("handshake_clinet_data",bytes.hex(handshake_clinet_data))
        self.UDPClientSocket.sendto((initial_clinet_data + handshake_clinet_data ), ("127.0.0.1", DPORT))


    def send_finish(self, only_reset):

        handshake_client_ACK_header = QUICHeader.QUICHandshakeHeader()
        # set destination and source id in header
        handshake_client_ACK_header.setfieldval("Public_Flags", 0xe1)
        handshake_client_ACK_header.setfieldval("DCID",  string_to_ascii(SessionInstance.get_instance().initial_destination_connection_id)) 
        handshake_client_ACK_header.setfieldval("SCID",  string_to_ascii(SessionInstance.get_instance().initial_source_connection_id))
        handshake_client_ACK_header.setfieldval("Length",bytes.fromhex("4050"))
        handshake_client_ACK_header.setfieldval("Packet_Number",3)
        _handshake_client_ACK_header =  bytes.fromhex(extract_from_packet_as_bytestring(handshake_client_ACK_header))

        ackFrame_handshake = ACKFrame()
        ackFrame_handshake.setfieldval("Largest_Acknowledged",2)
        ackFrame_handshake.setfieldval("ACK_delay",bytes.fromhex("40de"))
        ackFrame_handshake.setfieldval("First_ACK_Range",1)
        _ackFrame = extract_from_packet_as_bytestring(ackFrame_handshake)

        cryptoFrame = CryptoFrame() 
        cryptoFrame.setfieldval("Length",bytes.fromhex("4034"))
        _crypatoFrame = extract_from_packet_as_bytestring(cryptoFrame)

        finished_verify_data = secret_all.finished_verify_data(0x1302,SessionInstance.get_instance().handshake_secret)

        tlsfinsh = TLSFinished(msglen = 48 ,
                  vdata = finished_verify_data)
        _tlsFinish = extract_from_packet_as_bytestring(tlsfinsh)
        data  = bytes.fromhex(_ackFrame + _crypatoFrame + _tlsFinish )
        clinet_handshak_secret = secret_all.nth_secret(cipher_suite = 0x1302,shared_key = SessionInstance.get_instance().shared_key, lable = b"c hs traffic")
        crypto_context_sever = CryptoContext()
        crypto_context_sever.setup(cipher_suite = 0x1302,secret =  clinet_handshak_secret ,version = 1)
    
        handshake_clinet_data = crypto_context_sever.encrypt_packet(_handshake_client_ACK_header,data,3)

        self.UDPClientSocket.sendto((handshake_clinet_data ), ("127.0.0.1", DPORT))
        







        


  


s = QUIC()
s.send_initial_chlo(True)
s.send_ACK(True)
s.send_finish(True)
