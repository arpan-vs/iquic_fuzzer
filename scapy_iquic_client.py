
import QUICHeader
import socket
from utils.string_to_ascii import string_to_ascii
from utils.packet_to_hex import extract_from_packet, extract_from_packet_as_bytestring
import random
from utils.SessionInstance import SessionInstance
from aioquic.quic.crypto import CryptoContext,CryptoPair
from crypto.Secret import dhke
from CryptoFrame import CryptoFrame ,ACKFrame


from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from scapy.layers.tls.handshake import TLSFinished

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
from crypto.Frame import new_connection_id, quic_stream, quic_offset_stream ,quic_connection_closed
import os

DPORT = 4433
ip ="127.0.0.1"
class QUIC : 

    def __init__(self) -> None:

        self.crypto_pair = None       

        # set Destination conncetion id 
        destination_id = random.getrandbits(64)
        SessionInstance.get_instance().initial_destination_connection_id = str(format(destination_id, 'x').zfill(16))
        SessionInstance.get_instance().client_initial_destination_connection_id =   SessionInstance.get_instance().initial_destination_connection_id
        
        # set source conncetion id 
        source_id = random.getrandbits(64)
        SessionInstance.get_instance().initial_source_connection_id = str(format(source_id, 'x').zfill(16))

        self.UDPClientSocket = socket.socket(family = socket.AF_INET, type =socket.SOCK_DGRAM)

        #PUB and Privete key generate 
        _x25519_private_key = x25519.X25519PrivateKey.generate()
        SessionInstance.get_instance().public_values_bytes = _x25519_private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        SessionInstance.get_instance().private_value = _x25519_private_key

        # self.UDPClientSocket.settimeout(0.1)


    def initial_chlo(self, only_reset):

        # Long Header
        chlo = QUICHeader.QUICHeader() 

        # set destination and source id in header
        chlo.setfieldval("DCID",  string_to_ascii(SessionInstance.get_instance().initial_destination_connection_id)) 
        chlo.setfieldval("SCID",  string_to_ascii(SessionInstance.get_instance().initial_source_connection_id))
        header = bytes.fromhex(extract_from_packet_as_bytestring(chlo)) 

        # crypato Frame continent client hello hanshake messages  
        cryptoFrame = CryptoFrame() 
        crypto_frame = extract_from_packet_as_bytestring(cryptoFrame)

        ClientHello = extract_from_packet_as_bytestring(CryptoFrame.TLSObject())
        SessionInstance.get_instance().tlschlo = bytes.fromhex(ClientHello)

        # padding
        padding = "00" * (775)
        
        # client hello hanshake messages + padding
        initial_frame = bytes.fromhex(crypto_frame + ClientHello + padding)

        #client initial packet encrypt using initial traffic secret
        self.crypto_pair = CryptoPair()
        self.crypto_pair.setup_initial(string_to_ascii(SessionInstance.get_instance().initial_destination_connection_id),True,1)
        data = self.crypto_pair.encrypt_packet(header,initial_frame,0)

        
        #send -> Initial[0] : crypato(CH)
        self.UDPClientSocket.sendto(data, (ip, DPORT))

        
        
        try :
            # receive -> Initial[0] : crypato(SH)
            datarev_1 = self.UDPClientSocket.recv(1200) 
            '''
            Here handshake packet is in fragmentation  
            '''
            # receive -> handshake[0] : crypato(EE,CRT,CV,FIN)
            server_handshake_2 = self.UDPClientSocket.recv(1200) 
            # receive -> 1-RTT[0] : appliction_data
            appliction_data = self.UDPClientSocket.recv(1200) 

            server_initial = datarev_1[:144]  #Initial[0] : crypato(SH)
            server_handshake_1 = datarev_1[144:] #handshake[0] : crypato(EE,CRT,CV,FIN)
       
            #server initial packet decrypat using initial traffic secret
            plain_header, payload, packet_number = self.crypto_pair.decrypt_packet(server_initial,26,0)

            sever_public_key = payload[-32:]
            server_hello_data = payload[10:]
            DCID = plain_header[6:14]
            SCID = plain_header[15:23]

            SessionInstance.get_instance().initial_destination_connection_id = bytes.hex(SCID)
            SessionInstance.get_instance().tlsshalo = server_hello_data

            # shared_key computation using client private key 
            private_key = SessionInstance.get_instance().private_value  # client private key 
            shared_key = private_key.exchange(x25519.X25519PublicKey.from_public_bytes(sever_public_key)) 
            SessionInstance.get_instance().shared_key = shared_key 

            # find handshake traffic secret using shared_key
            sever_handshake_secret = dhke.handshake_secret(cipher_suite = 0x1302,shared_key = shared_key, lable = b"s hs traffic")
    
            crypto_context_sever = CryptoContext()
            crypto_context_sever.setup(cipher_suite = 0x1302,secret =  sever_handshake_secret ,version = 1)
            plain_header, payload, packet_number , crypto = crypto_context_sever.decrypt_packet(server_handshake_1,25,0)
            plain_header_sp , payload_sp, packet_number_sp, crypto_sp = crypto_context_sever.decrypt_packet(server_handshake_2,25,0)

            SessionInstance.get_instance().crypto_extensions = payload[4:114]                    # EE
            SessionInstance.get_instance().crypto_cert = payload[114:] + payload_sp[5:644]       # CERT
            SessionInstance.get_instance().crypto_certverify = payload_sp[644:1036]              # CV       
            SessionInstance.get_instance().crypto_finished = payload_sp[1036:]                   # FIN   
        
            # find appliction traffic secret using handshake_secret
            sever_ap_secret = dhke.ap_secret(cipher_suite = 0x1302, handshake_secret = SessionInstance.get_instance().handshake_secret , label=  b"s ap traffic")
            SessionInstance.get_instance().server_appliction_traffic_secret = sever_ap_secret
            crypto_context_sever.setup(cipher_suite = 0x1302,secret =  sever_ap_secret ,version = 1)
            plain_header_ap, payload_ap, packet_number_ap, crypto_ap = crypto_context_sever.decrypt_packet(appliction_data,9,0)

        except :  
            print("packet Not receive")
            return b"EXP"

    def send_ACK(self, only_reset):

        #initial ACK packet        
     
        # Long Header
        initial_client_ACK_header = QUICHeader.QUICHeader()
        # set destination and source id in header
        initial_client_ACK_header.setfieldval("Public_Flags", 0xc1)
        initial_client_ACK_header.setfieldval("DCID",  string_to_ascii(SessionInstance.get_instance().initial_destination_connection_id)) 
        initial_client_ACK_header.setfieldval("SCID",  string_to_ascii(SessionInstance.get_instance().initial_source_connection_id))
        initial_client_ACK_header.setfieldval("Length",bytes.fromhex("4018"))
        initial_client_ACK_header.setfieldval("Packet_Number",256)

        #acknowledgement for Server Initial[0] 
        ackFrame = ACKFrame()
        ackFrame.setfieldval("Largest_Acknowledged",0)
        ackFrame.setfieldval("ACK_delay",bytes.fromhex("42d3"))
        initial_header = bytes.fromhex(extract_from_packet_as_bytestring(initial_client_ACK_header)) 
        ACK_frame = extract_from_packet_as_bytestring(ackFrame)
        initial_clinet_ACK = bytes.fromhex(ACK_frame)

        #Initial ACK packet encrypt using initial traffic secret
        initial_clinet_data = self.crypto_pair.encrypt_packet(initial_header,initial_clinet_ACK,1)

        #handshake ACK packet
        
        # Long Header
        handshake_client_ACK_header = QUICHeader.QUICHandshakeHeader()
        # set destination and source id in header
        handshake_client_ACK_header.setfieldval("Public_Flags", 0xe1)
        handshake_client_ACK_header.setfieldval("DCID",  string_to_ascii(SessionInstance.get_instance().initial_destination_connection_id)) 
        handshake_client_ACK_header.setfieldval("SCID",  string_to_ascii(SessionInstance.get_instance().initial_source_connection_id))
        handshake_client_ACK_header.setfieldval("Length",bytes.fromhex("4018"))
        handshake_client_ACK_header.setfieldval("Packet_Number",256*2)

        #acknowledgement for Server handshake[0] 
        ackFrame_handshake = ACKFrame()
        ackFrame_handshake.setfieldval("Largest_Acknowledged",1)
        ackFrame_handshake.setfieldval("ACK_delay",bytes.fromhex("42d3"))
       

        handshake_clinet_ACK = bytes.fromhex(extract_from_packet_as_bytestring(ackFrame_handshake)  )
        handshake_header = bytes.fromhex(extract_from_packet_as_bytestring(handshake_client_ACK_header))

        #handshake ACK packet encrypt using handshake traffic secret
        clinet_handshak_secret = dhke.handshake_secret(cipher_suite = 0x1302,shared_key = SessionInstance.get_instance().shared_key, lable = b"c hs traffic")
       
        crypto_context_sever = CryptoContext()
        crypto_context_sever.setup(cipher_suite = 0x1302,secret =  clinet_handshak_secret ,version = 1)
        handshake_clinet_data = crypto_context_sever.encrypt_packet(handshake_header,handshake_clinet_ACK,2)

        #send ACK Packet from client -> server 
        self.UDPClientSocket.sendto((initial_clinet_data + handshake_clinet_data ), (ip, DPORT))


    def send_finish(self, only_reset):

        handshake_client_finish_header = QUICHeader.QUICHandshakeHeader()

        # set header data
        handshake_client_finish_header.setfieldval("Public_Flags", 0xe1)
        handshake_client_finish_header.setfieldval("DCID",  string_to_ascii(SessionInstance.get_instance().initial_destination_connection_id)) 
        handshake_client_finish_header.setfieldval("SCID",  string_to_ascii(SessionInstance.get_instance().initial_source_connection_id))
        handshake_client_finish_header.setfieldval("Length",bytes.fromhex("4050"))
        handshake_client_finish_header.setfieldval("Packet_Number",256* 3)
        _handshake_client_ACK_header =  bytes.fromhex(extract_from_packet_as_bytestring(handshake_client_finish_header))

        #ack frame
        ackFrame_handshake = ACKFrame()
        ackFrame_handshake.setfieldval("Largest_Acknowledged",2)
        ackFrame_handshake.setfieldval("ACK_delay",bytes.fromhex("40de"))
        ackFrame_handshake.setfieldval("First_ACK_Range",1)
        _ackFrame = extract_from_packet_as_bytestring(ackFrame_handshake)

        #crypto frame for finish 
        cryptoFrame = CryptoFrame() 
        cryptoFrame.setfieldval("Length",bytes.fromhex("4034"))
        _crypatoFrame = extract_from_packet_as_bytestring(cryptoFrame)

        clinet_handshak_secret = dhke.handshake_secret(cipher_suite = 0x1302,shared_key = SessionInstance.get_instance().shared_key, lable = b"c hs traffic")
        finished_verify_data = dhke.finished_verify_data(0x1302,clinet_handshak_secret)
        
        #finsh message 
        tlsfinsh = TLSFinished(msglen = 48 , vdata = finished_verify_data)
        _tlsFinish = extract_from_packet_as_bytestring(tlsfinsh)
        data  = bytes.fromhex(_ackFrame + _crypatoFrame + _tlsFinish )
        
        crypto_context_sever = CryptoContext()
        crypto_context_sever.setup(cipher_suite = 0x1302,secret =  clinet_handshak_secret ,version = 1)
        handshake_clinet_data = crypto_context_sever.encrypt_packet(_handshake_client_ACK_header,data,3)

      
        # 1 - RTT packet 
        haeader = QUICHeader.QUICShortHeader()
        haeader.setfieldval("Public_Flags",0x41)
        haeader.setfieldval("DCID",  string_to_ascii(SessionInstance.get_instance().initial_destination_connection_id)) 
        haeader.setfieldval("Packet_Number",string_to_ascii("0004"))
        _haeader =  bytes.fromhex(extract_from_packet_as_bytestring(haeader))
        
  
        _new_connection_id_data = b""
        
        for i in range(1,8) :
            new_connection_id_data = new_connection_id()
            new_connection_id_data.setfieldval("Sequence" ,i)
            new_connection_id_data.setfieldval("CID" ,os.urandom(8))
            new_connection_id_data.setfieldval("Stateless_Reset_Token" ,os.urandom(16))
            _new_connection_id_data +=  bytes.fromhex(extract_from_packet_as_bytestring(new_connection_id_data))
      
        stream_data = bytes.fromhex("0004090150000710080121010d0108")
        stream_1 = quic_stream()
        stream_1.setfieldval("stream_id",2)
        stream_1.setfieldval("Length",bytes.fromhex("400f"))
        stream_1.setfieldval("Data",stream_data)
        _stream_1 = bytes.fromhex(extract_from_packet_as_bytestring(stream_1))
        
        stream_2 = quic_stream()
        stream_2.setfieldval("stream_id",6)
        stream_2.setfieldval("Length",bytes.fromhex("4001"))
        stream_2.setfieldval("Data",bytes.fromhex("02"))
        _stream_2 = bytes.fromhex(extract_from_packet_as_bytestring(stream_2))

        stream_3 = quic_stream()
        stream_3.setfieldval("stream_id",10)
        stream_3.setfieldval("Length",bytes.fromhex("4001"))
        stream_3.setfieldval("Data",bytes.fromhex("03"))
        _stream_3 = bytes.fromhex(extract_from_packet_as_bytestring(stream_3))

        data = _new_connection_id_data + _stream_1 + _stream_2 + _stream_3
        #encrypation using ap traffic secret
        clinet_ap_secret = dhke.ap_secret(cipher_suite = 0x1302,handshake_secret = SessionInstance.get_instance().handshake_secret , label= b"c ap traffic")
        crypto_context_sever = CryptoContext()
        crypto_context_sever.setup(cipher_suite = 0x1302,secret =  clinet_ap_secret ,version = 1)
        appliction_clinet_data = crypto_context_sever.encrypt_packet(_haeader,data,4)
        self.UDPClientSocket.sendto((handshake_clinet_data + appliction_clinet_data), (ip, DPORT))
        

    def send_ACK_applictiondata(self, only_reset):
        haeader = QUICHeader.QUICShortHeader()
        haeader.setfieldval("Public_Flags",0x61)
        haeader.setfieldval("DCID",  string_to_ascii(SessionInstance.get_instance().initial_destination_connection_id)) 
        haeader.setfieldval("Packet_Number",string_to_ascii("0005"))
        _haeader =  bytes.fromhex(extract_from_packet_as_bytestring(haeader))

        #ack frame
        ackFrame_appliction = ACKFrame()
        ackFrame_appliction.setfieldval("Largest_Acknowledged",3)
        ackFrame_appliction.setfieldval("ACK_delay",bytes.fromhex("4194"))
        ackFrame_appliction.setfieldval("First_ACK_Range",0)
        _ackFrame =  bytes.fromhex(extract_from_packet_as_bytestring(ackFrame_appliction))

        stream_data = bytes.fromhex("3fe11f")
        stream_1 = quic_offset_stream()
        stream_1.setfieldval("stream_id",6)
        stream_1.setfieldval("offset",1)
        stream_1.setfieldval("Length",bytes.fromhex("4003"))
        stream_1.setfieldval("Data",stream_data)
        _stream_1 = bytes.fromhex(extract_from_packet_as_bytestring(stream_1))

       
        data = _ackFrame + _stream_1
        clinet_ap_secret = dhke.ap_secret(cipher_suite = 0x1302,handshake_secret = SessionInstance.get_instance().handshake_secret , label= b"c ap traffic")
        crypto_context_sever = CryptoContext()
        crypto_context_sever.setup(cipher_suite = 0x1302,secret =  clinet_ap_secret ,version = 1)
        appliction_clinet_data = crypto_context_sever.encrypt_packet(_haeader,data,5)
        self.UDPClientSocket.sendto( appliction_clinet_data, (ip, DPORT))
        
    
    def send_ACK_applictionhadear(self, only_reset):
        haeader = QUICHeader.QUICShortHeader()
        haeader.setfieldval("Public_Flags",0x61)
        haeader.setfieldval("DCID",  string_to_ascii(SessionInstance.get_instance().initial_destination_connection_id)) 
        haeader.setfieldval("Packet_Number",string_to_ascii("0006"))
        _haeader =  bytes.fromhex(extract_from_packet_as_bytestring(haeader))

        stream_data = bytes.fromhex("011e0000d1d7508aa0e41d139d09b8d34cb3c15f508a198fdad311802efae26f")
        stream_1 = quic_stream()
        stream_1.setfieldval("Frame_Type",0x0b)
        stream_1.setfieldval("stream_id",0)
        stream_1.setfieldval("Length",bytes.fromhex("4020"))
        stream_1.setfieldval("Data",stream_data)
        _stream_1 = bytes.fromhex(extract_from_packet_as_bytestring(stream_1))

        data =  _stream_1

        # appliction data Encryption using appliction traffic secret
        clinet_ap_secret = dhke.ap_secret(cipher_suite = 0x1302,handshake_secret = SessionInstance.get_instance().handshake_secret , label= b"c ap traffic")
        crypto_context_sever = CryptoContext()
        crypto_context_sever.setup(cipher_suite = 0x1302,secret =  clinet_ap_secret ,version = 1)
        appliction_clinet_data = crypto_context_sever.encrypt_packet(_haeader,data,6)
        self.UDPClientSocket.sendto( appliction_clinet_data, (ip, DPORT))

        try :
            #1 - RTT[1]: [HD, Application Data]        
            recv_handshake_done = self.UDPClientSocket.recv(1200) # recive frist packet 4
            recv_ACK_ = self.UDPClientSocket.recv(100) # recive ACK packet 6

            crypto_context_sever = CryptoContext()
            crypto_context_sever.setup(cipher_suite = 0x1302,secret =   SessionInstance.get_instance().server_appliction_traffic_secret ,version = 1)
            plain_header_ap, payload_ap, packet_number_ap, crypto_ap = crypto_context_sever.decrypt_packet(recv_handshake_done,9,0)
            
            handshake_done = payload_ap[6:7]
            if(extract_from_packet_as_bytestring(handshake_done) == "1E") :
                print("handshake done")

        except :  
            print("packet Not receive")
            return b"EXP"

    def send_ACK_ack_5(self, only_reset):
        haeader = QUICHeader.QUICShortHeader()
        haeader.setfieldval("Public_Flags",0x61)
        haeader.setfieldval("DCID",  string_to_ascii(SessionInstance.get_instance().initial_destination_connection_id)) 
        haeader.setfieldval("Packet_Number",string_to_ascii("0007"))
        _haeader =  bytes.fromhex(extract_from_packet_as_bytestring(haeader))

        #ack frame
        ackFrame_4 = ACKFrame()
        ackFrame_4.setfieldval("Largest_Acknowledged",4)
        ackFrame_4.setfieldval("ACK_delay",bytes.fromhex("405a"))
        ackFrame_4.setfieldval("First_ACK_Range",0)
        _ackFrame_4 =  bytes.fromhex(extract_from_packet_as_bytestring(ackFrame_4))

        
        ackFrame_appliction = ACKFrame()
        ackFrame_appliction.setfieldval("Largest_Acknowledged",5)
        ackFrame_appliction.setfieldval("ACK_delay",bytes.fromhex("405a"))
        ackFrame_appliction.setfieldval("First_ACK_Range",0)
        _ackFrame =  bytes.fromhex(extract_from_packet_as_bytestring(ackFrame_appliction))

        data = _ackFrame_4 +_ackFrame 
        
        clinet_ap_secret = dhke.ap_secret(cipher_suite = 0x1302,handshake_secret = SessionInstance.get_instance().handshake_secret , label= b"c ap traffic")
        crypto_context_sever = CryptoContext()
        crypto_context_sever.setup(cipher_suite = 0x1302,secret =  clinet_ap_secret ,version = 1)
        appliction_clinet_data = crypto_context_sever.encrypt_packet(_haeader,data,7)
        self.UDPClientSocket.sendto( appliction_clinet_data, (ip, DPORT))
        strem = self.UDPClientSocket.recv(120) # recive frist packet 6

    def connection_close(self,only_reset) :
        haeader = QUICHeader.QUICShortHeader()
        haeader.setfieldval("Public_Flags",0x61)
        haeader.setfieldval("DCID",  string_to_ascii(SessionInstance.get_instance().initial_destination_connection_id)) 
        haeader.setfieldval("Packet_Number",string_to_ascii("0010"))
        _haeader =  bytes.fromhex(extract_from_packet_as_bytestring(haeader))

        #connection_closed
        connection_clodsed = quic_connection_closed()
        _connection_clodsed=  bytes.fromhex(extract_from_packet_as_bytestring(connection_clodsed))

        clinet_ap_secret = dhke.ap_secret(cipher_suite = 0x1302,handshake_secret = SessionInstance.get_instance().handshake_secret , label= b"c ap traffic")
        crypto_context_sever = CryptoContext()
        crypto_context_sever.setup(cipher_suite = 0x1302,secret =  clinet_ap_secret ,version = 1)
        appliction_clinet_data = crypto_context_sever.encrypt_packet(_haeader,_connection_clodsed,10)
        self.UDPClientSocket.sendto( appliction_clinet_data, (ip, DPORT))




# s = QUIC()
# s.initial_chlo(True)
# s.send_ACK(True)
# s.send_finish(True)
# s.send_ACK_applictiondata(True)
# s.send_ACK_applictionhadear(True)
# s.send_ACK_ack_5(True)
# s.connection_close(True)