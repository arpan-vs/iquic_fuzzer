
import QUICHeader
import socket
from utils.string_to_ascii import string_to_ascii
from utils.packet_to_hex import extract_from_packet, extract_from_packet_as_bytestring, hex_to_binary
import random
from utils.SessionInstance import SessionInstance
from utils.PacketNumberInstance import PacketNumberInstance
from aioquic.quic.crypto import CryptoContext,CryptoPair
from crypto.Secret import dhke, Crypto
from CryptoFrame import CryptoFrame, ACKFrame, ACKFrameModify,TLSFinish
from events.Events import SendInitialCHLOEvent, SendGETRequestEvent, CloseConnectionEvent,SendFINEvent

# from scapy.layers.tls.handshake import TLSFinished

from crypto.Frame import new_connection_id, quic_stream, quic_offset_stream ,quic_connection_closed
import os
import qpack 
import logging
import time
from  Keylog import KeyFile

# https://quic.aiortc.org:443
# DPORT = 4433
# ip ="127.0.0.1"

DPORT = 443
ip ="quic.aiortc.org"
class QUIC : 

    Largest_Acked = 0

    def __init__(self,s) -> None:

        self.crypto_pair = CryptoPair()    
        self.crypto_context = CryptoContext()
        self.crypto = Crypto()

        # set Destination conncetion id 
        destination_id = random.getrandbits(64)
        SessionInstance.get_instance().initial_destination_connection_id = str(format(destination_id, 'x').zfill(16))
        SessionInstance.get_instance().client_initial_destination_connection_id =   SessionInstance.get_instance().initial_destination_connection_id
        
        # set source conncetion id 
        source_id = random.getrandbits(64)
        SessionInstance.get_instance().initial_source_connection_id = str(format(source_id, 'x').zfill(16))

        self.UDPClientSocket = socket.socket(family = socket.AF_INET, type =socket.SOCK_DGRAM)
        dhke.set_up_my_keys()
        self.UDPClientSocket.settimeout(5)

    def reset(self, reset_server, reset_run=True):
        if reset_run:
            # For the three times a command we do not want to remove the run events, only when there is a complete reset
            # which occurs after an iteration or after an explicit RESET command.

            self.run = ""
            # set Destination conncetion id 
            destination_id = random.getrandbits(64)
            SessionInstance.get_instance().initial_destination_connection_id = str(format(destination_id, 'x').zfill(16))
            SessionInstance.get_instance().client_initial_destination_connection_id =   SessionInstance.get_instance().initial_destination_connection_id
            
            # set source conncetion id 
            source_id = random.getrandbits(64)
            SessionInstance.get_instance().initial_source_connection_id = str(format(source_id, 'x').zfill(16))

            # PacketNumberInstance.get_instance().reset()
            destination_id = random.getrandbits(64)
            SessionInstance.get_instance().initial_destination_connection_id = str(format(destination_id, 'x').zfill(16))
            SessionInstance.get_instance().client_initial_destination_connection_id =   SessionInstance.get_instance().initial_destination_connection_id
            PacketNumberInstance.get_instance().reset()

            SessionInstance.get_instance().public_values_bytes = ""
            SessionInstance.get_instance().private_value = ""
            SessionInstance.get_instance().shared_key= b""
            SessionInstance.get_instance().server_handshake_traffic_secret = b"" 
            SessionInstance.get_instance().client_handshake_traffic_secret = b""
            SessionInstance.get_instance().server_appliction_traffic_secret =b""
            SessionInstance.get_instance().client_appliction_traffic_secret =b""
            SessionInstance.get_instance().client_handshake_secret = b""
            SessionInstance.get_instance().server_handshake_secret =b""
            SessionInstance.get_instance().handshake_done = False
            SessionInstance.get_instance().crypto_extensions = b''
            SessionInstance.get_instance().crypto_cert = b''
            SessionInstance.get_instance().crypto_certverify = b''
            dhke.set_up_my_keys()


    def initial_chlo(self, only_reset):

        self.reset(only_reset)

        # Long Header
        chlo = QUICHeader.QUICHeader() 

        # set destination and source id in header
        chlo.setfieldval("DCID",  string_to_ascii(SessionInstance.get_instance().initial_destination_connection_id)) 
        chlo.setfieldval("SCID",  string_to_ascii(SessionInstance.get_instance().initial_source_connection_id))
        plain_header = bytes.fromhex(extract_from_packet_as_bytestring(chlo)) 

        # crypato Frame continent client hello hanshake messages  
        cryptoFrame = CryptoFrame() 
        cryptoFrame.setfieldval("Length",bytes.fromhex("417f"))
        crypto_frame = extract_from_packet_as_bytestring(cryptoFrame)

        ClientHello = bytes.hex(CryptoFrame().TLSObject(server_name=ip).data)
        SessionInstance.get_instance().tlschlo = bytes.fromhex(ClientHello)

        # padding
        padding = "00" * (769)
        
        # client hello hanshake messages + padding
        plain_payload = bytes.fromhex(crypto_frame + ClientHello + padding)

        #client initial packet encrypt using initial traffic secret
        self.crypto_pair.setup_initial(string_to_ascii(SessionInstance.get_instance().initial_destination_connection_id),True,1)
        data = self.crypto_pair.encrypt_packet(plain_header,plain_payload,0)
        
        #send -> Initial[0] : crypato(CH)
        self.UDPClientSocket.sendto(data, (ip, DPORT))
        pattern = b""
        try :
           
            # receive -> Initial[0] : crypato(SH)
            datarev_1 = self.UDPClientSocket.recv(1300)
            # only Receive Initial packet
            while hex_to_binary(bytes.hex(datarev_1[0:1]))[2:4] != "00" :
                datarev_1 = self.UDPClientSocket.recv(1300) 
                if(hex_to_binary(bytes.hex(datarev_1[0:1]))[2:4] == "00") : break 
            plain_header, payload, packet_number = self.crypto_pair.decrypt_packet(datarev_1,26,0)

            server_hello = payload[10:100]
            sever_public_key = server_hello[-32:]
            server_hello_data = server_hello
            DCID = plain_header[6:14]
            SCID = plain_header[15:23]

            PacketNumberInstance.get_instance().highest_received_packet_number = packet_number
            SessionInstance.get_instance().initial_destination_connection_id = bytes.hex(SCID)
            SessionInstance.get_instance().tlsshalo = server_hello_data
            dhke.shared_key_computation(sever_public_key)
            dhke.handshake_traffic_computation()
            pattern += b"Sever_Hello"
        except :  
            print("initial packet Not receive")
            return b"EXP"

        try :
            '''
            Here handshake packet is in fragmentation  
            '''
            # receive -> handshake[0] : crypato(EE,CRT,CV,FIN)
            server_handshake_2 = self.UDPClientSocket.recv(1300)


            # plain_header_sp, payload_sp, packet_number_sp = self.crypto.decrypt_handshake_packet(server_handshake_2)
            self.crypto_context.setup(cipher_suite = 0x1302, secret = SessionInstance.get_instance().server_handshake_traffic_secret, version = 1)
            plain_header_sp, payload_sp, packet_number_sp, crypto = self.crypto_context.decrypt_packet(server_handshake_2,25,0)
            SessionInstance.get_instance().crypto_extensions += payload_sp[4:114]    
            SessionInstance.get_instance().crypto_cert += payload_sp[114:]    
        except:
            print("handshake Packet 1 not receive")
            return b"EXP"

        try :
            '''
            Here handshake packet is in fragmentation  
            '''
            # receive -> handshake[0] : crypato(EE,CRT,CV,FIN)
            server_handshake_3 = self.UDPClientSocket.recv(1300)

            # plain_header_tp, payload_tp, packet_number_tp = self.crypto.decrypt_handshake_packet(server_handshake_3)
            plain_header_tp, payload_tp, packet_number_tp, crypto = self.crypto_context.decrypt_packet(server_handshake_3,25,0)
            SessionInstance.get_instance().crypto_cert += payload_tp[5:]    
            self.send_initial_ack_0()
            self.send_handshake_ack_1()
            self.send_handshake_ack_2()
        except:
            print("handshake Packet 2 not receive")
            return b"EXP"
        
        try :
            # receive -> 1-RTT[0] : appliction_data
            packet = self.UDPClientSocket.recv(1300)  
            handshake_1 = packet[:755]
            application_1 = packet[755:]
            plain_header_fp, payload_fp, packet_number_fp, crypto = self.crypto_context.decrypt_packet(handshake_1,25,0)
            SessionInstance.get_instance().crypto_cert += payload_fp[5:396]
            SessionInstance.get_instance().crypto_certverify = payload_fp[396:660]
            SessionInstance.get_instance().crypto_finished = payload_fp[660:]   
            
            dhke.appliction_traffic_computation()
            self.crypto_context.setup(cipher_suite = 0x1302,secret =  SessionInstance.get_instance().server_appliction_traffic_secret  ,version = 1)
            # plain_header_ap, payload_ap, packet_number_ap =  self.crypto.decrypt_application_packet(application_1)
            plain_header, payload, packet_number, crypto = self.crypto_context.decrypt_packet(application_1,9,0)  
            pattern += b"Handshake"
            pattern += b"appliction_data"
        except:
            print("appliction Packet not receive")
            # return b"EXP"
        return pattern
    

    def send_initial_ack_0(self) :
        # Long Header
        initial_client_ACK_header = QUICHeader.QUICHeader()

        # set destination and source id in header
        initial_client_ACK_header.setfieldval("Public_Flags", 0xc1)
        initial_client_ACK_header.setfieldval("DCID",  string_to_ascii(SessionInstance.get_instance().initial_destination_connection_id)) 
        initial_client_ACK_header.setfieldval("SCID",  string_to_ascii(SessionInstance.get_instance().initial_source_connection_id))
        initial_client_ACK_header.setfieldval("Length",bytes.fromhex("4018"))
        initial_client_ACK_header.setfieldval("Packet_Number",256 * PacketNumberInstance.get_instance().get_next_packet_number())

        #acknowledgement for Server Initial[0] 
        ackFrame = ACKFrame()
        ackFrame.setfieldval("Largest_Acknowledged",0)
        ackFrame.setfieldval("ACK_delay",bytes.fromhex("4073"))
        initial_header = bytes.fromhex(extract_from_packet_as_bytestring(initial_client_ACK_header)) 
        ACK_frame = extract_from_packet_as_bytestring(ackFrame)
        initial_clinet_ACK = bytes.fromhex(ACK_frame)

        #Initial ACK packet encrypt using initial traffic secret
        initial_clinet_data = self.crypto_pair.encrypt_packet(initial_header,initial_clinet_ACK,1)
        self.UDPClientSocket.sendto((initial_clinet_data) , (ip, DPORT))

    def send_handshake_ack_1(self) :
        # Long Header
        handshake_client_ACK_header = QUICHeader.QUICHandshakeHeader()
        # set destination and source id in header
        handshake_client_ACK_header.setfieldval("Public_Flags", 0xe1)
        handshake_client_ACK_header.setfieldval("DCID",  string_to_ascii(SessionInstance.get_instance().initial_destination_connection_id)) 
        handshake_client_ACK_header.setfieldval("SCID",  string_to_ascii(SessionInstance.get_instance().initial_source_connection_id))
        handshake_client_ACK_header.setfieldval("Length",bytes.fromhex("4018"))
        handshake_client_ACK_header.setfieldval("Packet_Number",256* PacketNumberInstance.get_instance().get_next_packet_number())

         #acknowledgement for Server handshake[0] 
        ackFrame_handshake = ACKFrame()
        ackFrame_handshake.setfieldval("Largest_Acknowledged",1)
        ackFrame_handshake.setfieldval("ACK_delay",bytes.fromhex("4048"))

        handshake_clinet_ACK = bytes.fromhex(extract_from_packet_as_bytestring(ackFrame_handshake))
        handshake_client_data = self.crypto.encrypt_handshake_packet(bytes.fromhex(extract_from_packet_as_bytestring(handshake_client_ACK_header)),handshake_clinet_ACK)
        self.UDPClientSocket.sendto((handshake_client_data) , (ip, DPORT))

    def send_handshake_ack_2(self) :
        # Long Header
        handshake_client_ACK_header = QUICHeader.QUICHandshakeHeader()
        # set destination and source id in header
        handshake_client_ACK_header.setfieldval("Public_Flags", 0xe1)
        handshake_client_ACK_header.setfieldval("DCID",  string_to_ascii(SessionInstance.get_instance().initial_destination_connection_id)) 
        handshake_client_ACK_header.setfieldval("SCID",  string_to_ascii(SessionInstance.get_instance().initial_source_connection_id))
        handshake_client_ACK_header.setfieldval("Length",bytes.fromhex("4017"))
        handshake_client_ACK_header.setfieldval("Packet_Number",256* PacketNumberInstance.get_instance().get_next_packet_number())

         #acknowledgement for Server handshake[0] 
        ackFrame_handshake = ACKFrameModify()
        ackFrame_handshake.setfieldval("Largest_Acknowledged",2)
        ackFrame_handshake.setfieldval("ACK_delay",bytes.fromhex("0e"))

        handshake_clinet_ACK = bytes.fromhex(extract_from_packet_as_bytestring(ackFrame_handshake))
        handshake_client_data = self.crypto.encrypt_handshake_packet(bytes.fromhex(extract_from_packet_as_bytestring(handshake_client_ACK_header)),handshake_clinet_ACK)
        self.UDPClientSocket.sendto((handshake_client_data) , (ip, DPORT))


    def send_ACK(self):

        #initial ACK packet        
     
        # Long Header
        initial_client_ACK_header = QUICHeader.QUICHeader()

        # set destination and source id in header
        initial_client_ACK_header.setfieldval("Public_Flags", 0xc1)
        initial_client_ACK_header.setfieldval("DCID",  string_to_ascii(SessionInstance.get_instance().initial_destination_connection_id)) 
        initial_client_ACK_header.setfieldval("SCID",  string_to_ascii(SessionInstance.get_instance().initial_source_connection_id))
        initial_client_ACK_header.setfieldval("Length",bytes.fromhex("4018"))
        initial_client_ACK_header.setfieldval("Packet_Number",256 * PacketNumberInstance.get_instance().get_next_packet_number())

        #acknowledgement for Server Initial[0] 
        ackFrame = ACKFrame()
        ackFrame.setfieldval("Largest_Acknowledged",0)
        ackFrame.setfieldval("ACK_delay",bytes.fromhex("408d"))
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
        handshake_client_ACK_header.setfieldval("Packet_Number",256* PacketNumberInstance.get_instance().get_next_packet_number())

        #acknowledgement for Server handshake[0] 
        ackFrame_handshake = ACKFrame()
        ackFrame_handshake.setfieldval("Largest_Acknowledged",1)
        ackFrame_handshake.setfieldval("ACK_delay",bytes.fromhex("408d"))


        handshake_clinet_ACK = bytes.fromhex(extract_from_packet_as_bytestring(ackFrame_handshake))
        handshake_header = bytes.fromhex(extract_from_packet_as_bytestring(handshake_client_ACK_header))
       
        self.crypto_context.setup(cipher_suite = 0x1302,secret =  SessionInstance.get_instance().client_handshake_traffic_secret ,version = 1)
        handshake_clinet_data = self.crypto_context.encrypt_packet(handshake_header,handshake_clinet_ACK,2)

        
        #send ACK Packet from client -> server 
        self.UDPClientSocket.sendto((initial_clinet_data + handshake_clinet_data  ) , (ip, DPORT))


    
    def send_finish(self):

        if SessionInstance.get_instance().handshake_done == True : return "ERROR" 
        handshake_client_finish_header = QUICHeader.QUICHandshakeHeader()
        _packet_number = PacketNumberInstance.get_instance().get_next_packet_number()
        # set header data
        handshake_client_finish_header.setfieldval("Public_Flags", 0xe1)
        handshake_client_finish_header.setfieldval("DCID",  string_to_ascii(SessionInstance.get_instance().initial_destination_connection_id)) 
        handshake_client_finish_header.setfieldval("SCID",  string_to_ascii(SessionInstance.get_instance().initial_source_connection_id))
        handshake_client_finish_header.setfieldval("Length",bytes.fromhex("4050"))
        handshake_client_finish_header.setfieldval("Packet_Number",256 * _packet_number)
        _handshake_client_ACK_header =  bytes.fromhex(extract_from_packet_as_bytestring(handshake_client_finish_header))

        #ack frame
        ackFrame_handshake = ACKFrame()
        ackFrame_handshake.setfieldval("Largest_Acknowledged",3)
        ackFrame_handshake.setfieldval("ACK_delay",bytes.fromhex("40de"))
        ackFrame_handshake.setfieldval("First_ACK_Range",1)
        _ackFrame = extract_from_packet_as_bytestring(ackFrame_handshake)

        #crypto frame for finish 
        cryptoFrame = CryptoFrame() 
        cryptoFrame.setfieldval("Length",bytes.fromhex("4034"))
        _crypatoFrame = extract_from_packet_as_bytestring(cryptoFrame)

        finished_verify_data = dhke.finished_verify_data(0x1302,SessionInstance.get_instance().client_handshake_traffic_secret)
    

        tlsfinsh = TLSFinish()
        tlsfinsh.setfieldval("vdata",bytes.fromhex(bytes.hex(finished_verify_data)))
        _tlsFinish = extract_from_packet_as_bytestring(tlsfinsh)
        data  = bytes.fromhex(_ackFrame + _crypatoFrame + _tlsFinish )
    
        self.crypto_context.setup(cipher_suite = 0x1302,secret =  SessionInstance.get_instance().client_handshake_traffic_secret ,version = 1)
        handshake_clinet_data =self.crypto_context.encrypt_packet(_handshake_client_ACK_header,data,_packet_number )

        # 1 - RTT packet 
        haeader = QUICHeader.QUICShortHeader()
        packet_number = PacketNumberInstance.get_instance().get_next_packet_number()
        haeader.setfieldval("Public_Flags",0x41)
        haeader.setfieldval("DCID",  string_to_ascii(SessionInstance.get_instance().initial_destination_connection_id)) 
        haeader.setfieldval("Packet_Number",string_to_ascii( bytes.hex(packet_number.to_bytes(2, byteorder='big'))))
        _haeader =  bytes.fromhex(extract_from_packet_as_bytestring(haeader))
  

         #ack frame
        ackFrame_handshake = ACKFrame()
        ackFrame_handshake.setfieldval("Largest_Acknowledged",0x04)
        ackFrame_handshake.setfieldval("ACK_delay",bytes.fromhex("40de"))
        ackFrame_handshake.setfieldval("First_ACK_Range",1)
        _ackFrame =  bytes.fromhex(extract_from_packet_as_bytestring(ackFrame_handshake))

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
        stream_2.setfieldval("Length",bytes.fromhex("4004"))
        stream_2.setfieldval("Data",bytes.fromhex("023fe11f"))
        _stream_2 = bytes.fromhex(extract_from_packet_as_bytestring(stream_2))

        stream_3 = quic_stream()
        stream_3.setfieldval("stream_id",10)
        stream_3.setfieldval("Length",bytes.fromhex("4001"))
        stream_3.setfieldval("Data",bytes.fromhex("03"))
        _stream_3 = bytes.fromhex(extract_from_packet_as_bytestring(stream_3))

        data = _ackFrame + _new_connection_id_data + _stream_1 + _stream_2 + _stream_3
        #encrypation using ap traffic secret
        self.crypto_context.setup(cipher_suite = 0x1302,secret =  SessionInstance.get_instance().client_appliction_traffic_secret ,version = 1)
        appliction_clinet_data =  self.crypto_context.encrypt_packet(_haeader,data,packet_number)

        self.UDPClientSocket.sendto((handshake_clinet_data + appliction_clinet_data), (ip, DPORT))
        # self.Send_application_header_2()
        try :
            # 1 - RTT[1]: [HD, Application Data]        
            recv_handshake_done = self.UDPClientSocket.recv(1200) # recive frist packet 4
            while len(recv_handshake_done) != 238 :
                print(len(recv_handshake_done))
                recv_handshake_done = self.UDPClientSocket.recv(1200)

            self.crypto_context.setup(cipher_suite = 0x1302,secret =  SessionInstance.get_instance().server_appliction_traffic_secret ,version = 1)
            plain_header, payload, packet_number, crypto = self.crypto_context.decrypt_packet(recv_handshake_done,9,0)
                
            PacketNumberInstance.get_instance().update_highest_received_packet_number(packet_number)
            pattern = b''    
            handshake_done = payload[6:7]
            if(extract_from_packet_as_bytestring(handshake_done) == "1E") :
                pattern += b"HD"
                
            SessionInstance.get_instance().handshake_done = True
            self.send_ACK_applictiondata()
            self.send_ack_for_message()
                
            return pattern

        except : 
            print("packet Not receive")
            return b"EXP"
    
    def Send_application_header_2(self):
        haeader = QUICHeader.QUICShortHeader()
        packet_number = PacketNumberInstance.get_instance().get_next_packet_number()
        haeader.setfieldval("Public_Flags",0x61)
        haeader.setfieldval("DCID",  string_to_ascii(SessionInstance.get_instance().initial_destination_connection_id)) 
        haeader.setfieldval("Packet_Number",string_to_ascii(bytes.hex(packet_number.to_bytes(2, byteorder='big'))))
        _haeader =  bytes.fromhex(extract_from_packet_as_bytestring(haeader))

        stream_data = bytes.fromhex("01220000d1d7508eed6988b8cc7b1245cf64d71a699fc15f508a198fdad311802efae26f")
        stream_1 = quic_stream()
        stream_1.setfieldval("Frame_Type",0x0b)
        stream_1.setfieldval("stream_id",0)
        stream_1.setfieldval("Length",bytes.fromhex("4024"))
        stream_1.setfieldval("Data",stream_data)
        _stream_1 = bytes.fromhex(extract_from_packet_as_bytestring(stream_1))

        data = _stream_1
        
        self.crypto_context.setup(cipher_suite = 0x1302,secret =  SessionInstance.get_instance().client_appliction_traffic_secret ,version = 1)
        appliction_clinet_data = self.crypto_context.encrypt_packet(_haeader,data,packet_number)
        self.UDPClientSocket.sendto(appliction_clinet_data, (ip, DPORT)) 

        try :
            push_promise = self.UDPClientSocket.recv(1000)
            self.crypto_context.setup(cipher_suite = 0x1302,secret =  SessionInstance.get_instance().server_appliction_traffic_secret ,version = 1)
            plain_header_ap, payload_ap, packet_number_ap, crypto_ap = self.crypto_context.decrypt_packet(push_promise,9,3)
        except :
            return b"EXP"  
        
        try :
            Application_header = self.UDPClientSocket.recv(1000) 
            self.crypto_context.setup(cipher_suite = 0x1302,secret =  SessionInstance.get_instance().server_appliction_traffic_secret ,version = 1)
            plain_header_ap, payload_ap, packet_number_ap, crypto_ap = self.crypto_context.decrypt_packet(Application_header,9,3)
        except :
            return b"EXP" 
        
        pattern = b""
        try :
            html_page_1 = self.UDPClientSocket.recv(1300) 
            self.crypto_context.setup(cipher_suite = 0x1302,secret =  SessionInstance.get_instance().server_appliction_traffic_secret ,version = 1)
            plain_header_ap, payload_ap, packet_number_ap, crypto_ap = self.crypto_context.decrypt_packet(html_page_1,9,3)
            if payload_ap.find(b"html") :
                pattern += b"html"
            else :
                return "ERROR"
            PacketNumberInstance.get_instance().update_highest_received_packet_number(packet_number_ap)
        except : 
            print(" HTML Page 1 packet Not receive")
            return b"EXP"

        try :
            html_page_2 = self.UDPClientSocket.recv(1300) 
            self.crypto_context.setup(cipher_suite = 0x1302,secret =  SessionInstance.get_instance().server_appliction_traffic_secret ,version = 1)
            plain_header_ap, payload_ap, packet_number_ap, crypto_ap = self.crypto_context.decrypt_packet(html_page_2,9,3)
            PacketNumberInstance.get_instance().update_highest_received_packet_number(packet_number_ap)
            self.send_ack_for_message_6()
        except : 
            print("HTML Page 2 packet Not receive")
            return b"EXP"
        
        return pattern


    def send_ACK_applictiondata(self):
        haeader = QUICHeader.QUICShortHeader()
        packet_number = PacketNumberInstance.get_instance().get_next_packet_number()
        haeader.setfieldval("Public_Flags",0x61)
        haeader.setfieldval("DCID",  string_to_ascii(SessionInstance.get_instance().initial_destination_connection_id)) 
        haeader.setfieldval("Packet_Number",string_to_ascii(bytes.hex(packet_number.to_bytes(2, byteorder='big'))))
        _haeader =  bytes.fromhex(extract_from_packet_as_bytestring(haeader))

        #ack frame
        ackFrame_appliction = ACKFrame()
        ackFrame_appliction.setfieldval("Largest_Acknowledged",3)
        ackFrame_appliction.setfieldval("ACK_delay",bytes.fromhex("4194"))
        ackFrame_appliction.setfieldval("First_ACK_Range",0)
        _ackFrame =  bytes.fromhex(extract_from_packet_as_bytestring(ackFrame_appliction))

        data = _ackFrame 
        self.crypto_context.setup(cipher_suite = 0x1302,secret =  SessionInstance.get_instance().client_appliction_traffic_secret ,version = 1)
        appliction_clinet_data =  self.crypto_context.encrypt_packet(_haeader,data,packet_number)
        self.UDPClientSocket.sendto(appliction_clinet_data, (ip, DPORT))

        
    
    def  Send_application_header(self):
        haeader = QUICHeader.QUICShortHeader()
        packet_number = PacketNumberInstance.get_instance().get_next_packet_number()
        haeader.setfieldval("Public_Flags",0x61)
        haeader.setfieldval("DCID",  string_to_ascii(SessionInstance.get_instance().initial_destination_connection_id)) 
        haeader.setfieldval("Packet_Number",string_to_ascii(bytes.hex(packet_number.to_bytes(2, byteorder='big'))))
        _haeader =  bytes.fromhex(extract_from_packet_as_bytestring(haeader))

        stream_data_2 = bytes.fromhex("3fe11f")
        stream_2 = quic_offset_stream()
        stream_2.setfieldval("stream_id",6)
        stream_2.setfieldval("offset",1)
        stream_2.setfieldval("Length",bytes.fromhex("4003"))
        stream_2.setfieldval("Data",stream_data_2)
        _stream_2 = bytes.fromhex(extract_from_packet_as_bytestring(stream_2))

        stream_data = bytes.fromhex("011e0000d1d7508aa0e41d139d09b8d34cb3c15f508a198fdad311802efae26f")
        stream_1 = quic_stream()
        stream_1.setfieldval("Frame_Type",0x0b)
        stream_1.setfieldval("stream_id",0)
        stream_1.setfieldval("Length",bytes.fromhex("4020"))
        stream_1.setfieldval("Data",stream_data)
        _stream_1 = bytes.fromhex(extract_from_packet_as_bytestring(stream_1))

        data =  _stream_2 +_stream_1
        
        self.crypto_context.setup(cipher_suite = 0x1302,secret =  SessionInstance.get_instance().client_appliction_traffic_secret ,version = 1)
        appliction_clinet_data = self.crypto_context.encrypt_packet(_haeader,data,packet_number)
        self.UDPClientSocket.sendto(appliction_clinet_data, (ip, DPORT))

        try :
            push_promise = self.UDPClientSocket.recv(1000)
            self.crypto_context.setup(cipher_suite = 0x1302,secret =  SessionInstance.get_instance().server_appliction_traffic_secret ,version = 1)
            plain_header_ap, payload_ap, packet_number_ap, crypto_ap = self.crypto_context.decrypt_packet(push_promise,9,3)
        except :
            return b"EXP"  
        
        try :
            Application_header = self.UDPClientSocket.recv(1000) 
            self.crypto_context.setup(cipher_suite = 0x1302,secret =  SessionInstance.get_instance().server_appliction_traffic_secret ,version = 1)
            plain_header_ap, payload_ap, packet_number_ap, crypto_ap = self.crypto_context.decrypt_packet(Application_header,9,3)
        except :
            return b"EXP" 
        
        pattern = b""
        try :
            html_page_1 = self.UDPClientSocket.recv(1300) 
            self.crypto_context.setup(cipher_suite = 0x1302,secret =  SessionInstance.get_instance().server_appliction_traffic_secret ,version = 1)
            plain_header_ap, payload_ap, packet_number_ap, crypto_ap = self.crypto_context.decrypt_packet(html_page_1,9,3)
            if payload_ap.find(b"html") :
                pattern += b"html"
            else :
                return "ERROR"
            PacketNumberInstance.get_instance().update_highest_received_packet_number(packet_number_ap)
        except : 
            print(" HTML Page 1 packet Not receive")
            return b"EXP"

        try :
            html_page_2 = self.UDPClientSocket.recv(1300) 
            self.crypto_context.setup(cipher_suite = 0x1302,secret =  SessionInstance.get_instance().server_appliction_traffic_secret ,version = 1)
            plain_header_ap, payload_ap, packet_number_ap, crypto_ap = self.crypto_context.decrypt_packet(html_page_2,9,3)
            PacketNumberInstance.get_instance().update_highest_received_packet_number(packet_number_ap)
            self.send_ack_for_message_6()
        except : 
            print("HTML Page 2 packet Not receive")
            return b"EXP"
        
        return pattern
        
    def send_ack_for_message(self):

        haeader = QUICHeader.QUICShortHeader()
        packet_number = PacketNumberInstance.get_instance().get_next_packet_number()
        haeader.setfieldval("Public_Flags",0x61)
        haeader.setfieldval("DCID",  string_to_ascii(SessionInstance.get_instance().initial_destination_connection_id)) 
        haeader.setfieldval("Packet_Number",string_to_ascii(bytes.hex(packet_number.to_bytes(2, byteorder='big'))))
        _haeader =  bytes.fromhex(extract_from_packet_as_bytestring(haeader))

        ackFrame = ACKFrame()
        ackFrame.setfieldval("Largest_Acknowledged",PacketNumberInstance.get_instance().get_highest_received_packet_number())
        ackFrame.setfieldval("ACK_delay",bytes.fromhex("405a"))
        ackFrame.setfieldval("First_ACK_Range",0)
        _ackFrame =  bytes.fromhex(extract_from_packet_as_bytestring(ackFrame))

        try : 
            self.crypto_context.setup(cipher_suite = 0x1302,secret =  SessionInstance.get_instance().client_appliction_traffic_secret ,version = 1)
            appliction_clinet_data = self.crypto_context.encrypt_packet(_haeader,_ackFrame,packet_number)
        except:
            return b"EXP"
        
        self.UDPClientSocket.sendto( appliction_clinet_data, (ip, DPORT))

       
    def send_ack_for_message_6(self):

        haeader = QUICHeader.QUICShortHeader()
        packet_number = PacketNumberInstance.get_instance().get_next_packet_number()
        haeader.setfieldval("Public_Flags",0x61)
        haeader.setfieldval("DCID",  string_to_ascii(SessionInstance.get_instance().initial_destination_connection_id)) 
        haeader.setfieldval("Packet_Number",string_to_ascii(bytes.hex(packet_number.to_bytes(2, byteorder='big'))))
        _haeader =  bytes.fromhex(extract_from_packet_as_bytestring(haeader))

        ackFrame = ACKFrame()
        ackFrame.setfieldval("Largest_Acknowledged",6)
        ackFrame.setfieldval("ACK_delay",bytes.fromhex("405a"))
        ackFrame.setfieldval("First_ACK_Range",0)
        _ackFrame =  bytes.fromhex(extract_from_packet_as_bytestring(ackFrame))

        try : 
            self.crypto_context.setup(cipher_suite = 0x1302,secret =  SessionInstance.get_instance().client_appliction_traffic_secret ,version = 1)
            appliction_clinet_data = self.crypto_context.encrypt_packet(_haeader,_ackFrame,packet_number)
        except:
            return b"EXP"
        
        self.UDPClientSocket.sendto( appliction_clinet_data, (ip, DPORT))
        
        try :
            push_promise = self.UDPClientSocket.recv(1000)
            push_promise = self.UDPClientSocket.recv(1000)
            push_promise = self.UDPClientSocket.recv(1000)
            self.crypto_context.setup(cipher_suite = 0x1302,secret =  SessionInstance.get_instance().server_appliction_traffic_secret ,version = 1)
            plain_header_ap, payload_ap, packet_number_ap, crypto_ap = self.crypto_context.decrypt_packet(push_promise,9,3)
        except :
            return b"EXP" 
    
    def connection_close(self) :
        haeader = QUICHeader.QUICShortHeader()
        packet_number = PacketNumberInstance.get_instance().get_next_packet_number()
        haeader.setfieldval("Public_Flags",0x61)
        haeader.setfieldval("DCID",  string_to_ascii(SessionInstance.get_instance().initial_destination_connection_id)) 
        haeader.setfieldval("Packet_Number",string_to_ascii(bytes.hex(packet_number.to_bytes(2, byteorder='big'))))
        _haeader =  bytes.fromhex(extract_from_packet_as_bytestring(haeader))

        #connection_closed
        connection_clodsed = quic_connection_closed()
        _connection_clodsed=  bytes.fromhex(extract_from_packet_as_bytestring(connection_clodsed))
        if SessionInstance.get_instance().handshake_done == False :
            return b"EXP" 
        try :
            self.crypto_context.setup(cipher_suite = 0x1302,secret =  SessionInstance.get_instance().client_appliction_traffic_secret ,version = 1)
            connection_close_data = self.crypto_context.encrypt_packet(_haeader,_connection_clodsed,packet_number)
            self.UDPClientSocket.sendto( connection_close_data,(ip, DPORT))
            return b"closed"
        except :
            return b"EXP" 
        
    def send(self, command):
        try:
            if isinstance(command, SendInitialCHLOEvent):
                print("Sending InitialCHLO")
                return self.initial_chlo(True)
            elif isinstance(command, SendFINEvent):
                print("Sending FIN")
                return self.send_finish()
            elif isinstance(command, SendGETRequestEvent):
                print("Sending GET")
                return self.Send_application_header_2()
            elif isinstance(command, CloseConnectionEvent):
                print("Closing connection")
                return self.connection_close()
            else:
                print("Unknown command {}".format(command))
        except Exception as err:
            print("error")


s = QUIC("quic.aiortc.org")
print(s.initial_chlo(True))
# print(s.initial_chlo(True))
KeyFile.FileGenret()
# print(s.send_finish())
# # print(s.Send_application_header())
# print(s.Send_application_header_2())
# print(s.connection_close())
