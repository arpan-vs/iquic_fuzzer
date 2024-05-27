
import re
import QUICHeader
import socket
from utils.string_to_ascii import string_to_ascii
from utils.packet_to_hex import extract_from_packet, extract_from_packet_as_bytestring, hex_to_binary
import random
from utils.SessionInstance import SessionInstance
from utils.PacketNumberInstance import PacketNumberInstance
from crypto.Secret import dhke, Crypto
from CryptoFrame import CryptoFrame ,ACKFrame,ACKFrameModify,TLSFinish
from events.Events import *

# from scapy.layers.tls.handshake import TLSFinished
from crypto.Frame import new_connection_id, quic_stream, quic_offset_stream ,quic_connection_closed
from aioquic.quic.packet import QuicStreamFrame  
from aioquic.quic.stream import QuicStream 
import os
import qpack 
from aioquic.quic.crypto import CryptoContext,CryptoPair
# https://quic.aiortc.org:443
DPORT = 4433
# DPORT = 4433
ip ="127.0.0.1"

# DPORT = 443
# ip ="34.247.195.106"
class QUIC : 

    Largest_Acked = 0

    def __init__(self, s, fuzz = False) -> None:

        self.fuzz = fuzz
        self.crypto = Crypto()
        self.cryptoContext = CryptoContext()
        self.crypto_pair = CryptoPair()   
        # set Destination conncetion id 
        destination_id = random.getrandbits(64)
        SessionInstance.get_instance().initial_destination_connection_id = str(format(destination_id, 'x').zfill(16))
        SessionInstance.get_instance().client_initial_destination_connection_id =   SessionInstance.get_instance().initial_destination_connection_id
        
        # set source conncetion id 
        source_id = random.getrandbits(64)
        SessionInstance.get_instance().initial_source_connection_id = str(format(source_id, 'x').zfill(16))

        self.UDPClientSocket = socket.socket(family = socket.AF_INET, type =socket.SOCK_DGRAM)
        self.UDPClientSocket.connect((ip, DPORT))
        dhke.set_up_my_keys()
        self.UDPClientSocket.settimeout(1)

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
            dhke.set_up_my_keys()


    def initial_chlo(self, only_reset, InvalidPacket = False):

        self.reset(only_reset)

        # Long Header
        chlo = QUICHeader.QUICHeader() 

        # set destination and source id in header
        chlo.setfieldval("DCID",  string_to_ascii(SessionInstance.get_instance().initial_destination_connection_id)) 
        chlo.setfieldval("SCID",  string_to_ascii(SessionInstance.get_instance().initial_source_connection_id))
        plain_header = bytes.fromhex(extract_from_packet_as_bytestring(chlo)) 

        # crypato Frame continent client hello hanshake messages  
        cryptoFrame = CryptoFrame() 
        crypto_frame = extract_from_packet_as_bytestring(cryptoFrame)

        ClientHello = bytes.hex(CryptoFrame().TLSObject("localhost").data)

        if InvalidPacket and not self.fuzz:
            ClientHello = bytearray.fromhex(ClientHello)
            ClientHello[3] = 0
            ClientHello = ClientHello.hex()
        elif InvalidPacket and self.fuzz:
            ClientHello = bytearray.fromhex(ClientHello)
            index = random.randrange(0, len(ClientHello))
            ClientHello[index] = random.randrange(0, 255)
            ClientHello = ClientHello.hex()

        SessionInstance.get_instance().tlschlo = bytes.fromhex(ClientHello)
        # padding
        padding = "00" * (775)
        
        # client hello hanshake messages + padding
        plain_payload = bytes.fromhex(crypto_frame + ClientHello + padding)

        #client initial packet encrypt using initial traffic secret
        data =self.crypto.encrypt_initial_packet(plain_header,plain_payload,0)
      
        #send -> Initial[0] : crypato(CH)
        self.UDPClientSocket.send(data)
        pattern = b""
        try :
           
            # receive -> Initial[0] : crypato(SH)
            datarev_1 = self.UDPClientSocket.recv(1300)
            # only Receive Initial packet
            while hex_to_binary(bytes.hex(datarev_1[0:1]))[2:4] != "00" :
                datarev_1 = self.UDPClientSocket.recv(1300) 
                if(hex_to_binary(bytes.hex(datarev_1[0:1]))[2:4] == "00") : break 
                
            server_initial = datarev_1 #Initial[0] : crypato(SH)
        
            #server initial packet decrypat using initial traffic secret
            
            plain_header, temo_payload, packet_number = self.crypto.decrypt_initial_packet(server_initial)
            payload = temo_payload[:100]
            sever_public_key = payload[-32:]
            
            server_hello_data = payload[10:]
            # print("server_hello_data",bytes.hex(server_hello_data))
            DCID = plain_header[6:14]
            SCID = plain_header[15:23]


            PacketNumberInstance.get_instance().highest_received_packet_number = packet_number
            SessionInstance.get_instance().initial_destination_connection_id = bytes.hex(SCID)
            SessionInstance.get_instance().tlsshalo = server_hello_data
            
            dhke.shared_key_computation(sever_public_key)
            dhke.handshake_traffic_computation()
            pattern += b"Server_Hello"

        except :  
            print("initial packet Not receive")
            return b"EXP"

        try :
            '''
            Here handshake packet is in fragmentation  
            '''
            # receive -> handshake[0] : crypato(EE,CRT,CV,FIN)
            server_handshake_1 = self.UDPClientSocket.recv(1300)
            self.cryptoContext.setup(cipher_suite = 0x1302, secret = SessionInstance.get_instance().server_handshake_traffic_secret, version = 1)
            plain_header_sp, payload_sp, packet_number_sp,crypto = self.cryptoContext.decrypt_packet(server_handshake_1,25,1)

            PacketNumberInstance.get_instance().update_highest_received_packet_number(packet_number_sp)

            SessionInstance.get_instance().crypto_extensions = payload_sp[4:114]                    # EE
            SessionInstance.get_instance().crypto_cert = payload_sp[114:]                         # CERT
            # SessionInstance.get_instance().crypto_finished = payload_sp[1036:]                   # FIN   
        except:
            print("handshake Packet 1 not receive")
            return b"EXP"

        try :
            # receive -> 1-RTT[0] : appliction_data
            data = self.UDPClientSocket.recv(1300) 
            handshake_data_2 = data[:987]
            appliction_data = data[987:]

            self.cryptoContext.setup(cipher_suite = 0x1302, secret = SessionInstance.get_instance().server_handshake_traffic_secret, version = 1)
            plain_header_tp, payload_tp, packet_number_tp,crypto = self.cryptoContext.decrypt_packet(handshake_data_2,25,1)

            SessionInstance.get_instance().crypto_cert += payload_tp[5:500]
            SessionInstance.get_instance().crypto_certverify = payload_tp[500:892]
            SessionInstance.get_instance().crypto_finished = payload_tp[892:]
            pattern += b"+Handshake"
            dhke.appliction_traffic_computation()
            self.cryptoContext.setup(cipher_suite = 0x1302, secret = SessionInstance.get_instance().server_appliction_traffic_secret, version = 1)
            plain_header_ap, payload_ap, packet_number_ap,crypto =  self.cryptoContext.decrypt_packet(appliction_data,9,0)
            PacketNumberInstance.get_instance().update_highest_received_packet_number(packet_number_ap)
            pattern += b"+appliction_data"
            self.send_ACK()
            self.send_handshake()
            self.send_ACK_applictiondata()
        except:
            print("appliction Packet 2  not receive")
            return b"EXP"
        
        return pattern
    

    def send_ACK(self):

        #initial ACK packet        
     
        # Long Header
        initial_client_ACK_header = QUICHeader.QUICHeader()
        _packet_number = PacketNumberInstance.get_instance().get_next_packet_number()
        # set destination and source id in header
        initial_client_ACK_header.setfieldval("Public_Flags", 0xc1)
        initial_client_ACK_header.setfieldval("DCID",  string_to_ascii(SessionInstance.get_instance().initial_destination_connection_id)) 
        initial_client_ACK_header.setfieldval("SCID",  string_to_ascii(SessionInstance.get_instance().initial_source_connection_id))
        initial_client_ACK_header.setfieldval("Length",bytes.fromhex("4496"))
        initial_client_ACK_header.setfieldval("Packet_Number",256 * _packet_number)
        initial_header = bytes.fromhex(extract_from_packet_as_bytestring(initial_client_ACK_header)) 
        #acknowledgement for Server Initial[0] 
        ackFrame = ACKFrame()
        ackFrame.setfieldval("Largest_Acknowledged",0)
        ackFrame.setfieldval("ACK_delay",bytes.fromhex("4059"))
        ACK_frame = extract_from_packet_as_bytestring(ackFrame)
        padding = "00" * (1150)
        initial_clinet_ACK = bytes.fromhex(ACK_frame + padding)

        #Initial ACK packet encrypt using initial traffic secret
       # initial_clinet_data = self.crypto.encrypt_initial_packet(initial_header,initial_clinet_ACK,_packet_number)
        self.crypto_pair.setup_initial(string_to_ascii(SessionInstance.get_instance().client_initial_destination_connection_id ),True,1)
        data = self.crypto_pair.encrypt_packet(initial_header,initial_clinet_ACK,_packet_number)
        self.UDPClientSocket.send(data)
        
    
    def send_handshake(self) :
        # Long Header
        handshake_client_ACK_header = QUICHeader.QUICHandshakeHeader()
        # set destination and source id in header
        handshake_client_ACK_header.setfieldval("Public_Flags", 0xe1)
        handshake_client_ACK_header.setfieldval("DCID",  string_to_ascii(SessionInstance.get_instance().initial_destination_connection_id)) 
        handshake_client_ACK_header.setfieldval("SCID",  string_to_ascii(SessionInstance.get_instance().initial_source_connection_id))
        handshake_client_ACK_header.setfieldval("Length",bytes.fromhex("4016"))
        handshake_client_ACK_header.setfieldval("Packet_Number",256* PacketNumberInstance.get_instance().get_next_packet_number())

         #acknowledgement for Server handshake[0] 
        ackFrame_handshake = ACKFrame()
        ackFrame_handshake.setfieldval("Largest_Acknowledged",1)
        ackFrame_handshake.setfieldval("ACK_delay",bytes.fromhex("407e"))
        handshake_clinet_ACK = bytes.fromhex(extract_from_packet_as_bytestring(ackFrame_handshake))

        ackFrame_handshake.setfieldval("Largest_Acknowledged",2)
        ackFrame_handshake.setfieldval("ACK_delay",bytes.fromhex("407e"))
        handshake_clinet_ACK1 = bytes.fromhex(extract_from_packet_as_bytestring(ackFrame_handshake))
        
        handshake_client_data = self.crypto.encrypt_handshake_packet(bytes.fromhex(extract_from_packet_as_bytestring(handshake_client_ACK_header)),handshake_clinet_ACK + handshake_clinet_ACK1)
        self.UDPClientSocket.send(handshake_client_data)

    
    def send_finish(self, InvalidPacket = False):

        if SessionInstance.get_instance().handshake_done == True : return b"ERROR" 
        handshake_client_finish_header = QUICHeader.QUICHandshakeHeader()
        # set header data
        handshake_client_finish_header.setfieldval("Public_Flags", 0xe1)
        handshake_client_finish_header.setfieldval("DCID",  string_to_ascii(SessionInstance.get_instance().initial_destination_connection_id)) 
        handshake_client_finish_header.setfieldval("SCID",  string_to_ascii(SessionInstance.get_instance().initial_source_connection_id))
        handshake_client_finish_header.setfieldval("Length",bytes.fromhex("4050"))
        handshake_client_finish_header.setfieldval("Packet_Number",256 * PacketNumberInstance.get_instance().get_next_packet_number())
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

        finished_verify_data = dhke.finished_verify_data(0x1302,SessionInstance.get_instance().client_handshake_traffic_secret)
        #finsh message 
        tlsfinsh = TLSFinish()
        tlsfinsh.setfieldval("vdata",bytes.fromhex(bytes.hex(finished_verify_data)))
        
        
        _tlsFinish = extract_from_packet_as_bytestring(tlsfinsh)
        if InvalidPacket and not self.fuzz:   
            tlsfinsh.setfieldval("Length",bytes.fromhex("000010"))
            _tlsFinish = extract_from_packet_as_bytestring(tlsfinsh)

        elif InvalidPacket and self.fuzz:
            _tlsFinish = extract_from_packet_as_bytestring(tlsfinsh)
            _tlsFinish = bytearray.fromhex(_tlsFinish)
            index = random.randrange(0, len(_tlsFinish))
            _tlsFinish[index] = random.randrange(0, 255)
            _tlsFinish = _tlsFinish.hex()
            
        data  = bytes.fromhex(_ackFrame + _crypatoFrame + _tlsFinish )
    
        handshake_clinet_data =self.crypto.encrypt_handshake_packet(_handshake_client_ACK_header,data)

        # 1 - RTT packet 
        haeader = QUICHeader.QUICShortHeader()
        packet_number = PacketNumberInstance.get_instance().get_next_packet_number()
        haeader.setfieldval("Public_Flags",0x41)
        haeader.setfieldval("DCID",  string_to_ascii(SessionInstance.get_instance().initial_destination_connection_id)) 
        haeader.setfieldval("Packet_Number",string_to_ascii( bytes.hex(packet_number.to_bytes(2, byteorder='big'))))
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
        self.send_ACK_applictiondata()

        #encrypation using ap traffic secret

        appliction_clinet_data =  self.crypto.encrypt_application_packet(_haeader,data)
        self.UDPClientSocket.send(handshake_clinet_data + appliction_clinet_data)
        try :
            #1 - RTT[1]: [HD, Application Data]        
            recv_handshake_done = self.UDPClientSocket.recv(1200) # recive frist packet 4
            recv_ACK_ = self.UDPClientSocket.recv(100) # recive ACK packet 6

            plain_header, payload, packet_number = self.crypto.decrypt_application_packet(recv_handshake_done)
            
            PacketNumberInstance.get_instance().update_highest_received_packet_number(packet_number)
            
            handshake_done = payload[6:7]
            if(extract_from_packet_as_bytestring(handshake_done) == "1E") :
                print("handshake done")
            
            SessionInstance.get_instance().handshake_done = True
            self.send_ACK_applictiondata()
            self.send_ack_for_message()
            
            return b"HD"

        except : 
            print("packet Not receive")
            return b"EXP"
        

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
        appliction_clinet_data =  self.crypto.encrypt_application_packet(_haeader,_ackFrame)
        self.UDPClientSocket.send(appliction_clinet_data)
        
    
    def Send_application_header(self, InvalidPacket = False):
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
        if InvalidPacket and not self.fuzz:  
            stream_1.setfieldval("Length",bytes.fromhex("4010"))
            _stream_1 = bytes.fromhex(extract_from_packet_as_bytestring(stream_1))

        elif InvalidPacket and self.fuzz:
            _stream_1 = bytes.fromhex(extract_from_packet_as_bytestring(stream_1))
            _stream_1 = extract_from_packet_as_bytestring(_stream_1)
            _stream_1 = bytearray.fromhex(_stream_1)
            index = random.randrange(0, len(_stream_1))
            _stream_1[index] = random.randrange(0, 255)
            _stream_1 = _stream_1.hex()
            

        data =  _stream_2 +_stream_1
        
        appliction_clinet_data = self.crypto.encrypt_application_packet(_haeader,data)
        self.UDPClientSocket.send(appliction_clinet_data)

        try :
            push_promise = self.UDPClientSocket.recv(1000)
            plain_header_ap, payload_ap, packet_number_ap = self.crypto.decrypt_application_packet(push_promise)
        except :
            pass
        
        try :
            Application_header = self.UDPClientSocket.recv(1000) 
            plain_header_ap, payload_ap, packet_number_ap = self.crypto.decrypt_application_packet(Application_header)
        except :
            pass
        
        try :
            Application_header = self.UDPClientSocket.recv(1000) 
            plain_header_ap, payload_ap, packet_number_ap = self.crypto.decrypt_application_packet(Application_header)
        except :
            pass
        
        pattern = b""
        try :
            html_page_1 = self.UDPClientSocket.recv(1300) 
            plain_header_ap, payload_ap, packet_number_ap = self.crypto.decrypt_application_packet(html_page_1)
            # print(payload_ap)
            pattern_match = re.search(b"html", payload_ap)
            if pattern_match:
                pattern += b"html"
            else :
                return b"EXP"
            PacketNumberInstance.get_instance().update_highest_received_packet_number(packet_number_ap)
        except : 
            print(" HTML Page 1 packet Not receive")
            return b"EXP"

        try :
            html_page_2 = self.UDPClientSocket.recv(1300) 
            plain_header_ap, payload_ap, packet_number_ap = self.crypto.decrypt_application_packet(html_page_2)
            PacketNumberInstance.get_instance().update_highest_received_packet_number(packet_number_ap)
            self.send_ack_for_message_6()

        except : 
            print("HTML Page 2 packet Not receive")
            # return b"EXP"
        
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
            appliction_clinet_data = self.crypto.encrypt_application_packet(_haeader,_ackFrame)
        except:
            return b"EXP"
        
        self.UDPClientSocket.send(appliction_clinet_data)

       
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
            appliction_clinet_data = self.crypto.encrypt_application_packet(_haeader,_ackFrame)
        except:
            return b"EXP"
        
        self.UDPClientSocket.send(appliction_clinet_data)
        
        try :
            push_promise = self.UDPClientSocket.recv(1000)
            push_promise = self.UDPClientSocket.recv(1000)
            push_promise = self.UDPClientSocket.recv(1000)
            plain_header_ap, payload_ap, packet_number_ap, crypto_ap = self.crypto.decrypt_application_packet(push_promise)
        except :
            return b"EXP" 
    
    def connection_close(self) :
        haeader = QUICHeader.QUICShortHeader()
        packet_number = PacketNumberInstance.get_instance().get_next_packet_number()
        haeader.setfieldval("Public_Flags",0x60)
        haeader.setfieldval("DCID",  string_to_ascii(SessionInstance.get_instance().initial_destination_connection_id)) 
        haeader.setfieldval("Packet_Number",string_to_ascii(bytes.hex(packet_number.to_bytes(2, byteorder='big'))))
        _haeader =  bytes.fromhex(extract_from_packet_as_bytestring(haeader))

        #connection_closed
        connection_clodsed = quic_connection_closed()
        _connection_clodsed=  bytes.fromhex(extract_from_packet_as_bytestring(connection_clodsed))
        if SessionInstance.get_instance().handshake_done == False :
            return b"EXP" 
        try :
            connection_close_data = self.crypto.encrypt_application_packet(_haeader,_connection_clodsed)
            self.UDPClientSocket.send(connection_close_data)
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
                return self.Send_application_header()
            elif isinstance(command, SendInvalidInitialCHLOEvent):
                print("Sending Invalid InitialCHLO")
                return self.initial_chlo(True, InvalidPacket=True)
            elif isinstance(command, SendInvalidFINEvent):
                print("Sending Invalid FIN")
                return self.send_finish(InvalidPacket=True)
            elif isinstance(command, SendInvalidGETRequestEvent):
                print("Sending Invalid GET")
                return self.Send_application_header(InvalidPacket=True)
            elif isinstance(command, CloseConnectionEvent):
                print("Closing connection")
                return self.connection_close()
            else:
                print("Unknown command {}".format(command))
        except Exception as err:
            print("error")

# from  Keylog import KeyFile
# s = QUIC("localhost")

# print(s.initial_chlo(True))
# print(s.initial_chlo(True, InvalidPacket=True))
# print(s.initial_chlo(True))
# KeyFile.FileGenret()
# print(s.send_finish())
# print(s.Send_application_header(InvalidPacket=True))
# print(s.connection_close())
# print(s.Send_application_header())
