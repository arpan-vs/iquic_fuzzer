
import QUICHeader
import socket
from utils.string_to_ascii import string_to_ascii
from utils.packet_to_hex import extract_from_packet, extract_from_packet_as_bytestring
import random
from events.Events import SendInitialCHLOEvent, SendGETRequestEvent, CloseConnectionEvent, SendFullCHLOEvent, ZeroRTTCHLOEvent, ResetEvent
from utils.SessionInstance import SessionInstance
from Crypto.Cipher import AES
from aioquic.quic.crypto import hkdf_extract,hkdf_expand_label,cipher_suite_hash , CipherSuite, AEAD, CryptoError, HeaderProtection ,CryptoContext,CryptoPair
from crypto.Secret import secret_all
from frames.CryptoFrame import CryptoFrame

DPORT = 4433
class QUIC : 
    def __init__(self) -> None:

        destination_id = random.getrandbits(64)
        SessionInstance.get_instance().initial_destination_connection_id = str(format(destination_id, 'x').zfill(16))

        source_id = random.getrandbits(64)
        SessionInstance.get_instance().initial_source_connection_id = str(format(source_id, 'x').zfill(16))

        self.UDPClientSocket = socket.socket(family = socket.AF_INET, type =socket.SOCK_DGRAM)
        # self.UDPClientSocket.settimeout(0.1)


    def send_initial_chlo(self, only_reset):
        # Long Header
        chlo = QUICHeader.QUICHeader() 
        # set destination and source id in header
        chlo.setfieldval("DCID",  string_to_ascii(SessionInstance.get_instance().initial_destination_connection_id)) 
        chlo.setfieldval("SCID",  string_to_ascii(SessionInstance.get_instance().initial_source_connection_id))
        header = bytes.fromhex(extract_from_packet_as_bytestring(chlo)) 
        # cryptoFrame + cryptodat(TLS Object)
        cryptoFrame = CryptoFrame() 
        tlsObjct = extract_from_packet_as_bytestring(CryptoFrame.TLSObject())
        # padding
        padding = "00" * (775)
    
        crypto_frame = extract_from_packet_as_bytestring(cryptoFrame)

        # full packet
        initial_frame = bytes.fromhex(crypto_frame + tlsObjct + padding)
        # client_initial_secret = secret.client_initial_secret()


        # crypto_context = CryptoContext()
        # crypto_context.setup(cipher_suite = 0x1301 , secret = client_initial_secret,version = 1)
        # data = crypto_context.encrypt_packet(header,initial_frame,0)
        crypto_context = CryptoPair()
        crypto_context.setup_initial(string_to_ascii(SessionInstance.get_instance().initial_destination_connection_id),True,1)
        data = crypto_context.encrypt_packet(header,initial_frame,0)
        self.UDPClientSocket.sendto(data, ("127.0.0.2", DPORT))

        datarecv = self.UDPClientSocket.recv(1200)
        datarecv_2 = self.UDPClientSocket.recv(1200)
        daya_rec = extract_from_packet_as_bytestring(datarecv)
        daya_rec_2 = extract_from_packet_as_bytestring(datarecv_2)
        server_initial = datarecv[:177]
        server_handshake = datarecv[177:]
        print(extract_from_packet_as_bytestring(server_initial) ,"\n\n")
        print(extract_from_packet_as_bytestring(server_handshake),"\n\n")
        print(daya_rec_2,"\n\n")
        print("datareve_2 len " ,len(daya_rec_2) /2 )
        print("\n\n",len(daya_rec) ," " , (len(daya_rec)/2) )
        print()

        # sever_initial_secret = secret.server_initial_secret()

        crypto_context_decode_1 = CryptoContext()

        # crypto_context_decode.setup(cipher_suite=0x1301,secret=sever_initial_secret,version=1)

        # plain_header, payload, packet_number, crypto_self =  crypto_context_decode.decrypt_packet(server_initial,26,0)
        # print(extract_from_packet_as_bytestring(plain_header)) 
        # print("\n")
        # print(extract_from_packet_as_bytestring(payload))
        # print("\n")
        # print((packet_number))
        # print((crypto_self))

        # plain_header, payload, packet_number, crypto_self =  crypto_context_decode.decrypt_packet(server_handshake,25,1)
        crypto_context_decode = CryptoPair()
        crypto_context_decode.setup_initial(string_to_ascii(SessionInstance.get_instance().initial_destination_connection_id),True,1)

        plain_header, payload, packet_number = crypto_context.decrypt_packet(server_initial,26,0)

        print(extract_from_packet_as_bytestring(plain_header)) 
        print("\n")
        print(extract_from_packet_as_bytestring(payload))
        print("\n")
        print((packet_number))

        # secret_pa = secret_all.nth_secret(secret_all.server_initial_secret()) 
        # crypto_context_decode_1.setup(cipher_suite=0x1301,secret = secret_pa,version=1)
        # plain_header, payload, packet_number = crypto_context_decode_1.decrypt_packet((server_handshake),25,0)   

        # print(extract_from_packet_as_bytestring(plain_header)) 
        # print("\n")
        # print(extract_from_packet_as_bytestring(payload))
        # print("\n")
        # print((packet_number))



    

       

s = QUIC()
s.send_initial_chlo(True)

# tes1 = "c000000001082d35022d62b561f20857cd3f4488154533004097f877daa978e7288e4c009e76c37c845d9cd8a90084005c016f05ba1f31bea46e6601144197a600caf3cf724a89d7bb3b813d3ba3c7e1706f2f9c52e0dfe6d4e45dc5077be1ff1267328fff9914bad937d5e7cfbde05499859102c7327a9719b3a0665b09418a06fd0affc83d2067c8cf518147295a7ed7f82ab9d8d32661310884a965be4a266268f57181f93a5fd47196425afe47b462ef00000001082d35022d62b561f20857cd3f448815453343e6e3005e6f595e40acf7169ff6f6f4d1653ca22268575d93e703773973aa59b9c9af58bfb3c6517f7e3ca6581121f6d2e621409b81639a92a2673f0b0a85f92c75ddd91b8b1935635a0e9b55cc6a6c96f4be9ed5a0e48afbebd0afb7389f90db7714eaba1051aeaa95ea1b3dea844c9282c0eb29fe03cec760b53009596704d9f174606891850362aef5484a914d048fb5260132d9d693c553584235d88aeb8f79e17c7be81f400d5bf82597be5041cd8a578d5565c9e9ade954ef66382b565e03a16705d8c1c871f5209784d4778f1d385bf35314b1411037eba4d146eaa61562683beda0ee6f11d1751bc2ac7ce03ab6358e44ba76592d820ca69c1ca9f32fc6af26701fafc0f004d88a0c2454d311f2b956e876f658cb528720f3d9bc957f21dc82f4d69f9ec0de1e34a329466e727ec23b5c6006d1632fc79176bb4f2a2d225d5a8a778a02687dd1d0cec0805723df26e0884e14890c7bbcb86e035dbb6a90f102a7f6e32e8181bbee2f31fafc33787255ae7dcb6e35e1ecadc209261c279a4aa2efc1478d3638744ee807b678e71faae07344c1cf67facd6745e0c7b1d3e0982558bfb7238b18946589a9cf7e7eb194bee004c1528c1c22b473361caf6849d35c3c2a7a952cdc024ab55db0c087a67ea4350c1b79c3b114b50f83e56750a15b89d052aef9994ed671689ea1f7dc9261905fb1d1f3527fb723b30a9f3a4cffb51fb363f34de765571392c077c8b8f251d7a000b51eae4bf1d0fa6a247fe7eb7ee43faeeb45416c1c1d83e2d8ef57b2350d12cee10621c2c75b71fe928fbb3d192132f7eeced8f1c7c6e675bd59739b71eb4dd11a464d7ad0885b8cf78422fa496d4890657df68eee8eb7a804c59e55924490a527432138bd60e56bb54d995d31d1439d47b654d303a760f2eb8586c9521ccc1615311b345798074bca3047058b41835d61cd293bcd718ee2ee3820c185676227a8d1a8c51f6ffd25eb7dab2188071de21165bd06ff87f132ecf5e89bee15e4dae849cd468dad2198bb606d72d9a60d78edb120e2f889ae134d6dfe2d8129503a99196d4516b2f22220590d1d2aba826ddc90f88b28bda0054c1823741447f54b21addafa0603aa32f2409bc28b4f0e4271ba966f44f00e982a8b855188952df3ac48c7b5e633eaa6ecf725e494aaf1c2d219a75de6994d046aaef346250d8f9ddc2fd3fcfe8a3322a3c64df87b4ceb5753129b4238cc5847b06d1bc2facef18d4158fb57dcc88b1a5ddd78ba6de2951c1e2e5094b67a7617af3178074117285de6d3d1ceea57a020beb3ca9f2985246135d4178b9e034f341ee1fc7f2e58fa5c3dcf0fa00e25f8c4313f86021c3fdbaa83f26aac8f311cdba3ec5f5415a2aa30cb047f24f424ecac360251c6290c828af2db"

# crypto_context_decode = CryptoPair()
# crypto_context_decode.setup_initial(string_to_ascii("2d35022d62b561f2"),False,1)
# plain_header, payload, packet_number = crypto_context_decode.decrypt_packet(string_to_ascii(tes1),26,0)