
import QUICHeader
import socket
from utils.string_to_ascii import string_to_ascii
from utils.packet_to_hex import extract_from_packet, extract_from_packet_as_bytestring
import random
from events.Events import SendInitialCHLOEvent, SendGETRequestEvent, CloseConnectionEvent, SendFullCHLOEvent, ZeroRTTCHLOEvent, ResetEvent
from utils.SessionInstance import SessionInstance
from Crypto.Cipher import AES
from aioquic.quic.crypto import hkdf_extract,hkdf_expand_label,cipher_suite_hash , CipherSuite, AEAD, CryptoError, HeaderProtection ,CryptoContext
from utils.dhke import dhke

DPORT = 4433
class QUIC : 
    def __init__(self) -> None:

        destination_id = random.getrandbits(64)
        SessionInstance.get_instance().initial_destination_connection_id = str(format(destination_id, 'x').zfill(16))

        source_id = random.getrandbits(64)
        SessionInstance.get_instance().initial_source_connection_id = str(format(source_id, 'x').zfill(16))

        self.UDPClientSocket = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
        self.UDPClientSocket.settimeout(0.1)

    def send_chlo(self, only_reset):
        chlo = QUICHeader.QUICHeader()

        chlo.setfieldval("DCID",  string_to_ascii(SessionInstance.get_instance().initial_destination_connection_id))
        chlo.setfieldval("SCID",  string_to_ascii(SessionInstance.get_instance().initial_source_connection_id))

        

        header = bytes.fromhex(extract_from_packet_as_bytestring(chlo)) 
        cryptoFrame = QUICHeader.CryptoFrame() 
        tlsObjct = extract_from_packet_as_bytestring(QUICHeader.TLSObject())
        padding = "00" * (775)
        crypto_frame = extract_from_packet_as_bytestring(cryptoFrame)

        initial_frame = bytes.fromhex(crypto_frame + tlsObjct + padding)


        client_initial_secret = dhke.client_initial_secret()

        crypto_context = CryptoContext()
        crypto_context.setup(cipher_suite = 0x1301 , secret = client_initial_secret,version = 1)
        data = crypto_context.encrypt_packet(header,initial_frame,0)
        print(len(data))
        self.UDPClientSocket.sendto(data, ("127.0.0.2", DPORT))
    

       

s = QUIC()
data = s.send_chlo(True)
print(data)
