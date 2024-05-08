
import os
import struct

from cryptography.hazmat.primitives import hashes

from utils.string_to_ascii import string_to_ascii
from utils.SessionInstance import SessionInstance
from utils.packet_to_hex import  extract_from_packet, extract_from_packet_as_bytestring, hex_to_binary,hex_to_decimal
from typing import Callable, Optional, Tuple
from aioquic.quic.crypto import hkdf_extract,hkdf_expand_label,cipher_suite_hash , CipherSuite
from cryptography.hazmat.primitives import hashes, hmac, serialization
import binascii

INITIAL_CIPHER_SUITE = CipherSuite.AES_128_GCM_SHA256
INITIAL_SALT_DRAFT_29 = binascii.unhexlify("afbfec289993d24c9e9786f19c6111e04390a899")
INITIAL_SALT_VERSION_1 = binascii.unhexlify("38762cf7f55934b34d179ae6a4c80cadccbb7f0a")
import hashlib

from cryptography.hazmat.primitives.asymmetric import (
    x25519,
)
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from aioquic.quic.crypto import CryptoContext,CryptoPair

class dhke:

    def set_up_my_keys() :
        #PUB and Privete key generate 
        _x25519_private_key = x25519.X25519PrivateKey.generate()
        SessionInstance.get_instance().public_values_bytes = _x25519_private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        SessionInstance.get_instance().private_value = _x25519_private_key
    
    def shared_key_computation(server_public_key : bytes ) :
        private_key = SessionInstance.get_instance()._x25519_private_key   # client private key 
        shared_key = private_key.exchange(x25519.X25519PublicKey.from_public_bytes(server_public_key)) 
        SessionInstance.get_instance().shared_key = shared_key 
        # print("SessionInstance.get_instance().shared_key",bytes.hex(SessionInstance.get_instance().shared_key))

    def handshake_traffic_computation() :
        SessionInstance.get_instance().server_handshake_traffic_secret =  dhke.handshake_secret(cipher_suite = 0x1302,shared_key = SessionInstance.get_instance().shared_key, lable = b"s hs traffic",isClient = False)
        # print("SessionInstance.get_instance().server_handshake_traffic_secret",bytes.hex(SessionInstance.get_instance().server_handshake_traffic_secret))
        SessionInstance.get_instance().client_handshake_traffic_secret =  dhke.handshake_secret(cipher_suite = 0x1302,shared_key = SessionInstance.get_instance().shared_key, lable = b"c hs traffic",isClient = True)
        # print("SessionInstance.get_instance().client_handshake_traffic_secret",bytes.hex(SessionInstance.get_instance().client_handshake_traffic_secret))

   
    def appliction_traffic_computation() :
        SessionInstance.get_instance().server_appliction_traffic_secret =  dhke.ap_secret(cipher_suite = 0x1302, handshake_secret = SessionInstance.get_instance().server_handshake_secret , label=  b"s ap traffic")
        # print("SessionInstance.get_instance().server_appliction_traffic_secret",bytes.hex(SessionInstance.get_instance().server_appliction_traffic_secret))
        SessionInstance.get_instance().client_appliction_traffic_secret =  dhke.ap_secret(cipher_suite = 0x1302, handshake_secret = SessionInstance.get_instance().client_handshake_secret , label=  b"c ap traffic")
        # print("SessionInstance.get_instance().client_appliction_traffic_secret",bytes.hex(SessionInstance.get_instance().client_appliction_traffic_secret))


    def ap_secret(cipher_suite: CipherSuite, handshake_secret , label) :

        algorithm = cipher_suite_hash(cipher_suite)
        binary_data = b''
        binary_data += SessionInstance.get_instance().tlschlo
        binary_data += SessionInstance.get_instance().tlsshalo
        binary_data += SessionInstance.get_instance().crypto_extensions
        binary_data += SessionInstance.get_instance().crypto_cert
        binary_data += SessionInstance.get_instance().crypto_certverify
        binary_data += SessionInstance.get_instance().crypto_finished
        
        hash_empty_value  = hashlib.sha256(b'').digest()
        handshake_hash = hashlib.sha384(binary_data).digest()
        key_material = bytes.fromhex("000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")
        
        if cipher_suite in [
        CipherSuite.AES_256_GCM_SHA384,
        ]:
            hash_empty_value  = hashlib.sha384(b'').digest()
            handshake_hash = hashlib.sha384(binary_data).digest()
            key_material = bytes.fromhex("000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")
        else:
            hash_empty_value  = hashlib.sha256(b'').digest()
            handshake_hash = hashlib.sha256(binary_data).digest()
            key_material = bytes.fromhex("0000000000000000000000000000000000000000000000000000000000000000")
        
        derived_secret = hkdf_expand_label(
            algorithm = algorithm,
            secret= handshake_secret,
            label= b"derived", 
            hash_value = hash_empty_value, 
            length = algorithm.digest_size,
            )

        master_secret = hkdf_extract( 
            algorithm = algorithm,
            salt= derived_secret, 
            key_material =key_material)
    
        server_ap_secret = hkdf_expand_label(
            algorithm = algorithm,
            secret= master_secret, 
            label= label,  
            hash_value= handshake_hash, 
            length = algorithm.digest_size)

        return server_ap_secret
    
    def handshake_secret(cipher_suite: CipherSuite, shared_key , lable , isClient) :

        algorithm = cipher_suite_hash(cipher_suite)
        binary_data = b''
        binary_data += SessionInstance.get_instance().tlschlo
        binary_data += SessionInstance.get_instance().tlsshalo
        hash_empty_value  = hashlib.sha256(b'').digest()
        hello_hash = hashlib.sha384(binary_data).digest()
        salt = bytes.fromhex("000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")
        key_material = bytes.fromhex("000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")

        
        if cipher_suite in [
        CipherSuite.AES_256_GCM_SHA384,
        ]:
            hash_empty_value  = hashlib.sha384(b'').digest()
            hello_hash = hashlib.sha384(binary_data).digest()
            salt = bytes.fromhex("000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")
            key_material = bytes.fromhex("000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")
        else:
            hash_empty_value  = hashlib.sha256(b'').digest()
            hello_hash = hashlib.sha256(binary_data).digest()
            salt = bytes.fromhex("0000000000000000000000000000000000000000000000000000000000000000")
            key_material = bytes.fromhex("0000000000000000000000000000000000000000000000000000000000000000")
        
        early_secret = hkdf_extract(
            algorithm = algorithm, 
            salt = salt, 
            key_material = key_material
        )

        derived_secret = hkdf_expand_label(
            algorithm = algorithm,
            secret= early_secret,
            label= b"derived", 
            hash_value = hash_empty_value, 
            length = algorithm.digest_size,
            )
    
        handshake_secret = hkdf_extract( 
            algorithm = algorithm,
            salt= derived_secret, 
            key_material = shared_key)
        
        if isClient  :
            SessionInstance.get_instance().client_handshake_secret = handshake_secret
        else :  SessionInstance.get_instance().server_handshake_secret = handshake_secret

        server_secret = hkdf_expand_label(
            algorithm = algorithm,
            secret= handshake_secret, 
            label=  lable,  
            hash_value= hello_hash, 
            length = algorithm.digest_size)
        return server_secret
    
    def finished_verify_data(cipher_suite: CipherSuite ,client_secret)  :
        algorithm = cipher_suite_hash(cipher_suite)
        
        finished_key = hkdf_expand_label(
            algorithm = algorithm,
            secret= client_secret,
            label=  b"finished",
            hash_value= b"",
            length = algorithm.digest_size
        )

        binary_data = b''
        binary_data += SessionInstance.get_instance().tlschlo
        binary_data += SessionInstance.get_instance().tlsshalo
        binary_data += SessionInstance.get_instance().crypto_extensions
        binary_data += SessionInstance.get_instance().crypto_cert
        binary_data += SessionInstance.get_instance().crypto_certverify
        binary_data += SessionInstance.get_instance().crypto_finished
        
        
        if cipher_suite in [
        CipherSuite.AES_256_GCM_SHA384,
        ]:
            finished_hash = hashlib.sha384(binary_data).digest()
        else : 
            finished_hash = hashlib.sha256(binary_data).digest()

        # print("finsh_hash" , bytes.hex(finished_hash))
        h = hmac.HMAC(finished_key, algorithm=algorithm)
        h.update(finished_hash)
        return h.finalize()
    
    def get_early_secret() :
        
        algorithm = cipher_suite_hash(0x1301) 
        salt = bytes.fromhex("0"*32)
        key_material = bytes.fromhex("0"*32)

        early_secret = hkdf_extract(
            algorithm = algorithm, 
            salt = salt, 
            key_material = key_material
        )
        return early_secret


class Crypto :

    def __init__(self) -> None:
        self.cryptopair = CryptoPair()  
        self.crypto_context = CryptoContext()
    
    def decrypt_initial_packet(self, packet: bytes)-> Tuple[bytes, bytes, int]:
        plain_header, payload, packet_number = self.cryptopair.decrypt_packet(packet,(len(packet)- hex_to_decimal(extract_from_packet_as_bytestring(packet[24:26])[1:])),0)
        return plain_header, payload, packet_number

    def encrypt_initial_packet(self, plain_header: bytes, plain_payload: bytes, packet_number: int)-> bytes:
        self.cryptopair.setup_initial(string_to_ascii(SessionInstance.get_instance().initial_destination_connection_id),True,1)
        payload = self.cryptopair.encrypt_packet(plain_header,plain_payload,packet_number)
        return payload
    
    def decrypt_handshake_packet(self, packet: bytes)-> Tuple[bytes, bytes, int]:
        self.crypto_context.setup(cipher_suite = 0x1302, secret = SessionInstance.get_instance().server_handshake_traffic_secret, version = 1)
        plain_header, payload, packet_number, crypto = self.crypto_context.decrypt_packet(packet,(len(packet)- hex_to_decimal(extract_from_packet_as_bytestring(packet[23:25])[1:])),0)
        return plain_header, payload, packet_number

    def encrypt_handshake_packet(self, plain_header: bytes, plain_payload: bytes)-> bytes:
        self.crypto_context.setup(cipher_suite = 0x1302,secret =  SessionInstance.get_instance().client_handshake_traffic_secret ,version = 1)
        payload = self.crypto_context.encrypt_packet(plain_header,plain_payload,hex_to_decimal(extract_from_packet_as_bytestring(plain_header)[-4:]))
        return payload
    
    def decrypt_application_packet(self, packet: bytes)-> Tuple[bytes, bytes, int]:
        self.crypto_context.setup(cipher_suite = 0x1302,secret =  SessionInstance.get_instance().server_appliction_traffic_secret  ,version = 1)
        plain_header, payload, packet_number, crypto = self.crypto_context.decrypt_packet(packet,9,0)
        return plain_header, payload, packet_number
    
    def encrypt_application_packet(self, plain_header: bytes, plain_payload: bytes)-> bytes:
        self.crypto_context.setup(cipher_suite = 0x1302,secret =  SessionInstance.get_instance().client_appliction_traffic_secret ,version = 1)
        payload = self.crypto_context.encrypt_packet(plain_header,plain_payload,hex_to_decimal(extract_from_packet_as_bytestring(plain_header)[-4:]))
        return payload

