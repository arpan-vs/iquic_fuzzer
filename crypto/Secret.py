
import os
import struct

from cryptography.hazmat.primitives import hashes

from utils.string_to_ascii import string_to_ascii
from utils.SessionInstance import SessionInstance
from typing import Callable, Optional, Tuple
from aioquic.quic.crypto import hkdf_extract,hkdf_expand_label,cipher_suite_hash , CipherSuite
from donna25519 import PrivateKey, PublicKey
from cryptography.hazmat.primitives import hashes, hmac, serialization
import binascii

INITIAL_CIPHER_SUITE = CipherSuite.AES_128_GCM_SHA256
INITIAL_SALT_DRAFT_29 = binascii.unhexlify("afbfec289993d24c9e9786f19c6111e04390a899")
INITIAL_SALT_VERSION_1 = binascii.unhexlify("38762cf7f55934b34d179ae6a4c80cadccbb7f0a")
import hashlib

class secret_all:

    # initial_secret = HKDF-Extract(initial_salt, cid)        
    @staticmethod
    def initial_secret(DCID = "6bafa3cda6256d3c"):
        initial_salt = INITIAL_SALT_VERSION_1  #initial salt is fix (Ref:- RFC 9001 => 5.2)
        initial_secret = hkdf_extract(
                algorithm = hashes.SHA256(),
                salt = initial_salt,
                key_material = DCID)
        return initial_secret


    # client_initial_secret  = HKDF-Expand-Label(initial_secret, "client in", "", 32)
    @staticmethod
    def client_initial_secret() :
        client_initial_secret = hkdf_expand_label(
            algorithm = hashes.SHA256(),
            secret = secret_all.initial_secret(string_to_ascii(SessionInstance.get_instance().initial_destination_connection_id)),
            label=b"client in",
            hash_value=b"",
            length = 32,
            )
        return client_initial_secret
    
    # server_initial_secret  = HKDF-Expand-Label(initial_secret, "server in", "", 32)
    def server_initial_secret() :
        server_initial_secret = hkdf_expand_label(
            algorithm = hashes.SHA256(),
            secret = secret_all.initial_secret(string_to_ascii(SessionInstance.get_instance().initial_destination_connection_id)),
            label=b"server in",
            hash_value=b"",
            length = 32,
            )
        return server_initial_secret 
    
    def ap_secret(cipher_suite: CipherSuite, handshake_secret ) :

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

        # print("handshake_hash" , bytes.hex(handshake_hash))
        print(len(key_material))

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
            key_material = key_material)
    
       
        server_ap_secret = hkdf_expand_label(
            algorithm = algorithm,
            secret= master_secret, 
            label=  b"s ap traffic",  
            hash_value= bytes.fromhex("75d42b78281057895817feb3416195d3bc8d67de0a6ed3ad76b01782ef399f5baea95cad0a44e0ebca65a9d72868ecee"), 
            length = algorithm.digest_size)
        
        print("hand KEY ", bytes.hex(hkdf_expand_label(algorithm, server_ap_secret, b"quic key", b"", 16)))
        return server_ap_secret
    
    def nth_secret(cipher_suite: CipherSuite, shared_key) :

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
        
        print("handshake_hash" , bytes.hex(hello_hash))
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
       
        server_secret = hkdf_expand_label(
            algorithm = algorithm,
            secret= handshake_secret, 
            label=  b"s hs traffic",  
            hash_value= hello_hash, 
            length = algorithm.digest_size)
        print("hand KEY ", bytes.hex(hkdf_expand_label(algorithm, server_secret, b"quic key", b"", 16)))
        return server_secret
    
    