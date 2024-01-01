
import os
import struct

from cryptography.hazmat.primitives import hashes
from utils.string_to_ascii import string_to_ascii
from utils.SessionInstance import SessionInstance
from typing import Callable, Optional, Tuple
from aioquic.quic.crypto import hkdf_extract,hkdf_expand_label,cipher_suite_hash , CipherSuite, AEAD, CryptoError, HeaderProtection
import binascii

INITIAL_CIPHER_SUITE = CipherSuite.AES_128_GCM_SHA256
INITIAL_SALT_DRAFT_29 = binascii.unhexlify("afbfec289993d24c9e9786f19c6111e04390a899")
INITIAL_SALT_VERSION_1 = binascii.unhexlify("38762cf7f55934b34d179ae6a4c80cadccbb7f0a")


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
            algorithm = hashes.SHA3_256(),
            secret = secret_all.initial_secret(string_to_ascii(SessionInstance.get_instance().initial_destination_connection_id)),
            label=b"server in",
            hash_value=b"",
            length = 32,
            )
        return server_initial_secret 
    
    def nth_secret(Secret) :
        nth_secret = hkdf_expand_label(
            algorithm = hashes.SHA256(),
            secret = Secret,
            label=b"quic ku",
            hash_value=b"",
            length = 32,
            )
        return nth_secret 