from enum import Enum


class SessionInstance:
    __instance = None
    connection_id = -1
    initial_source_connection_id = "" 
    initial_destination_connection_id = ""
    server_config_id = ""
    source_address_token = ""
    public_value = None # object
    public_values_bytes = ""
    private_value = None
    client_initial_destination_connection_id = ""
    shared_key = b''
    chlo = ""
    shlo = ""
    tlschlo= b''
    tlsshalo= b''
    crypto_extensions = b''
    crypto_cert = b''
    crypto_certverify =b''
    crypto_finished =b''
    server_handshake_secret = b''
    client_handshake_secret = b''
    client_handshake_traffic_secret= b''
    server_handshake_traffic_secret= b''
    client_appliction_traffic_secret= b''
    server_appliction_traffic_secret= b''
    handshake_done = False
    randome_value = b''

    scfg = ""
    cert_chain = ""
    cert_localhost = ""

    initial_keys = {}
    final_keys = {}
    peer_public_value_initial = ""
    peer_public_value_final = ""
    div_nonce = ""
    message_authentication_hash = ""
    associated_data = ""
    packet_number = ""
    largest_observed_packet_number = -1
    shlo_received = False
    nr_ack_send = 0
    connection_id_as_number = -1
    destination_ip = "127.0.0.1"  # Home connectiopns
    # destination_ip = "192.168.43.228"   # hotspot connections
    zero_rtt = False
    last_received_rej = ""  # We are only interested in the last REJ for the initial keys.
    last_received_shlo = ""
    app_keys = {'type': None, 'mah': "", 'key': {}}
    first_packet_of_new_command = False
    currently_sending_zero_rtt = False  # If it is set to True, then we do not need to store the REJ otherwise it will not work.

    @staticmethod
    def get_instance():
        if SessionInstance.__instance is None:
            return SessionInstance()
        else:
            return SessionInstance.__instance

    def __init__(self):
        if SessionInstance.__instance is not None:
            raise Exception("Singleton bla")
        else:
            self.server_config_id = "-1"
            self.source_address_token = "-1"
            SessionInstance.__instance = self

    @staticmethod
    def reset():  
        SessionInstance.__instance = None      

