
from utils.SessionInstance import SessionInstance
class KeyFile:

    def FileGenret(file_name = "keylog") :
        # print("run function")
        with open(file_name, 'a') as f:
            # Append more data to the file
            # print( bytes.hex(SessionInstance.get_instance().randome_value))
            # print("valid")
            s_h = "\nSERVER_HANDSHAKE_TRAFFIC_SECRET " + bytes.hex(SessionInstance.get_instance().randome_value) + " " + bytes.hex(SessionInstance.get_instance().server_handshake_traffic_secret)
            c_h = "\nCLIENT_HANDSHAKE_TRAFFIC_SECRET " + bytes.hex(SessionInstance.get_instance().randome_value) + " " + bytes.hex(SessionInstance.get_instance().client_handshake_traffic_secret)
            s_a = "\nSERVER_TRAFFIC_SECRET_0 " + bytes.hex(SessionInstance.get_instance().randome_value) + " " + bytes.hex(SessionInstance.get_instance().server_appliction_traffic_secret)
            c_a = "\nCLIENT_TRAFFIC_SECRET_0 " + bytes.hex(SessionInstance.get_instance().randome_value) + " " + bytes.hex(SessionInstance.get_instance().client_appliction_traffic_secret)
            f.write(s_h+c_h+s_a+c_a)