from scapy_iquic_client import QUIC


s = QUIC()
s.initial_chlo(True)
s.send_ACK(True)
s.send_finish(True)
s.send_ACK_applictiondata(True)
s.send_ACK_applictionhadear(True)
s.send_ACK_ack_5(True)
# s.connection_close(True)