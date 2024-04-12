
from events import *
from events.Events import *
# s = Scapy()


def QuicInputMapper(alphabet, s):
    match alphabet:
        case "Clinet_Hello":
            x = s.send(SendInitialCHLOEvent())
        case "GET":
            x = s.send(SendGETRequestEvent())
        case "CLOSE":
            x = s.send(CloseConnectionEvent())
        case "Clinet_FIN":
            x = s.send(SendFINEvent())
        case default:
            pass
    return x


def QuicOutputMapper(data):
    output = ""
    if data == b"Sever_HelloHandshakeappliction_data":
        output = "Sever_Hello, Handshake, Appliction_data"
    elif data == b"push_promiseApplication_headerHTML" :
        output = "push_promise, Application_header, HTTP3 "
    elif data == b"ERROR":
        output = "ERROR"
    elif data == b"closed":
        output = "CLOSED"
    elif data == b"html":
        output = "HTTP"
    elif data == b"HTML":
        output = "HTTP"
    elif data == b"EXP":
        output = "EXP"
    elif data == b'HD':
        output = "handshakedone"
    else:
        output = "ERROR"
    return output