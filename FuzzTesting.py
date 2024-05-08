import random
import socket
import threading
import time
from pylstar.automata.DOTParser import DOTParser
from pylstar.Letter import Letter, EmptyLetter
from pylstar.Word import Word
from scapy.all import sniff, wrpcap

from scapy_iquic_client import QUIC
from mapper import QuicInputMapper, QuicOutputMapper
from utils.SessionInstance import SessionInstance
from utils.PacketNumberInstance import PacketNumberInstance

# packets = []
# ask = 0
# def pkt_callback(packet):
    # global ask
    # print(ask)

    # wrpcap('pcap/captured_traffic'+str(ask)+'.pcap', packet, append=True)
    # packets.append(packet.summary()) # save the packet

# monitor function
# stop = False
# def stop_sniff(x):
#     global stop
#     return stop
    
# def monitor(e):
    
#     bpf_filter = "port 443"      # set this filter to capture the traffic you want
#     sniff(prn=pkt_callback, filter=bpf_filter, iface='lo', stop_filter=e.is_set(), store=True)
    # print(capture.summary())
    # wrpcap('pcap/captured_traffic'+str(ask)+'.pcap', capture, append=True)

class FuzzTesting:

    def __init__(self, dotfilename) -> None:
        file = open(dotfilename)
        dot_content = file.read() 
        self.mealyAutomata = DOTParser().parse(dot_content)
        self.initialState = self.mealyAutomata.initial_state
        # self.FuzzingMapper = FuzzingMapper
        self.client = ""
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.UDP_IP = "127.0.0.1"
        self.UDP_PORT = 443

    def randomWalkWithFuzzing(self, numWalks, walkLength):
        for i in range(numWalks):
            currentState = self.initialState
            inputs = []
            Model_outputs = []


            # PacketNumberInstance.get_instance().reset()
            # SessionInstance.reset()
            self.socket.sendto(b"test case "+ str(i).encode(), (self.UDP_IP, self.UDP_PORT))
            print(b"test case "+ str(i).encode())
            # time.sleep(.5)
            self.client = QUIC("localhost")
            
            for j in range(walkLength):
                input = self.randomStep(currentState)
                # print(input)
                inputs.append(input)
                output_letter, output_state =  currentState.visit(input)
                # print(outputTransition)
                currentState = output_state
                Model_outputs.append(output_letter)
            # print(inputs, Model_outputs)
            # print()

            SUT_outputs = []
            stopFlag = False
            currentState = self.initialState

            # e = threading.Event()
            # global ask
            # ask = i
            # e = threading.Event()
            # mon = threading.Thread(target=monitor, args=(e,))
            # mon.start()
            for j in range(walkLength):
                output_letter, output_state =  currentState.visit(inputs[j])
                currentState = output_state

                try:
                    to_send = ''.join([symbol for symbol in inputs[j].symbols])
                    processed = QuicInputMapper(to_send, self.client)
                    # print(processed)
                    output = QuicOutputMapper(processed)
                    # print([to_send+ "/"+output])
                    output_letter = Letter(output)
                except Exception as e:
                    self._logger.error(e)
            
                SUT_outputs.append(output_letter)

                if Model_outputs[:j+1] != SUT_outputs:
                    stopFlag = True
                    if  not((Model_outputs[j] == Letter('EXP') or Model_outputs[j] == Letter('REJ')) and (SUT_outputs[j] == Letter('EXP') or SUT_outputs[j] == Letter('REJ') or SUT_outputs[j] == Letter('CLOSED'))):
                        print("input : ",inputs[:j+1])
                        print("Mod output : ", Model_outputs[:j+1])
                        print("SUT output : ", SUT_outputs)
                        print("bug Found")
                        print("!!\n")
                        print()

                if stopFlag:
                    break
            # print("input : ",inputs[:j+1])
            # print("Mod output : ", Model_outputs[:j+1])
            # print("SUT output : ", SUT_outputs)
            print()
            PacketNumberInstance.get_instance().reset()
            SessionInstance.reset()
            # self.client.reset()
            # global stop
            # stop = True
            # print(stop_sniff(None))
            # del mon
            # global e
            # e.set()
            # global packets
            # print("\n".join(packets))
            # e.set()
            # mon.join(0)
            # del e
            # del mon
            # packets = sniffer.stop()
            
            # wrpcap('captured_traffic.pcap', packets)

            # sniffer = sniff(filter="udp and port 443", store=0, iface='lo')
            # print(sniffer.summary())
        # return 0


    def randomStep(self, state):
        # transitions = state.transitions
        transitions = [ti.input_letter for ti in state.transitions]
        return random.choice(transitions)
    

# FuzzTesting('dot/localhost_43_invalid_0RTT.dot').randomWalkWithFuzzing(100,10)
starttime = time.time()
FuzzTesting('localhost_QUIC.dot').randomWalkWithFuzzing(100,10)
endtime = time.time()

print("\n\n\n==> Taken Time:" +  str(endtime - starttime))