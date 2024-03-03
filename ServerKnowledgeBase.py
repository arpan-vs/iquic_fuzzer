import os
import os.path
import sys
import time
import logging

from pylstar.LSTAR import LSTAR
from pylstar.ActiveKnowledgeBase import ActiveKnowledgeBase
from pylstar.Letter import Letter, EmptyLetter
from pylstar.Word import Word
from pylstar.eqtests.RandomWalkMethod import RandomWalkMethod
from pylstar.eqtests.WpMethodEQ import WpMethodEQ

from mapper import *

from utils.PacketNumberInstance import PacketNumberInstance
from utils.SessionInstance import SessionInstance


class QUICServerKnowledgeBase(ActiveKnowledgeBase):
    def __init__(self, server_name, server, timeout=5):
        super(QUICServerKnowledgeBase, self).__init__()
        self._i = 1
        self.timeout = timeout
        self.server_name = server_name
        self.server = server

    def start(self):
        pass

    def stop(self):
        pass

    def start_target(self):
        pass

    def stop_target(self):
        pass

    def submit_word(self, word):

        # if self.server==1:
        #     from socket_gquic_43 import Scapy
        # else:
        #     from socket_gquic_43_litespeed import Scapy
        from scapy_iquic_client import QUIC

        # self._logger.debug("Submiting word '{}' to the network target".format(word))

        output_letters = []

        print("-"*100)
        print("query : ",self._i)
        print("-"*100)
        # s = socket.socket()

        # if self.server==1:
        #     s = Scapy("localhost")
        # else:
        #     s = Scapy(self.server_name)

        s = QUIC("localhost")

        # # Reuse the connection
        # s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # s.settimeout(self.timeout)
        # s.connect((self.target_host, self.target_port))
        
        try:
            output_letters = [self._submit_letter(s, letter) for letter in word.letters]
            print("\nInput:- ",word.letters,"\nOutput:- ", output_letters)
        except:
            pass
        finally:
            # s.send(CloseConnectionEvent())
            del s
            # time.sleep(2)
            self._i+=1
            PacketNumberInstance.get_instance().reset()
            SessionInstance.reset()

        return Word(letters=output_letters)

    def _submit_letter(self, s, letter):
        output_letter = EmptyLetter()
        try:
            to_send = ''.join([symbol for symbol in letter.symbols])
            processed = QuicInputMapper(to_send, s)
            # time.sleep(0.2)
            # print(processed)
            output = QuicOutputMapper(processed)
            # print([to_send+ "/"+output])
            output_letter = Letter(output)
        except Exception as e:
            print("error")
            # self._logger.error(e)

        return output_letter
