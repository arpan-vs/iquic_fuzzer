import os
import os.path
import sys
import time
import logging

from pylstar.LSTAR import LSTAR
from pylstar.ActiveKnowledgeBase import ActiveKnowledgeBase
from pylstar.Letter import Letter
from pylstar.Word import Word
from pylstar.eqtests.RandomWalkMethod import RandomWalkMethod
from pylstar.eqtests.WpMethodEQ import WpMethodEQ



from ServerKnowledgeBase import QUICServerKnowledgeBase



def main():
    server = 0
    
    if len(sys.argv) ==1 or len(sys.argv) == 2:
        print("""Incorrect Command!!!\n\nsudo python3 learn_server.py [servername] [dotfilename].dot""")
        exit(0)
    if sys.argv[1] == "localhost":
        server = 1
    # elif: sys.argv[1] == "www.litespeedtech.com":
    else:
        server = 0
        # print("Enter correct Active Server!!!\nExample: localhost or www.litespeedtech.com")
        # exit(0)

    filename = sys.argv[2]
    if os.path.exists(filename):
        print("Enter different dotfile name. "+ filename+" aleady exist!!!")
        exit(0)


    input_vocabulary = [
        "Clinet_Hello",
        "Clinet_FIN",
        "GET",
        "CLOSE",
    ]


    quicServerBase = QUICServerKnowledgeBase(sys.argv[1], server)
    
    try:
        eqTests = RandomWalkMethod(quicServerBase, input_vocabulary, 1000, 0.75)
        lstar = LSTAR(input_vocabulary, quicServerBase, max_states = 10, eqtests = eqTests)
        starttime = time.time()
        quicServer_state_machine = lstar.learn()
        endtime = time.time()
    except:
        print("Some Error Occured")
        exit()
        
    dot_code = quicServer_state_machine.build_dot_code()

    output_file = filename

    print(dot_code)
    with open(output_file, "w") as fd:
        fd.write(dot_code)
        fd.write("\n\n\n")
        fd.write("==> QUIC machine Automata dumped in {}".format(output_file))
        fd.write("\n\nKnowledge base stats: {}".format(quicServerBase.stats))
        fd.write("==> Taken Time:" +  str(endtime - starttime))

    print("==> QUIC machine Automata dumped in {}".format(output_file))
    print("Knowledge base stats: {}".format(quicServerBase.stats))
    print("==> Taken Time:", str(endtime - starttime))


if __name__ == "__main__":
    main()
