#!/usr/bin/python3
import ssl
import socket
import argparse
import json

FORMAT = "utf-8"
class Client:
    def __init__(self, port, tls, host, username):
        self.port = port
        self.tls = tls
        self.host = host
        self.username = username
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.LoW = self.loadWordList()
        self.connect()

    def loadWordList(self):
        with open('project1-words.txt') as f:
            data = f.readlines()
        LoW = []
        for line in data:
            if line[-1] == "\n":
                LoW.append(line[:-1])
            else:
                LoW.append(line)
        return LoW

    def hellomsg(self):
        msg = {"type": "hello", "northeastern_username": "ngo.kho"}
        message = json.dumps(msg) + '\n'
        return message

    def wrap_tls(self, socket):
        protocal = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
        return protocal.wrap_socket(socket)

    def get_id(self):
        result = self.s.recv(1024)
        result = json.loads(result)
        return result["id"]

    def connect(self):
        ip = self.host
        port = self.port
        tls = self.tls
        try:
            print(f"Connecting to {ip}:{port}")
            if (tls):
                self.s.connect((ip, port))
                self.s = self.wrap_tls(self.s)
                self.s.send(bytes(self.hellomsg(), FORMAT))
                self.guess(self.get_id())
            else:
                self.s.connect((ip, port))
                self.s.send(bytes(self.hellomsg(), FORMAT))
                self.guess(self.get_id())

        except socket.error as msg:
            self.s.close()

    def guess(self, idGiven):
        # Store characters in pairs 
        LoP = []
        # Store number of guesses
        cG = 0
        # Loop guesses max:500
        for word in self.LoW: 
            if cG > 500: 
                break
            # Boolean validWord 
            validWord = True
            # Initialize Array of Character from Word    
            LoC = list(word)
            # Loop checking with pairs if character and index is in the LoP 
            characterIndex = 0
            for C in LoC: 
                for pair in LoP: 
                    if C == pair[0] and characterIndex == pair[1]:
                        validWord = False
                        break 
                characterIndex += 1

            if validWord: 
                g = {"type": "guess", "id": idGiven, "word": word}
                str_g = json.dumps(g) + "\n"
                self.s.send(bytes(str_g,FORMAT))

                serverRes = ""

                while True: 
                    response = self.s.recv(4096).decode(FORMAT)
                    serverRes += response
                    if len(serverRes) > 0 and serverRes[-1] == "\n":
                        break
                
                data = json.loads(serverRes)
                if data["type"] == "retry":
                    LoL = list(word)
                    LoM = data["guesses"][cG]["marks"]
                    countIndex = -1
                    for letter in LoL:
                        countIndex += 1
                        if LoM[countIndex] == 0:
                            pair = (letter, countIndex)
                            LoP.append(pair)
                    cG += 1 

                if data["type"] == "bye":
                    print(data["flag"])
                    exit()

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("hostname", type=str)
    parser.add_argument("NortheasternUsername", type=str)
    parser.add_argument("-p", "-port", type=int, default=27993)
    parser.add_argument("-s", action="store_true", default=False)

    args = parser.parse_args()

    c = Client(args.p, args.s, args.hostname, args.NortheasternUsername)
main()
