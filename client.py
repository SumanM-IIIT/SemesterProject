import time
from random import randint
import sys
import socket
import threading

class Server:
    connections = []
    peers = []

    def __init__(self, ip, port):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((ip, port))
        sock.listen(2)

        print("Server <" + ip + ":" + str(port) + "> Running...")
        while True:
            conn, addr = sock.accept()
            connThread = threading.Thread(target = self.handler, args = (conn, addr))
            connThread.daemon = True
            connThread.start()
            print("Faltu")
            self.connections.append(conn)
            self.peers.append(addr[0])
            print(str(addr[0]) + ":" + str(addr[1]), "Connected !!")
            self.sendPeersInfo()

    def handler(self, conn, addr):
        while True:
            data = conn.recv(1024)
            for connections in self.connections:
                connections.send(data)
            if not data:
                print(str(addr[0]) + ":" + str(addr[1]), "Disonnected :(")
                self.connections.remove(conn)
                self.peers.remove(addr[0])
                conn.close()
                self.sendPeersInfo()
                break

    def sendPeersInfo(self):
        pStr = ""
        for peer in self.peers:
            pStr += peer + ","

        for c in self.connections:
            c.send(b'\x11' + bytes(p, "utf-8"))

class Client:
    def __init__(self, ip, port):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.connect((ip, port))

        c2Thread = threading.Thread(target = self.sendMsg, args = (sock,))
        c2Thread.daemon = True
        c2Thread.start()

        print("Client <" + ip + ":" + str(port) + "> Running...")
        while True:
            data = sock.recv(1024)
            if not data:
                break
            if data[0:1] == b'\x11':
                print("Got Peers List :)")
                self.updatePeersList(data[1:])
            else:
                print(str(data, "utf-8"))

    def sendMsg(self, sock):
        while True:
            sock.send(bytes(input("->"), "utf-8"))

    def updatePeersList(self, peersData):
        p2p.peers = str(peersData, "utf-8").split(",")[:-1]

class p2p:
    peers = []

def main():
    if (len(sys.argv) > 1):
        #client = Client(sys.argv[2], sys.argv[3])
        peer_full = sys.argv[1] + ":" + sys.argv[2]
        p2p.peers.append(peer_full)
        while True:
            try:
                print("Connecting...")
                time.sleep(randint(1, 5))
                for i in range(len(p2p.peers)):
                    try:
                        ip_port = p2p.peers[i].split(":")
                        client = Client(ip_port[0], int(ip_port[1]))
                    #except KeyboardInterrupt:
                    #    sys.exit(0)
                    except:
                        print("CONNECTION REFUSED")
                    try:
                        ip_port = p2p.peers[i].split(":")
                        server = Server(ip_port[0], int(ip_port[1]))
                    except KeyboardInterrupt:
                        sys.exit(0)
                    except:
                        print("Couldn't start the server !!")

            except KeyboardInterrupt:
                sys.exit(0)
    else:
        print("Too Few Arguments !!")

if __name__=="__main__":
    main()

### REFERENCES:
# 1. https://www.youtube.com/watch?v=Rvfs6Xx3Kww - "P2P Chat App in Python" by "howCode" - Jun 24, 2017