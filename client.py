from tkinter import *
#from ttk import *
#from tkinter import ttk
from tkinter.ttk import *
from tkinter.filedialog import askopenfile
import socket
import threading
import emoji
import time
import PySimpleGUI as sg
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto import Random
from Crypto.Random import get_random_bytes
from binascii import hexlify
import time


class ChatClient(Frame):
  
    def __init__(self, root):
        Frame.__init__(self, root)
        self.root = root
        self.initUI()
        self.serverSoc = None
        self.serverStatus = 0
        self.buffsize = 2048
        self.allClients = {}
        self.counter = 0
        self.separator = '<SEP>'
        self.emojiCodes = [':grinning_face:', ':grinning_face_with_big_eyes:', ':grinning_face_with_smiling_eyes:', ':beaming_face_with_smiling_eyes:', ':grinning_squinting_face:', ':grinning_face_with_sweat:', ':rolling_on_the_floor_laughing:', ':slightly_smiling_face:', ':upside-down_face:', ':winking_face:', ':smiling_face_with_smiling_eyes:', ':smiling_face_with_halo:', ':smiling_face_with_heart-eyes:', ':star-struck:', ':face_blowing_a_kiss:', ':expressionless_face:', ':smiling_face_with_tear:', ':face_savoring_food:', ':winking_face_with_tongue:', ':squinting_face_with_tongue:', ':money-mouth_face:', ':smiling_face_with_open_hands:', ':face_with_hand_over_mouth:', ':thinking_face:', ':zipper-mouth_face:', ':neutral_face:', ':face_without_mouth:', ':unamused_face:', ':sleepy_face:', ':drooling_face:', ':sleeping_face:', ':face_with_medical_mask:', ':face_with_thermometer:', ':nauseated_face:', ':face_vomiting:', ':face_with_head-bandage:', ':sneezing_face:', ':hot_face:', ':cold_face:', ':face_with_crossed-out_eyes:', ':partying_face:', ':smiling_face_with_sunglasses:', ':face_with_monocle:', ':worried_face:', ':face_with_open_mouth:', ':flushed_face:', ':loudly_crying_face:', ':crying_face:', ':face_screaming_in_fear:', ':confounded_face:', ':disappointed_face:', ':downcast_face_with_sweat:', ':face_with_steam_from_nose:', ':pouting_face:', ':face_with_symbols_on_mouth:', ':smiling_face_with_horns:', ':skull:', ':pile_of_poo:', ':ogre:', ':ghost:', ':alien:', ':robot:', ':grinning_cat:', ':bomb:']
        
        self.key128 = b'abcdefghijklmnop'
        self.symKey = get_random_bytes(16)
        #self.x = 6
        self.privateKey = RSA.generate(1024)
        self.publicKey = self.privateKey.publickey()
        
        self.privateKeyStr = self.privateKey.export_key().decode()
        self.publicKeyStr = self.publicKey.export_key().decode()
        
        self.peerPublicKeys = {}
 
  
    def initUI(self):
        self.root.title("SecureChat_P2P")
        ScreenSizeX = self.root.winfo_screenwidth()
        ScreenSizeY = self.root.winfo_screenheight()
        self.FrameSizeX  = 800
        self.FrameSizeY  = 600
        FramePosX   = (ScreenSizeX - self.FrameSizeX)/2
        FramePosY   = (ScreenSizeY - self.FrameSizeY)/2
        self.root.geometry("%sx%s+%s+%s" % (self.FrameSizeX,self.FrameSizeY,int(FramePosX),int(FramePosY)))
        self.root.resizable(width=False, height=False)
        
        padX = 10
        padY = 10
        parentFrame = Frame(self.root)
        parentFrame.grid(padx=padX, pady=padY, stick=E+W+N+S)
        
        ipGroup = Frame(parentFrame)
        serverLabel = Label(ipGroup, text="Your Details: ")
        self.nameVar = StringVar()
        self.nameVar.set("Suman")
        nameField = Entry(ipGroup, width=10, textvariable=self.nameVar)
        #serverIPLabel = Label(ipGroup, text="IP: ")
        self.serverIPVar = StringVar()
        self.serverIPVar.set("127.0.0.1")
        serverIPField = Entry(ipGroup, width=15, textvariable=self.serverIPVar)
        #serverPortLabel = Label(ipGroup, text="Port: ")
        self.serverPortVar = StringVar()
        self.serverPortVar.set("8000")
        serverPortField = Entry(ipGroup, width=5, textvariable=self.serverPortVar)
        serverSetButton = Button(ipGroup, text="Set", width=10, command=self.handleSetServer)
        addClientLabel = Label(ipGroup, text="Friend's Address: ")
        self.clientIPVar = StringVar()
        self.clientIPVar.set("127.0.0.1")
        clientIPField = Entry(ipGroup, width=15, textvariable=self.clientIPVar)
        #friendPortLabel = Label(ipGroup, text="Port: ")
        self.clientPortVar = StringVar()
        self.clientPortVar.set("8002")
        clientPortField = Entry(ipGroup, width=5, textvariable=self.clientPortVar)
        clientSetButton = Button(ipGroup, text="Add", width=10, command=self.handleAddClient)
        serverLabel.grid(row=0, column=0)
        nameField.grid(row=0, column=1)
        serverIPField.grid(row=0, column=2)
        serverPortField.grid(row=0, column=3)
        serverSetButton.grid(row=0, column=4, padx=5)
        addClientLabel.grid(row=0, column=5)
        clientIPField.grid(row=0, column=6)
        clientPortField.grid(row=0, column=7)
        clientSetButton.grid(row=0, column=8, padx=5)
        
        readChatGroup = Frame(parentFrame)
        self.receivedChats = Text(readChatGroup, bg="white", width=60, height=30, state=DISABLED)
        
        self.friends = Listbox(readChatGroup, bg="white", width=30, height=30)
        self.receivedChats.grid(row=0, column=0, sticky=W+N+S, padx = (0,10))
        self.friends.grid(row=0, column=1, sticky=E+N+S)

        writeChatGroup = Frame(parentFrame)
        self.chatVar = StringVar()
        self.chatField = Entry(writeChatGroup, width=80, textvariable=self.chatVar)
        sendChatButton = Button(writeChatGroup, text="Send", width=10, command=self.handleSendChat)
        sendFileButton = Button(writeChatGroup, text="Attach", width=10, command=self.handleAttachChat)
        sendEmojiButton = Button(writeChatGroup, text="Emoji", width=10, command=self.handleEmoji)
        self.chatField.grid(row=0, column=0, sticky=W)
        sendChatButton.grid(row=0, column=1, padx=2)
        sendFileButton.grid(row=0, column=3, padx=2)
        sendEmojiButton.grid(row=0, column=2, padx=2)

        self.statusLabel = Label(parentFrame)

        bottomLabel = Label(parentFrame, text="Made by Aditya Mahajan, Suman Mitra & Akshay Chaudhary under Prof. K. Srinathan, IIIT Hyd")
        
        ipGroup.grid(row=0, column=0)
        readChatGroup.grid(row=1, column=0)
        writeChatGroup.grid(row=2, column=0, pady=10)
        self.statusLabel.grid(row=3, column=0)
        bottomLabel.grid(row=4, column=0, pady=10)
  
    def padding(self, text):
        while len(text) % 16 != 0:
            text += ' ' 
        return text
    
    def handleEmoji(self):
        emojiWindow = Toplevel()
        emojiWindow.title("Emoji Window")
        emojiWindow.geometry("")
        
        
        emojiCount = len(self.emojiCodes)
        emojiButtons = []
        k = 0
        rowCount = 0
        global clickEmojiBtn 
        clickEmojiBtn = []
    
        for i in range(emojiCount):
            clickEmojiBtn.append(PhotoImage(file='emojis/' + str(i + 1) + '.png'))
            emojiButtons.append(Button(emojiWindow, width=5, image = clickEmojiBtn[i], command=lambda k=i:self.handleEmojiPress(k)))
            emojiButtons[i].grid(row=rowCount, column=k+1, padx=2)
            k += 1
            if k >= 8:
                rowCount += 1
                k = 0
            #emojiButtons[i].pack()
  
    
    def handleEmojiPress(self, emojiNum):
        msg = self.chatVar.get()
        self.chatVar.set(emoji.emojize(msg + str(self.emojiCodes[emojiNum])))
 
  
    def handleSetServer(self):
        if self.serverSoc != None:
            self.serverSoc.close()
            self.serverSoc = None
            self.serverStatus = 0
        serveraddr = (self.serverIPVar.get().replace(' ',''), int(self.serverPortVar.get().replace(' ','')))
        try:
            self.serverSoc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            #print(1)
            self.serverSoc.bind(serveraddr)
            #print(2)
            self.serverSoc.listen(5)
            #print(3)
            self.setStatus("Server listening on %s:%s" % serveraddr)
            #print(4)
            #thread.start_new_thread(self.listenClients,())
            threading.Thread(target=self.listenClients).start()
            #print(5)
            self.serverStatus = 1
            #print(6)
            self.name = self.nameVar.get().replace(' ','')
            #print(7)
            if self.name == '':
                self.name = "%s:%s" % serveraddr
        except:
            self.setStatus("Error setting up server")
    
  
    def listenClients(self):
        while True:
            clientsoc, clientaddr = self.serverSoc.accept()
            self.setStatus("Client connected from %s:%s" % clientaddr)
            self.addClient(clientsoc, clientaddr)
            #thread.start_new_thread(self.handleClientMessages, (clientsoc, clientaddr))
            
            tmp = clientsoc.recv(self.buffsize).decode()
            self.peerPublicKeys[clientsoc] = tmp
            clientsoc.send(self.publicKeyStr.encode())
            
            threading.Thread(target=self.handleClientMessages, args=(clientsoc, clientaddr, 2)).start()
        self.serverSoc.close()
  
    def handleAddClient(self):
        if self.serverStatus == 0:
            self.setStatus("Set server address first")
            return
        clientaddr = (self.clientIPVar.get().replace(' ',''), int(self.clientPortVar.get().replace(' ','')))
        try:
            clientsoc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            clientsoc.connect(clientaddr)
            self.setStatus("Connected to client on %s:%s" % clientaddr)
            self.addClient(clientsoc, clientaddr)
            #thread.start_new_thread(self.handleClientMessages, (clientsoc, clientaddr))
            
            clientsoc.send(self.publicKeyStr.encode())
            tmp = clientsoc.recv(self.buffsize).decode()
            self.peerPublicKeys[clientsoc] = tmp
            
            threading.Thread(target=self.handleClientMessages, args=(clientsoc, clientaddr, 1)).start()
        except:
            self.setStatus("Error connecting to the client !!")
  
    def handleClientMessages(self, clientsoc, clientaddr, flag):
        while 1:
            try:
                recvSymKey = clientsoc.recv(self.buffsize)
                print('recvSymKey:', recvSymKey)
                decipherRsa = PKCS1_OAEP.new(self.privateKey)
                peerSymKey = decipherRsa.decrypt(recvSymKey)
                #peerSymKey = self.privateKey.decrypt(recvSymKey)
                print(peerSymKey)
                #print('client2 - 1st recv')
                #print(recvPubK)
                #clientsoc.send(b'ACK')
                #print('client2 - 1st send')
                time.sleep(0.3)                
                recvData = clientsoc.recv(self.buffsize)#.decode()
                #print('client2 - 2nd recv')
                iv = recvData[:AES.block_size]
                recvData = recvData[AES.block_size:]
                #print('received iv:', iv)
                
                decipher = AES.new(self.key128, AES.MODE_OFB, iv)
                data = decipher.decrypt(recvData)
                
                if not data:
                    break
                data = emoji.emojize(str(data)[2:-1])
                #print('Data:', data)
                actualData = data.split(self.separator)
                #print('Actual Data:', actualData)
                msgCon = ''
                for i in range(len(actualData) - 1):
                    msgCon += actualData[i] + ' '
                #self.addChat("%s:%s" % clientaddr, actualData[0])
                self.addChat(actualData[-1].strip(), msgCon)
            except:
                break
        self.removeClient(clientsoc, clientaddr)
        clientsoc.close()
        self.setStatus("Client disconnected from %s:%s" % clientaddr)
  
    def handleSendChat(self):
        if self.serverStatus == 0:
            self.setStatus("Set server address first")
            return
        msg = emoji.demojize(self.chatVar.get())
        if msg == '':
            return
                
        self.addChat("Me (" + self.nameVar.get() + ")", msg)
        msg = msg.replace(' ',self.separator)
        msg += self.separator + self.nameVar.get()
        
        paddedMsg = self.padding(msg) 
        iv = Random.new().read(AES.block_size)
        #print('sent iv:', iv)
        cipher = AES.new(self.key128, AES.MODE_OFB, iv)
        #print('padded msg: ', paddedMsg)
        msgCipher = cipher.encrypt(paddedMsg.encode())
        
        #X = int(pow(G, self.x, P))
        
        #print(paddedMsg)
        for client in self.allClients.keys():
            peerPubKey = RSA.import_key(self.peerPublicKeys[client])
            print('peerPubKey:', peerPubKey)
            cipherRsa = PKCS1_OAEP.new(peerPubKey)
            encr = cipherRsa.encrypt(self.key128)
            client.send(encr)
            #print('client1 - 1st send')
            #tmp = client.recv(self.buffsize).decode()
            #print('client1 - 1st recv')
            #print('sender ack:', tmp)
            time.sleep(0.3)
            client.send(iv + msgCipher) 
            #print('client1 - 2nd send')
            #print('sent iv:', iv)
        self.chatVar.set('')
        
        #key = b'abcdefghijklmnop'
        
        #print(type(msgCipher))
        #print(msgCipher)
        #print(bytes(paddedMsg, 'utf-8'))
        #print(str(msgCipher))
        #print(msgCipher.encode('hex'))
        #decipher = AES.new(self.key128, AES.MODE_ECB)
        #print(decipher.decrypt(msgCipher))
        
  
    def handleAttachChat(self):
        ws = Tk()
        ws.title('Attach File')
        ws.geometry('400x200') 

    
    def open_file():
        file_path = askopenfile(mode='r', filetypes=[('Files', '*')])
        if file_path is not None:
            pass

    def uploadFiles():
        file = Label(ws, text='Attach File')
        file.grid(row=0, column=0, padx=10) 

        filebtn = Button(
            ws, 
            text ='Choose File', 
            command = lambda:open_file()
            ) 
        filebtn.grid(row=0, column=1)

        pb1 = Progressbar(
            ws, 
            orient=HORIZONTAL, 
            length=300, 
            mode='determinate'
            )
        pb1.grid(row=4, columnspan=3, pady=20)
        for i in range(5):
            ws.update_idletasks()
            pb1['value'] += 20
            time.sleep(1)
        pb1.destroy()
        Label(ws, text='File Uploaded Successfully!', foreground='green').grid(row=4, columnspan=3, pady=10)

        upld = Button(
            ws, 
        text='Upload Files', 
        command=uploadFiles
        )
        upld.grid(row=3, columnspan=3, pady=10)
  
  
    def addChat(self, client, msg):
        msg = msg.strip()
        msgPrint = emoji.emojize(msg)
        self.receivedChats.config(state=NORMAL)
        self.receivedChats.insert("end",client+": "+msgPrint+"\n")
        self.receivedChats.config(state=DISABLED)
  
    def addClient(self, clientsoc, clientaddr):
        self.allClients[clientsoc]=self.counter
        self.counter += 1
        self.friends.insert(self.counter,"%s:%s" % clientaddr)
  
    def removeClient(self, clientsoc, clientaddr):
        print(self.allClients)
        self.friends.delete(self.allClients[clientsoc])
        del self.allClients[clientsoc]
        print(self.allClients)
  
    def setStatus(self, msg):
        self.statusLabel.config(text=msg)
        print(msg)
      

def main():  
    root = Tk()
    app = ChatClient(root)
    root.mainloop()  

if __name__ == '__main__':
    main()  
