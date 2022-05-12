from tkinter import *
#from ttk import *
#from tkinter import ttk
from tkinter.ttk import *
from tkinter.filedialog import askopenfile, askopenfilename
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
        self.byteSep = b'<SEP>'
        self.emojiCodes = [':grinning_face:', ':grinning_face_with_big_eyes:', ':grinning_face_with_smiling_eyes:', ':beaming_face_with_smiling_eyes:', ':grinning_squinting_face:', ':grinning_face_with_sweat:', ':rolling_on_the_floor_laughing:', ':slightly_smiling_face:', ':upside-down_face:', ':winking_face:', ':smiling_face_with_smiling_eyes:', ':smiling_face_with_halo:', ':smiling_face_with_heart-eyes:', ':star-struck:', ':face_blowing_a_kiss:', ':expressionless_face:', ':smiling_face_with_tear:', ':face_savoring_food:', ':winking_face_with_tongue:', ':squinting_face_with_tongue:', ':money-mouth_face:', ':smiling_face_with_open_hands:', ':face_with_hand_over_mouth:', ':thinking_face:', ':zipper-mouth_face:', ':neutral_face:', ':face_without_mouth:', ':unamused_face:', ':sleepy_face:', ':drooling_face:', ':sleeping_face:', ':face_with_medical_mask:', ':face_with_thermometer:', ':nauseated_face:', ':face_vomiting:', ':face_with_head-bandage:', ':sneezing_face:', ':hot_face:', ':cold_face:', ':face_with_crossed-out_eyes:', ':partying_face:', ':smiling_face_with_sunglasses:', ':face_with_monocle:', ':worried_face:', ':face_with_open_mouth:', ':flushed_face:', ':loudly_crying_face:', ':crying_face:', ':face_screaming_in_fear:', ':confounded_face:', ':disappointed_face:', ':downcast_face_with_sweat:', ':face_with_steam_from_nose:', ':pouting_face:', ':face_with_symbols_on_mouth:', ':smiling_face_with_horns:', ':skull:', ':pile_of_poo:', ':ogre:', ':ghost:', ':alien:', ':robot:', ':grinning_cat:', ':bomb:']
        
        self.symKey = get_random_bytes(16)
        
        self.privateKey = RSA.generate(1024)
        self.publicKey = self.privateKey.publickey()
        
        self.privateKeyStr = self.privateKey.export_key().decode()
        self.publicKeyStr = self.publicKey.export_key().decode()
        
        self.peerPublicKeys = {}
        self.peerSymKeys = {}
        self.allClientAddrs = []
 
  
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
        
        self.serverIPVar = StringVar()
        self.serverIPVar.set("127.0.0.1")
        serverIPField = Entry(ipGroup, width=15, textvariable=self.serverIPVar)
        
        self.serverPortVar = StringVar()
        self.serverPortVar.set("8000")
        serverPortField = Entry(ipGroup, width=5, textvariable=self.serverPortVar)
        serverSetButton = Button(ipGroup, text="Set", width=10, command=self.handleSetServer)
        addClientLabel = Label(ipGroup, text="Friend's Address: ")
        self.clientIPVar = StringVar()
        self.clientIPVar.set("127.0.0.1")
        clientIPField = Entry(ipGroup, width=15, textvariable=self.clientIPVar)
        
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
  
    
    def padFileChunk(self, fileChunk):
        while len(fileChunk) % 8 != 0:
            fileChunk.extend(b'9')
        return fileChunk
        
  
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
            self.serverSoc.bind(serveraddr)
            self.serverSoc.listen(5)
            self.setStatus("Server listening on %s:%s" % serveraddr)
            threading.Thread(target=self.listenClients).start()
            self.serverStatus = 1
            self.name = self.nameVar.get().replace(' ','')
            if self.name == '':
                self.name = "%s:%s" % serveraddr
        except:
            self.setStatus("Error setting up server")
    
  
    def listenClients(self):
        while True:
            try:
                clientsoc, clientaddr = self.serverSoc.accept()
                self.setStatus("Client connected from %s:%s" % clientaddr)
                #self.addClient(clientsoc, clientaddr)
                
                clientsoc.send(self.name.encode())
                tmp = clientsoc.recv(self.buffsize).decode()
                self.peerPublicKeys[clientsoc] = tmp
                clientsoc.send(self.publicKeyStr.encode())
                
                recvSymKey = clientsoc.recv(self.buffsize)
                decipherRsa = PKCS1_OAEP.new(self.privateKey)
                peerSymKey = decipherRsa.decrypt(recvSymKey)
                print('recvSymKey2:', peerSymKey)
                self.peerSymKeys[clientsoc] = peerSymKey
                
                peerPubKey = RSA.import_key(tmp)
                cipherRsa = PKCS1_OAEP.new(peerPubKey)
                encr = cipherRsa.encrypt(self.symKey)
                print('SentSymKey2:', self.symKey)
                clientsoc.send(encr)
                
                threading.Thread(target=self.handleClientMessages, args=(clientsoc, clientaddr, 2)).start()
            except KeyboardInterrupt:
                if self.serverSoc:
                    self.serverSoc.close()
                break
        #self.serverSoc.close()
  
    def handleAddClient(self):
        if self.serverStatus == 0:
            self.setStatus("Set server address first")
            return
        clientaddr = (self.clientIPVar.get().replace(' ',''), int(self.clientPortVar.get().replace(' ','')))
        if self.serverIPVar.get().replace(' ','') == self.clientIPVar.get().replace(' ','') and int(self.clientPortVar.get().replace(' ','')) == int(self.serverPortVar.get().replace(' ','')):
            self.setStatus("This is your own address !! Please type any of your friend's addresses...")
            return
        try:
            clientsoc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            clientsoc.connect(clientaddr)
            self.setStatus("Connected to client on %s:%s" % clientaddr)
            
            peerName = clientsoc.recv(self.buffsize).decode()
            self.addClient(clientsoc, clientaddr, peerName)
            self.allClientAddrs.append(clientaddr)
            
            clientsoc.send(self.publicKeyStr.encode())
            tmp = clientsoc.recv(self.buffsize).decode()
            self.peerPublicKeys[clientsoc] = tmp
            
            peerPubKey = RSA.import_key(tmp)
            cipherRsa = PKCS1_OAEP.new(peerPubKey)
            encr = cipherRsa.encrypt(self.symKey)
            print('SentSymKey:', self.symKey)
            clientsoc.send(encr)
            
            recvSymKey = clientsoc.recv(self.buffsize)
            decipherRsa = PKCS1_OAEP.new(self.privateKey)
            peerSymKey = decipherRsa.decrypt(recvSymKey)
            print('recvSymKey:', peerSymKey)
            self.peerSymKeys[clientsoc] = peerSymKey
            
            threading.Thread(target=self.handleClientMessages, args=(clientsoc, clientaddr, 1)).start()
        except:
            self.setStatus("Error connecting to the client !!")
  
  
    def handleClientMessages(self, clientsoc, clientaddr, flag):
        while 1:
            #try:
            recvData = clientsoc.recv(self.buffsize)
            splitData = recvData.split(self.byteSep)
            if splitData[0] == b'FILE':
                chunkCount = int(splitData[1].decode())
                iv = splitData[-1]
                clientName = splitData[-2]
                fileName = splitData[-3]
                print('recv chunkcount:', chunkCount)
                print('recv iv:', iv)
                print('recv fileName:', fileName)
                time.sleep(0.1)
                
                decipher = AES.new(self.peerSymKeys[clientsoc], AES.MODE_OFB, iv)
                #print(5)
                tmpC = 0
                with open(fileName, "wb") as f:
                    #print(6)
                    for i in range(0, chunkCount):
                        #print(7)
                        time.sleep(0.5)
                        chunk = clientsoc.recv(self.buffsize)
                        data = decipher.decrypt(chunk).strip(b'9')
                        f.write(chunk)
                        tmpC += 1
                        #print(8)
                        
                if tmpC > 0:
                    #self.setStatus(fileName.decode() + "received successfully !!")
                    self.addChat(clientName.decode(), 'FILE <' + fileName.decode() + '>')
                
            
            else:
                iv = recvData[:AES.block_size]
                recvData = recvData[AES.block_size:]
                
                decipher = AES.new(self.peerSymKeys[clientsoc], AES.MODE_OFB, iv)
                data = decipher.decrypt(recvData)
                
                if not data:
                    break
                data = emoji.emojize(str(data)[2:-1])
                actualData = data.split(self.separator)
                msgCon = ''
                for i in range(len(actualData) - 1):
                    msgCon += actualData[i] + ' '
                self.addChat(actualData[-1].strip(), msgCon)
            #except:
            #    break
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
        cipher = AES.new(self.symKey, AES.MODE_OFB, iv)
        msgCipher = cipher.encrypt(paddedMsg.encode())
        
        for client in self.allClients.keys():
            client.send(iv + msgCipher) 
        self.chatVar.set('')
        
  
    def handleAttachChat(self):
        ws = Tk()
        ws.title('Attach File')
        ws.geometry('400x200') 
        
        fileLabel = Label(
            ws, 
            text='Upload a file'
            )
        fileLabel.grid(row=0, column=0, padx=10)
        
        fileButton = Button(
            ws, 
            text ='Choose File', 
            command = lambda:self.openFile(ws, fileLabel, fileButton)
            ) 
        fileButton.grid(row=0, column=1)
        ws.mainloop()

    
    def openFile(self, ws, fileLabel, fileButton):
        #file_path = askopenfile(mode='r', filetypes=[('Files', '*')])
        fileName = askopenfilename(filetypes=[('Files', '*')])
        actFileName = fileName.split('/')[-1]
        
        if fileName is not None:
            if actFileName:
                fileLabel.destroy()
                fileButton.destroy()
                fileNameLabel = Label(ws, text = actFileName, foreground='black').grid(row=0, column=1, padx=10)
                
                closeButton = Button(
                    ws, 
                    text='Close', 
                    command = lambda:ws.destroy()
                    )
                closeButton.grid(row=0, column=4, padx=10)
                uploadButton = Button(
                    ws, 
                    text='Send File', 
                    command = lambda:self.uploadFiles(ws, fileName, actFileName)
                    )
                uploadButton.grid(row=0, column=3, padx=10)
            #ws.mainloop()
            

    def uploadFiles(self, ws, fileName, actFileName):
        fileChunkCount = 0
        with open(fileName, "rb") as f:
            while True:
                bytesRead = f.read(self.buffsize)
                if not bytesRead:
                    break
                fileChunkCount += 1
        tmpStr = 'FILE' + self.separator + str(fileChunkCount) + self.separator + actFileName + self.separator + self.nameVar.get()
        iv = Random.new().read(AES.block_size)
        
        tmpiv = tmpStr.encode() + self.byteSep + iv
        print('tmpiv:', tmpiv)
        for client in self.allClients.keys():
            client.send(tmpiv)
        
        
        cipher = AES.new(self.symKey, AES.MODE_OFB, iv)
        #msgCipher = cipher.encrypt(paddedMsg.encode())
        
        #print(1)
        cnt = 0
        
        pb1 = Progressbar(
            ws, 
            orient=HORIZONTAL, 
            length=300, 
            mode='determinate'
            )
        pb1.grid(row=4, columnspan=3, pady=20)
                    
        with open(fileName, "rb") as f:
            while True:
                bytesRead = f.read(self.buffsize)
                if not bytesRead:
                    break
                
                actualBytesRead = self.padFileChunk(bytearray(bytesRead))
                encr = cipher.encrypt(bytes(actualBytesRead))
                #print(2)
                for client in self.allClients.keys():
                    #print(3)
                    time.sleep(0.5)
                    client.send(encr)
                    #print(4)
                cnt += 1
                ws.update_idletasks()
                pb1['value'] += int((cnt / fileChunkCount) * 100)
        if cnt > 0:
            self.addChat("Me (" + self.nameVar.get() + ")", 'FILE SENT: <' + actFileName + '>')
         
        #for i in range(5):
        #    ws.update_idletasks()
        #    pb1['value'] += 20
        #    time.sleep(0.2)
        pb1.destroy()
        fileSentLabel = Label(ws, text='File Sent Successfully!', foreground='green').grid(row=4, columnspan=3, pady=10)
        #time.sleep(2)
        #ws.destroy()
  
  
    def addChat(self, client, msg):
        msg = msg.strip()
        msgPrint = emoji.emojize(msg)
        self.receivedChats.config(state=NORMAL)
        self.receivedChats.insert("end",client+": "+msgPrint+"\n")
        self.receivedChats.config(state=DISABLED)
  
    def addClient(self, clientsoc, clientaddr, peerName):
        if clientaddr not in self.allClientAddrs:
            self.allClients[clientsoc]=self.counter
            self.counter += 1
            if peerName is not None:
                self.friends.insert(self.counter,peerName + " - %s:%s" % clientaddr)
            else:
                self.friends.insert(self.counter,"%s:%s" % clientaddr)
        else:
            self.setStatus('This client is already connected...')
  
    def removeClient(self, clientsoc, clientaddr):
        self.friends.delete(self.allClients[clientsoc])
        del self.allClients[clientsoc]
        
    def setStatus(self, msg):
        self.statusLabel.config(text=msg)
        print(msg)
      

def main():  
    root = Tk()
    app = ChatClient(root)
    root.mainloop()  


if __name__ == '__main__':
    main()  
