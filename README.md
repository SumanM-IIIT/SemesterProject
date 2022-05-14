# Final Semester Project

#### SecureChat - An E2EE P2P Chatting App

**Made by** -
- Suman Mitra - **2020202018**
- Aditya Mahajan - **2020202017**
- Akshay Choudhary - **2020202013**

**Batch** - MTech 2k20 - 2nd Yr (CSIS), IIIT Hyderabad 
**Mentor** - Dr. Kannan Srinathan, CSTAR Lab, IIIT Hyderabad
**Submission Date** - 14th May, 2022

**Running the app** - Open a client using the following command: `python3 ./client.py`

**Dependencies** - Install the following packages before running the code:
- PyCrypto: `pip3 install pycryptodome`
- Emoji: `pip3 install emoji`
- Tkinter: `pip3 install tk`

**Brief Explanation** - 
- It is an End-to-end encrypted P2P chatting app.
- Message encryption is done using AES-128.
- Initial AES symmetric key exchange among the clients is done using RSA public key cryptography.
- All types of files can also be sent. Files are also end-to-end encrypted.
- Emojis are supported.

