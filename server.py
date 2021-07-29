import socket
import threading
import tkinter
import random
import tkinter.scrolledtext
from tkinter import simpledialog
from math import sqrt

import base64
import hashlib
from Crypto.Cipher import AES
from Crypto import Random

HOST = '127.0.0.1'
PORT = 9090

# Pre generated primes
first_primes_list = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29,
                     31, 37, 41, 43, 47, 53, 59, 61, 67, 
                     71, 73, 79, 83, 89, 97, 101, 103, 
                     107, 109, 113, 127, 131, 137, 139, 
                     149, 151, 157, 163, 167, 173, 179, 
                     181, 191, 193, 197, 199, 211, 223,
                     227, 229, 233, 239, 241, 251, 257,
                     263, 269, 271, 277, 281, 283, 293,
                     307, 311, 313, 317, 331, 337, 347, 349]

def nBitRandom(numBits):
    return random.randrange(2**(numBits-1) + 1, 2**numBits - 1)
  
def getLowLevelPrime(numBits):
    while True:
        pc = nBitRandom(numBits) 
        for divisor in first_primes_list:
            if pc % divisor == 0 and divisor**2 <= pc:
                break
        else: return pc
  
def isMillerRabinPassed(n):
    k = 0
    q = n-1
    while q % 2 == 0:
        q >>= 1
        k += 1
    assert(2**k * q == n-1)
  
    def trialComposite(a):
        if pow(a, q, n) == 1:
            return False
        for i in range(k):
            if pow(a, 2**i * q, n) == n-1:
                return False
        return True
  
    numberOfRabinTrials = 20 
    for i in range(numberOfRabinTrials):
        a = random.randrange(2, n)
        if trialComposite(a):
            return False
    return True

def findLargePrimeNumberOfNBytes(numBit):
    while True:
        prime_candidate = getLowLevelPrime(numBit)
        if not isMillerRabinPassed(prime_candidate):
            continue
        else:
            return prime_candidate
            break
 
def powmod(x,y,p):
    res = 1 
    x = x % p 
    while (y > 0):
        if (y & 1):
            res = (res * x) % p
        y = y >> 1 
        x = (x * x) % p
    return res

def findPrimefactors(s, n) :
    while (n % 2 == 0) :
        s.add(2)
        n = n // 2
    for i in range(3, int(sqrt(n)), 2):
        while (n % i == 0) :
 
            s.add(i)
            n = n // i
    if (n > 2) :
        s.add(n)

def findPrimitive(n) :
    s = set()
    phi = n - 1
    findPrimefactors(s, phi)
    for r in range(2, phi + 1):
        flag = False
        for it in s:
            if (powmod(r, phi // it, n) == 1):
                flag = True
                break
        if (flag == False):
            return r
    return -1

def ConvertNum(s):
    num = 0
    s = s.replace("\n", "")
    j = len(s) - 1
    for i in s:
        num = num + int(i)*pow(10, j)
        j -= 1
    return num

BLOCK_SIZE = 16
pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * chr(BLOCK_SIZE - len(s) % BLOCK_SIZE)
unpad = lambda s: s[:-ord(s[len(s) - 1:])]

def encrypt(raw, password):
    private_key = hashlib.sha256(password.encode("utf-8")).digest()
    raw = pad(raw)
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(private_key, AES.MODE_CBC, iv)
    return base64.b64encode(iv + cipher.encrypt(raw))


def decrypt(enc, password):
    private_key = hashlib.sha256(password.encode("utf-8")).digest()
    enc = base64.b64decode(enc)
    iv = enc[:16]
    cipher = AES.new(private_key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(enc[16:]))

class Server:
    def __init__(self, host, port):
        self.PrivateKey = 0
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.bind((HOST, PORT))
        self.server.listen()
        
        msg = tkinter.Tk()
        msg.withdraw()

        self.gui_done = False
        self.running = True

        self.isSecurity = False
        gui_thread = threading.Thread(target=self.gui_loop)
        receive_thread = threading.Thread(target=self.receive)

        gui_thread.start()
        receive_thread.start()

    def gui_loop(self):
        self.win = tkinter.Tk()
        self.win.configure(bg="lightgray")

        self.chat_label = tkinter.Label(self.win, text = "SERVER", bg = "lightgray")
        self.chat_label.config(font=("Arial", 12))
        self.chat_label.pack(padx=20, pady=5)

        self.text_area = tkinter.scrolledtext.ScrolledText(self.win)
        self.text_area.pack(padx=20, pady=5)
        self.text_area.config(state='disabled')

        self.msg_label = tkinter.Label(self.win, text = "Message", bg = "lightgray")
        self.msg_label.config(font=("Arial", 12))
        self.msg_label.pack(padx=20, pady=5)

        self.input_area = tkinter.Text(self.win, height = 3)
        self.input_area.pack(padx=20, pady=5)

        self.send_button = tkinter.Button(self.win, text = "Send", command = self.write)
        self.send_button.config(font=("Arial", 12))
        self.send_button.pack(padx=20, pady=5)

        self.gui_done = True

        self.win.protocol("WM_DELETE_WINDOW", self.stop)

        self.win.mainloop()

    def write(self):
        self.text_area.config(state='normal')
        self.text_area.insert('end', self.input_area.get('1.0', 'end'))
        message = f"BOD: >{self.input_area.get('1.0', 'end')}"
        print(self.isSecurity)
        if self.isSecurity == False:
            self.client.send(message.encode('utf-8'))
            self.input_area.delete('1.0', 'end')
        else:
            cipher = encrypt(message, self.shared_key)
            self.client.send(cipher.encode('utf-8'))
            self.input_area.delete('1.0', 'end')

    def stop(self):
        self.running = False
        self.win.destroy()
        self.client.close()
        exit(0)

    def receive(self):
        while self.running:
            try:
                self.client, self.address = self.server.accept()
                while True:
                    message = self.client.recv(1024)

                    if self.gui_done:
                        self.text_area.config(state='normal')
                        self.text_area.insert('end', message)

                    if message == b"ALICE: >Let's use DH!\n":
                        message_send = "Choose the bit length for our P\n"

                        self.text_area.config(state='normal')
                        self.text_area.insert('end', message_send)

                        message_send = "BOD: >Choose the bit length for our P\n"
                        self.client.send(message_send.encode('utf-8'))

                    if (message.decode('utf-8')[8:len(message)-2]).isnumeric() == True:
                        numBits = ConvertNum(message.decode('utf-8')[8:])
                        #print(numBits)
                        self.P = findLargePrimeNumberOfNBytes(numBits)
                        message_send = "BOD: >P = " + str(self.P) + "\n"
                        #print(message)

                        mess1 = "g is less than\n"
                        mess2 = "I am sending you a prime number P = " + str(self.P) +"\n"
                        #print(mess1 + mess2)

                        self.text_area.config(state='normal')
                        self.text_area.insert('end', mess1)

                        self.text_area.config(state='normal')
                        self.text_area.insert('end', mess2)

                        self.client.send(message_send.encode('utf-8'))
                    
                    self.G = findPrimitive(self.P)
                    if message.decode('utf-8')[8:] == "Give me G!\n":  
                        print(self.G)
                        message_send = "BOD: >G = " + str(self.G) + "\n"

                        mess = "I am sending you G = " + str(self.G) +"\n"
                        self.text_area.config(state='normal')
                        self.text_area.insert('end', mess)

                        self.client.send(message_send.encode('utf-8'))
 
                    if message.decode('utf-8')[8:] == "Send me your public key!\n":
                        self.PrivateKey = random.randrange(1, self.P - 1)
                        self.PublicKey = pow(self.G, self.PrivateKey, self.P)
                        message_send = "BOD: >My public key is: " + str(self.PublicKey) + "\n"

                        mess = "I am sending you my public key: " + str(self.PublicKey) + "\n"
                        self.text_area.config(state='normal')
                        self.text_area.insert('end', mess)
                        self.client.send(message_send.encode('utf-8'))

                    if message.decode('utf-8')[:26] == "ALICE: >My public key is: ":
                        self.PublicKey_Client = ConvertNum(message.decode('utf-8')[26:])

                    if message.decode('utf-8')[8:] == "shared_key\n":
                        self.shared_key = pow(self.PublicKey_Client, self.PrivateKey, self.P)
                        print(self.PrivateKey)
                        mess = "My sharePrivate_Server is: " + str(self.shared_key) + "\n"

                        self.text_area.config(state='normal')
                        self.text_area.insert('end', mess)

                    if message.decode('utf-8')[8:] == "Done\n":
                        print("OK")
                        self.isSecurity = True
            except ConnectionAbortedError:
                break
            '''except:
                print("Error")
                self.client.close()
                break'''
    

server = Server(HOST, PORT)

