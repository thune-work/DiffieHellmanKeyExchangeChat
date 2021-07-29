import socket
import threading
import tkinter
import random
import tkinter.scrolledtext
from tkinter import simpledialog

import base64
import hashlib
from Crypto.Cipher import AES
from Crypto import Random

HOST = '127.0.0.1'
PORT = 9090
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

class Client:
    def __init__(self, host, port):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((host, port))
        self.isSecurity = False
        msg = tkinter.Tk()
        msg.withdraw()

        self.gui_done = False
        self.running = True

        gui_thread = threading.Thread(target=self.gui_loop)
        receive_thread = threading.Thread(target=self.receive)

        gui_thread.start()
        receive_thread.start()


    def gui_loop(self):
        self.win = tkinter.Tk()
        self.win.configure(bg="lightgray")

        self.chat_label = tkinter.Label(self.win, text = "CLIENT", bg = "lightgray")
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
        message = f"ALICE: >{self.input_area.get('1.0', 'end')}"

        self.text_area.config(state='normal')
        self.text_area.insert('end', self.input_area.get('1.0', 'end'))

        self.sock.send(message.encode('utf-8'))
        if self.input_area.get('1.0', 'end') == "shared_key\n":
            mess = "My sharePrivate_Client is: " + str(self.shared_key) + "\n"
            self.text_area.insert('end', mess)

        if self.input_area.get('1.0', 'end') == "Done\n":
            self.isSecurity == True
        self.input_area.delete('1.0', 'end')

    def stop(self):
        self.running = False
        self.win.destroy()
        self.sock.close()
        exit(0)

    def receive(self):
        while self.running:
            try:
                message = self.sock.recv(1024)
                if self.gui_done:
                    print(self.isSecurity)
                    if self.isSecurity == False:
                        self.text_area.config(state='normal')
                        self.text_area.insert('end', message)
                    else:
                        plaintext = decrypt(message.decode('utf-8'), self.shared_key)
                        self.text_area.insert('end', bytes.decode(plaintext))

                if message.decode('utf-8')[:9] == "BOD: >P =":
                    self.P = ConvertNum(message.decode('utf-8')[10:])

                if message.decode('utf-8')[:9] == "BOD: >G =":
                    self.G = ConvertNum(message.decode('utf-8')[10:])

                if message.decode('utf-8')[6:] == "Send me your public key, please!\n":
                    self.PrivateKey = random.randrange(1, self.P - 1)
                    self.PublicKey = pow(self.G, self.PrivateKey, self.P)
                    message_send = "ALICE: >My public key is: " + str(self.PublicKey) + "\n"

                    mess = "I am sending you my public key: " + str(self.PublicKey) + "\n"
                    self.text_area.config(state='normal')
                    self.text_area.insert('end', mess)
                    self.sock.send(message_send.encode('utf-8'))
                
                if message.decode('utf-8')[:24] == "BOD: >My public key is: ":
                    self.PublicKey_Client = ConvertNum(message.decode('utf-8')[24:])
                    print(self.PrivateKey)
                    self.shared_key = pow(self.PublicKey_Client, self.PrivateKey, self.P)
                    
            except ConnectionAbortedError:
                break
            except:
                print("Error")
                self.sock.close()
                break

client = Client(HOST, PORT)
