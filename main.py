"""
    This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License 
    as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

    This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; 
    without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along with this program. If not, see <https://www.gnu.org/licenses/>.


    This is a server to communicate with ESP8266 counters that students bring to workshops
    The ESP8266 chips are low power, and do not support any sort of asymmetrical encryption, but does support AES encryption
    To make sure both sides generate the same key, the esp will first pass the epoch time when it recieves a connection
    At the moment this is in plain text
    Afterwards that number is put through the obfuscate algorithm to generate the key used for AES

    Requires Pycryptodome to be installed

    TODO:
    Stress testing
    look into pipenv
    requirements file
    readme
"""


import socket
import time
import threading
from Crypto.Cipher import AES


class Store:
    # Class attributes. Same across all instances
    localStorage = []
    storedMac = []


    def __init__(self):
        self.lock = threading.Lock()  # When used, only lets a single thread use this object at a time, avoids race conditions
        self.threadNum = 0


    def addMAC(self, mac):
        self.lock.acquire()
        self.storedMac.append(mac)
        self.lock.release()


    def checkMAC(self, mac):
        if mac in self.storedMac:
            return True

        return False


    def addObj(self, obj):
        self.lock.acquire()
        self.localStorage.append([self.threadNum, obj])
        self.threadNum += 1
        self.lock.release()


    def delObj(self, num):
        self.lock.acquire()
        print("del num ", num)

        for i in range(len(self.localStorage)):
            if self.localStorage[i][0] == num:
                del self.localStorage[i]
                break

        self.lock.release()


class HandleString:
    def __init__(self, c, num):
        store = Store()
        recvInfo = []  # Will store the MAC address of the client, and the epoch time that was sent

        while True:
            r = c.recv(1024)
            try:
                recvInfo.append(r.decode())
            except Exception as e:
                print(e)
                recvInfo.append(str(r))

            if len(recvInfo) >= 2:
                break

            time.sleep(1)
        print(recvInfo)

        while True:
            try:
                multiply = self.obfuscate(recvInfo[1])  # Obfucate key to use for encryption
                keyArr = self.addLetter(multiply)
                key = "".join(keyArr)
            except Exception as e:
                print(e)
                c.send("Invalid string. Closing connection\r\n".encode())
                break

            key = self.checkSize(key)  # If the key ends up being less that 32 bytes, this will pad it out
            key = key.encode()

            repeatCheck = store.checkMAC(recvInfo[0])
            if repeatCheck:  # MAC addresses are stored in the Store class
                message = "0"  # If the MAC addres is found, this ends the thread and does not increment the ESP's counter
            else:
                message = "1"  # If the MAC address is not found, tell ESP to increment it's counter
                store.addMAC(recvInfo[0])  # Add the MAC address to the list of used MACs

            time.sleep(5)
            conMessage = self.encryptText(message, key)  # Encrypt the message before sending
            c.send(conMessage)  # Send the result to the ESP
            break

        c.close()
        time.sleep(1)  # I don't remember if this does something, but i'm scared to remove it

        store.delObj(num)  # Delete this object from the Store class list


    def checkSize(self, key):
        blockSize = 32  # Specify the bit length of the key
        newKey = key

        while len(newKey) < blockSize:
            newKey += newKey  # Append newKey to its self until it is longer than 32 bytes

        return newKey[0:blockSize]  # Return a 32 byte portion to be used as the encryption key


    def encryptText(self, text, key):
        blockSize = 16  # Specify the length to pad the message to
        keyPad = blockSize - len(text) % blockSize
        message = text + " "*keyPad
        message = bytes(message, 'utf-8')

        # Not a very secure mode, but only requires a key for encryption and decryption
        # Also probably easier for ESP to process
        cipher = AES.new(key, AES.MODE_ECB)

        # encypted text must be an increment of 16. If it snot, i will kill you
        cypherText = cipher.encrypt(message)
        return cypherText


    def obfuscate(self, r):
        curTime = r
        divStr = curTime[2:-1]  # Cut off first two digits of the string
        divInt = int(divStr)
    
        factors = []

        for i in range(2, divInt):  # Get the first 5 factors that go into div int
            if divInt % i == 0:
                listLen = len(factors)
                if listLen >= 5:
                    break
                else:
                    factors.append(i)
    
        if len(factors) == 0:  # In the off chance divInt is a prime number, just use divInt
            for i in curTime:
                factors.append(int(i))

        total = 1
    
        for i in factors:  # Multiply all factors together
            total = total * i
    
        total = total * total * total  # Cube it

        return total


    def addLetter(self, total):
        keyStr = str(total)
        keyArr = []  # Create array to characters can be inserted in

        for i in keyStr:  # Break string into an array
            keyArr.append(i)

        for i in range(len(keyStr)):  # Convert each number into a char type. Then use the initial number as the index to insert the char into the array
            keyArr.insert(int(keyStr[int(i)]), chr(int(keyStr[int(i)]) + 97))

        return keyArr


def main():
    store = Store()   # Create a class object to store information from different threads
    port = 6060
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)   # Specify ipv4 and tcp
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("", port))

    while True:
        try:
            s.listen()

            c, addr = s.accept()
            conn = HandleString

            store.addObj(conn)

            threading.Thread(target=store.localStorage[-1][1], args=(c, store.localStorage[-1][0],)).start()
        except Exception as e:
            print(e)
            break

    s.close()


if __name__ == "__main__":
   main()
