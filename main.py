from tests import *
from vigenere import *
import os 
dir_path = os.path.dirname(os.path.realpath(__file__))

if __name__ == '__main__':
    # unittest.main()

    vb = VigenereBreaker()
    option = 1
    language = "english"

    while(option != 0):
        f = open(dir_path + "/" + "message.txt", "r")
        message = f.read()
        f.close()
        
        print("\nChoose a option")
        print("1 - Encrypt a message")
        print("2 - Decrypt a message")
        print("3 - Attack a message - Find possible key length")
        print("4 - Attack a message - Decode message")
        print("5 - Choose Language")
        print("0 - Exit")
        option = int(input())
        if option == 1:
            key = input("Type a key\n")

            v = Vigenere(key)

            print(v.encode(message))

        if option == 2:
            key = input("Type a key\n")

            v = Vigenere(key)

            print(v.decode(message))

        if option == 3:
            print(vb.intersection(message, language))

        if option == 4:
            keyLength = {int(input("Type the key length \n"))}

            print(vb.findPossibleKeys(message, language, keyLength, 4))

        if option == 5:
            language = input("Wich language? (portuguese | english)\n")

        print("\n")
