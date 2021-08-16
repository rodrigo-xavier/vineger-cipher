import string
import letter_frequency
import re
from collections import Counter
import numpy as np

OFFSET_INDEX = 65


class Vigenere:
    charString = string.ascii_uppercase + string.ascii_uppercase

    def __init__(self, key):
        self.key = key.upper()
        self.matriz = self.initMatriz()

    def initMatriz(self):
        auxMatriz = []
        for i in range(26):
            auxMatriz.append(self.charString[i: i + 26])

        return auxMatriz

    def getKeystramValue(self, index):
        keyIndex = index % len(self.key)

        return self.key[keyIndex]

    def encode(self, message):
        message = message.upper()
        encodedMessage = ''

        i = 0
        for char in message:
            if (char in string.ascii_uppercase):
                messageIndex = ord(char) - OFFSET_INDEX
                keystreamIndex = ord(self.getKeystramValue(i)) - OFFSET_INDEX
                encodedMessage += self.matriz[messageIndex][keystreamIndex]
                i += 1

        return encodedMessage

    def decode(self, encodedMessage):
        message = ''
        encodedMessage = encodedMessage.upper()
        i = 0
        for char in encodedMessage:
            if (char in string.ascii_uppercase):
                keystreamIndex = ord(self.getKeystramValue(i)) - OFFSET_INDEX
                messageIndex = self.matriz[keystreamIndex].find(char)
                message += string.ascii_uppercase[messageIndex]
                i += 1

        return message


class VigenereBreaker:

    # Only returns uppercase letters of the cipher
    def manipulateCipher(self, cipher):
        return (''.join(filter(str.isalpha, cipher))).upper()

    def getFactors(self, toFactor):
        factors = []

        for i in toFactor:
            for j in range(2, i + 1):
                if i % j == 0:
                    factors.append(j)
        return factors
    
    def shiftText(self, text, shift):
        a = ord('A')
        return ''.join(chr((ord(char) - a + shift) % 26 + a) for char in text.upper())

    # Determines the index of coincidence over a cipher
    def indexOfCoincidence(self, cipher):
        sum = 0

        for c in string.ascii_uppercase:
            charCounter = cipher.count(c)
            cipherLength = len(cipher)

            sum = sum + (charCounter*(charCounter - 1))
        sum = sum / (cipherLength * (cipherLength - 1))

        return sum

    # Determines the number of possible characteres on the key using index of coincidence method
    def indexOfCoincidenceMethod(self, cipher, language):
        LanguageAbsIC = {}
        languageIC = letter_frequency.LANGUAGE_IC[language]
        cipher = self.manipulateCipher(cipher)

        for i in range(2, int(len(cipher)/2)):
            IC = 0
            for j in range(i):
                IC = IC + self.indexOfCoincidence(cipher[j:-1:i]) # [start:stop:step]
            LanguageAbsIC.update({i: abs((IC/i) - languageIC)})

        # Explicação: Na linha de código anterior, é calculado o IC médio por N cosets (N tamanho da chave) e subtraído do IC da linguagem.
        # Feito isso, os tamanhos de chave com IC absoluto mais próximos de 0, são aqueles que mais se aproximam do IC da linguagem
        # Aqueles tamanhos N que mais se aproximam do IC da linguagem são os prováveis valores da chave.
        # Nas linhas seguintes, é retornado os 20% de valores mais prováveis para o tamanho da chave.
        # Note que cifras pequenas podem possuir valores IC próximos de valores aleatórios, o que não permite encontrar com precisão o tamanho correto da chave
        orderedIC = [key for key, value in sorted(LanguageAbsIC.items(), key=lambda x: x[1])]
        
        return orderedIC[:int(0.3*len(orderedIC))] # Retorna 30% dos resultados

    # Determines the number of possible characteres on the key using Kasiski method
    def kasiskiMethod(self, cipher):
        toFactor = set()
        cipher = self.manipulateCipher(cipher)

        # Starts in 2 because we want a pattern with more than 2 characters
        for i in range(3, len(cipher)):
            for j in range(len(cipher) - i):
                substringOcurrences = [_.start() for _ in re.finditer(cipher[j:j+i], cipher[j+i:])]
                distances = [(k+i) for k in substringOcurrences]
                toFactor.update(distances)

                if distances:
                    print(str(len(distances) + 1) + " ocorrencias da substring: " + str(cipher[j:j+i]))

        # We want a factor that repeats more than 1 time
        return [key for key, value in Counter(self.getFactors(toFactor)).items() if value > 2]
    
    def intersection(self, cipher, language):
        kasiski = self.kasiskiMethod(cipher)
        IC = self.indexOfCoincidenceMethod(cipher, language)

        return set(kasiski[:3] + IC[:3])
        # return (kasiski | IC)
        # return (kasiski & IC)

    def x2Method(self, cipher, language, possiblesKeyLength):
        alphabetLen = 26
        letterFrequency = letter_frequency.LETTER_FREQUENCY[language]
        cipher = self.manipulateCipher(cipher)

        for i in possiblesKeyLength:
            key = ""
            x2perncoset = []
            for shift in range(alphabetLen):
                cosetX2 = []
                for j in range(i):
                    shiftedCoset = self.shiftText(cipher[j:-1:i], - shift)
                    cosetX2.append(sum([(((value/10 - letterFrequency[key])**2)/letterFrequency[key]) for key, value in Counter(list(shiftedCoset)).items()]))
                x2perncoset.append(cosetX2)
            
            transpose = np.array(x2perncoset).T.tolist()

        return transpose

    def findPossibleKeys(self, cipher, language, keyLength, nResults):
        possibleKeys = {}
        # possiblesKeyLength = self.intersection(cipher, language) # Tem que retornar um set(), meio que uma lista entre chaves {}

        for i in keyLength:
            keyList = []
            keyString = []
            x2Matrix = self.x2Method(cipher, language, {i})

            for j in range(i):
                characters = []
                for n in range(nResults):
                    index = x2Matrix[j].index(min(x2Matrix[j]))
                    characters.append(chr(65 + index))
                    x2Matrix[j].pop(index)
                keyList.append(characters)
                # keyList += chr(65 + x2Matrix[j].index(min(x2Matrix[j])))
            
            transpose = np.array(keyList).T.tolist()

            for n in range(nResults):
                keyString.append(''.join(transpose[n]))

            possibleKeys.update({i: keyString})
        
        return possibleKeys
