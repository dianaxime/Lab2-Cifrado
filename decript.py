#Maria Jose Castro 181202
#Diana de Leon 18607
#Camila Gonzalez 18398
#Maria Ines Vasquez 18250
#Christopher Barrios 18207
#Jose Garavito 18071

#Laboratorio 2
#BLOCK CIPHERS

'''
CODIGO REFERNECIADO DE:
https://riptutorial.com/es/python/example/18926/cifrado-simetrico-utilizando-pycrypto#:~:text=El%20algoritmo%20AES%20toma%20tres,un%20vector%20de%20inicializaci%C3%B3n%20aleatorio.
'''

import hashlib
import math
import os

from Crypto.Cipher import AES

IV_SIZE = 16    # 128 bit, fixed for the AES algorithm
KEY_SIZE = 32   # 256 bit meaning AES-256, can also be 128 or 192 bits
SALT_SIZE = 16  # This size is arbitrary

#aqui vamos a leer el archivo con el texto encriptado
encriptado = open ('cript.txt','rb')
encrypted = encriptado.read()
encriptado.close()
#contrasena de seguridad
password = input('Ingrese su password segura')
#convertir de texto a bytes
password= str.encode(password)

salt = encrypted[0:SALT_SIZE]
derived = hashlib.pbkdf2_hmac('sha256', password, salt, 100000,
                              dklen=IV_SIZE + KEY_SIZE)
iv = derived[0:IV_SIZE]
key = derived[IV_SIZE:]
#aqui se desencripta el texto
cleartext = AES.new(key, AES.MODE_CFB, iv).decrypt(encrypted[SALT_SIZE:])
#Escribir el archivo con el texto desencriptado
f = open ('text-decripted.txt','wb')
f.write(cleartext)
f.close()