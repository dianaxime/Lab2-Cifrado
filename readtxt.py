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
https://riptutorial.com/es/python/example/18926/cifrado-simetrico-utilizando-pycrypto#:~:text=El%20algoritmo%20AES%20toma%20tres,un%20vector%20de%20inicializaci%C3%B3n%20aleatorio.'''

import hashlib
import math
import os

from Crypto.Cipher import AES

IV_SIZE = 16    # 128 bit, fixed for the AES algorithm
KEY_SIZE = 32   # 256 bit meaning AES-256, can also be 128 or 192 bits
SALT_SIZE = 16  # This size is arbitrary

#aqui vamos a leer el archivo texto plano
archivo = open('text.txt','rb')
cleartext = archivo.read()
#cerramos archivo
archivo.close()
#contrasena de seguridad
password = input('Ingrese password')
#convertir texto de password a bytes
password= str.encode(password)
salt = os.urandom(SALT_SIZE)
derived = hashlib.pbkdf2_hmac('sha256', password, salt, 100000,
                              dklen=IV_SIZE + KEY_SIZE)
#vector inicial con tamano 16
iv = derived[0:IV_SIZE]
#llave con tamano 32
key = derived[IV_SIZE:]

#aqui se encripta el texto
encrypted = salt + AES.new(key, AES.MODE_CFB, iv).encrypt(cleartext)
cript = open ('cript.txt','wb')
cript.write(encrypted)
cript.close()


salt = encrypted[0:SALT_SIZE]
derived = hashlib.pbkdf2_hmac('sha256', password, salt, 100000,
                              dklen=IV_SIZE + KEY_SIZE)
iv = derived[0:IV_SIZE]
key = derived[IV_SIZE:]
#MODO
cleartext = AES.new(key, AES.MODE_CFB, iv).decrypt(encrypted[SALT_SIZE:])
#archivo-salida.py
f = open ('holamundo.txt','wb')
f.write(cleartext)
f.close()

'''
PREGUNTAS

¿Que modo de AES uso? ¿Por que?

Cipher feedback (CFB) y output feedback (OFB)
Estas permiten poder codificar en unidades inferiores al tamano del bloque de
texto. Aprovechado la capacidad de transmision con mayor seguridad.
Este tambien nos proteje con respecto a la sustitucion de bloques.

ii.¿Que parametros tuvo que hacer llegar desde su funcion de Encrypt a la Decrypt?
¿Porque?
SALT_SIZE
PASSWORD
AES_MODE
IV

iii.¿Que variables considera las mas importantes dentro de su implementacion? ¿Por que?
'''
