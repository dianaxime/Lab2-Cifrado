"""
Grupo 6 - Lab 2 de cifrado
Implementacion de AES basada en:
https://riptutorial.com/es/python/example/18926/cifrado-simetrico-utilizando-pycrypto#:~:text=El%20algoritmo%20AES%20toma%20tres,un%20vector%20de%20inicializaci%C3%B3n%20aleatorio
"""
import hashlib
import math
import os

from Crypto.Cipher import AES

#Se establecen los tamaños de elementos necesarios para la encriptacion
IV_SIZE = 16    # vector de inicialización aleatorio de 128 bits 
KEY_SIZE = 32   # 256 bit meaning AES-256, can also be 128 or 192 bits
SALT_SIZE = 16  # This size is arbitrary

cleartext=input("Ingrese el texto a cifrar: ")
password=input("Ingrese el password: ")
pass1 = password

# ENCRIPTACION
cleartext = bytes(cleartext, encoding= 'utf-8') # se covierte el mensaje en bytes
password = bytes(password, encoding= 'utf-8') # se covierte la key en bytes
salt = os.urandom(SALT_SIZE) # creacion aleatoria de la sal que se utilizara en la encriptacion para poder derivar el mismo vector de inicialización y la clave para descifrar
derived = hashlib.pbkdf2_hmac('sha256', password, salt, 100000,
                              dklen=IV_SIZE + KEY_SIZE) #se construyen los valores para el iv y la key
iv = derived[0:IV_SIZE]  # se genera el vector de inicializacion de 128 bits
key = derived[IV_SIZE:] # se genera la clave de cifrado de 256 bits a partir de la contraseña

encrypted = salt + AES.new(key, AES.MODE_CFB, iv).encrypt(cleartext) #el mensaje se encripta junto con la llave y sal 
print('\nMensaje encriptado: ')
print(encrypted)

#DESCIFRADO DEL MENSAJE
salt = encrypted[0:SALT_SIZE] # se obtiene la sal almacenada junto con el txtcifrado para poder derivar el mismo vector de inicialización y la clave para descifrar
derived = hashlib.pbkdf2_hmac('sha256', password, salt, 100000,
                              dklen=IV_SIZE + KEY_SIZE)
iv = derived[0:IV_SIZE] # se almacena el vector de inicializacion 
key = derived[IV_SIZE:] # se obtiene la llave requerida 
cleartext = AES.new(key, AES.MODE_CFB, iv).decrypt(encrypted[SALT_SIZE:]) # el mensaje se desencripta utilizando la sal y key

opcion = input("\n¿Desea desenciptar el mensaje? Y/N: ")

if opcion == "Y" or opcion == "y":
    contra = input("\nIngrese el password: ")
    if contra == pass1:
        print('\nMensaje desencriptado: ')
        print(cleartext)
        print("\nAdios hacker!")
    else:
        print("Password incorrecto, adios hacker")
else:
    print("\nAdios hacker!")

"""
i.¿Tuvo que usar “encode” de algo? ¿Sobre qué variables? 
    Si. Sobre la password y el texto ingresados por el user          
ii.¿Qué modo de AES usó? ¿Por qué? 
    Se utiliza el modo CFB (Cipher feedback), muy parecido al Cipher block chainning en el cual a cada bloque se le XOR con el cifrado de bloques 
    anteriores, siendo una función recursiva. Se puede diferenciar facilmente por necesitar un vector de inicialización. A diferencia de CBC, es paralelizable
    en la desencriptación y permite acceso de lectura aleatorio dado que permite cifrar y transferir algunos valores de texto sin formato al instante, uno 
    a la vez.       
iii.¿Qué parámetros tuvoque hacer llegar desde sufunción de Encrypta la Decrypt?¿Porqué?
    La key, el vector de inicialización, la sal y el mensaje encriptado

"""
