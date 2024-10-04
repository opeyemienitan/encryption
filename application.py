"""

This application was developed using code samples from:
50% https://cryptography.io/en/latest/
15% https://pypi.org/project
10% https://pycryptodome.readthedocs.io/
5%  https://pillow.readthedocs.io/en/stable/reference/Image.html
5%  https://www.geeksforgeeks.org/security-of-rsa/
5%  https://nitratine.net/blog/post/asymmetric-encryption-and-decryption-in-python/#:~:text=Asymmetric%20encryption%20uses%20two%20keys,key%20can%20decrypt%20the%20message.
5%  https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/#encryption
5%  https://pillow.readthedocs.io/en/stable/reference/Image.html

All comments are original

"""


import cryptography ## Importing crytography module for generating, storing keys and performing RSA encryption and decryption.
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa  ## using this for generating the keys for RSA.
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
import tkinter as tk # used for importing the files.
from tkinter import filedialog #inmporting dialog for selecting and importing multiple files.
import zlib # importing this library for compressing the files.
import random   # for generating the random characters for generating 256bit key for the AES encryption/Decryption.
import string
import docx2txt  # used for reading and converting the .doc files.
import os
import sys
import PyPDF2  # used for reading and converting the .pdf files .
import base64
from Cryptodome import Random
from Cryptodome.Cipher import AES  #importing AES algorithm from the crypto library.
from Cryptodome.Util.Padding import pad, unpad
import io
import PIL.Image
from Cryptodome.Util.Padding import pad

BLOCK_SIZE = 32  # selecting the block size of the data for AES encryption/ decryption.

def generate_keys(folder_name, key):             
    ## Process of generating the two keys (private and public) for RSA
    private_key = rsa.generate_private_key( public_exponent=65537, key_size=2048,  backend=default_backend()) #this is for private key generation for the RSA
    public_key= private_key.public_key() #this is for public key generation for the RSA

    ## Process of Serializing and storing the Private Key
    pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(key.encode('utf-8')) 
            )            
    with open(f'{folder_name}/private_key.pem', 'wb') as f:
                f.write(pem) #writing serialize data into pem file.

        ## Process of Serializing and storing the Public Key 
    pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
    with open(f'{folder_name}/public_key.pem', 'wb') as f:
            f.write(pem) #writing serialize data into pem file.


def load_private_key(folder_name, key):
        #Process of Reading and Loading the Keys from these pem files.
    with open(f"{folder_name}/private_key.pem", "rb") as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=key.encode('utf-8'),
                backend=default_backend()
                )

    return private_key
    

def load_public_key(folder_name):
        ## loading the public key  
    with open(f"{folder_name}/public_key.pem", "rb") as key_file:
            public_key = serialization.load_pem_public_key(
                key_file.read(),
                backend=default_backend()
                )  
    return public_key

#this function is used for padding bits during AES ecryption Function.
def _pad(s):
    return s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * chr(BLOCK_SIZE - len(s) % BLOCK_SIZE)

#this function is used for padding bits during AES decryption Function.
def _unpad(s):
    return s[:-ord(s[len(s)-1:])]

# encrypting text using AES by randomly generating key and encrypts key with public key 
def encrypt_text(public_key, raw):
    raw = raw.encode()
    print("BEFORE COMPRESSION")
    print(raw)
    # compression of data
    raw = zlib.compress(raw)
    print("SIZE:", sys.getsizeof(raw))
    print("\nAfter COMPRESSION")
    print(raw)
    print("SIZE:", sys.getsizeof(raw))
    # process of AES key generation
    key = os.urandom(16)
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    # encrypting key
    encrypted_key = encrypt_key(public_key, key)
    # encrypting data
    encoded = base64.b64encode(iv + cipher.encrypt(pad(raw, BLOCK_SIZE)))
    return encrypted_key, encoded

# encrypting image using AES by randomly generating key and encrypts key with public key 
def encrypt_image(public_key, data):
    print("BEFORE COMPRESSION")
    print("SIZE:", sys.getsizeof(data))
    data = zlib.compress(data)
    print("\nAfter COMPRESSION")
    print("SIZE:", sys.getsizeof(data))
    data = pad(data, BLOCK_SIZE)
    # generate Random key
    key = os.urandom(16)
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    # encrypting data
    encoded = base64.b64encode(iv + cipher.encrypt(data))
    # encrypting key
    encrypted_key = encrypt_key(public_key, key)    
    return encrypted_key, encoded

# encryption of  AES key using public key
def encrypt_key(public_key, text):
    cipher_text = public_key.encrypt(
        text,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return cipher_text

# decryption of text using AES
def decrypt_text(key, enc):
    enc = base64.b64decode(enc)
    iv = enc[:AES.block_size]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plain_text = _unpad(cipher.decrypt(enc[AES.block_size:]))
    print("BEFORE DECRYPTION")
    print(plain_text)
    print("SIZE:", sys.getsizeof(plain_text))
    # decompressing data
    plain_text = zlib.decompress(plain_text).decode('utf-8')
    print("\nAFTER DECRYPTION")
    print("SIZE:", sys.getsizeof(plain_text))
    print(plain_text)
    # writing plain text to file
    with open(f"{folder_name}/decrypted/{file_name}", 'w') as cipher_file:
        cipher_file.write(plain_text)
    return plain_text

# decryption of image using AES
def decrypt_image(key, enc):
    enc = base64.b64decode(enc)
    iv = enc[:AES.block_size]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    # decrypting data
    plain_text = cipher.decrypt(enc[AES.block_size:])
    print("BEFORE DECRYPTION")
    print("SIZE:", sys.getsizeof(plain_text))
    # decompressing data
    plain_text = zlib.decompress(plain_text)
    print("\nAFTER DECRYPTION")
    print("SIZE:", sys.getsizeof(plain_text))
    # with open(f"{folder_name}/decrypted/{file_name}", 'w') as cipher_file:
    #     cipher_file.write(plain_text)

    # creation of image object and saving it
    imageStream = io.BytesIO(plain_text)
    imageFile = PIL.Image.open(imageStream)
    imageFile.save(file_name)

    # opens image window
    im = PIL.Image.open(file_name)
    im.show()
    return plain_text

# decrypting AES key with private key
def decrypt_key(private_key, key):
    plaint_text = private_key.decrypt(
        key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaint_text


if __name__ == '__main__': 
    print("Welcome!")
    while True:
        
        print("\t1. Create a new user")
        print("\t2. Encryption")
        print("\t3. Decryption")
        print("\tq. Exit")

        choice = input("Enter you choice: ") #creating a user
        if choice == '1':
            while True:
                folder_name = input("Enter your username: ")

                # checking if user exists
                if not os.path.exists(folder_name):
                    # makes directories if the above user is non-existing
                    os.makedirs(folder_name)
                    os.makedirs(f"{folder_name}/encrypted")
                    os.makedirs(f"{folder_name}/decrypted")
                    break
                else:
                    print("User already exists. Select other name")

            # checks key length
            while True:
                key = input("Enter your secret key.\nThis will be used to sign your private key: ")
                if len(key) >= 6:
                    break
                else:
                    print("Enter key containing atleast 6 characters")

            # generating set of public and private key for user
            generate_keys(folder_name, key)

            print("Your keys have been generated successfully!")


        # performs encryption
        elif choice == '2':
            
            # authenticates the user
            while True:
                try:
                    folder_name = input("Enter your username: ")
                    key = input("Enter your secret key: ")
                    # decryption and loading private key by using secret key
                    private_key = load_private_key(folder_name, key)
                    break

                except ValueError:
                    print("Incorrect username or secret key")

            while True:
                print("1. Encrypt text")
                print("2. Encrypt file(s)")
                print("3. Encrypt an image")
                print("4. Back to Menu")

                choice = input("Select your choice: ")

                if choice == '4':
                    break

                elif choice not in ['1', '2', '3']:
                    print("Invalid choice")
                    continue
                
                # request for recipents username
                while True:
                    folder_name = input("Enter username of recipent: ")
                    if os.path.exists(folder_name):
                        break
                    else:
                        print("User doesnt exist. Enter correct username")

                # loading public key of recipent
                public_key = load_public_key(folder_name)

                if choice == '1':
                    text = input("Enter your text: ")
                    file_name = input("Enter file name to store encrypted text: ")
                    # text encryption
                    encrypted_key, cipher = encrypt_text(public_key, text) 
                    print("Text encryption successful")
                    print(cipher)

                    # signing the text
                    signature = private_key.sign(
                        cipher,
                        padding.PSS(
                            mgf=padding.MGF1(hashes.SHA256()),
                            salt_length=padding.PSS.MAX_LENGTH
                        ),
                        hashes.SHA256()
                    )
                    print("Signed successfully")
                    print(signature)

                    # writes signature, encrypted key and cipher text to file
                    with open(f"{folder_name}/encrypted/{file_name}", 'wb') as cipher_file:
                        cipher_file.write(b"START OF SIGNATURE\n")
                        cipher_file.write(signature)
                        cipher_file.write(b"\nEND OF SIGNATURE\n")
                        cipher_file.write(b"START OF ENCRYPTED KEY\n")
                        cipher_file.write(encrypted_key)
                        cipher_file.write(b"\nEND OF ENCRYPTED KEY\n")
                        cipher_file.write(cipher)
                        
                    
                # encrypting files
                elif choice == '2':
                    print("Select .txt, .pdf and .docx files only")
                    root = tk.Tk()
                    root.withdraw()
                    root.call('wm', 'attributes', '.', '-topmost', True)
                    files = filedialog.askopenfilename(multiple=True) # asking the user to select the files for encryption....
                    var = root.tk.splitlist(files)
                    print("Files selected successfully......")

                    # loops over files
                    for f in var:

                        file_name, extension = os.path.splitext(f)

                        # extracts text from .txt file
                        if extension == ".txt":
                            with open(f, 'r') as file:
                                text = file.read()

                        # extracts text from .docx file
                        elif extension==".docx":
                            text = docx2txt.process(f) #reading and encoding the data of word file

                        # extracts text from .pdf file
                        elif extension==".pdf":
                            pdfFileObj = open(f, 'rb')  # creating a pdf file object
                            pdfReader = PyPDF2.PdfFileReader(pdfFileObj) # creating a pdf reader object
                            pageObj = pdfReader.getPage(0) # creating a page object 
                            text = pageObj.extractText() # extracting text from page
                            pdfFileObj.close() # closing the pdf file object

                        else:
                            print("Select .txt and .docx files only")
                            continue
                        
                        file_name = file_name.split("/")[-1] + ".txt"
                        # encrypts text
                        encrypted_key, cipher = encrypt_text(public_key, text)
                        print("File encryption successful")
                        print(cipher)

                        # signs the text
                        signature = private_key.sign(
                            cipher,
                            padding.PSS(
                                mgf=padding.MGF1(hashes.SHA256()),
                                salt_length=padding.PSS.MAX_LENGTH
                            ),
                            hashes.SHA256()
                        )
                        print("Signed successfully")
                        print(signature)

                        # writes signature, encrypted key and cipher to file
                        with open(f"{folder_name}/encrypted/{file_name}", 'wb') as cipher_file:
                            cipher_file.write(b"START OF SIGNATURE\n")
                            cipher_file.write(signature)
                            cipher_file.write(b"\nEND OF SIGNATURE\n")
                            cipher_file.write(b"START OF ENCRYPTED KEY\n")
                            cipher_file.write(encrypted_key)
                            cipher_file.write(b"\nEND OF ENCRYPTED KEY\n")
                            cipher_file.write(cipher)

                elif choice == '3':
                    print("Select images only")
                    root = tk.Tk()
                    root.withdraw()
                    root.call('wm', 'attributes', '.', '-topmost', True)
                    files = filedialog.askopenfilename(multiple=True) # asking the user to select the files for encryption
                    var = root.tk.splitlist(files)
                    print("Files selected successfully......")

                    for f in var:
                        with open(f, 'rb') as file:
                            image = file.read()
                        
                        file_name = f.split("/")[-1]
                        # encrypts image
                        encrypted_key, cipher = encrypt_image(public_key, image)
                        print("Image encryption successful")
                        print(cipher)

                        # signs image
                        signature = private_key.sign(
                            cipher,
                            padding.PSS(
                                mgf=padding.MGF1(hashes.SHA256()),
                                salt_length=padding.PSS.MAX_LENGTH
                            ),
                            hashes.SHA256()
                        )
                        print("Signed successfully")
                        print(signature)

                        # writes signature, encrypted key and cipher to file
                        with open(f"{folder_name}/encrypted/{file_name}", 'wb') as cipher_file:
                            cipher_file.write(b"START OF SIGNATURE\n")
                            cipher_file.write(signature)
                            cipher_file.write(b"\nEND OF SIGNATURE\n")
                            cipher_file.write(b"START OF ENCRYPTED KEY\n")
                            cipher_file.write(encrypted_key)
                            cipher_file.write(b"\nEND OF ENCRYPTED KEY\n")
                            cipher_file.write(cipher)
                
        elif choice == '3':

            # authenticates user
            while True:
                try:
                    folder_name = input("Enter your username: ")
                    key = input("Enter your secret key: ")
                    private_key = load_private_key(folder_name, key)
                    break

                except ValueError:
                    print("Incorrect username or secret key")

            while True:
                print("1. Decrypt a file")
                print("2. Decrypt image")
                print("3. Back to menu")

                choice = input("Select your choice: ")

                # decrypts files
                if choice == '1':
                    print("Files available for decryption: ")
                    # prints list on encrypted files available
                    for file in os.listdir(f"{folder_name}/encrypted"):
                        print(file)

                    # takes filename from user
                    file_name = input("Enter cipher text file path: ")
                    key = b''
                    signature = b''
                    # reads file and gets signature, encrypted key and cipher 
                    with open(f"{folder_name}/encrypted/{file_name}", 'rb') as cipher_file:
                        line = cipher_file.readline()
                        for line in cipher_file:
                            if line.decode('utf-8', "ignore").strip() == 'END OF SIGNATURE':
                                line.decode('utf-8', "ignore").strip()
                                break
                            else:
                                signature += line

                        line = cipher_file.readline()
                        for line in cipher_file:
                            if line.decode('utf-8', "ignore").strip() == 'END OF ENCRYPTED KEY':
                                line.decode('utf-8', "ignore").strip()
                                break
                            else:
                                key += line

                        text = cipher_file.read()

                    # removes trailing new line character '\n'
                    key = key[:-1]
                    signature = signature[:-1]

                    # ask for senders username
                    while True:
                        user_name = input("Enter username of sender: ")
                        if os.path.exists(user_name):
                            break
                        else:
                            print("User doesnt exist. Enter correct username")

                    # loads public key of sender
                    public_key = load_public_key(user_name)

                    # verifies senders signature
                    try:
                        public_key.verify(
                            signature,
                            text,
                            padding.PSS(
                                mgf=padding.MGF1(hashes.SHA256()),
                                salt_length=padding.PSS.MAX_LENGTH
                            ),
                            hashes.SHA256()
                        )

                        print(f"The signature of {file_name} is valid")

                    except cryptography.exceptions.InvalidSignature:
                        print("The signature is not valid")
                        continue
                    
                    # decrypts key 
                    key = decrypt_key(private_key, key)
                    # decrypts text
                    plain_text = decrypt_text(key, text)

                    print("\nDecrypted Message")
                    print(plain_text) 
                    print()

                elif choice == '2':
                    
                    # gets senders username
                    while True:
                        user_name = input("Enter username of sender: ")
                        if os.path.exists(user_name):
                            break
                        else:
                            print("User doesnt exist. Enter correct username")

                    # loads senders public key
                    public_key = load_public_key(user_name)

                    # selects image
                    print("Select images only")
                    root = tk.Tk()
                    root.withdraw()
                    root.call('wm', 'attributes', '.', '-topmost', True)
                    # opens dialog and asks for image
                    files = filedialog.askopenfilename(multiple=False) 
                    var = root.tk.splitlist(files)
                    print("Files selected successfully......")
                    key = b''
                    signature = b''
                    print(var)

                    for file_name in var:
                        print(file_name)
                        # reads file and gets signature, encrypted key and cipher 
                        with open(file_name, 'rb') as cipher_file:
                            line = cipher_file.readline()
                            for line in cipher_file:
                                if line.decode('utf-8', "ignore").strip() == 'END OF SIGNATURE':
                                    line.decode('utf-8', "ignore").strip()
                                    break
                                else:
                                    signature += line

                            line = cipher_file.readline()
                            for line in cipher_file:
                                if line.decode('utf-8', "ignore").strip() == 'END OF ENCRYPTED KEY':
                                    line.decode('utf-8', "ignore").strip()
                                    break
                                else:
                                    key += line

                            text = cipher_file.read()

                        # removes trailing new line character
                        key = key[:-1]
                        signature = signature[:-1]

                        # verifies senders signature
                        try:
                            public_key.verify(
                                signature,
                                text,
                                padding.PSS(
                                    mgf=padding.MGF1(hashes.SHA256()),
                                    salt_length=padding.PSS.MAX_LENGTH
                                ),
                                hashes.SHA256()
                            )

                            print(f"The signature of {file_name} is valid")

                        except cryptography.exceptions.InvalidSignature:
                            print("The signature is not valid")
                            continue
                            
                        file_name = file_name.split('/')[-1]
                        file_name = f"{folder_name}/decrypted/{file_name}" 
                        print(file_name)
                        # decrypts key
                        key = decrypt_key(private_key, key)
                        print(key)
                        # decrypts image
                        plain_text = decrypt_image(key, text)

                        print("\nDecrypted Image")


                elif choice == '3':
                    break
        
        elif choice == 'q':
            break

        else:
            print("Invalid choice")


                    

