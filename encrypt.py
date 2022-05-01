"""
Description: A backend script that uses pgp to encrypt data.
Author: Aleksa Zatezalo
Date: May 2022
"""

import pgpy
import fcntl, os, sys

global g_key

def setKey(key):
    """
    A function to set the g_key to key.
    """

    g_key = key

def saveKey(name):
    """
    Saves a key to a new file.
    """

     f = open(name, "w")
     f.write(g_key)

def openKey(name):
    """
    Opens key from file.
    """    

    f = open(name, "r")
    setKey(f.read()))


def genKeys():
    """
    A function to generate public and privite keys.
    """
    
    key = pgpy.PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 4096)

    # we now have some key material, but our new key doesn't have a user ID yet, and therefore is not yet usable!
    uid = pgpy.PGPUID.new('Abraham Lincoln', comment='Honest Abe', email='abraham.lincoln@whitehouse.gov')

    # now we must add the new user id to the key. We'll need to specify all of our preferences at this point
    # because PGPy doesn't have any built-in key preference defaults at this time
    # this example is similar to GnuPG 2.1.x defaults, with no expiration or preferred keyserver
    key.add_uid(uid, usage={KeyFlags.Sign, KeyFlags.EncryptCommunications, KeyFlags.EncryptStorage},
                hashes=[HashAlgorithm.SHA256, HashAlgorithm.SHA384, HashAlgorithm.SHA512, HashAlgorithm.SHA224],
                ciphers=[SymmetricKeyAlgorithm.AES256, SymmetricKeyAlgorithm.AES192, SymmetricKeyAlgorithm.AES128],
                compression=[CompressionAlgorithm.ZLIB, CompressionAlgorithm.BZ2, CompressionAlgorithm.ZIP, CompressionAlgorithm.Uncompressed])
    setKey(key)
    return key

def pgpy_encrypt(key, data):
    """
    Encrypts data using key.
    """

    message = pgpy.PGPMessage.new(data)
    enc_message = key.pubkey.encrypt(message)
    return bytes(enc_message)


def pgpy_decrypt(key, enc_data):
    """
    Decrypts data using key.
    """

    message = pgpy.PGPMessage.from_blob(enc_data)
    return str(key.decrypt(message).message)

def encryptFile(path, key):
    """
    A function that encrypts the content of a file at path path, using
    the cypher indicated by the cypher var.
    """

    f = open("D:\\myfiles\welcome.txt", "w")
    data = f.read()
    enc = pgpy_encrypt(g_key, data)
    f.write(enc)

def dencryptFile(path, key):
    """
    A function that dencrypts the content of a file at path path, using
    the cypher indicated by the cypher var.
    """

    f = open("D:\\myfiles\welcome.txt", "w")
    data = f.read()
    denc = pgpy_encrypt(g_key, data)
    f.write(denc)