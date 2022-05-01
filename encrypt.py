"""
Description: A backend script that uses pgp to encrypt data.
Author: Aleksa Zatezalo
Date: May 2022
"""

import pgpy
import fcntl, os, sys

global privKey, pubKey

def setPrivKey(path):
    """
    A function to set the Priv Key to a key at path.
    """
    pass

def setPupKey(path):
    """
    A function to set the Public Key to a key at path.
    """
    pass

def genKeys():
    """
    A function to generate public and privite keys.
    """
    pass

def encryptFile(path, cypher):
    """
    A function that encrypts the content of a file at path path, using
    the cypher indicated by the cypher var.
    """
    pass
