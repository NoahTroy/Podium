import os , base64 , getpass

# Modules for handling asymmetric cryptography:
from Crypto.PublicKey import RSA
from Crypto import Random

#Modules for handling symmetric cryptography:
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet

class Node:
	'''
	Create a node on the Podium network capable of executing the following tasks:
	 - Automatically selecting and saving media segments
	 - Receiving and forwarding media requests
	 - Transmitting requested media segment back to the requesting party
	 - Sending and receiving PO
	 - Recording and storing PO ledger
	 - Making a media request
	 - Reconstructing received media
	'''
	def __init__(self):
		# Set backend folder location:
		self.backend = './PodiumBackend/'
		# Load the user's private and public keys:
		self.publicKey , self.privateKey = self.keyHandling()

	def keyHandling():
		if (os.file.exists((self.backend + 'pubKey.podium')) and os.file.exists((self.backend + 'privKey.podium'))):
			password = (getpass.getpass('Password:\t')).encode()
			symKey = base64.urlsafe_b64encode((PBKDF2HMAC(algorithm = hashes.SHA512() , length = 32 , iterations = 100000 , backend = default_backend())).derive(password))
			fernet = Fernet(symKey)

			with open((self.backend + 'pubKey.podium') , 'rb') as file:
				pubKey = fernet.decrypt(file.read())
			with open((self.backend + 'privKey.podium') , 'rb') as file:
				privKey = fernet.decrypt(file.read())
				
		else:
			asymKeys = RSA.generate(8192 , Random.new().read)
			pubKey , privKey = asymKeys.publickey().exportKey('PEM') , asymKeys.exportKey('PEM')
			password = (getpass.getpass('Password:\t')).encode()
			symKey = base64.urlsafe_b64encode((PBKDF2HMAC(algorithm = hashes.SHA512() , length = 32 , iterations = 100000 , backend = default_backend())).derive(password))
			fernet = Fernet(symKey)

			with open((self.backend + 'pubKey.podium') , 'wb') as file:
				file.write(fernet.encrypt(pubKey))
			with open((self.backend + 'privKey.podium') , 'wb') as file:
				file.write(fernet.encrypt(privKey))

		return pubKey , privKey
