import os , base64 , getpass , time , ntplib

# Load the plugin for the applicable cryptocurrency:
from PodiumBackend.cryptoPlugin import MetaHash as coin

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
		if (not (os.path.exists(self.backend))):
			os.makedirs(self.backend)

		# Load the user's private and public keys:
		self.publicKey , self.privateKey = self.keyHandling()

		# Load the user's wallet object:
		self.wallet = coin(self.backend)

		# Set the time difference (may remove this later):
		#self.timeDiff = self.timeSync()

	def keyHandling(self):
		'''
		This fuction is designed to create or load the user's public and private RSA 8192-bit keys, and store them in local files encrypted with a password.
		'''
		if ((os.path.isfile((self.backend + 'pubKey.podium')) and os.path.isfile((self.backend + 'privKey.podium'))) and os.path.isfile((self.backend + 'salt.podium'))):
			password = (getpass.getpass('Password:\t')).encode()

			with open((self.backend + 'salt.podium') , 'rb') as file:
				salt = file.read()

			symKey = base64.urlsafe_b64encode((PBKDF2HMAC(algorithm = hashes.SHA512() , length = 32 , salt = salt , iterations = 100000 , backend = default_backend())).derive(password))
			fernet = Fernet(symKey)

			try:
				with open((self.backend + 'pubKey.podium') , 'rb') as file:
					pubKey = fernet.decrypt(file.read())
				with open((self.backend + 'privKey.podium') , 'rb') as file:
					privKey = fernet.decrypt(file.read())
			except:
				print('Unable to decrypt your public and private keys.\nThese keys are necessary for Podium to run.\nPlease make sure you entered the correct password.')
				exit()
				
		else:
			asymKeys = RSA.generate(8192 , Random.new().read)
			pubKey , privKey = asymKeys.publickey().exportKey('PEM') , asymKeys.exportKey('PEM')
			password = (getpass.getpass('Password:\t')).encode()

			salt = os.urandom(16)
			with open((self.backend + 'salt.podium') , 'wb') as file:
				file.write(salt)

			symKey = base64.urlsafe_b64encode((PBKDF2HMAC(algorithm = hashes.SHA512() , length = 32 , salt = salt , iterations = 100000 , backend = default_backend())).derive(password))
			fernet = Fernet(symKey)

			with open((self.backend + 'pubKey.podium') , 'wb') as file:
				file.write(fernet.encrypt(pubKey))
			with open((self.backend + 'privKey.podium') , 'wb') as file:
				file.write(fernet.encrypt(privKey))

		return pubKey , privKey

	# May remove this function later:
	def timeSync(self):
		'''
		Get an accurate time to allow synchronized updates with other nodes. This is critical, especially when communicating with nodes behind NAT.
		'''
		for i in range(0 , 5):
			try:
				ntpResponse = ntplib.NTPClient().request('time.nist.gov')
				return ntpResponse.offset
			except:
				time.sleep(4)

		print('Unable to contact time servers')
		exit()
