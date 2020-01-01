import os

# Modules for handling key generation and saving:
import hashlib , binascii , getpass , base64
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding , PrivateFormat , NoEncryption , PublicFormat
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet

class MetaHash:
	'''This is the MetaHash plugin for Podium, designating MetaHash as the cryptocurrency used to negotiate among other nodes, and setting the standards.'''

	def __init__(self , backend):
		# Set backend folder location:
		self.backend = backend

		# Load the private and public keys and address for the wallet:
		self.publicKey , self.privateKey , self.address = self.keyHandling()

		print(self.publicKey , self.privateKey , self.address)

	def keyHandling(self):
		if (((os.path.isfile((self.backend + 'metaHashPub.podium')) and os.path.isfile((self.backend + 'metaHashPriv.podium'))) and os.path.isfile((self.backend + 'metaHashSalt.podium'))) and os.path.isfile((self.backend + 'metaHashAddress.podium'))):
			password = (getpass.getpass('Wallet Password:\t')).encode()

			with open((self.backend + 'metaHashSalt.podium') , 'rb') as file:
				salt = file.read()

			symKey = base64.urlsafe_b64encode((PBKDF2HMAC(algorithm = hashes.SHA512() , length = 32 , salt = salt , iterations = 100000 , backend = default_backend())).derive(password))
			fernet = Fernet(symKey)

			try:
				with open((self.backend + 'metaHashPub.podium') , 'rb') as file:
					pubKey = fernet.decrypt(file.read())
				with open((self.backend + 'metaHashPriv.podium') , 'rb') as file:
					privKey = fernet.decrypt(file.read())
				with open((self.backend + 'metaHashAddress.podium') , 'rb') as file:
					address = fernet.decrypt(file.read())
			except:
				print('Unable to decrypt your wallet.\nThis is necessary for Podium to run.\nPlease make sure you entered the correct password.')
				exit()
		else:
			privKey = ec.generate_private_key(ec.SECP256K1() , default_backend())
			pubKey = privKey.public_key()
			privKey = privKey.private_bytes(encoding=Encoding.PEM , format = PrivateFormat.TraditionalOpenSSL , encryption_algorithm=NoEncryption())

			XHex = hex(pubKey.public_numbers().x)[2:]
			YHex = hex(pubKey.public_numbers().y)[2:]
			if ((64 - (len(XHex))) > 0):
				XHex = (('0' * len(XHex)) + XHex)
			if ((64 - (len(YHex))) > 0):
				YHex = (('0' * len(YHex)) + YHex)

			code = ('04' + str(XHex) + str(YHex))

			hs = hashlib.new('sha256')
			hr = hashlib.new('rmd160')

			hs.update(binascii.a2b_hex(code))
			hr.update(binascii.a2b_hex(hs.hexdigest().encode('utf-8')))
			rmd160res = ('00' + hr.hexdigest())
			hs2 = hashlib.new('sha256')
			hs2.update(binascii.a2b_hex(rmd160res.encode('utf-8')))
			sha256rmd160res = hs2.hexdigest()
			hs3 = hashlib.new('sha256')
			hs3.update(binascii.a2b_hex(sha256rmd160res.encode('utf-8')))
			sha256rmd160res = hs3.hexdigest()

			address = ('0x' + rmd160res + sha256rmd160res[0:8])

			pubKey = pubKey.public_bytes(encoding = Encoding.PEM , format = PublicFormat.SubjectPublicKeyInfo)

			password = (getpass.getpass('Wallet Password:\t')).encode()

			salt = os.urandom(16)
			with open((self.backend + 'metaHashSalt.podium') , 'wb') as file:
				file.write(salt)

			symKey = base64.urlsafe_b64encode((PBKDF2HMAC(algorithm = hashes.SHA512() , length = 32 , salt = salt , iterations = 100000 , backend = default_backend())).derive(password))
			fernet = Fernet(symKey)

			with open((self.backend + 'metaHashPub.podium') , 'wb') as file:
				file.write(fernet.encrypt(pubKey))
			with open((self.backend + 'metaHashPriv.podium') , 'wb') as file:
				file.write(fernet.encrypt(privKey))
			with open((self.backend + 'metaHashAddress.podium') , 'wb') as file:
				file.write(fernet.encrypt(address.encode('utf-8')))

		return pubKey , privKey , address
