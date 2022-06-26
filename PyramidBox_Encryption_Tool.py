#!/usr/bin/python3

try:
	from Crypto import Random
	from Crypto.Util.py3compat import bchr
	from Crypto.Cipher import AES
	from Crypto.Protocol.KDF import PBKDF2
	from Crypto.Hash import SHA256	
except:
	print("------------------------------------")
	print("\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\")
	print("     PyramidBox Encryption Tool")
	print("\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\")

	print("------------------------------------")
	print(" Requirement Package : \"Install Now\"")
	print("------------------------------------")
	print("Express Installation:")
	print("---------------------")
	print("#. Install All: \"sudo pip3 install -r requirements.txt\"")
	print("--------------------")
	print("Custom Installation:")
	print("--------------------")
	print("1. Install pycryptodome: \"sudo pip3 install -r pycryptodome.txt\"")
	print("2. Install pbkdf2: \"sudo pip3 install -r pbkdf2.txt\"")
	print("------------------------------------")
	exit(1)
import os, sys
from base64 import b64encode
from getpass import getpass
import codecs


def main():
	# sanitize input
	if len(sys.argv) < 2:
		print("------------------------------------")
		print("\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\")
		print("     PyramidBox Encryption Tool")
		print("\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\")
		
		print("------------------------------------")
		print("             User Guide")
		print("------------------------------------")
		print("#:\n%s filename [passphrase]"%sys.argv[0])
		exit(0)
	inputfile = sys.argv[1]
	try:
		with open(inputfile, "rb") as f:
			data = f.read()
	except:
		print("Cannot open file: %s"%inputfile)
		exit(1)

	if len(sys.argv) > 2:
		passphrase = sys.argv[2]
	else:
		while True:
			passphrase = getpass(prompt='Password: ')
			if passphrase == getpass(prompt='Confirm: '):
				break
			print("Passwords don\'t match, Please try again.")

	salt = Random.new().read(32)
	key = PBKDF2(
		passphrase.encode('utf-8'), 
		salt, 
		count=100000,
		dkLen=32, 
		hmac_hash_module=SHA256
	)
	iv = Random.new().read(16)

	cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
	encrypted, tag = cipher.encrypt_and_digest(data)

	projectFolder = os.path.dirname(__file__)
	with open(os.path.join(projectFolder, "encryptTemplate.html")) as f:
		templateHTML = f.read()


	encryptedPl = f'"{b64encode(salt+iv+encrypted+tag).decode("utf-8")}"'
	encryptedDocument = templateHTML.replace("/*{{ENCRYPTED_PAYLOAD}}*/\"\"", encryptedPl)

	filename, extension = os.path.splitext(inputfile)
	outputfile = filename + "-Encrypted" + extension
	with codecs.open(outputfile, 'w','utf-8-sig') as f:
		f.write(encryptedDocument)
	print("File saved to %s"%outputfile)

if __name__ == "__main__":
	main()