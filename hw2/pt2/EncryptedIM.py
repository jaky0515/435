"""
this file contains python code for HW2 part 2
@author: Kevin Jang (kj460)
"""

import socket, sys, select, argparse, signal, hashlib, hmac
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto import Random
from pprint import pprint

listen_socket = None

"""
this function exits the program
"""
def exit_program(socket):
	socket.close()
	exit(0)

"""
this function controls the argument parameters
"""
def get_args():
	parser = argparse.ArgumentParser()
	# list of possible arguments
	parser.add_argument("-s", dest="wait", action="store_true", default=False)
	parser.add_argument("-p", dest="port")
	parser.add_argument("-c", dest="hostname")
	parser.add_argument("--confkey", dest="confkey", required=True)
	parser.add_argument("--authkey", dest="authkey", required=True)
	# collect all the arguments from the parser
	return parser.parse_args()

"""
this function creates AES-256-CBC AESCipher object and return it
"""
def create_aes_cipher(confkey, iv, mode):
	# AES-256-CBC AESCipher object
	aes_cipher = AES.new(confkey, mode, iv)
	return aes_cipher

"""
this function performs an AES encryption and returns a cipher text
"""
def aes_encrypt(confkey, authkey, plain_msg, mode):
	# create AESCipher object with random generated IV
	iv = Random.new().read(AES.block_size)
	aes_cipher = create_aes_cipher(confkey, iv, mode)
	# add padding to a plain message and encrypt padded message and add IV
	cipher_msg = iv + aes_cipher.encrypt( pad(plain_msg, AES.block_size) )
	# create signature using HMAC (encrypt-then-MAC)
	sign = hmac.new(authkey, cipher_msg, hashlib.sha256).digest()
	return cipher_msg + sign

"""
this function performs an AES decryption and returns a plain text
"""
def aes_decrypt(confkey, authkey, cipher, mode):
	# split the cipher to get signatrure and cipher message
	rec_sign = cipher[-(hashlib.sha256().digest_size):]
	cipher_msg = cipher[:-(hashlib.sha256().digest_size)]
	# validate received signature
	check_sign( hmac.new(authkey, cipher_msg, hashlib.sha256).digest(), rec_sign )
	# create AESCipher object using the data received
	iv = cipher_msg[:AES.block_size]
	aes_cipher = create_aes_cipher(confkey, iv, mode)
	# decrypt to get padded message and unpad that message to get a plain message
	return unpad( aes_cipher.decrypt(cipher_msg[AES.block_size:]) )

"""
this function addes padding to a message and return it
"""
def pad(msg, block_size):
	pad_len = block_size - (len(msg) % block_size)
	msg += chr(pad_len) * pad_len
	return msg

"""
this function removes padding from a padded message and return it
"""
def unpad(msg):
	return msg[:-ord(msg[-1])]

"""
this function verifies the signature
"""
def check_sign(my_sign, rec_sign):
	global listen_socket
	if not hmac.compare_digest(my_sign, rec_sign):
		raise Exception('Invalid signature detected! Exiting...')
		exit_program(listen_socket)

"""
main function
"""
def main():
	global listen_socket

	"""
	this function handles CTRL+C
	"""
	def sigint_handler(signum, frame):
		exit_program(listen_socket)

	# setting a signal to handle CTRL+C
	signal.signal(signal.SIGINT, sigint_handler)

	# get arguments
	args = get_args()

	# SHA-256 hash on keys to force the size to be equal to 256; convert each string key to a byte string
	confkey_256 = hashlib.sha256(args.confkey.encode()).digest()
	authkey_256 = hashlib.sha256(args.authkey.encode()).digest()

	listen_socket = socket.socket(socket.AF_INET,socket.SOCK_STREAM)

	if args.wait is True:
		listen_socket.bind(('', int(args.port)))
		listen_socket.listen(1)
	else:
		listen_socket.connect((args.hostname, int(args.port)))

	connected_clients = []
	connected_client = None
	is_connected = False

	while True:
		read_list = [sys.stdin, listen_socket] + connected_clients
		(ready_list, _, _) = select.select(read_list, [], [])

		for ready in ready_list:
			if ready is listen_socket and args.wait is True:
				if is_connected is True:
					data = ready.recv(1024)
					if len(data) == 0:
						exit_program(listen_socket)
					else:
						sys.stdout.write("{}\n".format(aes_decrypt(confkey_256, authkey_256, data.rstrip(), AES.MODE_CBC)))
				else:
					connected_client, addr = ready.accept()
					connected_clients.append(connected_client)
				is_connected = True
			elif ready is sys.stdin:
				# gets a cipher text
				cipher = aes_encrypt(confkey_256, authkey_256, raw_input(), AES.MODE_CBC)
				if args.wait is True:
					connected_client.send(cipher)
				else:
					listen_socket.send(cipher)
			else:
				data = ready.recv(1024)
				if len(data) == 0:
					exit_program(listen_socket)
				else:
					sys.stdout.write("{}\n".format(aes_decrypt(confkey_256, authkey_256, data.rstrip(), AES.MODE_CBC)))

if __name__ == "__main__":
	main()