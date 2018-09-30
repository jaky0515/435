import socket, sys, select, argparse, signal, hashlib
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto import Random
from pprint import pprint

key_size_bits = 256
key_size_bytes = 32

"""
this function exits the program
"""
def exit_program(socket):
	socket.close()
	exit(0)

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

def get_aes_enc_cipher(confkey, iv):
	# AES-256-CBC AESCipher object
	aes_cipher = AES.new(confkey, AES.MODE_CFB, iv)
	print("{}".format(iv))
	return aes_cipher

def aes_decrypt(confkey, cipher_msg):
	# extract initialization vector from the cipher message
	iv = cipher_msg[:AES.block_size]
	print("{}".format(iv))
	# AES-256-CBC AESCipher object
	aes_cipher = AES.new(confkey, AES.MODE_CBC, iv)
	print("cipher_msg = {}".format(cipher_msg[AES.block_size:]))
	return aes_cipher.decrypt(cipher_msg[AES.block_size:])

"""
main function
"""
def main():
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

	# initialization vector for AES-256-CBC encryption
	iv_enc = Random.new().read(AES.block_size)
	# use confidentiality key for AES-256-CBC encryption
	aes_enc_cipher = get_aes_enc_cipher(confkey_256, iv_enc)

	# use authenticity key to compute the SHA-256-based HMAC (encrypt-then-MAC scheme)

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
						# sys.stdout.write("{} | {}\n".format(aes_dec_cipher.decrypt(data.rstrip()), data.rstrip()))
						sys.stdout.write("{}".format(aes_decrypt(confkey_256, data.rstrip())))
				else:
					connected_client, addr = ready.accept()
					connected_clients.append(connected_client)
				is_connected = True
			elif ready is sys.stdin:
				plain_msg = raw_input()
				cipher_msg = iv_enc + aes_enc_cipher.encrypt(plain_msg)
				if args.wait is True:
					connected_client.send(cipher_msg)
				else:
					listen_socket.send(cipher_msg)
			else:
				data = ready.recv(1024)
				if len(data) == 0:
					exit_program(listen_socket)
				else:
					# sys.stdout.write("{} | {}\n".format(aes_dec_cipher.decrypt(data.rstrip()), data.rstrip()))
					sys.stdout.write("{}".format(aes_decrypt(confkey_256, data.rstrip())))

if __name__ == "__main__":
	main()