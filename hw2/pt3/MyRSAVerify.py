"""
This file contains python code for HW2 part3 verify
@author: Kevin Jang (kj460)
"""

import json, argparse, hashlib, sys

"""
this function converts data to JSON format
"""
def load_json(file_name):
	with open(file_name, 'r') as file:
		data = file.read()
	return json.loads(data)

"""
this function decrypts the sign
"""
def decrypt_sign(e, n, sign):
	return pow(sign, e, n)

"""
this function controls the argument parameters
"""
def get_args():
	parser = argparse.ArgumentParser()
	# list of possible arguments
	parser.add_argument(dest="pubkey_file_name")
	parser.add_argument(dest="sign_file_name")
	return parser.parse_args()

"""
main function
"""
def main():
	# get arguments
	args = get_args()

	pubkey_file_name = args.pubkey_file_name
	sign_file_name = args.sign_file_name

	pubkey_data = load_json(pubkey_file_name)
	sign_data = load_json(sign_file_name)

	decrypted_sign = decrypt_sign(pubkey_data['e'], pubkey_data['n'], sign_data['sig'])
	hashed_m = int(hashlib.sha256(sign_data['m']).hexdigest(),16)
	if decrypted_sign == hashed_m:
		sys.stdout.write("True\n")
	else:
		sys.stdout.write("False\n")

if __name__ == "__main__":
	main()