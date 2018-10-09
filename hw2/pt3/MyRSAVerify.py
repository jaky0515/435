import json, argparse, hashlib, sys

def load_json(file_name):
	with open(file_name, 'r') as file:
		data = file.read()
	return json.loads(data)

def create_sign(d, n, M):
	return pow(M, d, n)

"""
main function
"""
def main():
	# get arguments
	pubkey_file_name = 'pubkey.json'
	sign_file_name = 'mysig.json'

	pubkey_data = load_json(pubkey_file_name)
	sign_data = load_json(sign_file_name)

	decrypted_sign = create_sign(pubkey_data['e'], pubkey_data['n'], sign_data['sig'])
	hashed_m = int(hashlib.sha256(sign_data['m']).hexdigest(),16)
	if decrypted_sign == hashed_m:
		sys.stdout.write("True\n")
	else:
		sys.stdout.write("False\n")

if __name__ == "__main__":
	main()