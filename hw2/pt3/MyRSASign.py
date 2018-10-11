"""
This file contains python code for HW2 part3 sign
@author: Kevin Jang (kj460)
"""

import json, argparse, hashlib

"""
this function converts data to JSON format
"""
def load_json(file_name):
	with open(file_name, 'r') as file:
		data = file.read()
	return json.loads(data)

"""
this function creates a sign
"""
def create_sign(d, n, M):
	return pow(M, d, n)

"""
this function writes a JSON file
"""
def write_json(json_dict, file_name):
	json_data = json.dumps(json_dict)
	with open(file_name, 'w') as file:
		file.write(json_data)

"""
this function controls the argument parameters
"""
def get_args():
	parser = argparse.ArgumentParser()
	# list of possible arguments
	parser.add_argument(dest="privkey_file_name")
	parser.add_argument(dest="msg")
	return parser.parse_args()

"""
main function
"""
def main():
	# get arguments
	args = get_args()

	privkey_file_name = args.privkey_file_name
	msg = args.msg

	privkey_data = load_json(privkey_file_name)
	sign = create_sign(privkey_data['d'], privkey_data['n'], int(hashlib.sha256(msg).hexdigest(),16))
	write_json({'sig': sign, 'm': msg}, 'mysig.json')

if __name__ == "__main__":
	main()