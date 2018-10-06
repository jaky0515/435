import json, argparse, hashlib
from pprint import pprint

def load_json(file_name):
	with open(file_name, 'r') as file:
		data = file.read()
	return json.loads(data)

def create_sign(d, n, M):
	return pow(M, d, n)

def write_json(json_dict, file_name):
	json_data = json.dumps(json_dict)
	with open(file_name, 'w') as file:
		file.write(json_data)

"""
main function
"""
def main():
	# get arguments

	privkey_file_name = 'privkey.json'
	msg = 'hello world'

	privkey_data = load_json(privkey_file_name)
	sign = create_sign(privkey_data['d'], privkey_data['n'], int(hashlib.sha256(msg).hexdigest(),16))
	write_json({'sig': sign, 'm': msg}, 'mysig.json')

if __name__ == "__main__":
	main()