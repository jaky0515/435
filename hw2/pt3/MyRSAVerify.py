import json, argparse, hashlib
from pprint import pprint

def load_json(file_name):
	with open(file_name, 'r') as file:
		data = file.read()
	return json.loads(data)

def gcd(n, m):
	if n == 0:
		return m
	return gcd(m%n, n)

def euler_totient(n):
	result = 1
	for i in range(2, n):
		if gcd(i, n) == 1:
			result += 1
		return result

def create_sign(d, n, M):
	return pow(M, d, n)

def calc_priv_exp(e, n):
	return pow(e, -1, euler_totient(n))

"""
main function
"""
def main():
	# get arguments
	pubkey_file_name = 'pubkey.json'
	sign_file_name = 'mysig.json'

	pubkey_data = load_json(pubkey_file_name)
	sign_data = load_json(sign_file_name)

	d = calc_priv_exp(pubkey_data['e'], pubkey_data['n'])
	sign = create_sign(d, pubkey_data['n'], int(hashlib.sha256(sign_data['m']).hexdigest(),16))

	pprint(sign)

if __name__ == "__main__":
	main()