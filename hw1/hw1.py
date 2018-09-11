import socket, sys, select, argparse, signal

"""
this function exits the program
"""
def exit_program():
	listen_socket.close()
	exit(0)

"""
this function handles CTRL+C
"""
def sigint_handler(signum, frame):
	exit_program()

signal.signal(signal.SIGINT, sigint_handler)

parser = argparse.ArgumentParser()
# list of possible arguments
parser.add_argument("-s", dest="wait", action="store_true", default=False)
parser.add_argument("-p", dest="port")
parser.add_argument("-c", dest="hostname")
# collect all the arguments from the parser
args = parser.parse_args()

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
					exit_program()
				else:
					sys.stdout.write("%s\n" % data.rstrip())
			else:
				connected_client, addr = ready.accept()
				connected_clients.append(connected_client)
			is_connected = True
		elif ready is sys.stdin:
			message = raw_input()
			if args.wait is True:
				connected_client.send(message)
			else:
				listen_socket.send(message)
		else:
			data = ready.recv(1024)
			if len(data) == 0:
				exit_program()
			else:
				sys.stdout.write("%s\n" % data.rstrip())