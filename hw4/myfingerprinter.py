'''
This file contains the python code that train the model using the training pcap data-set and test the built model using the test pcap data-set to make its prediction
@author: Kevin Jang (kj460)
@last_updated: 11/28/18
'''

from scapy.all import *
from pprint import pprint
import sys

def read_pcap_file( file_name ):
	'''
	This function reads pcap file and return its features. 
	Used this page (https://medium.com/@vworri/extracting-the-payload-from-a-pcap-file-using-python-d938d7622d71) as a reference
	@param:
		file_name - name of the pcap file
	@return:
		num_in_packets - number of inbound packets
		num_out_packets - number of outbound packets
		first_packet_timestamp - timestamp of the first packet
		last_packet_timestamp - timestamp of the last packet
	'''
	sessions = rdpcap( file_name ).sessions()
	num_in_packets = 0
	num_out_packets = 0
	first_packet_timestamp = None
	last_packet_timestamp = None
	for session in sessions:
		for packet in sessions[session]:
			if not first_packet_timestamp:
				first_packet_timestamp = packet[ TCP ].time
			last_packet_timestamp = packet[ TCP ].time

			if IP in packet:
				ip_src = packet[ IP ].src
				ip_dst = packet[ IP ].dst
			if TCP in packet:
				tcp_src_port = packet[ TCP ].sport
				tcp_src_dport = packet[ TCP ].dport

			if packet[ Ether ].src.lower() == get_if_hwaddr( conf.iface ).lower():
				num_in_packets += 1
			else:
				num_out_packets += 1
	return num_in_packets, num_out_packets, first_packet_timestamp, last_packet_timestamp
			
def train():
	'''
	This function trains the model using the provided training data-set and return the model information
	@return:
		model_info - dictionary that contains the averaged feature values of each site
	'''
	print( '** Start training...' )
	pcap_file_names = [
		'canvas',
		'google',
		'tor',
		'spider',
		'neverssl',
		'acm',
		'autolab',
	]
	MAX_ITER = 10
	model_info = {}
	for file_name in pcap_file_names:
		total_num_in_packets = 0
		total_num_out_packets = 0
		total_duration = 0
		for i in range( 0, MAX_ITER ):
			print( '\t* Reading {}_{}.pcap...'.format( file_name, i ) )
			num_in_packets, num_out_packets, first_packet_timestamp, last_packet_timestamp = read_pcap_file( '{}_{}.pcap'.format( file_name, i ) )
			total_num_in_packets += num_in_packets
			total_num_out_packets += num_out_packets
			total_duration += last_packet_timestamp - first_packet_timestamp
		model_info[ file_name ] = {}
		model_info[ file_name ][ 'num_in_packets' ] = total_num_in_packets / float( MAX_ITER )
		model_info[ file_name ][ 'num_out_packets' ] = total_num_out_packets / float( MAX_ITER )
		model_info[ file_name ][ 'duration' ] = total_duration / float( MAX_ITER )
	return model_info

def test( file_name, model_info ):
	'''
	This function test the model using the given test file and return its prediction
	@param:
		file_name - name of the test pcap file
		model_info - dictionary that contains the averaged feature values of each site
	@return:
		predicted site label
	'''
	print( '** Start testing...' )
	print( '\t* Reading {}...'.format( file_name ) )
	num_in_packets, num_out_packets, first_packet_timestamp, last_packet_timestamp = read_pcap_file( file_name )

	test_result = {}
	for site in model_info:
		# calculate distances
		distances = [ abs( num_in_packets - model_info[ site ][ 'num_in_packets' ] ), 
						abs( num_out_packets - model_info[ site ][ 'num_out_packets' ] ),
						abs( ( last_packet_timestamp - first_packet_timestamp ) - model_info[ site ][ 'duration' ] ) ]
		# normalize distances
		norm_distances = [ float( i ) / sum( distances ) for i in distances ]
		# calculate the average distance
		test_result[ site ] = ( norm_distances[ 0 ] + norm_distances[ 1 ] + norm_distances[ 2 ] ) / float( len( norm_distances ) )

	predicted_site = None
	predicted_site_val = None
	for site in test_result:
		if not predicted_site or predicted_site_val > test_result[ site ]:
			predicted_site = site
			predicted_site_val = test_result[ site ]
	return predicted_site

def main():
	'''
	This is the main driver function
	'''
	# validation
	if len( sys.argv ) != 2:
		print( "Error: test file name is not provided! Terminating...\n" )
		exit()

	# train with the training data set
	model_info = train()
	# test with the testing data set
	matching_site = test( sys.argv[ 1 ], model_info )
	# print result
	print( '** Result: \"{}\"'.format( matching_site ) )

if __name__ == "__main__":
	main()