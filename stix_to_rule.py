#!/usr/bin/python
#This script has used some part of TAXIIExample.py from Soltra

import optparse
import ConfigParser
import random
import StringIO
import pycurl
import xml.etree.ElementTree as ET
import datetime
import re


# This function is for searching a word with a list elements


parser = optparse.OptionParser()
group1 = optparse.OptionGroup(parser, 'Extracting Options')
group2 = optparse.OptionGroup(parser, 'Poll Options')
parser.add_option('-c',help = 'to take the configuration file path',action="store",dest="conf_file_path",metavar="<conf_file_path>")
group1.add_option('--hash',help = 'to enable extracting file hashes from the feed',action="store_true",dest="extract_hash",default=False)
group1.add_option('--ip',help = 'to enable extracting IP addresses from the feed',action="store_true",dest="extract_ip",default=False)
group1.add_option('--domain',help = 'to enable extracting domain names from the feed',action="store_true",dest="extract_domain",default=False)
group1.add_option('--url',help = 'to enable extracting URLs from the feed',action="store_true",dest="extract_url",default=False)
group1.add_option('--all',help = 'to enable extracting all four types at once from the feed',action="store_true",dest="extract_all",default=False)
group2.add_option('--since-last-poll',help = 'to enable polling feeds available after last poll time, in this case, start_time is set to the value in \'last_poll_time\' and end_time is set to be the current time ',action="store_true",dest="since_last_poll",default=False)
group2.add_option('--start-time',help = 'to specify the date from which to poll the feed, format 2000-12-30T00:00:00Z',action="store",dest="start_time",metavar="date")
group2.add_option('--end-time',help = 'to specify the date till which to poll the feed, format: 2000-12-30T00:00:00Z',action="store",dest="end_time",metavar="date")


parser.add_option_group(group1)
parser.add_option_group(group2)
(opts,args) = parser.parse_args()


config = ConfigParser.ConfigParser()


if opts.conf_file_path is not None:
	config.read(opts.conf_file_path)
	if not (opts.extract_hash or opts.extract_ip or opts.extract_domain or opts.extract_url or opts.extract_all):
		print "\n\n\n\tYou did not specify option(s) for extracting. See the help below.\n\n\n"
		parser.print_help()
		print "" 
		exit(0)
else:
	print "\n\n\n\tConfiguration file should be provided. See the help below.\n\n\n"
	parser.print_help()
	print ""
	exit(0)


#time command => (date +"%Y-%m-%dT%H:%M:%SZ")




xmlstart = """<?xml version="1.0" encoding="UTF-8" ?>"""


boilerplate = """xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:taxii_11="http://taxii.mitre.org/messages/taxii_xml_binding-1.1" xsi:schemaLocation="http://taxii.mitre.org/messages/taxii_xml_binding-1.1 http://taxii.mitre.org/messages/taxii_xml_binding-1.1" """


message_id = str(random.randint(345271,9999999999))


user_pwd = config.get('feed_options','service_username') + ":" + config.get('feed_options','service_password')


#
# cert_pwd - password emailed from Repository with subject line "Your TAXII Credentials - password"
#
cert_pwd = "test_pass"


#
# fullpath to your certificate (PEM file)
#
pem_file_location = "/opt/soltra/edge/repository/repository_api/tests/xxxx.pem"


start_end = ""
feed_name = config.get('feed_options','feed_name')
taxii_url = config.get('feed_options','feed_service_url')


# In the next few lines, we are trying to time interval for the feed
time_file = open(config.get('feed_options','time_file'),"a+")


if opts.since_last_poll:
	poll_time = time_file.readlines()
	if len(poll_time) != 0:
		start_time = poll_time[0][:-1]
	else:
		start_time = raw_input("\n\n\tLast poll time could not be found! Please enter it below. Example format: 2015-04-18T02:10:10Z \n\n\t")	
#unless since-last-poll is specified, start_time takes value from the "--start-time" option.
	end_time = datetime.datetime.now().isoformat().replace(".","ZX").split("X")[0] # end_time takes value of current time.
else:
	start_time = opts.start_time 
	end_time = opts.end_time 
	if start_time is None or end_time is None:
		print "\n\n\n\tBoth start_time and end_time should be provided. See the help below.\n\n\n"
		parser.print_help()
		print ""		
		exit(0)

time_file.close()	


start_end = """ 
<taxii_11:Exclusive_Begin_Timestamp>%s</taxii_11:Exclusive_Begin_Timestamp>
<taxii_11:Inclusive_End_Timestamp>%s</taxii_11:Inclusive_End_Timestamp>""" % (start_time,end_time)

#-- Poll template ---------------------------------------------------
xml_poll = xmlstart + """ 
<taxii_11:Poll_Request {{boilerplate}} message_id="{{message_id}}" collection_name="{{feed_name}}" >
    <taxii_11:Poll_Parameters allow_asynch="false">
        <taxii_11:Response_Type>FULL</taxii_11:Response_Type>
        <taxii_11:Content_Binding binding_id="{{content_binding}}" />
    </taxii_11:Poll_Parameters>
    {{start_end}}
</taxii_11:Poll_Request>"""


xml=xml_poll.replace('{{boilerplate}}',boilerplate)\
	.replace('{{message_id}}',message_id)\
	.replace('{{feed_name}}',feed_name)\
	.replace('{{start_end}}',start_end)\
	.replace('{{content_binding}}',"urn:stix.mitre.org:xml:1.1.1")




headers = [
    "Content-Type: application/xml",
    "Content-Length: " + str(len(xml)),
    "User-Agent: TAXII Client Application",
    "Accept: application/xml",
    "X-TAXII-Accept: urn:taxii.mitre.org:message:xml:1.1",
    "X-TAXII-Content-Type: urn:taxii.mitre.org:message:xml:1.1",
    "X-TAXII-Protocol: urn:taxii.mitre.org:protocol:https:1.0",
]


buf = StringIO.StringIO()


conn = pycurl.Curl()
conn.setopt(pycurl.URL, taxii_url)
conn.setopt(pycurl.USERPWD, user_pwd)
conn.setopt(pycurl.HTTPHEADER, headers)
conn.setopt(pycurl.POST, 1)
conn.setopt(pycurl.TIMEOUT, 999999)
conn.setopt(pycurl.SSLCERT, pem_file_location)
conn.setopt(pycurl.SSLKEYPASSWD, cert_pwd)
conn.setopt(pycurl.SSL_VERIFYPEER, 0)
conn.setopt(pycurl.SSLVERSION, pycurl.SSLVERSION_TLSv1)
conn.setopt(pycurl.SSL_VERIFYHOST, 0)
conn.setopt(pycurl.WRITEFUNCTION, buf.write)
conn.setopt(pycurl.POSTFIELDS, xml)
conn.perform()


print 'request complete'






#--------------------------------------------------------------------
# example - write raw xml to disk
import HTMLParser
hp = HTMLParser.HTMLParser()
result = hp.unescape(buf.getvalue()).encode('ascii', 'ignore')
try:
	root = ET.fromstring(result.replace("&","and")) # '&' causes error while parsing xml, so we replace in with 'and'
except Exception,e:
	print result
	print "\n\n\n\t\tHey, you got an EXCEPTION. See the details below: \n\n\t\t%s \n\n" % str(e)
	exit(0)


url_stripped_regex = '^[^a-zA-Z0-9]*|[ ]*$'
domain_stripped_regex = '^[^a-zA-Z0-9]*|[^a-zA-Z0-9]*$'
ip_stripped_regex = '^[^0-9]*|[^0-9]*$'
hash_stripped_regex = '^[^a-fA-F0-9]*|[^a-fA-F0-9]*$'


if opts.extract_domain or opts.extract_all:
	dns_filename = config.get("output_files","dns_rules_file")
	dns_file_handle = open(dns_filename,"a+")
	dns_file_handle.write("\n\n" + str(datetime.datetime.now()) + "\n") #datetime.datetime.now().isoformat()
	for domain_object in root.findall(".//{http://cybox.mitre.org/objects#DomainNameObject-1}Value"):
		if domain_object.attrib['condition'] == "Equals":
			stripped_domain = re.sub(domain_stripped_regex,'',domain_object.text)
			dns_file_handle.write("\nalert dns any 53 -> any any (msg:" + "\"Malicious resolution attempt\";dns_query; content:\"" + stripped_domain + "\"; nocase; sid:" + str(random.randint(3000000,4000000)) + ";)\n")
	
	dns_file_handle.close()


if opts.extract_url or opts.extract_all:
	url_filename = config.get("output_files","url_rules_file")
	url_file_handle = open(url_filename,"a+")
	url_file_handle.write("\n\n" + str(datetime.datetime.now()) + "\n") #datetime.datetime.now().isoformat()
	for url_object in root.findall(".//{http://cybox.mitre.org/objects#URIObject-2}Value"):
		if url_object.attrib['condition'] == "Equals":
			stripped_url = re.sub(url_stripped_regex,'',url_object.text)
			if stripped_url.find("://") != -1:
				pos1 = stripped_url.find(":") + 3
				pos2 = stripped_url[pos1:].find("/")
				host_part = stripped_url[pos1:][:pos2]
				uri_part = stripped_url[pos1:][pos2:]


			else:
				pos = stripped_url.find("/")
				host_part = stripped_url[:pos]
				uri_part = stripped_url[pos:]		
					
			url_file_handle.write("\n" + "alert http any any -> any any (msg:\"Malicious site visit attempt\"; content:\"" + host_part+ "\"; http_header; content:\"" + uri_part + "\"; http_uri; sid:" + str(random.randint(345271,9999999999)) + ";)" + "\n")
	
	url_file_handle.close()


if opts.extract_ip or opts.extract_all:
	ip_blacklist_filename = config.get("output_files","ip_blacklist_file")
	ip_file_handle = open(ip_blacklist_filename,"a+")
	ip_file_handle.write("\n\n" + str(datetime.datetime.now()) + "\n") #datetime.datetime.now().isoformat()
	for ip_object in root.findall(".//{http://cybox.mitre.org/objects#AddressObject-2}Address_Value"):
		if ip_object.attrib['condition'] == "Equals" or ip_object.attrib['condition'] == "InclusiveBetween":
			stripped_ip = re.sub(ip_stripped_regex,'',ip_object.text)
			ip_file_handle.write("\n" + stripped_ip)


	ip_file_handle.close()


if opts.extract_hash or opts.extract_all:
	hash_blacklist_filename = config.get("output_files","hash_blacklist_file")
	hash_file_handle = open(hash_blacklist_filename,"a+")
	hash_file_handle.write("\n\n" + str(datetime.datetime.now()) + "\n") #datetime.datetime.now().isoformat()
	for hash_object in root.findall(".//{http://cybox.mitre.org/common-2}Hash"):
		if hash_object.find("{http://cybox.mitre.org/common-2}Type").text == "MD5":
			if hash_object.find(".{http://cybox.mitre.org/common-2}Simple_Hash_Value").attrib['condition'] == "Equals":
				stripped_hash = re.sub(hash_stripped_regex,'',hash_object.find(".{http://cybox.mitre.org/common-2}Simple_Hash_Value").text)
				hash_file_handle.write("\n" + stripped_hash)
	
	hash_file_handle.close()


time_file = open(config.get('feed_options','time_file'),"w")
time_file.write(end_time)
time_file.close()
