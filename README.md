# ConvertSTIXtoSuricataRules

**[General Information]**

This script is able to extract IP addresses in a feed and make a rule at which a list of IP addresses is matched. Every time a 
feed is polled and IP addresses are extracted, that list of IP addresses, namely the blacklist will grow. This rule will enable
Suricata to recognize emerging bad IPs and alert or drop them once detected. <br /><br />
Likely, malicious domains can be extracted from a feed with the help of the script. After extracting domain names, the script
will create DNS level rules for Suricata which will look for that domains in DNS responses. If a DNS response contains such a
domain name, it is an indication of a client in our network, attempting to go to that address and awaiting name resolution to
happen. This script will help us to be alert to previously unknown malicious domains visited by users in our local network. <br /><br />
Another type of threat that an IPS/IDS engine is supposed to be fighting against, are malicious pages. This script is also able
to generate Suricata rules at HTTP level using HTTP keywords after extracting URL data from a feed downloaded. <br />
Considering the Suricata feature of calculating the hash of a file opened/downloaded over HTTP and matching that hash against
blacklist of hashes, another feature that we have added to the script is to extract MD5 hash values from a feed and update the
MD5 hash blacklist with newest threats' hash values. <br />
