# dns-whitelist

Simple application that uses an ip address resolved from a DNS record as the single ip to whitelist via an Oracle cloud network security group.
I use this application to provide ip based restrictions on my cloud host. Note: this is just to avoid traffic spam from outside hosts and nothing more. Proper 
authorization still exists at the application level. 

Environment Variables:

* `NSG_ID` - The OCID for the network security group to update
* `DNS_RECORD` - The full DNS name to use for looking up the ip address to whitelist