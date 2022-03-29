module MyDNSEnrichment;

# Add additional dns fields based on input framework
#Extending the dns.log - adding the following field to the record (dns info is what is logged)
redef record dns::Info += {
	enrichment_uri:	Val	&log	&optional;
};

#The event that will be used to observe all the connections
event connection_state_remove(c: connection)
{
	if ( c$id$uri in enrichment_table ){
		c$dns$enrichment_orig=enrichment_table[c$id$uri];
	}
}
