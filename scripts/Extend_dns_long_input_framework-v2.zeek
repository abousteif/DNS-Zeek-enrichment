module MyDNSEnrichment;

type Idx: record {
        domain: string;
};

type Val: record {
        enrichment: string &log;
};

global DNSenrichment_table: table[domain] of Val = table();

event zeek_init()
{
    Input::add_table([
        $source="DNSenrichment.csv", 
	$name="DNSenrichment_table",
        $idx=Idx, 
	$val=Val, 
	$destination=DNSenrichment_table,
        $mode=Input::REREAD
    ]);
}
© 2022 GitHub, Inc.
Terms


# Add additional dns fields based on input framework
#Extending the dns.log - adding the following field to the record (dns info is what is logged)
redef record dns::Info += {
	Reputation:	Val	&log	&optional;
};

#The event that will be used to observe all the connections
event connection_state_remove(c: connection)
{
	if ( c$id$query in enrichment_table ){
		c$dns$enrichment_orig=enrichment_table[c$id$query];
	}
}
