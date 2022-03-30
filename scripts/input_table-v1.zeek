module MyDNSEnrichment;

type Idx: record {
        uri: domain;
};

type Val: record {
        reason: string;
};

global DNSenrichment_table: table[domain] of Val = table();

event zeek_init()
{
    Input::add_table([
        $source="DNSenrichment.csv", $name="DNSenrichment_table",
        $idx=Idx, $val=Val, $destination=DNSenrichment_table,
        $mode=Input::REREAD
    ]);
}
