##! Script measuring the top-dns-queries

module NetworkStats;

event zeek_init()
	{
	create_topk_measurement("dns");
	}

event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count)
	{
	if ( c$id$resp_p == 53/udp && query != "" )
		topk_observation("dns", DNS::query_types[qtype], query);
	}
