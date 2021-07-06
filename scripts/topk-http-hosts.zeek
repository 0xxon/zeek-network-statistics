##! Script to count the top HTTP hosts that we encounter

module NetworkStats;

event zeek_init()
	{
	create_topk_measurement("http-hosts");
	}


event HTTP::log_http(i: HTTP::Info)
	{
	if ( i?$host )
		topk_observation("http-hosts", "", i$host);
	}
