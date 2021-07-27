##! Script to count the top HTTP hosts that we encounter

event zeek_init()
	{
	NetworkStats::create_topk_measurement("http-hosts");
	}

event HTTP::log_http(i: HTTP::Info)
	{
	if ( i?$host )
		NetworkStats::topk_observation("http-hosts", "", i$host);
	}
