##! Script measuring the top-dns-queries

module NetworkStats;

export {
	redef enum Log::ID += { TOPK_LOG };

	global topk_log_policy: Log::PolicyHook;

	type TopKInfo: record {
		## Time at which the log record was written
		ts: time &log &default=network_time();
		## Key of the measurement
		key: string &log &optional;
		## Values of the measurement
		values: vector of string &log;
		## Counts of the topk-measurement
		counts: vector of count &log;
		## Epsilons of the topk-measurement
		epsilons: vector of count &log;
	};
}

event zeek_init()
	{
	Log::create_stream(NetworkStats::TOPK_LOG, [$columns=TopKInfo, $path="ns", $policy=topk_log_policy]);

	local r1 = SumStats::Reducer($stream="ns-dns-15min", $apply=set(SumStats::TOPK), $topk_size=1000);
	SumStats::create([$name="ns-sumstat-dns-15min",
	                  $epoch=15min,
	                  $reducers=set(r1),
	                  $epoch_result(ts: time, key: SumStats::Key, result: SumStats::Result) =
	                  	{
	                  	local r = result["ns-dns-15min"];
	                  	local s: vector of SumStats::Observation;
	                  	s = topk_get_top(r$topk, 100);

	                  	local values: vector of string = vector();
	                  	local counts: vector of count = vector();
	                  	local epsilons: vector of count = vector();
	                  	for ( element in s )
	                  		{
	                  		values += s[element]$str;
	                  		counts += topk_count(r$topk, s[element]);
	                  		epsilons += topk_epsilon(r$topk, s[element]);
	                  		}

	                  	local loginfo = TopKInfo($values=values, $counts=counts, $epsilons=epsilons);
	                  	if ( key?$str )
	                  		loginfo$key = key$str;
	                  	Log::write(TOPK_LOG, loginfo);
	                  	}
	                  ]);
    }

event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count)
	{
	if ( c$id$resp_p == 53/udp && query != "" )
		SumStats::observe("ns-dns-15min", [$str=DNS::query_types[qtype]], [$str=query]);
	}
