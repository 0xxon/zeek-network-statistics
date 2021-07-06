##! Script measuring the top-dns-queries

module NetworkStats;

export {
	redef enum Log::ID += { TOPK_LOG };

	global topk_log_policy: Log::PolicyHook;

	global measurement_intervals: set[interval] = set(5mins, 15mins, 1hr, 1day);

	type TopKInfo: record {
		## Time at which the log record was written
		ts: time &log &default=network_time();
		## Duration for which this measurement ran
		duration: interval &log;
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

function create_topk_measurement(name: string)
	{
	local make_epoch_result = function(pass_name: string, pass_intv: interval): function(ts: time, key: SumStats::Key, result: SumStats::Result)
		{
		return function [pass_name, pass_intv] (ts: time, key: SumStats::Key, result: SumStats::Result)
			{
			local r = result[fmt("ns-%s-%s", pass_name, pass_intv)];
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

			local loginfo = TopKInfo($duration=pass_intv, $values=values, $counts=counts, $epsilons=epsilons);

			if ( key?$str )
				loginfo$key = key$str;

			Log::write(TOPK_LOG, loginfo);
			};
		};

	for ( intv in measurement_intervals )
		{
		local r1 = SumStats::Reducer($stream=fmt("ns-%s-%s", name, intv), $apply=set(SumStats::TOPK), $topk_size=1000);

		SumStats::create([$name=fmt("ns-sumstat-%s-%s", name, intv),
											$epoch=intv,
											$reducers=set(r1),
											$epoch_result=make_epoch_result(name, intv)
											]);
		}
	}

function topk_observation(name: string, key: string, value: string)
	{
	for ( intv in measurement_intervals )
		{
		SumStats::observe(fmt("ns-%s-%s", name, intv), [$str=key], [$str=value]);
		}
	}

event zeek_init()
	{
	Log::create_stream(NetworkStats::TOPK_LOG, [$columns=TopKInfo, $path="ns", $policy=topk_log_policy]);
	create_topk_measurement("dns");
	}

event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count)
	{
	if ( c$id$resp_p == 53/udp && query != "" )
		topk_observation("dns", DNS::query_types[qtype], query);
	}
