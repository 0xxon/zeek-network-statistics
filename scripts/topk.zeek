##! Script exposing functions to make taking measurements more convenient

module NetworkStats;

export {
	redef enum Log::ID += { TOPK_LOG };

	global topk_log_policy: Log::PolicyHook;

	option topk_measurement_intervals: set[interval] = set(5mins, 15mins, 1hr, 1day);

	option topk_top = 100;

	option topk_size = 1000;

	option topk_unified_log = F;

	option topk_separate_log = T;

	option topk_per_interval_logs = F;

	type TopKSettings: record {
		## Number of elements to return
		top: count &default=topk_top;
		## Number of elements to keep track of
		topk_size: count &default=topk_size;
		## If set to true, will log to a unified log with all other top-k-measurements
		unified_log: bool &default=topk_unified_log;
		## If set to true, will log to a separate log file.
		separate_log: bool &default=topk_separate_log;
		## If not given, the log-path will be "topk-[name]"
		log_path: string &optional;
		## Measurement intervals for this TopK measurement
		measurement_intervals: set[interval] &default=copy(topk_measurement_intervals);
		## If set to yes, there will be separate logs for each interval. Each log
		## will have a "-interval" added to the end of the log name. This setting
		## only applies if ``separate_log`` is also set to true.
		per_interval_logs: bool &default=topk_per_interval_logs;
	};

	type TopKInfo: record {
		## Time at which the measurement was finished
		ts: time &log;
		## Duration for which this measurement ran
		duration: interval &log;
		## Name of the measurement
		name: string &log;
		## Key of the measurement
		key: string &log &optional;
		## Values of the measurement
		values: vector of string &log;
		## Counts of the topk-measurement
		counts: vector of count &log;
		## Epsilons of the topk-measurement
		epsilons: vector of count &log;
	};

	global create_topk_measurement: function(name: string, settings: TopKSettings &default=[]);

	global log_topk: event(rec: TopKInfo);
}

## topk measurements that we log into the default log
global topk_measurement_default_log: set[string] = {};

global topk_measurements: table[string] of TopKSettings;

redef record Log::Filter += {
	## Addition for NetworkStats - track which measurement to allow to pass through this filter
	ns_measurement: string &optional;
};

hook topk_filter_pass_specific(rec: TopKInfo, id: Log::ID, filter: Log::Filter)
	{
	if ( filter?$ns_measurement && rec$name == filter$ns_measurement)
		return;

	break;
	}

function create_topk_measurement(name: string, settings: TopKSettings &default=[])
	{
	if ( name in topk_measurements )
		{
		Reporter::error("TopK measurement %s was requested to be created; measurement exists already");
		return;
		}

	topk_measurements[name] = settings;

	local make_epoch_result = function(pass_name: string, pass_intv: interval, pass_settings: TopKSettings): function(ts: time, key: SumStats::Key, result: SumStats::Result)
		{
		return function [pass_name, pass_intv, pass_settings] (ts: time, key: SumStats::Key, result: SumStats::Result)
			{
			local r = result[fmt("ns-%s-%s", pass_name, pass_intv)];
			local s: vector of SumStats::Observation;
			s = topk_get_top(r$topk, pass_settings$top);

			local values: vector of string = vector();
			local counts: vector of count = vector();
			local epsilons: vector of count = vector();
			for ( element in s )
				{
				values += s[element]$str;
				counts += topk_count(r$topk, s[element]);
				epsilons += topk_epsilon(r$topk, s[element]);
				}

			local loginfo = TopKInfo($ts=ts, $duration=pass_intv, $name=pass_name, $values=values, $counts=counts, $epsilons=epsilons);

			if ( key?$str )
				loginfo$key = key$str;

			Log::write(TOPK_LOG, loginfo);
			};
		};

	local make_path_func = function(pass_path_name: string): function(id: Log::ID, path: string, rec: TopKInfo): string
		{
		return function [pass_path_name] (id: Log::ID, path: string, rec: TopKInfo): string
			{
			return fmt("%s-%s", pass_path_name, subst_string(cat(rec$duration), " ", ""));
			};
		};

	for ( intv in settings$measurement_intervals )
		{
		local r1 = SumStats::Reducer($stream=fmt("ns-%s-%s", name, intv), $apply=set(SumStats::TOPK), $topk_size=settings$topk_size);

		SumStats::create([$name=fmt("ns-sumstat-%s-%s", name, intv),
											$epoch=intv,
											$reducers=set(r1),
											$epoch_result=make_epoch_result(name, intv, settings)
											]);
		}

	if ( settings$unified_log )
		add topk_measurement_default_log[name];

	# Let's create a separate log filter that only allows these top-k entries through
	if ( settings$separate_log )
		{
		local filter = Log::Filter(
			$exclude=set("name"),
			$name=fmt("topk_separate_%s", name),
			$policy=topk_filter_pass_specific,
			$ns_measurement=name
		);

		if ( settings?$log_path )
			filter$path = settings$log_path;
		else
			filter$path = fmt("topk-%s", name);

		if ( settings$per_interval_logs )
			{
			filter$path_func = make_path_func(filter$path);
			delete filter$path;
			}

		Log::add_filter(NetworkStats::TOPK_LOG, filter);
		}
	}

function topk_observation(name: string, key: string, value: string)
	{
	if ( name !in topk_measurements )
		{
		Reporter::error("TopK observation for non-existing measurement %s");
		return;
		}

	for ( intv in topk_measurements[name]$measurement_intervals )
		{
		SumStats::observe(fmt("ns-%s-%s", name, intv), [$str=key], [$str=value]);
		}
	}

hook default_filter_policy(rec: TopKInfo, id: Log::ID, filter: Log::Filter)
	{
	if ( rec$name ! in topk_measurement_default_log )
		break;
	}

event zeek_init() &priority=2
	{
	Log::create_stream(NetworkStats::TOPK_LOG, [$columns=TopKInfo, $policy=topk_log_policy, $ev=log_topk]);
	Log::remove_default_filter(NetworkStats::TOPK_LOG);
	Log::add_filter(NetworkStats::TOPK_LOG, Log::Filter($name="top_log_default_filtered", $path="ns", $policy=default_filter_policy));
	}
