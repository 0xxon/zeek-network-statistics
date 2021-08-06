# Easy network statistics with Zeek

The goal of this repository is to provide convenience scripts to make it easier to create and report aggregate statistics.

This still is a work and progress; more functionality will be added in the future and functionality might change.

At the moment, this script contains convenience-functions that allow the easy creation of top-k statistics.

### DNS Query example

To give a short example, the following script will set up a top-k measurement for the top-DNS names.

Per default, the top-100 DNS hostnames are counted for the last 15 minutes, the last hour and the last day separately, and the information is logged into a dedicated log-file. All of these settings are easily changeable.

```zeek
event zeek_init()
	{
	NetworkStats::create_topk_measurement("dns-queries");
	}

event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count)
	{
	NetworkStats::topk_observation("dns-queries", DNS::query_types[qtype], query);
	}
```

The resulting log-file is called `topk-dns-queries.log` and looks like this (using a short test trace):

```
#path	topk-dns-queries
#fields	ts	duration	key	values	counts	epsilons
#types	time	interval	string	vector[string]	vector[count]	vector[count]
1300475173.475401	300.000000	AAAA	upload.wikimedia.org,upload.wikimedia.org.ncsa.uiuc.edu,meta.wikimedia.org	4,4,1	0,0,0
1300475173.475401	300.000000	A	upload.wikimedia.org,meta.wikimedia.org	4,1	0,0
1300475173.475401	900.000000	AAAA	upload.wikimedia.org,upload.wikimedia.org.ncsa.uiuc.edu,meta.wikimedia.org	4,4,1	0,0,0
...
```

## Installation

This repository is part of the [Zeek Package Manager](https://github.com/zeek/package-manager). It can be installed using the following command:

```bash
zkg install 0xxon/zeek-network-statistics
```

## Default logs

After installation, the scripts that are part of this repository will, by default, create a number of new log-files. Note that these logs will be created with the default settings that are customizable (see below).

If you are only interested in creating your own measurements, you can prevent these scripts from being loaded by putting `const NS_NO_MEASUREMENTS = T;` into your `local.zeek` before the `@load packages` line.

### `topk-dns-queries.log`

The log file `topk-dns-queries.log` contains the top-100 DNS queries for each DNS query-type.

### `topk-http-hosts.log`

The log file `topk-http-hosts.log` contains the top-100 values encountered in the `HOST` header of HTTP requests.

### `topk-ports.log`

The log file `topk-ports` lists the top-100 ports that were used for connections, for udp and tcp connections individually. By default this is also split up for incoming and outgoing connections; this behavior is customizable.

## Global Configuration options

A number of global configuration options are available. All of these options also can be changed separately for each measurement.

### `NetworkStats::topk_measurement_intervals` (set of interval)

This option sets the measurement intervals for the top-k measurements. By default, the measurement intervals are 15 minutes, 1 hour, and 1 day.

### `NetworkStats::topk_top` (count)

The number of results reported for the measurement. The default value is 100.

### `NetworkStats::topk_size` (count)

The number of items tracked for the measurement. The default value is 1000.

### `NetworkStats::topk_unified_log` (bool)

If set to true, measurements will be written into unified log-file (called `ns.log`). Set to false (disabled) by default.

### `NetworkStats::topk_separate_log` (bool)

If set to true, each measurement will have its own dedicated log-file called `topk-[measurement].log`. Set to true (enabled) by default.

### `NetworkStats::topk_per_interval_logs` (bool)

If set to true, each measurement will have its own dedicated log-file called `topk-[measurement].log`. Set to false (disabled) by default. Only works if `NetworkStats::topk_separate_log` is also enabled.

## Script-level functions

We currently export two script-level functions, one for creating top-k measurements and one for submitting observations. These functions are wrappers around the [Summary Statistics Framework](https://docs.zeek.org/en/master/frameworks/sumstats.html) of Zeek, which provided the underlying functionalitu.

### `NetworkStats::create_topk_measurement(name: string, settings: TopKSettings &default=[])`

The `NetworkStats::create_topk_measurement` function creates a new measurement using the specified `name`. Optionally, a `TopKSettings` record can be passed to the function. The settings record mirrors the global settings above. The full record definition is:

```zeek
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
```

### `NetworkStats::topk_observation(name: string, key: string, value: string)`

The `NetworkStats::topk_observation` is our equivalent of the [`SumStats::observe`](https://docs.zeek.org/en/master/scripts/base/frameworks/sumstats/main.zeek.html#id-SumStats::observe) function of the Zeek Summary Statistics framework.

It submits one observation for the measurement specified by `name`. If several different keys are tracked, a `key` can be specified; otherwise just pass an empty string.

`value` specifies the value of the measurement to be submitted.
