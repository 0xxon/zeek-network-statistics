##! Script measuring the top-ports that we see in incoming/outgoing traffic.

module NetworkStats;

export {
	## Function that is called to classify the IP address. The output of this
	## function will be used as the key for the oservations.
	##
	## The default function uses ``Site::is_local_addr`` and creates four labels,
	## incoming-udp, incoming-tcp, outgoing-udp and outgoing-tcp.
	##
	## If "R" is returned, the connection is not counted.
	option classify_ip: function(id: conn_id): string = function(id: conn_id): string { return ""; };
}

function classify_local_net(id: conn_id): string
	{
	switch ( get_port_transport_proto(id$resp_p) )
		{
		case tcp:
			return Site::is_local_addr(id$resp_h) ? "incoming-tcp" : "outgoing-tcp";
			break;
		case udp:
			return Site::is_local_addr(id$resp_h) ? "incoming-udp" : "outgoing-udp";
			break;
		default:
			return "R";
		}
	}

redef classify_ip = classify_local_net;

event new_connection(c: connection)
	{
	local label = classify_ip(c$id);
	if ( label != "R" )
		topk_observation("ports", label, cat(c$id$resp_p));
	}

event zeek_init()
	{
	create_topk_measurement("ports");
	}
