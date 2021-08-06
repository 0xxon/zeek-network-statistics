# @TEST-EXEC: zeek -r $TRACES/wikipedia.trace $SCRIPTS/__load__.zeek %INPUT
# @TEST-EXEC: btest-diff topk-dns-queries.log
# @TEST-EXEC: btest-diff topk-http-hosts.log
# @TEST-EXEC: btest-diff topk-ports.log
