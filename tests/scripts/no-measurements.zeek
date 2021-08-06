# @TEST-EXEC: zeek -r $TRACES/wikipedia.trace %INPUT $SCRIPTS/__load__.zeek
# @TEST-EXEC: test ! -f topk-dns-queries.log

const NS_NO_MEASUREMENTS = T;
