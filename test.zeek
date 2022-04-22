event zeek_init()
	{
	print "Hello, World!";
	}
global record_table :  table[addr] of table[count] of int = table();
event http_reply(c: connection, version: string, code: count, reason: string)
{	# print c$id$orig_h;
	# print c$http$status_code;
	local ip :addr= c$id$orig_h;
	local status :count = c$http$status_code;
	if(	ip in record_table)
	{
		if(status in record_table[ip])
		{
			record_table[ip][status] +=1;
		}
		else
		{
			record_table[ip][status] =1;
		}
	}
	else{
		record_table[ip]=table();
	}
	
}
event zeek_done()
	{
	print  record_table;
	}
