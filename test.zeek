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
	for( ip in record_table)
	{
		local count_404 : double =0;
		local count_all : double =0;
		local count_unique_404 : double=0;
		for(status in record_table[ip])
		{
			count_all += record_table[ip][status];
			if(status == 404)
			{
				count_404=record_table[ip][status];
			}
		}
		
		if(count_404 > 2)
		{
			if(count_404 / count_all > 0.2)
			{
				if(count_unique_404 / count_404 >0.5)
				{
					print count_404/count_all;
				}
			}
		}
		print count_404;
		print count_all;
		print count_unique_404;
	}
	print  record_table;
}
