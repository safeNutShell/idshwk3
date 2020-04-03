global methTable :table[count] of int = table();

event zeek_init()
	{
	print "Hello, World!";
	}

event zeek_done()
	{
	print methTable;
	}

event http_request(c: connection, method: string, original_URI: string, unescaped_URI: string, version: string){
	if(method in methTable){
		methTable[method]+=1;
	}
	else {
	methTable[method] = 1;
	}
}
