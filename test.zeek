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
		print c;
	print "\n";
	print method；
	print "\n";
	print original_URI;
	print "\n";
	print unescaped_URI;
	print "\n";
	print version;
	print "\n\n";
}

event http_header(c: connection, is_orig: bool, name: string, value: string){
	print name;
	print "\n";
	print value;
	print "\n";
}
