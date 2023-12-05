/* Op Cleaver -------------------------------------------------------------- */

rule OPCLEAVER_BackDoorLogger
{
	meta:
		description = "Keylogger used by attackers in Operation Cleaver"
		reference = "http://cylance.com/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"
		date = "2014/12/02"
		author = "Cylance Inc."
		score = 70
		id = "e9149baa-83c0-597f-833c-ea0241bb60e6"
	strings:
		$s1 = "BackDoorLogger"
		$s2 = "zhuAddress"
	condition:
		all of them
}

rule OPCLEAVER_Jasus
{
	meta:
		description = "ARP cache poisoner used by attackers in Operation Cleaver"
		reference = "http://cylance.com/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"
		date = "2014/12/02"
		author = "Cylance Inc."
		score = 70
		id = "8e04b258-e071-5974-9778-b9d0b97be8d5"
	strings:
		$s1 = "pcap_dump_open"
		$s2 = "Resolving IPs to poison..."
		$s3 = "WARNNING: Gateway IP can not be found"
	condition:
		all of them
}

rule OPCLEAVER_LoggerModule
{
	meta:
		description = "Keylogger used by attackers in Operation Cleaver"
		reference = "http://cylance.com/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"
		date = "2014/12/02"
		author = "Cylance Inc."
		score = 70
		id = "949e7ff4-2102-5c89-83c9-f7ba64745661"
	strings:
		$s1 = "%s-%02d%02d%02d%02d%02d.r"
		$s2 = "C:\\Users\\%s\\AppData\\Cookies\\"
	condition:
		all of them
}

rule OPCLEAVER_NetC
{
	meta:
		description = "Net Crawler used by attackers in Operation Cleaver"
		reference = "http://cylance.com/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"
		date = "2014/12/02"
		author = "Cylance Inc."
		score = 70
		id = "68f32662-0d7d-5dfa-8bfd-ca41d383e19c"
	strings:
		$s1 = "NetC.exe" wide
		$s2 = "Net Service"
	condition:
		all of them
}

rule OPCLEAVER_ShellCreator2
{
	meta:
		description = "Shell Creator used by attackers in Operation Cleaver to create ASPX web shells"
		reference = "http://cylance.com/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"
		date = "2014/12/02"
		author = "Cylance Inc."
		score = 70
		id = "b62336c3-39e5-55f8-98df-6c2a2cb0764a"
	strings:
		$s1 = "ShellCreator2.Properties"
		$s2 = "set_IV"
	condition:
		all of them
}

rule OPCLEAVER_SmartCopy2
{
	meta:
		description = "Malware or hack tool used by attackers in Operation Cleaver"
		reference = "http://cylance.com/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"
		date = "2014/12/02"
		author = "Cylance Inc."
		score = 70
		id = "898d9060-208a-5dfb-a452-50ab49b80a9d"
	strings:
		$s1 = "SmartCopy2.Properties"
		$s2 = "ZhuFrameWork"
	condition:
		all of them
}

rule OPCLEAVER_SynFlooder
{
	meta:
		description = "Malware or hack tool used by attackers in Operation Cleaver"
		reference = "http://cylance.com/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"
		date = "2014/12/02"
		author = "Cylance Inc."
		score = 70
		id = "bdaf02f4-1226-569b-9f55-999be7ff397a"
	strings:
		$s1 = "Unable to resolve [ %s ]. ErrorCode %d"
		$s2 = "s IP is : %s"
		$s3 = "Raw TCP Socket Created successfully."
	condition:
		all of them
}

rule OPCLEAVER_TinyZBot
{
	meta:
		description = "Tiny Bot used by attackers in Operation Cleaver"
		reference = "http://cylance.com/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"
		date = "2014/12/02"
		author = "Cylance Inc."
		score = 70
		id = "4fad21a6-a900-5afb-876d-99a6d93e0c2c"
	strings:
		$s1 = "NetScp" wide
		$s2 = "TinyZBot.Properties.Resources.resources"
		$s3 = "Aoao WaterMark"
		$s4 = "Run_a_exe"
		$s5 = "netscp.exe"
		$s6 = "get_MainModule_WebReference_DefaultWS"
		$s7 = "remove_CheckFileMD5Completed"
		$s8 = "http://tempuri.org/"
		$s9 = "Zhoupin_Cleaver"
	condition:
		(($s1 and $s2) or ($s3 and $s4 and $s5) or ($s6 and $s7 and $s8) or $s9)
}

rule OPCLEAVER_ZhoupinExploitCrew
{
	meta:
		description = "Keywords used by attackers in Operation Cleaver"
		reference = "http://cylance.com/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"
		date = "2014/12/02"
		author = "Cylance Inc."
		score = 70
		id = "4e7457a0-e6e1-535c-b04b-ad313b496ce1"
	strings:
		$s1 = "zhoupin exploit crew" nocase
		$s2 = "zhopin exploit crew" nocase
	condition:
		1 of them
}

rule OPCLEAVER_antivirusdetector
{
	meta:
		description = "Hack tool used by attackers in Operation Cleaver"
		reference = "http://cylance.com/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"
		date = "2014/12/02"
		author = "Cylance Inc."
		score = 70
		id = "25ab4eaf-eae7-5a55-bed4-42f621d5f06c"
	strings:
		$s1 = "getShadyProcess"
		$s2 = "getSystemAntiviruses"
		$s3 = "AntiVirusDetector"
	condition:
		all of them
}

rule OPCLEAVER_csext
{
	meta:
		description = "Backdoor used by attackers in Operation Cleaver"
		reference = "http://cylance.com/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"
		date = "2014/12/02"
		author = "Cylance Inc."
		score = 70
		id = "f865eae5-9988-5533-a004-e1694761a557"
	strings:
		$s1 = "COM+ System Extentions"
		$s2 = "csext.exe"
		$s3 = "COM_Extentions_bin"
	condition:
		all of them
}

rule OPCLEAVER_kagent
{
	meta:
		description = "Backdoor used by attackers in Operation Cleaver"
		reference = "http://cylance.com/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"
		date = "2014/12/02"
		author = "Cylance Inc."
		score = 70
		id = "32d20495-eeed-5b2b-915d-cad60fa991f6"
	strings:
		$s1 = "kill command is in last machine, going back"
		$s2 = "message data length in B64: %d Bytes"
	condition:
		all of them
}

rule OPCLEAVER_mimikatzWrapper
{
	meta:
		description = "Mimikatz Wrapper used by attackers in Operation Cleaver"
		reference = "http://cylance.com/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"
		date = "2014/12/02"
		author = "Cylance Inc."
		score = 70
		id = "e9427e29-e581-5a5b-8f1d-4b9bfeec0946"
	strings:
		$s1 = "mimikatzWrapper"
		$s2 = "get_mimikatz"
	condition:
		all of them
}

rule OPCLEAVER_pvz_in
{
	meta:
		description = "Parviz tool used by attackers in Operation Cleaver"
		reference = "http://cylance.com/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"
		date = "2014/12/02"
		author = "Cylance Inc."
		score = 70
		id = "dede12b3-f1dd-58ba-a860-829b2331b740"
	strings:
		$s1 = "LAST_TIME=00/00/0000:00:00PM$"
		$s2 = "if %%ERRORLEVEL%% == 1 GOTO line"
	condition:
		all of them
}

rule OPCLEAVER_pvz_out
{
	meta:
		description = "Parviz tool used by attackers in Operation Cleaver"
		reference = "http://cylance.com/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"
		date = "2014/12/02"
		author = "Cylance Inc."
		score = 70
		id = "46b51bff-dfd9-5f56-897c-422112bc837b"
	strings:
		$s1 = "Network Connectivity Module" wide
		$s2 = "OSPPSVC" wide
	condition:
		all of them
}

rule OPCLEAVER_wndTest
{
	meta:
		description = "Backdoor used by attackers in Operation Cleaver"
		reference = "http://cylance.com/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"
		date = "2014/12/02"
		author = "Cylance Inc."
		score = 70
		id = "f8daa0a8-f0f0-5bf7-b9ab-eaf5335ff2b9"
	strings:
		$s1 = "[Alt]" wide
		$s2 = "<< %s >>:" wide
		$s3 = "Content-Disposition: inline; comp=%s; account=%s; product=%d;"
	condition:
		all of them
}

rule OPCLEAVER_zhCat
{
	meta:
		description = "Network tool used by Iranian hackers and used by attackers in Operation Cleaver"
		reference = "http://cylance.com/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"
		date = "2014/12/02"
		author = "Cylance Inc."
		score = 70
		id = "e1f1bc48-b895-5e23-8ffd-b6ea9c8eb26f"
	strings:
		$s1 = "Mozilla/4.0 ( compatible; MSIE 7.0; AOL 8.0 )" ascii fullword
		$s2 = "ABC ( A Big Company )" wide fullword
	condition:
		all of them
}

rule OPCLEAVER_zhLookUp
{
	meta:
		description = "Hack tool used by attackers in Operation Cleaver"
		reference = "http://cylance.com/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"
		date = "2014/12/02"
		author = "Cylance Inc."
		score = 70
		id = "45ef9a90-db4c-59c3-b694-da3f539b118b"
	strings:
		$s1 = "zhLookUp.Properties"
	condition:
		all of them
}

rule OPCLEAVER_zhmimikatz
{
	meta:
		description = "Mimikatz wrapper used by attackers in Operation Cleaver"
		reference = "http://cylance.com/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"
		date = "2014/12/02"
		author = "Cylance Inc."
		score = 70
		id = "fba8ab6e-3b61-53a1-b4df-178442e3cf24"
	strings:
		$s1 = "MimikatzRunner"
		$s2 = "zhmimikatz"
	condition:
		all of them
}

rule OPCLEAVER_Parviz_Developer
{
	meta:
		description = "Parviz developer known from Operation Cleaver"
		reference = "http://cylance.com/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"
		date = "2014/12/02"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		score = 70
		id = "2bfa90a0-0495-5b21-98f7-5ed7ebc74b2d"
	strings:
		$s1 = "Users\\parviz\\documents\\" nocase
	condition:
		$s1
}

rule OPCLEAVER_CCProxy_Config
{
	meta:
		description = "CCProxy config known from Operation Cleaver"
		reference = "http://cylance.com/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"
		date = "2014/12/02"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		score = 70
		id = "c4d80a2a-2a32-585e-bc20-1c5118e4ee48"
	strings:
		$s1 = "UserName=User-001" fullword ascii
		$s2 = "Web=1" fullword ascii
		$s3 = "Mail=1" fullword ascii
		$s4 = "FTP=0" fullword ascii
		$x1 = "IPAddressLow=78.109.194.114" fullword ascii
	condition:
		all of ($s*) or $x1
}
