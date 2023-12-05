/*
	Yara Rule Set
	Author: Florian Roth
	Date: 2016-08-15
	Identifier: EQGRP
*/

import "pe"

/* Rule Set ----------------------------------------------------------------- */

rule EQGRP_noclient_3_0_5 {
	meta:
		description = "Detects tool from EQGRP toolset - file noclient-3.0.5.3"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Research"
		date = "2016-08-15"
		score = 75
		id = "af7472ce-0605-5f50-8180-23438d2196b8"
	strings:
		$x1 = "-C %s 127.0.0.1\" scripme -F -t JACKPOPIN4 '&" fullword ascii
		$x2 = "Command too long!  What the HELL are you trying to do to me?!?!  Try one smaller than %d bozo." fullword ascii
		$x3 = "sh -c \"ping -c 2 %s; grep %s /proc/net/arp >/tmp/gx \"" fullword ascii
		$x4 = "Error from ourtn, did not find keys=target in tn.spayed" fullword ascii
		$x5 = "ourtn -d -D %s -W 127.0.0.1:%d  -i %s -p %d %s %s" fullword ascii
	condition:
		( uint16(0) == 0x457f and filesize < 700KB and 1 of them ) or ( all of them )
}

rule EQGRP_installdate {
	meta:
		description = "Detects tool from EQGRP toolset - file installdate.pl"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Research"
		date = "2016-08-15"
		score = 75
		id = "029b1213-1206-5b7c-bd72-93239a23fe8a"
	strings:
		$x1 = "#Provide hex or EP log as command-line argument or as input" fullword ascii
		$x2 = "print \"Gimme hex: \";" fullword ascii
		$x3 = "if ($line =~ /Reg_Dword:  (\\d\\d:\\d\\d:\\d\\d.\\d+ \\d+ - )?(\\S*)/) {" fullword ascii

		$s1 = "if ($_ =~ /InstallDate/) {" fullword ascii
		$s2 = "if (not($cmdInput)) {" fullword ascii
		$s3 = "print \"$hex in decimal=$dec\\n\\n\";" fullword ascii
	condition:
		filesize < 2KB and ( 1 of ($x*) or 3 of them )
}

rule EQGRP_teflondoor {
	meta:
		description = "Detects tool from EQGRP toolset - file teflondoor.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Research"
		date = "2016-08-15"
		score = 75
		id = "188f9ef1-5524-50be-ac62-91cb9726b155"
	strings:
		$x1 = "%s: abort.  Code is %d.  Message is '%s'" fullword ascii
		$x2 = "%s: %li b (%li%%)" fullword ascii

		$s1 = "no winsock" fullword ascii
		$s2 = "%s: %s file '%s'" fullword ascii
		$s3 = "peer: connect" fullword ascii
		$s4 = "read: write" fullword ascii
		$s5 = "%s: done!" fullword ascii
		$s6 = "%s: %li b" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 30KB and 1 of ($x*) and 3 of them
}

rule EQGRP_durablenapkin_solaris_2_0_1 {
	meta:
		description = "Detects tool from EQGRP toolset - file durablenapkin.solaris.2.0.1.1"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Research"
		date = "2016-08-15"
		score = 75
		id = "7b49a26d-9ee3-5aff-93fc-509239daef28"
	strings:
		$s1 = "recv_ack: %s: Service not supplied by provider" fullword ascii
		$s2 = "send_request: putmsg \"%s\": %s" fullword ascii
		$s3 = "port undefined" fullword ascii
		$s4 = "recv_ack: %s getmsg: %s" fullword ascii
		$s5 = ">> %d -- %d" fullword ascii
	condition:
		( uint16(0) == 0x457f and filesize < 40KB and 2 of them )
}

rule EQGRP_teflonhandle {
	meta:
		description = "Detects tool from EQGRP toolset - file teflonhandle.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Research"
		date = "2016-08-15"
		score = 75
		id = "4d82cc41-3777-5f8c-9392-aca69e6ed781"
	strings:
		$s1 = "%s [infile] [outfile] /k 0x[%i character hex key] </g>" fullword ascii
		$s2 = "File %s already exists.  Overwrite? (y/n) " fullword ascii
		$s3 = "Random Key : 0x" fullword ascii
		$s4 = "done (%i bytes written)." fullword ascii
		$s5 = "%s --> %s..." fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 20KB and 2 of them
}

rule EQGRP_false {
	meta:
		description = "Detects tool from EQGRP toolset - file false.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Research"
		date = "2016-08-15"
		score = 75
		id = "3a68790b-38fc-570b-8b19-c5478cdd2842"
	strings:
		$s1 = { 00 25 64 2E 0A 00 00 00 00 25 64 2E 0A 00 00 00
			00 25 6C 75 2E 25 6C 75 2E 25 6C 75 2E 25 6C 75
			00 25 64 2E 0A 00 00 00 00 25 64 2E 0A 00 00 00
			00 25 64 2E 0A 00 00 00 00 25 64 2E 0A 00 00 00
			00 25 32 2E 32 58 20 00 00 0A 00 00 00 25 64 20
			2D 20 25 64 20 25 64 0A 00 25 64 0A 00 25 64 2E
			0A 00 00 00 00 25 64 2E 0A 00 00 00 00 25 64 2E
			0A 00 00 00 00 25 64 20 2D 20 25 64 0A 00 00 00
			00 25 64 20 2D 20 25 64 }
	condition:
		uint16(0) == 0x5a4d and filesize < 50KB and $s1
}

rule EQGRP_dn_1_0_2_1 {
	meta:
		description = "Detects tool from EQGRP toolset - file dn.1.0.2.1.linux"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Research"
		date = "2016-08-15"
		score = 75
		id = "24b5fb51-2463-56ef-818a-949b4b3bbf5b"
	strings:
		$s1 = "Valid commands are: SMAC, DMAC, INT, PACK, DONE, GO" fullword ascii
		$s2 = "invalid format suggest DMAC=00:00:00:00:00:00" fullword ascii
		$s3 = "SMAC=%02x:%02x:%02x:%02x:%02x:%02x" fullword ascii
		$s4 = "Not everything is set yet" fullword ascii
	condition:
		( uint16(0) == 0x457f and filesize < 30KB and 2 of them )
}

rule EQGRP_morel {
	meta:
		description = "Detects tool from EQGRP toolset - file morel.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Research"
		date = "2016-08-15"
		score = 75
		hash1 = "a9152e67f507c9a179bb8478b58e5c71c444a5a39ae3082e04820a0613cd6d9f"
		id = "e741b727-0e41-53d0-832c-df7f4ea7964a"
	strings:
		$s1 = "%d - %d, %d" fullword ascii
		$s2 = "%d - %lu.%lu %d.%lu" fullword ascii
		$s3 = "%d - %d %d" fullword ascii
	condition:
		( uint16(0) == 0x5a4d and filesize < 60KB and all of them )
}

rule EQGRP_bc_parser {
	meta:
		description = "Detects tool from EQGRP toolset - file bc-parser"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Research"
		date = "2016-08-15"
		score = 75
		hash1 = "879f2f1ae5d18a3a5310aeeafec22484607649644e5ecb7d8a72f0877ac19cee"
		id = "ed4523de-b126-503a-83bd-aafd8533b0e5"
	strings:
		$s1 = "*** Target may be susceptible to FALSEMOREL      ***" fullword ascii
		$s2 = "*** Target is susceptible to FALSEMOREL          ***" fullword ascii
	condition:
		uint16(0) == 0x457f and 1 of them
}

rule EQGRP_1212 {
	meta:
		description = "Detects tool from EQGRP toolset - file 1212.pl"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Research"
		date = "2016-08-15"
		score = 75
		id = "428fed4f-df5c-5fc2-ac4b-4dea69ea4f2d"
	strings:
		$s1 = "if (!(($srcip,$dstip,$srcport,$dstport) = ($line=~/^([a-f0-9]{8})([a-f0-9]{8})([a-f0-9]{4})([a-f0-9]{4})$/)))" fullword ascii
		$s2 = "$ans=\"$srcip:$srcport -> $dstip:$dstport\";" fullword ascii
		$s3 = "return \"ERROR:$line is not a valid port\";" fullword ascii
		$s4 = "$dstport=hextoPort($dstport);" fullword ascii
		$s5 = "sub hextoPort" fullword ascii
		$s6 = "$byte_table{\"$chars[$sixteens]$chars[$ones]\"}=$i;" fullword ascii
	condition:
		filesize < 6KB and 4 of them
}

rule EQGRP_1212_dehex {
	meta:
		description = "Detects tool from EQGRP toolset - from files 1212.pl, dehex.pl"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Research"
		date = "2016-08-15"
		score = 75
		id = "2cc375e6-2bff-5623-b86c-a6413f736c42"
	strings:
		$s1 = "return \"ERROR:$line is not a valid address\";" fullword ascii
		$s2 = "print \"ERROR: the filename or hex representation needs to be one argument try using \\\"'s\\n\";" fullword ascii
		$s3 = "push(@octets,$byte_table{$tempi});" fullword ascii
		$s4 = "$byte_table{\"$chars[$sixteens]$chars[$ones]\"}=$i;" fullword ascii
		$s5 = "print hextoIP($ARGV[0]);" fullword ascii
	condition:
		( uint16(0) == 0x2123 and filesize < 6KB and ( 5 of ($s*) ) ) or ( all of them )
}

/*
	Yara Rule Set
	Author: Florian Roth
	Date: 2016-08-16
	Identifier: EQGRP
*/

/* Rule Set ----------------------------------------------------------------- */

rule install_get_persistent_filenames {
	meta:
		description = "EQGRP Toolset Firewall - file install_get_persistent_filenames"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Research"
		date = "2016-08-16"
		hash1 = "4a50ec4bf42087e932e9e67e0ea4c09e52a475d351981bb4c9851fda02b35291"
		id = "cf74b479-4b78-537a-878c-2f3ce004b775"
	strings:
		$s1 = "Generates the persistence file name and prints it out." fullword ascii
	condition:
		( uint16(0) == 0x457f and all of them )
}

rule EQGRP_create_dns_injection {
	meta:
		description = "EQGRP Toolset Firewall - file create_dns_injection.py"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Research"
		date = "2016-08-16"
		hash1 = "488f3cc21db0688d09e13eb85a197a1d37902612c3e302132c84e07bc42b1c32"
		id = "ef358ca6-ebd8-5d08-944b-f1fcd112f1f3"
	strings:
		$s1 = "Name:   A hostname: 'host.network.com', a decimal numeric offset within" fullword ascii
		$s2 = " www.badguy.net,CNAME,1800,host.badguy.net \\\\" ascii
	condition:
		1 of them
}

rule EQGRP_screamingplow {
	meta:
		description = "EQGRP Toolset Firewall - file screamingplow.sh"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Research"
		date = "2016-08-16"
		hash1 = "c7f4104c4607a03a1d27c832e1ebfc6ab252a27a1709015b5f1617b534f0090a"
		id = "cb535ef0-e3ea-54cc-9082-3d63cc96d93a"
	strings:
		$s1 = "What is the name of your PBD:" fullword ascii
		$s2 = "You are now ready for a ScreamPlow" fullword ascii
	condition:
		1 of them
}

rule EQGRP_MixText {
	meta:
		description = "EQGRP Toolset Firewall - file MixText.py"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Research"
		date = "2016-08-16"
		hash1 = "e4d24e30e6cc3a0aa0032dbbd2b68c60bac216bef524eaf56296430aa05b3795"
		id = "99b06100-8a05-5c22-8b7d-ed451d5f4e81"
	strings:
		$s1 = "BinStore enabled implants." fullword ascii
	condition:
		1 of them
}

rule EQGRP_tunnel_state_reader {
	meta:
		description = "EQGRP Toolset Firewall - file tunnel_state_reader"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Research"
		date = "2016-08-16"
		hash1 = "49d48ca1ec741f462fde80da68b64dfa5090855647520d29e345ef563113616c"
		id = "e48c9482-eae5-5c34-b7b2-502d0252f4a0"
	strings:
		$s1 = "Active connections will be maintained for this tunnel. Timeout:" fullword ascii
		$s5 = "%s: compatible with BLATSTING version 1.2" fullword ascii
	condition:
		1 of them
}

rule EQGRP_payload {
	meta:
		description = "EQGRP Toolset Firewall - file payload.py"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Research"
		date = "2016-08-16"
		hash1 = "21bed6d699b1fbde74cbcec93575c9694d5bea832cd191f59eb3e4140e5c5e07"
		id = "949cb68b-e384-578c-a906-a4d9234dc668"
	strings:
		$s1 = "can't find target version module!" fullword ascii
		$s2 = "class Payload:" fullword ascii
	condition:
		all of them
}

rule EQGRP_eligiblecandidate {
	meta:
		description = "EQGRP Toolset Firewall - file eligiblecandidate.py"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Research"
		date = "2016-08-16"
		hash1 = "c4567c00734dedf1c875ecbbd56c1561a1610bedb4621d9c8899acec57353d86"
		id = "e084b051-4aa1-54b2-9f56-69db386b46d6"
	strings:
		$o1 = "Connection timed out. Only a problem if the callback was not received." fullword ascii
		$o2 = "Could not reliably detect cookie. Using 'session_id'..." fullword ascii

		$c1 = "def build_exploit_payload(self,cmd=\"/tmp/httpd\"):" fullword ascii
		$c2 = "self.build_exploit_payload(cmd)" fullword ascii
	condition:
		1 of them
}

rule EQGRP_BUSURPER_2211_724 {
	meta:
		description = "EQGRP Toolset Firewall - file BUSURPER-2211-724.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Research"
		date = "2016-08-16"
		hash1 = "d809d6ff23a9eee53d2132d2c13a9ac5d0cb3037c60e229373fc59a4f14bc744"
		id = "d109210e-14df-5b90-a496-fa8a2454126b"
	strings:
		$s1 = ".got_loader" fullword ascii
		$s2 = "_start_text" ascii
		$s3 = "IMPLANT" fullword ascii
		$s4 = "KEEPGOING" fullword ascii
		$s5 = "upgrade_implant" fullword ascii
	condition:
		all of them
}

rule EQGRP_networkProfiler_orderScans {
	meta:
		description = "EQGRP Toolset Firewall - file networkProfiler_orderScans.sh"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Research"
		date = "2016-08-16"
		hash1 = "ea986ddee09352f342ac160e805312e3a901e58d2beddf79cd421443ba8c9898"
		id = "2d48df0c-f950-5bb6-8d3e-77c2f970eb57"
	strings:
		$x1 = "Unable to save off predefinedScans directory" fullword ascii
		$x2 = "Re-orders the networkProfiler scans so they show up in order in the LP" fullword ascii
	condition:
		1 of them
}

rule EQGRP_epicbanana_2_1_0_1 {
	meta:
		description = "EQGRP Toolset Firewall - file epicbanana_2.1.0.1.py"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Research"
		date = "2016-08-16"
		hash1 = "4b13cc183c3aaa8af43ef3721e254b54296c8089a0cd545ee3b867419bb66f61"
		id = "cc3346bd-0347-5cf3-b946-5c017d68d93e"
	strings:
		$s1 = "failed to create version-specific payload" fullword ascii
		$s2 = "(are you sure you did \"make [version]\" in versions?)" fullword ascii
	condition:
		1 of them
}

rule EQGRP_sniffer_xml2pcap {
	meta:
		description = "EQGRP Toolset Firewall - file sniffer_xml2pcap"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Research"
		date = "2016-08-16"
		hash1 = "f5e5d75cfcd86e5c94b0e6f21bbac886c7e540698b1556d88a83cc58165b8e42"
		id = "c284ac58-923c-5c34-b420-e87797915233"
	strings:
		$x1 = "-s/--srcip <sourceIP>  Use given source IP (if sniffer doesn't collect source IP)" fullword ascii
		$x2 = "convert an XML file generated by the BLATSTING sniffer module into a pcap capture file." fullword ascii
	condition:
		1 of them
}

rule EQGRP_BananaAid {
	meta:
		description = "EQGRP Toolset Firewall - file BananaAid"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Research"
		date = "2016-08-16"
		hash1 = "7a4fb825e63dc612de81bc83313acf5eccaa7285afc05941ac1fef199279519f"
		id = "bdd3ce51-1809-5b2f-9c7e-6c0b056d022b"
	strings:
		$x1 = "(might have to delete key in ~/.ssh/known_hosts on linux box)" fullword ascii
		$x2 = "scp BGLEE-" ascii
		$x3 = "should be 4bfe94b1 for clean bootloader version 3.0; " fullword ascii
		$x4 = "scp <configured implant> <username>@<IPaddr>:onfig" fullword ascii
	condition:
		1 of them
}

rule EQGRP_bo {
	meta:
		description = "EQGRP Toolset Firewall - file bo"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Research"
		date = "2016-08-16"
		hash1 = "aa8b363073e8ae754b1836c30f440d7619890ded92fb5b97c73294b15d22441d"
		id = "6aa71528-3ce6-5597-bb1a-e44cff3856d6"
	strings:
		$s1 = "ERROR: failed to open %s: %d" fullword ascii
		$s2 = "__libc_start_main@@GLIBC_2.0" ascii
		$s3 = "serial number: %s" fullword ascii
		$s4 = "strerror@@GLIBC_2.0" fullword ascii
		$s5 = "ERROR: mmap failed: %d" fullword ascii
	condition:
		( uint16(0) == 0x457f and filesize < 20KB and all of them )
}

rule EQGRP_SecondDate_2211 {
	meta:
		description = "EQGRP Toolset Firewall - file SecondDate-2211.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Research"
		date = "2016-08-16"
		hash1 = "2337d0c81474d03a02c404cada699cf1b86c3c248ea808d4045b86305daa2607"
		id = "00951270-6189-58b6-8b64-422c4ab15ebe"
	strings:
		$s1 = "SD_processControlPacket" fullword ascii
		$s2 = "Encryption_rc4SetKey" fullword ascii
		$s3 = ".got_loader" fullword ascii
		$s4 = "^GET.*(?:/ |\\.(?:htm|asp|php)).*\\r\\n" fullword ascii
	condition:
		( uint16(0) == 0x457f and filesize < 200KB and all of them )
}

rule EQGRP_config_jp1_UA {
	meta:
		description = "EQGRP Toolset Firewall - file config_jp1_UA.pl"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Research"
		date = "2016-08-16"
		hash1 = "2f50b6e9891e4d7fd24cc467e7f5cfe348f56f6248929fec4bbee42a5001ae56"
		id = "947e6f90-4eb4-5241-9819-677cee0c15d8"
	strings:
		$x1 = "This program will configure a JETPLOW Userarea file." fullword ascii
		$x2 = "Error running config_implant." fullword ascii
		$x3 = "NOTE:  IT ASSUMES YOU ARE OPERATING IN THE INSTALL/LP/JP DIRECTORY. THIS ASSUMPTION " fullword ascii
		$x4 = "First IP address for beacon destination [127.0.0.1]" fullword ascii
	condition:
		1 of them
}

rule EQGRP_userscript {
	meta:
		description = "EQGRP Toolset Firewall - file userscript.FW"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Research"
		date = "2016-08-16"
		hash1 = "5098ff110d1af56115e2c32f332ff6e3973fb7ceccbd317637c9a72a3baa43d7"
		id = "c6c1b70e-437f-50e7-9055-b943a1a62e6c"
	strings:
		$x1 = "Are you sure? Don't forget that NETSCREEN firewalls require BANANALIAR!! " fullword ascii
	condition:
		1 of them
}

rule EQGRP_BBALL_M50FW08_2201 {
	meta:
		description = "EQGRP Toolset Firewall - file BBALL_M50FW08-2201.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Research"
		date = "2016-08-16"
		hash1 = "80c0b68adb12bf3c15eff9db70a57ab999aad015da99c4417fdfd28156d8d3f7"
		id = "bced11a2-fac4-58e5-a4a8-1c6d5fe418f9"
	strings:
		$s1 = ".got_loader" fullword ascii
		$s2 = "LOADED" fullword ascii
		$s3 = "pageTable.c" fullword ascii
		$s4 = "_start_text" ascii
		$s5 = "handler_readBIOS" fullword ascii
		$s6 = "KEEPGOING" fullword ascii
	condition:
		( uint16(0) == 0x457f and filesize < 40KB and 5 of ($s*) )
}

rule EQGRP_BUSURPER_3001_724 {
	meta:
		description = "EQGRP Toolset Firewall - file BUSURPER-3001-724.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Research"
		date = "2016-08-16"
		hash1 = "6b558a6b8bf3735a869365256f9f2ad2ed75ccaa0eefdc61d6274df4705e978b"
		id = "006877e9-1e73-5a27-8b3a-bca3513a2035"
	strings:
		$s1 = "IMPLANT" fullword ascii
		$s2 = "KEEPGOING" fullword ascii
		$s3 = "upgrade_implant" fullword ascii
	condition:
		( uint16(0) == 0x457f and filesize < 200KB and 2 of them ) or ( all of them )
}

rule EQGRP_workit {
	meta:
		description = "EQGRP Toolset Firewall - file workit.py"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Research"
		date = "2016-08-16"
		modified = "2023-01-27"
		hash1 = "fb533b4d255b4e6072a4fa2e1794e38a165f9aa66033340c2f4f8fd1da155fac"
		id = "b582f990-5bd5-592d-a7c0-475fdfffc38c"
	strings:
		$s1 = "macdef init > /tmp/.netrc;" fullword ascii
		$s2 = "/usr/bin/wget http://" ascii
		$s3 = "HOME=/tmp ftp" fullword ascii
		$s4 = " >> /tmp/.netrc;" fullword ascii
		$s5 = "/usr/rapidstream/bin/tftp" fullword ascii
		$s6 = "created shell_command:" fullword ascii
		$s7 = "rm -f /tmp/.netrc;" fullword ascii
		$s8 = "echo quit >> /tmp/.netrc;" fullword ascii
		$s9 = "echo binary >> /tmp/.netrc;" fullword ascii
		$s10 = "chmod 600 /tmp/.netrc;" fullword ascii
		$s11 = "created cli_command:" fullword ascii
	condition:
		6 of them
}

rule EQGRP_tinyhttp_setup {
	meta:
		description = "EQGRP Toolset Firewall - file tinyhttp_setup.sh"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Research"
		date = "2016-08-16"
		hash1 = "3d12c83067a9f40f2f5558d3cf3434bbc9a4c3bb9d66d0e3c0b09b9841c766a0"
		id = "71dcc48f-f551-5596-9f03-dbbae470a62b"
	strings:
		$x1 = "firefox http://127.0.0.1:8000/$_name" fullword ascii
		$x2 = "What is the name of your implant:" fullword ascii /* it's called conscience */
		$x3 = "killall thttpd" fullword ascii
		$x4 = "copy http://<IP>:80/$_name flash:/$_name" fullword ascii
	condition:
		( uint16(0) == 0x2123 and filesize < 2KB and 1 of ($x*) ) or ( all of them )
}

rule EQGRP_shellcode {
	meta:
		description = "EQGRP Toolset Firewall - file shellcode.py"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Research"
		date = "2016-08-16"
		hash1 = "ac9decb971dd44127a6ca0d35ac153951f0735bb4df422733046098eca8f8b7f"
		id = "d923c1de-c6eb-511f-ae1f-bf3ac6e0eae8"
	strings:
		$s1 = "execute_post = '\\xe8\\x00\\x00\\x00\\x00\\x5d\\xbe\\xef\\xbe\\xad\\xde\\x89\\xf7\\x89\\xec\\x29\\xf4\\xb8\\x03\\x00\\x00\\x00" ascii
		$s2 = "tiny_exec = '\\x7f\\x45\\x4c\\x46\\x01\\x01\\x01\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x02\\x00\\x03\\x00\\x01\\x00\\x00" ascii
		$s3 = "auth_id = '\\x31\\xc0\\xb0\\x03\\x31\\xdb\\x89\\xe1\\x31\\xd2\\xb6\\xf0\\xb2\\x0d\\xcd\\x80\\x3d\\xff\\xff\\xff\\xff\\x75\\x07" ascii

		$c1 = { e8 00 00 00 00 5d be ef be ad de 89 f7 89 ec 29 f4 b8 03 00 00 00 }
		/* $c2 = { 7f 45 4c 46 01 01 01 00 00 00 00 00 00 00 00 00 02 00 03 00 01 00 00 }  too many fps */
		$c3 = { 31 c0 b0 03 31 db 89 e1 31 d2 b6 f0 b2 0d cd 80 3d ff ff ff ff 75 07 }
	condition:
		1 of them
}

rule EQGRP_EPBA {
	meta:
		description = "EQGRP Toolset Firewall - file EPBA.script"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Research"
		date = "2016-08-16"
		hash1 = "53e1af1b410ace0934c152b5df717d8a5a8f5fdd8b9eb329a44d94c39b066ff7"
		id = "5159c2f4-20b7-590d-b216-b3468c26e459"
	strings:
		$x1 = "./epicbanana_2.0.0.1.py -t 127.0.0.1 --proto=ssh --username=cisco --password=cisco --target_vers=asa804 --mem=NA -p 22 " fullword ascii
		$x2 = "-t TARGET_IP, --target_ip=TARGET_IP -- Either 127.0.0.1 or Win Ops IP" fullword ascii
		$x3 = "./bride-1100 --lp 127.0.0.1 --implant 127.0.0.1 --sport RHP --dport RHP" fullword ascii
		$x4 = "--target_vers=TARGET_VERS    target Pix version (pix712, asa804) (REQUIRED)" fullword ascii
		$x5 = "-p DEST_PORT, --dest_port=DEST_PORT defaults: telnet=23, ssh=22 (optional) - Change to LOCAL redirect port" fullword ascii
		$x6 = "this operation is complete, BananaGlee will" fullword ascii
		$x7 = "cd /current/bin/FW/BGXXXX/Install/LP" fullword ascii
	condition:
		( uint16(0) == 0x2023 and filesize < 7KB and 1 of ($x*) ) or ( 3 of them )
}

rule EQGRP_BPIE {
	meta:
		description = "EQGRP Toolset Firewall - file BPIE-2201.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Research"
		date = "2016-08-16"
		hash1 = "697e80cf2595c85f7c931693946d295994c55da17a400f2c9674014f130b4688"
		id = "a73f0216-3994-5ee6-8a8c-cbcc1279898e"
	strings:
		$s1 = "profProcessPacket" fullword ascii
		$s2 = ".got_loader" fullword ascii
		$s3 = "getTimeSlotCmdHandler" fullword ascii
		$s4 = "getIpIpCmdHandler" fullword ascii
		$s5 = "LOADED" fullword ascii
		$s6 = "profStartScan" fullword ascii
		$s7 = "tmpData.1" fullword ascii
		$s8 = "resetCmdHandler" fullword ascii
	condition:
		( uint16(0) == 0x457f and filesize < 70KB and 6 of ($s*) )
}

rule EQGRP_jetplow_SH {
	meta:
		description = "EQGRP Toolset Firewall - file jetplow.sh"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Research"
		date = "2016-08-16"
		hash1 = "ee266f84a1a4ccf2e789a73b0a11242223ed6eba6868875b5922aea931a2199c"
		id = "e7780540-29c9-5827-8ac0-a685d9ba8a5f"
	strings:
		$s1 = "cd /current/bin/FW/BANANAGLEE/$bgver/Install/LP/jetplow" fullword ascii
		$s2 = "***** Please place your UA in /current/bin/FW/OPS *****" fullword ascii
		$s3 = "ln -s ../jp/orig_code.bin orig_code_pixGen.bin" fullword ascii
		$s4 = "*****             Welcome to JetPlow              *****" fullword ascii
	condition:
		1 of them
}

rule EQGRP_BBANJO {
	meta:
		description = "EQGRP Toolset Firewall - file BBANJO-3011.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Research"
		date = "2016-08-16"
		hash1 = "f09c2f90464781a08436321f6549d350ecef3d92b4f25b95518760f5d4c9b2c3"
		id = "81af4769-7007-51f1-9569-bc370618b4ff"
	strings:
		$s1 = "get_lsl_interfaces" fullword ascii
		$s2 = "encryptFC4Payload" fullword ascii
		$s3 = ".got_loader" fullword ascii
		$s4 = "beacon_getconfig" fullword ascii
		$s5 = "LOADED" fullword ascii
		$s6 = "FormBeaconPacket" fullword ascii
		$s7 = "beacon_reconfigure" fullword ascii
	condition:
		( uint16(0) == 0x457f and filesize < 50KB and all of them )
}

rule EQGRP_BPATROL_2201 {
	meta:
		description = "EQGRP Toolset Firewall - file BPATROL-2201.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Research"
		date = "2016-08-16"
		hash1 = "aa892750b893033eed2fedb2f4d872f79421174eb217f0c34a933c424ae66395"
		id = "864a346c-e8aa-5c66-9867-faccb14b8bee"
	strings:
		$s1 = "dumpConfig" fullword ascii
		$s2 = "getstatusHandler" fullword ascii
		$s3 = ".got_loader" fullword ascii
		$s4 = "xtractdata" fullword ascii
		$s5 = "KEEPGOING" fullword ascii
	condition:
		( uint16(0) == 0x457f and filesize < 40KB and all of them )
}

rule EQGRP_extrabacon {
	meta:
		description = "EQGRP Toolset Firewall - file extrabacon_1.1.0.1.py"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Research"
		date = "2016-08-16"
		hash1 = "59d60835fe200515ece36a6e87e642ee8059a40cb04ba5f4b9cce7374a3e7735"
		id = "79b998ef-e548-5038-b8ad-da1abf362e7f"
	strings:
		$x1 = "To disable password checking on target:" fullword ascii
		$x2 = "[-] target is running" fullword ascii
		$x3 = "[-] problem importing version-specific shellcode from" fullword ascii
		$x4 = "[+] importing version-specific shellcode" fullword ascii
		$s5 = "[-] unsupported target version, abort" fullword ascii
	condition:
		1 of them
}

rule EQGRP_sploit_py {
	meta:
		description = "EQGRP Toolset Firewall - file sploit.py"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Research"
		date = "2016-08-16"
		hash1 = "0316d70a5bbf068a7fc791e08e816015d04ec98f088a7ff42af8b9e769b8d1f6"
		id = "9f403965-5fb1-55b2-bef6-65c18e08e58f"
	strings:
		$x1 = "the --spoof option requires 3 or 4 fields as follows redir_ip" ascii
		$x2 = "[-] timeout waiting for response - target may have crashed" fullword ascii
		$x3 = "[-] no response from health check - target may have crashed" fullword ascii
	condition:
		1 of them
}

rule EQGRP_uninstallPBD {
	meta:
		description = "EQGRP Toolset Firewall - file uninstallPBD.bat"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Research"
		date = "2016-08-16"
		hash1 = "692fdb449f10057a114cf2963000f52ce118d9a40682194838006c66af159bd0"
		id = "0153cb2a-a0de-51f9-80c2-22136d56f16d"
	strings:
		$s1 = "memset 00e9a05c 4 38845b88" fullword ascii
		$s2 = "_hidecmd" ascii
		$s3 = "memset 013abd04 1 0d" fullword ascii
	condition:
		all of them
}

rule EQGRP_BICECREAM {
	meta:
		description = "EQGRP Toolset Firewall - file BICECREAM-2140"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Research"
		date = "2016-08-16"
		hash1 = "4842076af9ba49e6dfae21cf39847b4172c06a0bd3d2f1ca6f30622e14b77210"
		id = "a10819ae-db48-5d30-8e2e-2e4fe33e005b"
	strings:
		$s1 = "Could not connect to target device: %s:%d. Please check IP address." fullword ascii
		$s2 = "command data size is invalid for an exec cmd" fullword ascii
		$s3 = "A script was specified but target is not a PPC405-based NetScreen (NS5XT, NS25, and NS50). Executing scripts is supported but ma" ascii
		$s4 = "Execute 0x%08x with args (%08x, %08x, %08x, %08x): [y/n]" fullword ascii
		$s5 = "Execute 0x%08x with args (%08x, %08x, %08x): [y/n]" fullword ascii
		$s6 = "[%d] Execute code." fullword ascii
		$s7 = "Execute 0x%08x with args (%08x): [y/n]" fullword ascii
		$s8 = "dump_value_LHASH_DOALL_ARG" fullword ascii
		$s9 = "Eggcode is complete. Pass execution to it? [y/n]" fullword ascii
	condition:
		( uint16(0) == 0x457f and filesize < 5000KB and 2 of them ) or ( 5 of them )
}

rule EQGRP_create_http_injection {
	meta:
		description = "EQGRP Toolset Firewall - file create_http_injection.py"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Research"
		date = "2016-08-16"
		hash1 = "de52f5621b4f3896d4bd1fb93ee8be827e71a2b189a9f8552b68baed062a992d"
		id = "92b6dad0-c7d8-5522-8fc1-fbd0aae00960"
	strings:
		$x1 = "required by SECONDDATE" fullword ascii

		$s1 = "help='Output file name (optional). By default the resulting data is written to stdout.')" fullword ascii
		$s2 = "data = '<html><body onload=\"location.reload(true)\"><iframe src=\"%s\" height=\"1\" width=\"1\" scrolling=\"no\" frameborder=\"" ascii
		$s3 = "version='%prog 1.0'," fullword ascii
		$s4 = "usage='%prog [ ... options ... ] url'," fullword ascii
	condition:
		( uint16(0) == 0x2123 and filesize < 3KB and ( $x1 or 2 of them ) ) or ( all of them )
}

rule EQGRP_BFLEA_2201 {
	meta:
		description = "EQGRP Toolset Firewall - file BFLEA-2201.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Research"
		date = "2016-08-16"
		hash1 = "15e8c743770e44314496c5f27b6297c5d7a4af09404c4aa507757e0cc8edc79e"
		id = "7dfdc2a2-73d1-5eba-8936-ed14b17495c5"
	strings:
		$s1 = ".got_loader" fullword ascii
		$s2 = "LOADED" fullword ascii
		$s3 = "readFlashHandler" fullword ascii
		$s4 = "KEEPGOING" fullword ascii
		$s5 = "flashRtnsPix6x.c" fullword ascii
		$s6 = "fix_ip_cksum_incr" fullword ascii
		$s7 = "writeFlashHandler" fullword ascii
	condition:
		( uint16(0) == 0x457f and filesize < 30KB and 5 of them ) or ( all of them )
}

rule EQGRP_BpfCreator_RHEL4 {
	meta:
		description = "EQGRP Toolset Firewall - file BpfCreator-RHEL4"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Research"
		date = "2016-08-16"
		hash1 = "bd7303393409623cabf0fcf2127a0b81fae52fe40a0d2b8db0f9f092902bbd92"
		id = "476185f2-b093-5fb9-8604-891e96fe52a9"
	strings:
		$s1 = "usage %s \"<tcpdump pcap string>\" <outfile>" fullword ascii
		$s2 = "error reading dump file: %s" fullword ascii
		$s3 = "truncated dump file; tried to read %u captured bytes, only got %lu" fullword ascii
		$s4 = "%s: link-layer type %d isn't supported in savefiles" fullword ascii
		$s5 = "DLT %d is not one of the DLTs supported by this device" fullword ascii
	condition:
		( uint16(0) == 0x457f and filesize < 2000KB and all of them )
}

rule EQGRP_StoreFc {
	meta:
		description = "EQGRP Toolset Firewall - file StoreFc.py"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Research"
		date = "2016-08-16"
		hash1 = "f155cce4eecff8598243a721389046ae2b6ca8ba6cb7b4ac00fd724601a56108"
		id = "48bbf5c9-e884-5126-93a2-d27650409882"
	strings:
		$x1 = "Usage: StoreFc.py --configFile=<path to xml file> --implantFile=<path to BinStore implant> [--outputFile=<file to write the conf" ascii
		$x2 = "raise Exception, \"Must supply both a config file and implant file.\"" fullword ascii
		$x3 = "This is wrapper for Store.py that FELONYCROWBAR will use. This" fullword ascii
	condition:
		1 of them
}

rule EQGRP_hexdump {
	meta:
		description = "EQGRP Toolset Firewall - file hexdump.py"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Research"
		date = "2016-08-16"
		hash1 = "95a9a6a8de60d3215c1c9f82d2d8b2640b42f5cabdc8b50bd1f4be2ea9d7575a"
		id = "32a7d845-2fa3-5d8f-84e1-2c7f8d2ca8c8"
	strings:
		$s1 = "def hexdump(x,lead=\"[+] \",out=sys.stdout):" fullword ascii
		$s2 = "print >>out, \"%s%04x  \" % (lead,i)," fullword ascii
		$s3 = "print >>out, \"%02X\" % ord(x[i+j])," fullword ascii
		$s4 = "print >>out, sane(x[i:i+16])" fullword ascii
	condition:
		( uint16(0) == 0x2123 and filesize < 1KB and 2 of ($s*) ) or ( all of them )
}

rule EQGRP_BBALL {
	meta:
		description = "EQGRP Toolset Firewall - file BBALL_E28F6-2201.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Research"
		date = "2016-08-16"
		hash1 = "498fc9f20b938b8111adfa3ca215325f265a08092eefd5300c4168876deb7bf6"
		id = "bced11a2-fac4-58e5-a4a8-1c6d5fe418f9"
	strings:
		$s1 = "Components/Modules/BiosModule/Implant/E28F6/../e28f640j3_asm.S" fullword ascii
		$s2 = ".got_loader" fullword ascii
		$s3 = "handler_readBIOS" fullword ascii
		$s4 = "cmosReadByte" fullword ascii
		$s5 = "KEEPGOING" fullword ascii
		$s6 = "checksumAreaConfirmed.0" fullword ascii
		$s7 = "writeSpeedPlow.c" fullword ascii
	condition:
		( uint16(0) == 0x457f and filesize < 40KB and 4 of ($s*) ) or ( all of them )
}

/* Super Rules ------------------------------------------------------------- */

rule EQGRP_BARPUNCH_BPICKER {
	meta:
		description = "EQGRP Toolset Firewall - from files BARPUNCH-3110, BPICKER-3100"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Research"
		date = "2016-08-16"
		super_rule = 1
		hash1 = "830538fe8c981ca386c6c7d55635ac61161b23e6e25d96280ac2fc638c2d82cc"
		hash2 = "d859ce034751cac960825268a157ced7c7001d553b03aec54e6794ff66185e6f"
		id = "7e88ba9d-1f15-533a-b388-a2a027ddb07c"
	strings:
		$x1 = "--cmd %x --idkey %s --sport %i --dport %i --lp %s --implant %s --bsize %hu --logdir %s --lptimeout %u" fullword ascii
		$x2 = "%s -c <cmdtype> -l <lp> -i <implant> -k <ikey> -s <port> -d <port> [operation] [options]" fullword ascii
		$x3 = "* [%lu] 0x%x is marked as stateless (the module will be persisted without its configuration)" fullword ascii
		$x4 = "%s version %s already has persistence installed. If you want to uninstall," fullword ascii
		$x5 = "The active module(s) on the target are not meant to be persisted" fullword ascii
	condition:
		( uint16(0) == 0x457f and filesize < 6000KB and 1 of them ) or ( 3 of them )
}

rule EQGRP_Implants_Gen6 {
	meta:
		description = "EQGRP Toolset Firewall"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Research"
		date = "2016-08-16"
		super_rule = 1
		hash1 = "3366b4bbf265716869a487203a8ac39867920880990493dd4dd8385e42b0c119"
		hash2 = "05031898f3d52a5e05de119868c0ec7caad3c9f3e9780e12f6f28b02941895a4"
		hash3 = "d9756e3ba272cd4502d88f4520747e9e69d241dee6561f30423840123c1a7939"
		hash4 = "8e4a76c4b50350b67cabbb2fed47d781ee52d8d21121647b0c0356498aeda2a2"
		hash5 = "6059bec5cf297266079d52dbb29ab9b9e0b35ce43f718022b5b5f760c1976ec3"
		hash6 = "d859ce034751cac960825268a157ced7c7001d553b03aec54e6794ff66185e6f"
		hash7 = "464b4c01f93f31500d2d770360d23bdc37e5ad4885e274a629ea86b2accb7a5c"
		id = "1b1c6426-7274-5fd4-9ea2-ef10bda769d4"
	strings:
		$s1 = "LP.c:pixSecurity - Improper number of bytes read in Security/Interface Information" fullword ascii
		$s2 = "LP.c:pixSecurity - Not in Session" fullword ascii
		$s3 = "getModInterface__preloadedModules" fullword ascii
		$s4 = "showCommands" fullword ascii
		$s5 = "readModuleInterface" fullword ascii
		$s6 = "Wrapping_Not_Necessary_Or_Wrapping_Ok" fullword ascii
		$s7 = "Get_CMD_List" fullword ascii
		$s8 = "LP_Listen2" fullword ascii
		$s9 = "killCmdList" fullword ascii
	condition:
		( uint16(0) == 0x457f and filesize < 6000KB and all of them )
}

rule EQGRP_Implants_Gen5 {
	meta:
		description = "EQGRP Toolset Firewall"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Research"
		date = "2016-08-16"
		super_rule = 1
		hash1 = "3366b4bbf265716869a487203a8ac39867920880990493dd4dd8385e42b0c119"
		hash2 = "830538fe8c981ca386c6c7d55635ac61161b23e6e25d96280ac2fc638c2d82cc"
		hash3 = "05031898f3d52a5e05de119868c0ec7caad3c9f3e9780e12f6f28b02941895a4"
		hash4 = "d9756e3ba272cd4502d88f4520747e9e69d241dee6561f30423840123c1a7939"
		hash5 = "8e4a76c4b50350b67cabbb2fed47d781ee52d8d21121647b0c0356498aeda2a2"
		hash6 = "6059bec5cf297266079d52dbb29ab9b9e0b35ce43f718022b5b5f760c1976ec3"
		hash7 = "d859ce034751cac960825268a157ced7c7001d553b03aec54e6794ff66185e6f"
		hash8 = "464b4c01f93f31500d2d770360d23bdc37e5ad4885e274a629ea86b2accb7a5c"
		id = "e35748ee-d530-5e73-a74d-5675d05725e9"
	strings:
		$x1 = "Module and Implant versions do not match.  This module is not compatible with the target implant" fullword ascii

		$s1 = "%s/BF_READ_%08x_%04d%02d%02d_%02d%02d%02d.log" fullword ascii
		$s2 = "%s/BF_%04d%02d%02d.log" fullword ascii
		$s3 = "%s/BF_READ_%08x_%04d%02d%02d_%02d%02d%02d.bin" fullword ascii
	condition:
		( uint16(0) == 0x457f and 1 of ($x*) ) or ( all of them )
}

rule EQGRP_pandarock {
	meta:
		description = "EQGRP Toolset Firewall - from files pandarock_v1.11.1.1.bin, pit"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Research"
		date = "2016-08-16"
		super_rule = 1
		hash1 = "1214e282ac7258e616ebd76f912d4b2455d1b415b7216823caa3fc0d09045a5f"
		hash2 = "c8a151df7605cb48feb8be2ab43ec965b561d2b6e2a837d645fdf6a6191ab5fe"
		id = "aa0ee05b-b3e4-576a-8a32-bdc8d98fe636"
	strings:
		$x1 = "* Not attempting to execute \"%s\" command" fullword ascii
		$x2 = "TERMINATING SCRIPT (command error or \"quit\" encountered)" fullword ascii
		$x3 = "execute code in <file> passing <argX> (HEX)" fullword ascii
		$x4 = "* Use arrow keys to scroll through command history" fullword ascii

		$s1 = "pitCmd_processCmdLine" fullword ascii
		$s2 = "execute all commands in <file>" fullword ascii
		$s3 = "__processShellCmd" ascii
		$s4 = "pitTarget_getDstPort" fullword ascii
		$s5 = "__processSetTargetIp" ascii

		$o1 = "Logging commands and output - ON" fullword ascii
		$o2 = "This command is too dangerous.  If you'd like to run it, contact the development team" fullword ascii
	condition:
		( uint16(0) == 0x457f and filesize < 3000KB and 1 of ($x*) ) or ( 4 of them ) or 1 of ($o*)
}

rule EQGRP_BananaUsurper_writeJetPlow {
	meta:
		description = "EQGRP Toolset Firewall - from files BananaUsurper-2120, writeJetPlow-2130"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Research"
		date = "2016-08-16"
		super_rule = 1
		hash1 = "3366b4bbf265716869a487203a8ac39867920880990493dd4dd8385e42b0c119"
		hash2 = "464b4c01f93f31500d2d770360d23bdc37e5ad4885e274a629ea86b2accb7a5c"
		id = "901af182-cbfa-533a-a055-565d95005d62"
	strings:
		$x1 = "Implant Version-Specific Values:" fullword ascii
		$x2 = "This function should not be used with a Netscreen, something has gone horribly wrong" fullword ascii

		$s1 = "createSendRecv: recv'd an error from the target." fullword ascii
		$s2 = "Error: WatchDogTimeout read returned %d instead of 4" fullword ascii
	condition:
		( uint16(0) == 0x457f and filesize < 2000KB and 1 of ($x*) ) or ( 3 of them )
}

rule EQGRP_Implants_Gen4 {
	meta:
		description = "EQGRP Toolset Firewall - from files BLIAR-2110, BLIQUER-2230, BLIQUER-3030, BLIQUER-3120"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Research"
		date = "2016-08-16"
		super_rule = 1
		hash1 = "05031898f3d52a5e05de119868c0ec7caad3c9f3e9780e12f6f28b02941895a4"
		hash2 = "d9756e3ba272cd4502d88f4520747e9e69d241dee6561f30423840123c1a7939"
		hash3 = "8e4a76c4b50350b67cabbb2fed47d781ee52d8d21121647b0c0356498aeda2a2"
		hash4 = "6059bec5cf297266079d52dbb29ab9b9e0b35ce43f718022b5b5f760c1976ec3"
		id = "8b2061f0-862d-51de-a7d0-7a36d3e71d61"
	strings:
		$s1 = "Command has not yet been coded" fullword ascii
		$s2 = "Beacon Domain  : www.%s.com" fullword ascii
		$s3 = "This command can only be run on a PIX/ASA" fullword ascii
		$s4 = "Warning! Bad or missing Flash values (in section 2 of .dat file)" fullword ascii
		$s5 = "Printing the interface info and security levels. PIX ONLY." fullword ascii
	condition:
		( uint16(0) == 0x457f and filesize < 3000KB and 3 of them ) or ( all of them )
}

rule EQGRP_Implants_Gen3 {
	meta:
		description = "EQGRP Toolset Firewall"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Research"
		date = "2016-08-16"
		super_rule = 1
		hash1 = "830538fe8c981ca386c6c7d55635ac61161b23e6e25d96280ac2fc638c2d82cc"
		hash2 = "05031898f3d52a5e05de119868c0ec7caad3c9f3e9780e12f6f28b02941895a4"
		hash3 = "d9756e3ba272cd4502d88f4520747e9e69d241dee6561f30423840123c1a7939"
		hash4 = "8e4a76c4b50350b67cabbb2fed47d781ee52d8d21121647b0c0356498aeda2a2"
		hash5 = "6059bec5cf297266079d52dbb29ab9b9e0b35ce43f718022b5b5f760c1976ec3"
		hash6 = "d859ce034751cac960825268a157ced7c7001d553b03aec54e6794ff66185e6f"
		id = "ec64bb2b-566b-50b6-a518-222afc88d400"
	strings:
		$x1 = "incomplete and must be removed manually.)" fullword ascii

		$s1 = "%s: recv'd an error from the target." fullword ascii
		$s2 = "Unable to fetch the address to the get_uptime_secs function for this OS version" fullword ascii
		$s3 = "upload/activate/de-activate/remove/cmd function failed" fullword ascii
	condition:
		( uint16(0) == 0x457f and filesize < 6000KB and 2 of them ) or ( all of them )
}

rule EQGRP_BLIAR_BLIQUER {
	meta:
		description = "EQGRP Toolset Firewall - from files BLIAR-2110, BLIQUER-2230"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Research"
		date = "2016-08-16"
		super_rule = 1
		hash1 = "05031898f3d52a5e05de119868c0ec7caad3c9f3e9780e12f6f28b02941895a4"
		hash2 = "d9756e3ba272cd4502d88f4520747e9e69d241dee6561f30423840123c1a7939"
		id = "6f83bb11-f789-544e-8dca-c2dc2c845331"
	strings:
		$x1 = "Do you wish to activate the implant that is already on the firewall? (y/n): " fullword ascii
		$x2 = "There is no implant present on the firewall." fullword ascii
		$x3 = "Implant Version :%lx%lx%lx" fullword ascii
		$x4 = "You may now connect to the implant using the pbd idkey" fullword ascii
		$x5 = "No reply from persistant back door." fullword ascii
		$x6 = "rm -rf pbd.wc; wc -c %s > pbd.wc" fullword ascii

		$p1 = "PBD_GetVersion" fullword ascii
		$p2 = "pbd/pbdEncrypt.bin" fullword ascii
		$p3 = "pbd/pbdGetVersion.pkt" fullword ascii
		$p4 = "pbd/pbdStartWrite.bin" fullword ascii
		$p5 = "pbd/pbd_setNewHookPt.pkt" fullword ascii
		$p6 = "pbd/pbd_Upload_SinglePkt.pkt" fullword ascii

		$s1 = "Unable to fetch hook and jmp addresses for this OS version" fullword ascii
		$s2 = "Could not get hook and jump addresses" fullword ascii
		$s3 = "Enter the name of a clean implant binary (NOT an image):" fullword ascii
		$s4 = "Unable to read dat file for OS version 0x%08lx" fullword ascii
		$s5 = "Invalid implant file" fullword ascii
	condition:
		( uint16(0) == 0x457f and filesize < 3000KB and ( 1 of ($x*) or 1 of ($p*) ) ) or ( 3 of them )
}

rule EQGRP_sploit {
	meta:
		description = "EQGRP Toolset Firewall - from files sploit.py, sploit.py"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Research"
		date = "2016-08-16"
		super_rule = 1
		hash1 = "0316d70a5bbf068a7fc791e08e816015d04ec98f088a7ff42af8b9e769b8d1f6"
		hash2 = "0316d70a5bbf068a7fc791e08e816015d04ec98f088a7ff42af8b9e769b8d1f6"
		id = "9f403965-5fb1-55b2-bef6-65c18e08e58f"
	strings:
		$s1 = "print \"[+] Connecting to %s:%s\" % (self.params.dst['ip'], self.params.dst['port'])" fullword ascii
		$s2 = "@overridable(\"Must be overriden if the target will be touched.  Base implementation should not be called.\")" fullword ascii
		$s3 = "@overridable(\"Must be overriden.  Base implementation should not be called.\")" fullword ascii
		$s4 = "exp.load_vinfo()" fullword ascii
		$s5 = "if not okay and self.terminateFlingOnException:" fullword ascii
		$s6 = "print \"[-] keyboard interrupt before response received\"" fullword ascii
		$s7 = "if self.terminateFlingOnException:" fullword ascii
		$s8 = "print 'Debug info ','='*40" fullword ascii
	condition:
		( uint16(0) == 0x2123 and filesize < 90KB and 1 of ($s*) ) or ( 4 of them )
}

rule EQGRP_Implants_Gen2 {
	meta:
		description = "EQGRP Toolset Firewall"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Research"
		date = "2016-08-16"
		super_rule = 1
		hash1 = "3366b4bbf265716869a487203a8ac39867920880990493dd4dd8385e42b0c119"
		hash2 = "05031898f3d52a5e05de119868c0ec7caad3c9f3e9780e12f6f28b02941895a4"
		hash3 = "d9756e3ba272cd4502d88f4520747e9e69d241dee6561f30423840123c1a7939"
		hash4 = "8e4a76c4b50350b67cabbb2fed47d781ee52d8d21121647b0c0356498aeda2a2"
		hash5 = "6059bec5cf297266079d52dbb29ab9b9e0b35ce43f718022b5b5f760c1976ec3"
		hash6 = "464b4c01f93f31500d2d770360d23bdc37e5ad4885e274a629ea86b2accb7a5c"
		id = "58b0b51d-d1f8-5ee2-a4af-491c49dd0573"
	strings:
		$x1 = "Modules persistence file written successfully" fullword ascii
		$x2 = "Modules persistence data successfully removed" fullword ascii
		$x3 = "No Modules are active on the firewall, nothing to persist" fullword ascii

		$s1 = "--cmd %x --idkey %s --sport %i --dport %i --lp %s --implant %s --bsize %hu --logdir %s " fullword ascii
		$s2 = "Error while attemping to persist modules:" fullword ascii
		$s3 = "Error while reading interface info from PIX" fullword ascii
		$s4 = "LP.c:pixFree - Failed to get response" fullword ascii
		$s5 = "WARNING: LP Timeout specified (%lu seconds) less than default (%u seconds).  Setting default" fullword ascii
		$s6 = "Unable to fetch config address for this OS version" fullword ascii
		$s7 = "LP.c: interface information not available for this session" fullword ascii
		$s8 = "[%s:%s:%d] ERROR: " fullword ascii
		$s9 = "extract_fgbg" fullword ascii
	condition:
		( uint16(0) == 0x457f and filesize < 3000KB and 1 of ($x*) ) or ( 5 of them )
}

rule EQGRP_Implants_Gen1 {
	meta:
		description = "EQGRP Toolset Firewall"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Research"
		date = "2016-08-16"
		super_rule = 1
		hash1 = "3366b4bbf265716869a487203a8ac39867920880990493dd4dd8385e42b0c119"
		hash2 = "830538fe8c981ca386c6c7d55635ac61161b23e6e25d96280ac2fc638c2d82cc"
		hash3 = "05031898f3d52a5e05de119868c0ec7caad3c9f3e9780e12f6f28b02941895a4"
		hash4 = "d9756e3ba272cd4502d88f4520747e9e69d241dee6561f30423840123c1a7939"
		hash5 = "8e4a76c4b50350b67cabbb2fed47d781ee52d8d21121647b0c0356498aeda2a2"
		hash6 = "6059bec5cf297266079d52dbb29ab9b9e0b35ce43f718022b5b5f760c1976ec3"
		hash7 = "d859ce034751cac960825268a157ced7c7001d553b03aec54e6794ff66185e6f"
		hash8 = "ee3e3487a9582181892e27b4078c5a3cb47bb31fc607634468cc67753f7e61d7"
		hash9 = "464b4c01f93f31500d2d770360d23bdc37e5ad4885e274a629ea86b2accb7a5c"
		id = "af0a1a2c-0efb-568f-9e80-baee7398fea2"
	strings:
		$s1 = "WARNING:  Session may not have been closed!" fullword ascii
		$s2 = "EXEC Packet Processed" fullword ascii
		$s3 = "Failed to insert the command into command list." fullword ascii
		$s4 = "Send_Packet: Trying to send too much data." fullword ascii
		$s5 = "payloadLength >= MAX_ALLOW_SIZE." fullword ascii
		$s6 = "Wrong Payload Size" fullword ascii
		$s7 = "Unknown packet received......" fullword ascii
		$s8 = "Returned eax = %08x" fullword ascii
	condition:
		( uint16(0) == 0x457f and filesize < 6000KB and ( 2 of ($s*) ) ) or ( 5 of them )
}

rule EQGRP_eligiblebombshell_generic {
	meta:
		description = "EQGRP Toolset Firewall - from files eligiblebombshell_1.2.0.1.py, eligiblebombshell_1.2.0.1.py"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Research"
		date = "2016-08-16"
		super_rule = 1
		hash1 = "dd0e3ae6e1039a755bf6cb28bf726b4d6ab4a1da2392ba66d114a43a55491eb1"
		hash2 = "dd0e3ae6e1039a755bf6cb28bf726b4d6ab4a1da2392ba66d114a43a55491eb1"
		id = "7abe53f6-9880-523a-b71f-6e3850047764"
	strings:
		$s1 = "logging.error(\"       Perhaps you should run with --scan?\")" fullword ascii
		$s2 = "logging.error(\"ERROR: No entry for ETag [%s] in %s.\" %" fullword ascii
		$s3 = "\"be supplied\")" fullword ascii
	condition:
		( filesize < 70KB and 2 of ($s*) ) or ( all of them )
}

rule EQGRP_ssh_telnet_29 {
	meta:
		description = "EQGRP Toolset Firewall - from files ssh.py, telnet.py"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Research"
		date = "2016-08-16"
		super_rule = 1
		hash1 = "630d464b1d08c4dfd0bd50552bee2d6a591fb0b5597ecebaa556a3c3d4e0aa4e"
		hash2 = "07f4c60505f4d5fb5c4a76a8c899d9b63291444a3980d94c06e1d5889ae85482"
		id = "cc6edf63-f7ef-579a-82c5-28e5012561e0"
	strings:
		$s1 = "received prompt, we're in" fullword ascii
		$s2 = "failed to login, bad creds, abort" fullword ascii
		$s3 = "sending command \" + str(n) + \"/\" + str(tot) + \", len \" + str(len(chunk) + " fullword ascii
		$s4 = "received nat - EPBA: ok, payload: mangled, did not run" fullword ascii
		$s5 = "no status returned from target, could be an exploit failure, or this is a version where we don't expect a stus return" ascii
		$s6 = "received arp - EPBA: ok, payload: fail" fullword ascii
		$s7 = "chopped = string.rstrip(payload, \"\\x0a\")" fullword ascii
	condition:
		( filesize < 10KB and 2 of them ) or ( 3 of them )
}

/* Extras */

rule EQGRP_tinyexec {
	meta:
		description = "EQGRP Toolset Firewall - from files tinyexec"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Research"
		date = "2016-08-16"
		id = "b783bafd-52e2-59e8-98ab-47de3250415e"
	strings:
		$s1 = { 73 68 73 74 72 74 61 62 00 2E 74 65 78 74 }
		$s2 = { 5A 58 55 52 89 E2 55 50 89 E1 }
	condition:
		uint32(0) == 0x464c457f and filesize < 270 and all of them
}

rule EQGRP_callbacks {
	meta:
		description = "EQGRP Toolset Firewall - Callback addresses"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Research"
		date = "2016-08-16"
		id = "dd1fbe09-4def-562d-825d-e790dc2c3dd9"
	strings:
		$s1 = "30.40.50.60:9342" fullword ascii wide /* DoD */
	condition:
		1 of them
}

rule EQGRP_Extrabacon_Output {
	meta:
		description = "EQGRP Toolset Firewall - Extrabacon exploit output"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Research"
		date = "2016-08-16"
		id = "b2070ed7-e95a-534a-8f27-63c5ca9251b4"
	strings:
		$s1 = "|###[ SNMPresponse ]###" fullword ascii
		$s2 = "[+] generating exploit for exec mode pass-disable" fullword ascii
		$s3 = "[+] building payload for mode pass-disable" fullword ascii
		$s4 = "[+] Executing:  extrabacon" fullword ascii
		$s5 = "appended AAAADMINAUTH_ENABLE payload" fullword ascii
	condition:
		2 of them
}

rule EQGRP_Unique_Strings {
	meta:
		description = "EQGRP Toolset Firewall - Unique strings"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Research"
		date = "2016-08-16"
		id = "08f5f1e3-ce4e-54ef-922f-50446edfcd70"
	strings:
		$s1 = "/BananaGlee/ELIGIBLEBOMB" ascii
		$s2 = "Protocol must be either http or https (Ex: https://1.2.3.4:1234)"
	condition:
		1 of them
}

rule EQGRP_RC5_RC6_Opcode {
	meta:
		description = "EQGRP Toolset Firewall - RC5 / RC6 opcode"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://securelist.com/blog/incidents/75812/the-equation-giveaway/"
		date = "2016-08-17"
		id = "b12a1a2c-8d32-5318-a658-6aa1a08c3263"
	strings:
		/*
			mov     esi, [ecx+edx*4-4]
			sub     esi, 61C88647h
			mov     [ecx+edx*4], esi
			inc     edx
			cmp     edx, 2Bh
		*/
		$s1 = { 8B 74 91 FC 81 EE 47 86 C8 61 89 34 91 42 83 FA 2B }
	condition:
		1 of them
}

/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-01-13
   Identifier: EquationGroup - ShadowBrokers Release January 2017
*/

/* Rule Set ----------------------------------------------------------------- */

rule EquationGroup_modifyAudit_Implant {
   meta:
      description = "EquationGroup Malware - file modifyAudit_Implant.dll"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://goo.gl/tcSoiJ"
      date = "2017-01-13"
      hash1 = "b7902809a15c4c3864a14f009768693c66f9e9234204b873d29a87f4c3009a50"
      id = "0321f6c0-2250-5991-a1d9-f0598e13c665"
   strings:
      $s1 = "LSASS.EXE" fullword wide
      $s2 = "hNtQueryInformationProcess" fullword ascii
      $s3 = "hZwOpenProcess" fullword ascii
      $s4 = ".?AVFeFinallyFailure@@" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 90KB and ( all of ($s*) ) ) or ( all of them )
}

rule EquationGroup_modifyAudit_Lp {
   meta:
      description = "EquationGroup Malware - file modifyAudit_Lp.dll"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://goo.gl/tcSoiJ"
      date = "2017-01-13"
      hash1 = "2a1f2034e80421359e3bf65cbd12a55a95bd00f2eb86cf2c2d287711ee1d56ad"
      id = "9dcfa774-0048-5bd9-ba7d-87bbdff9567a"
   strings:
      $s1 = "Read of audit related process memory failed" fullword wide
      $s2 = "** This may indicate that another copy of modify_audit is already running **" fullword wide
      $s3 = "Pattern match of code failed" fullword wide
      $s4 = "Base for necessary auditing dll not found" fullword wide
      $s5 = "Security auditing has been disabled" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 300KB and 3 of them ) or ( all of them )
}

rule EquationGroup_ProcessHide_Lp {
   meta:
      description = "EquationGroup Malware - file ProcessHide_Lp.dll"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://goo.gl/tcSoiJ"
      date = "2017-01-13"
      hash1 = "cdee0daa816f179e74c90c850abd427fbfe0888dcfbc38bf21173f543cdcdc66"
      id = "b0842897-f591-5213-9a26-0f8732e6f3b8"
   strings:
      $x1 = "Invalid flag.  Can only hide or unhide" fullword wide
      $x2 = "Process elevation failed" fullword wide
      $x3 = "Unknown error hiding process" fullword wide
      $x4 = "Invalid process links found in EPROCESS" fullword wide
      $x5 = "Unable to find SYSTEM process" fullword wide
      $x6 = "Process hidden, but EPROCESS location lost" fullword wide
      $x7 = "Invalid EPROCESS location for given ID" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 300KB and 1 of them ) or ( 3 of them )
}

rule EquationGroup_pwdump_Implant {
   meta:
      description = "EquationGroup Malware - file pwdump_Implant.dll"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://goo.gl/tcSoiJ"
      date = "2017-01-13"
      hash1 = "dfd5768a4825d1c7329c2e262fde27e2b3d9c810653585b058fcf9efa9815964"
      id = "55984c20-539e-5e51-b3c4-caa6157c993d"
   strings:
      $s1 = ".?AVFeFinallyFailure@@" fullword ascii
      $s8 = ".?AVFeFinallySuccess@@" fullword ascii
      $s3 = "\\system32\\win32k.sys" wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 100KB and all of them )
}

rule EquationGroup_EquationDrug_Gen_5 {
   meta:
      description = "EquationGroup Malware - file PC_Level3_http_dll"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://goo.gl/tcSoiJ"
      date = "2017-01-13"
      hash1 = "4ebfc1f6ec6a0e68e47e5b231331470a4483184cf715a578191b91ba7c32094d"
      id = "a67655eb-5593-5ac7-a6aa-81f235fa3c33"
   strings:
      $s1 = "Psxssdll.dll" fullword wide
      $s2 = "Posix Server Dll" fullword wide
      $s3 = "itanium" fullword wide
      $s6 = "Copyright (C) Microsoft" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 300KB and all of them )
}

rule EquationGroup_PC_Level3_http_flav_dll {
   meta:
      description = "EquationGroup Malware - file PC_Level3_http_flav_dll"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://goo.gl/tcSoiJ"
      date = "2017-01-13"
      hash1 = "27972d636b05a794d17cb3203d537bcf7c379fafd1802792e7fb8e72f130a0c4"
      id = "4bc4804b-c6d2-5c94-b451-24bb0f3dba43"
   strings:
      $s1 = "Psxssdll.dll" fullword wide
      $s2 = "Posix Server Dll" fullword wide
      $s4 = "itanium" fullword wide
      $s5 = "RHTTP/1.0" fullword wide
      $s8 = "Copyright (C) Microsoft" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 300KB and all of them )
}

rule EquationGroup_LSADUMP_Lp {
   meta:
      description = "EquationGroup Malware - file LSADUMP_Lp.dll"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://goo.gl/tcSoiJ"
      date = "2017-01-13"
      hash1 = "c7bf4c012293e7de56d86f4f5b4eeb6c1c5263568cc4d9863a286a86b5daf194"
      id = "8068ca41-6365-5c97-82f2-be9ad89628e0"
   strings:
      $x1 = "LSADUMP - - ERROR - - Injected" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 300KB and 1 of them )
}

rule EquationGroup_EquationDrug_mstcp32 {
   meta:
      description = "EquationGroup Malware - file mstcp32.sys"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://goo.gl/tcSoiJ"
      date = "2017-01-13"
      modified = "2023-01-06"
      hash1 = "26215bc56dc31d2466d72f1f4e1b6388e62606e9949bc41c28968fcb9a9d60a6"
      id = "bed26a7b-933f-5578-b65c-65179959050d"
   strings:
      $s1 = "mstcp32.sys" fullword wide
      $s2 = "p32.sys" fullword ascii
      $s3 = "\\Registry\\User\\CurrentUser\\" wide
      $s4 = "\\DosDevices\\%ws" wide
      $s5 = "\\Device\\%ws_%ws" wide
      $s6 = "sys\\mstcp32.dbg" fullword ascii
      $s7 = "%ws%03d%ws%wZ" fullword wide
      $s8 = "TCP/IP driver" fullword wide
      $s9 = "\\Device\\%ws" wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 200KB and 7 of them ) or ( all of them )
}

rule EquationGroup_nethide_Lp {
   meta:
      description = "EquationGroup Malware - file nethide_Lp.dll"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://goo.gl/tcSoiJ"
      date = "2017-01-13"
      hash1 = "137749c0fbb8c12d1a650f0bfc73be2739ff084165d02e4cb68c6496d828bf1d"
      id = "39e96239-2189-5993-90ba-27e47f7bfdea"
   strings:
      $x1 = "Error: Attempt to hide all TCP connections (any:any)." fullword wide
      $x2 = "privilegeRunInKernelMode failed" fullword wide
      $x3 = "Failed to unhide requested connection" fullword wide
      $x4 = "Nethide running in USER_MODE" fullword wide
      $x5 = "Not enough slots for all of the list.  Some entries may have not been hidden." fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 300KB and 1 of them ) or ( all of them )
}

rule EquationGroup_PC_Level4_flav_dll_x64 {
   meta:
      description = "EquationGroup Malware - file PC_Level4_flav_dll_x64"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://goo.gl/tcSoiJ"
      date = "2017-01-13"
      hash1 = "25a2549031cb97b8a3b569b1263c903c6c0247f7fff866e7ec63f0add1b4921c"
      id = "f05dd0b6-106c-5d1d-ba09-4ac3035e7030"
   strings:
      $s1 = "wship.dll" fullword wide
      $s2 = "   IP:      " fullword ascii
      $s3 = "\\\\.\\%hs" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 200KB and all of them )
}

rule EquationGroup_PC_Level4_flav_exe {
   meta:
      description = "EquationGroup Malware - file PC_Level4_flav_exe"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://goo.gl/tcSoiJ"
      date = "2017-01-13"
      hash1 = "33ba9f103186b6e52d8d69499512e7fbac9096e7c5278838127488acc3b669a9"
      id = "eb93a798-4e7e-52dc-a39b-bfb63a58d250"
   strings:
      $s1 = "Extended Memory Runtime Process" fullword wide
      $s2 = "memess.exe" fullword wide
      $s3 = "\\\\.\\%hs" fullword ascii
      $s4 = ".?AVOpenSocket@@" fullword ascii
      $s5 = "Corporation. All rights reserved." fullword wide
      $s6 = "itanium" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 200KB and all of them )
}

rule EquationGroup_processinfo_Implant {
   meta:
      description = "EquationGroup Malware - file processinfo_Implant.dll"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://goo.gl/tcSoiJ"
      date = "2017-01-13"
      hash1 = "aadfa0b1aec4456b10e4fb82f5cfa918dbf4e87d19a02bcc576ac499dda0fb68"
      id = "b110d819-2298-507b-91bb-2787bb11322e"
   strings:
      $s1 = "hZwOpenProcessToken" fullword ascii
      $s2 = "hNtQueryInformationProcess" fullword ascii
      $s3 = "No mapping" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 80KB and all of them )
}

rule EquationGroup_EquationDrug_Gen_2 {
   meta:
      description = "EquationGroup Malware - file PortMap_Implant.dll"
      author = "Auto Generated"
      reference = "https://goo.gl/tcSoiJ"
      date = "2017-01-13"
      hash1 = "964762416840738b1235ed4ae479a4b117b8cdcc762a6737e83bc2062c0cf236"
      id = "662ee1cf-b837-5362-84a8-1af7335d5e1b"
   strings:
      $op1 = { 0c 2b ca 8a 04 11 3a 02 75 01 47 42 4e 75 f4 8b }
      $op2 = { 14 83 c1 05 80 39 85 75 0c 80 79 01 c0 75 06 80 }
      $op3 = { eb 3d 83 c0 06 33 f6 80 38 ff 75 2c 80 78 01 15 }
   condition:
      ( uint16(0) == 0x5a4d and filesize < 250KB and all of them )
}


rule EquationGroup_EquationDrug_ntevt {
   meta:
      description = "EquationGroup Malware - file ntevt.sys"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://goo.gl/tcSoiJ"
      date = "2017-01-13"
      hash1 = "45e5e1ea3456d7852f5c610c7f4447776b9f15b56df7e3a53d57996123e0cebf"
      id = "36d23adb-dafe-5e99-8976-b146ceca2f9b"
   strings:
      $s1 = "ntevt.sys" fullword ascii
      $s2 = "c:\\ntevt.pdb" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 500KB and all of them )
}

rule EquationGroup_nethide_Implant {
   meta:
      description = "EquationGroup Malware - file nethide_Implant.dll"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://goo.gl/tcSoiJ"
      date = "2017-01-13"
	  modified = "2023-01-27"
      hash1 = "b2daf9058fdc5e2affd5a409aebb90343ddde4239331d3de8edabeafdb3a48fa"
      id = "36559b69-1718-5d9b-8d6f-3db4becba0c4"
   strings:
      $s1 = "\\\\.\\dlcndi" fullword ascii
      $s2 = "s\\drivers\\" wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 90KB and all of them )
}

rule EquationGroup_EquationDrug_Gen_4 {
   meta:
      description = "EquationGroup Malware - file PC_Level4_flav_dll"
      author = "Auto Generated"
      reference = "https://goo.gl/tcSoiJ"
      date = "2017-01-13"
      hash1 = "227faeb770ba538fb85692b3dfcd00f76a0a5205d1594bd0969a1e535ee90ee1"
      id = "e3fc376b-f7cc-5dfa-bcf4-4991962a4cf9"
   strings:
      $op1 = { 11 8b da 23 df 8d 1c 9e c1 fb 02 33 da 23 df 33 }
      $op2 = { c3 0c 57 8b 3b eb 27 8b f7 83 7e 08 00 8b 3f 74 }
      $op3 = { 00 0f b7 5e 14 8d 5c 33 18 8b c3 2b 45 08 50 ff }
   condition:
      ( uint16(0) == 0x5a4d and filesize < 300KB and all of them )
}

rule EquationGroup_EquationDrug_tdi6 {
   meta:
      description = "EquationGroup Malware - file tdi6.sys"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://goo.gl/tcSoiJ"
      date = "2017-01-13"
      hash1 = "12c082f74c0916a0e926488642236de3a12072a18d29c97bead15bb301f4b3f8"
      id = "c6dbc28a-ec52-5256-afff-ab15ed1b90a6"
   strings:
      $s1 = "tdi6.sys" fullword wide
      $s3 = "TDI IPv6 Wrapper" fullword wide
      $s5 = "Corporation. All rights reserved." fullword wide
      $s6 = "FailAction" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 100KB and all of them )
}

rule EquationGroup_modifyAuthentication_Implant {
   meta:
      description = "EquationGroup Malware - file modifyAuthentication_Implant.dll"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://goo.gl/tcSoiJ"
      date = "2017-01-13"
      hash1 = "e1dff24af5bfc991dca21b4e3a19ffbc069176d674179eef691afc6b1ac6f805"
      id = "990035c5-cd9c-59e0-b244-e2caafd2561f"
   strings:
      $s1 = "LSASS.EXE" fullword wide
      $s2 = "hsamsrv.dll" fullword ascii
      $s3 = "hZwOpenProcess" fullword ascii
      $s4 = "hOpenProcess" fullword ascii
      $s5 = ".?AVFeFinallyFailure@@" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 200KB and all of them )
}

rule EquationGroup_ntfltmgr {
   meta:
      description = "EquationGroup Malware - file ntfltmgr.sys"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://goo.gl/tcSoiJ"
      date = "2017-01-13"
      hash1 = "f7a886ee10ee6f9c6be48c20f370514be62a3fd2da828b0dff44ff3d485ff5c5"
      id = "dd7fd371-a097-5df5-9ffd-89babbadee96"
   strings:
      $s1 = "ntfltmgr.sys" fullword wide
      $s2 = "ntfltmgr.pdb" fullword ascii
      $s4 = "Network Filter Manager" fullword wide
      $s5 = "Corporation. All rights reserved." fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 100KB and all of them )
}

rule EquationGroup_DXGHLP16 {
   meta:
      description = "EquationGroup Malware - file DXGHLP16.SYS"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://goo.gl/tcSoiJ"
      date = "2017-01-13"
      modified = "2023-01-06"
      hash1 = "fcfb56fa79d2383d34c471ef439314edc2239d632a880aa2de3cea430f6b5665"
      id = "d9e39c22-f606-5d9c-a5e2-e536b8566595"
   strings:
      $s1 = "DXGHLP16.SYS" fullword wide
      $s2 = "P16.SYS" fullword ascii
      $s3 = "\\Registry\\User\\CurrentUser\\" wide
      $s4 = "\\DosDevices\\%ws" wide
      $s5 = "\\Device\\%ws_%ws" wide
      $s6 = "ct@SYS\\DXGHLP16.dbg" fullword ascii
      $s7 = "%ws%03d%ws%wZ" fullword wide
      $s8 = "TCP/IP driver" fullword wide
      $s9 = "\\Device\\%ws" wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 200KB and all of them )
}

rule EquationGroup_EquationDrug_msgkd {
   meta:
      description = "EquationGroup Malware - file msgkd.ex_"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://goo.gl/tcSoiJ"
      date = "2017-01-13"
      hash1 = "25eec68fc9f0d8d1b5d72c9eae7bee29035918e9dcbeab13e276dec4b2ad2a56"
      id = "41019119-9bf4-5a45-b74b-f75ab7738821"
   strings:
      $s1 = "KEysud" fullword ascii
      $s2 = "XWWWPWS" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 300KB and all of them )
}

rule EquationGroup_RunAsChild_Lp {
   meta:
      description = "EquationGroup Malware - file RunAsChild_Lp.dll"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://goo.gl/tcSoiJ"
      date = "2017-01-13"
      hash1 = "1097e1d562341858e241f1f67788534c0e340a2dc2e75237d57e3f473e024464"
      id = "f0623c3f-3a49-5cdf-89ea-2b3273fd8324"
   strings:
      $s1 = "Privilege elevation failed" fullword wide
      $s2 = "Unable to open parent process" fullword wide
      $s4 = "Invalid input to lpRunAsChildPPC" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 300KB and all of them )
}

rule EquationGroup_EquationDrug_Gen_6 {
   meta:
      description = "EquationGroup Malware - file PC_Level3_dll_x64"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://goo.gl/tcSoiJ"
      date = "2017-01-13"
      hash1 = "339855618fb3ef53987b8c14a61bd4519b2616e766149e0c21cbd7cbe7a632c9"
      id = "99b2fab0-1298-5d48-a78b-eb59942ecfca"
   strings:
      $s1 = "Psxssdll.dll" fullword wide
      $s2 = "Posix Server Dll" fullword wide
      $s3 = "Copyright (C) Microsoft" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 300KB and all of them )
}

rule EquationGroup_PC_Level3_http_flav_dll_x64 {
   meta:
      description = "EquationGroup Malware - file PC_Level3_http_flav_dll_x64"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://goo.gl/tcSoiJ"
      date = "2017-01-13"
      hash1 = "4e0209b4f5990148f5d6dee47dbc7021bf78a782b85cef4d6c8be22d698b884f"
      id = "93a3d47d-1dac-5621-8e69-d6d23b7628db"
   strings:
      $s1 = "Psxssdll.dll" fullword wide
      $s2 = "Posix Server Dll" fullword wide
      $s3 = ".?AVOpenSocket@@" fullword ascii
      $s4 = "RHTTP/1.0" fullword wide
      $s5 = "Copyright (C) Microsoft" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 400KB and ( all of ($s*) ) ) or ( all of them )
}

rule EquationGroup_EquationDrug_Gen_3 {
   meta:
      description = "EquationGroup Malware - file mssld.dll"
      author = "Auto Generated"
      reference = "https://goo.gl/tcSoiJ"
      date = "2017-01-13"
      hash1 = "69dcc150468f7707cc8ef618a4cea4643a817171babfba9290395ada9611c63c"
      id = "f664ad78-1820-5434-94cc-94f98b32e654"
   strings:
      $op1 = { f4 65 c6 45 f5 6c c6 45 f6 33 c6 45 f7 32 c6 45 }
      $op2 = { 36 c6 45 e6 34 c6 45 e7 50 c6 45 e8 72 c6 45 e9 }
      $op3 = { c6 45 e8 65 c6 45 e9 70 c6 45 ea 74 c6 45 eb 5f }
   condition:
      ( uint16(0) == 0x5a4d and filesize < 1000KB and all of them )
}

rule EquationGroup_GetAdmin_Lp {
   meta:
      description = "EquationGroup Malware - file GetAdmin_Lp.dll"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://goo.gl/tcSoiJ"
      date = "2017-01-13"
      hash1 = "e1c9c9f031d902e69e42f684ae5b35a2513f7d5f8bca83dfbab10e8de6254c78"
      id = "3bbe0553-a5a3-5207-a94e-ad978606d9a4"
   strings:
      $x1 = "Current user is System -- unable to join administrators group" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 300KB and all of them )
}


rule EquationGroup_ModifyGroup_Lp {
   meta:
      description = "EquationGroup Malware - file ModifyGroup_Lp.dll"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://goo.gl/tcSoiJ"
      date = "2017-01-13"
      hash1 = "dfb38ed2ca3870faf351df1bd447a3dc4470ed568553bf83df07bf07967bf520"
      id = "82c9617a-3d78-525f-a507-76c87aad7c59"
   strings:
      $s1 = "Modify Privileges failed" fullword wide
      $s2 = "Given privilege name not found" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 300KB and all of them )
}

rule EquationGroup_pwdump_Lp {
   meta:
      description = "EquationGroup Malware - file pwdump_Lp.dll"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://goo.gl/tcSoiJ"
      date = "2017-01-13"
      hash1 = "fda57a2ba99bc610d3ff71b2d0ea2829915eabca168df99709a8fdd24288c5e5"
      id = "6f356f13-9ec1-5dd9-91b2-6a3071398e81"
   strings:
      $x1 = "PWDUMP - - ERROR - -" wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 300KB and all of them )
}

rule EquationGroup_EventLogEdit_Implant {
   meta:
      description = "EquationGroup Malware - file EventLogEdit_Implant.dll"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://goo.gl/tcSoiJ"
      date = "2017-01-13"
      hash1 = "0bb750195fbd93d174c2a8e20bcbcae4efefc881f7961fdca8fa6ebd68ac1edf"
      id = "40239dd0-4159-5c10-96b3-4f1e28c92d97"
   strings:
      $s1 = "SYSTEM\\CurrentControlSet\\Services\\EventLog\\%ls" fullword wide
      $s2 = "Ntdll.dll" fullword ascii
      $s3 = "hZwOpenProcess" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 100KB and all of them )
}

rule EquationGroup_PortMap_Lp {
   meta:
      description = "EquationGroup Malware - file PortMap_Lp.dll"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://goo.gl/tcSoiJ"
      date = "2017-01-13"
      hash1 = "2b27f2faae9de6330f17f60a1d19f9831336f57fdfef06c3b8876498882624a6"
      id = "e1851a17-9858-5c93-9993-2da0559e5d2e"
   strings:
      $s1 = "Privilege elevation failed" fullword wide
      $s2 = "Portmap ended due to max number of ports" fullword wide
      $s3 = "Invalid parameters received for portmap" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 300KB and 2 of them )
}

rule EquationGroup_ProcessOptions_Lp {
   meta:
      description = "EquationGroup Malware - file ProcessOptions_Lp.dll"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://goo.gl/tcSoiJ"
      date = "2017-01-13"
      hash1 = "31d86f77137f0b3697af03dd28d6552258314cecd3c1d9dc18fcf609eb24229a"
      id = "5ccb9751-fbcc-538c-8d55-dfc495067ce5"
   strings:
      $s1 = "Invalid parameter received by implant" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 300KB and all of them )
}

rule EquationGroup_PassFreely_Lp {
   meta:
      description = "EquationGroup Malware - file PassFreely_Lp.dll"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://goo.gl/tcSoiJ"
      date = "2017-01-13"
      hash1 = "fe42139748c8e9ba27a812466d9395b3a0818b0cd7b41d6769cb7239e57219fb"
      id = "5fb99194-f0df-54aa-9f20-7f8458155e62"
   strings:
      $s1 = "Unexpected value in memory.  Run the 'CheckOracle' or 'memcheck' command to identify the problem" fullword wide
      $s2 = "Oracle process memory successfully modified!" fullword wide
      $s3 = "Unable to reset the memory protection mask to the memory" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 300KB and 1 of them )
}

/* Super Rules ------------------------------------------------------------- */

rule EquationGroup_EquationDrug_Gen_1 {
   meta:
      description = "EquationGroup Malware"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://goo.gl/tcSoiJ"
      date = "2017-01-13"
      super_rule = 1
      hash1 = "694be2698bcc5c7a1cce11f8ef65c1c96a883d14b98148c36b32888fb58b6a7e"
      hash2 = "73d1d55493886639c619e9f5e312daab93e4feeb74f24dbe51593842baac8d15"
      hash3 = "e1c9c9f031d902e69e42f684ae5b35a2513f7d5f8bca83dfbab10e8de6254c78"
      hash4 = "c7bf4c012293e7de56d86f4f5b4eeb6c1c5263568cc4d9863a286a86b5daf194"
      hash5 = "2a1f2034e80421359e3bf65cbd12a55a95bd00f2eb86cf2c2d287711ee1d56ad"
      hash6 = "8f5b97124de9fce16e2cfecb7dd2e171824c9e07546db7b3bee7c5f2c92ceda9"
      hash7 = "dfb38ed2ca3870faf351df1bd447a3dc4470ed568553bf83df07bf07967bf520"
      hash8 = "d92928a867a685274b0a74ec55c0b83690fca989699310179e184e2787d47f48"
      hash9 = "137749c0fbb8c12d1a650f0bfc73be2739ff084165d02e4cb68c6496d828bf1d"
      hash10 = "fe42139748c8e9ba27a812466d9395b3a0818b0cd7b41d6769cb7239e57219fb"
      hash11 = "2b27f2faae9de6330f17f60a1d19f9831336f57fdfef06c3b8876498882624a6"
      hash12 = "cdee0daa816f179e74c90c850abd427fbfe0888dcfbc38bf21173f543cdcdc66"
      hash13 = "31d86f77137f0b3697af03dd28d6552258314cecd3c1d9dc18fcf609eb24229a"
      hash14 = "fda57a2ba99bc610d3ff71b2d0ea2829915eabca168df99709a8fdd24288c5e5"
      hash15 = "1097e1d562341858e241f1f67788534c0e340a2dc2e75237d57e3f473e024464"
      id = "331d7ba5-e3fa-5ab7-b4de-c7af764be03d"
   strings:
      $x1 = "Injection Lib -  GetProcAddress failed on Kernel32.DLL function" fullword wide
      $x2 = "Injection Lib -  JUMPUP failed to open requested process" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 300KB and 1 of ($x*) ) or ( all of them )
}

/* The Cherry on the Cake */

rule EquationDrug_MS_Identifier {
	meta:
		description = "Microsoft Identifier used in EquationDrug Platform"
		author = "Florian Roth (Nextron Systems) @4nc4p"
		date = "2015/03/11"
		id = "c934c117-bf5a-5688-acd9-5d6c6aacd6bc"
	strings:
		$s1 = "Microsoft(R) Windows (TM) Operating System" fullword wide
	condition:
		// Epoch for 01.01.2000
		$s1 and pe.timestamp > 946684800
}
