/*
	Yara Rule Set
	Author: Florian Roth
	Date: 2016-06-09
	Identifier: Turla Samples from RUAG Cyber Attack
*/

/* Rule Set ----------------------------------------------------------------- */

rule Turla_APT_srsvc {
	meta:
		description = "Detects Turla malware (based on sample used in the RUAG APT case)"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		family = "Turla"
		reference = "https://www.govcert.admin.ch/blog/22/technical-report-about-the-ruag-espionage-case"
		date = "2016-06-09"
		hash1 = "65996f266166dbb479a42a15a236e6564f0b322d5d68ee546244d7740a21b8f7"
		hash2 = "25c7ff1eb16984a741948f2ec675ab122869b6edea3691b01d69842a53aa3bac"
		id = "951ee9f8-1ab0-5fd5-be9b-053ec82f6ea2"
	strings:
		$x1 = "SVCHostServiceDll.dll" fullword ascii

		$s2 = "msimghlp.dll" fullword wide
		$s3 = "srservice" fullword wide
		$s4 = "ModStart" fullword ascii
		$s5 = "ModStop" fullword ascii
	condition:
		( uint16(0) == 0x5a4d and filesize < 20KB and ( 1 of ($x*) or all of ($s*) ) )
		or ( all of them )
}

rule Turla_APT_Malware_Gen1 {
	meta:
		description = "Detects Turla malware (based on sample used in the RUAG APT case)"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		family = "Turla"
		reference = "https://www.govcert.admin.ch/blog/22/technical-report-about-the-ruag-espionage-case"
		date = "2016-06-09"
		hash1 = "0e1bf347c37fb199886f1e675e372ba55ac4627e8be2f05a76c2c64f9b6ed0e4"
		hash2 = "7206075cd8f1004e8f1f759d46e98bfad4098b8642412811a214c0155a1f08b9"
		hash3 = "fe3ffd7438c0d38484bf02a78a19ea81a6f51b4b3f2b2228bd21974c2538bbcd"
		hash4 = "c49111af049dd9746c6b1980db6e150b2a79ca1569b23ed2cba81c85c00d82b4"
		hash5 = "b62a643c96e2e41f639d2a8ce11d61e6b9d7fb3a9baf011120b7fec1b4ee3cf4"
		hash6 = "edb12790b5cd959bc2e53a4b369a4fd747153e6c9d50f6a69ff047f7857a4348"
		hash7 = "8f2ea0f916fda1dfb771f5441e919c561da5b6334b9f2fffcbf53db14063b24a"
		hash8 = "8dddc744bbfcf215346c812aa569e49523996f73a1f22fe4e688084ce1225b98"
		hash9 = "0c69258adcc97632b729e55664c22cd942812336d41e8ea0cff9ddcafaded20f"
		hash10 = "2b4fba1ef06f85d1395945db40a9f2c3b3ed81b56fb9c2d5e5bb693c230215e2"
		id = "7ead2da1-3544-5a26-8767-6d3f29de8b96"
	strings:
		$x1 = "too long data for this type of transport" fullword ascii
		$x2 = "not enough server resources to complete operation" fullword ascii
		$x3 = "Task not execute. Arg file failed." fullword ascii
		$x4 = "Global\\MSCTF.Shared.MUTEX.ZRX" fullword ascii

		$s1 = "peer has closed the connection" fullword ascii
		$s2 = "tcpdump.exe" fullword ascii
		$s3 = "windump.exe" fullword ascii
		$s4 = "dsniff.exe" fullword ascii
		$s5 = "wireshark.exe" fullword ascii
		$s6 = "ethereal.exe" fullword ascii
		$s7 = "snoop.exe" fullword ascii
		$s8 = "ettercap.exe" fullword ascii
		$s9 = "miniport.dat" fullword ascii
		$s10 = "net_password=%s" fullword ascii
	condition:
		( uint16(0) == 0x5a4d and filesize < 2000KB and ( 2 of ($x*) or 8 of ($s*) ) )
		or ( 12 of them )
}

rule RUAG_APT_Malware_Gen2 {
   meta:
      description = "Detects malware used in the RUAG APT case"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.govcert.admin.ch/blog/22/technical-report-about-the-ruag-espionage-case"
      date = "2016-06-09"
      modified = "2023-01-06"
      score = 90
      hash1 = "0e1bf347c37fb199886f1e675e372ba55ac4627e8be2f05a76c2c64f9b6ed0e4"
      hash2 = "7206075cd8f1004e8f1f759d46e98bfad4098b8642412811a214c0155a1f08b9"
      hash3 = "fe3ffd7438c0d38484bf02a78a19ea81a6f51b4b3f2b2228bd21974c2538bbcd"
      hash4 = "c49111af049dd9746c6b1980db6e150b2a79ca1569b23ed2cba81c85c00d82b4"
      id = "8a50e5d5-f16d-53c7-825c-a8e51c207eac"
   strings:
      $x1 = "Internal command not support =((" ascii
      $x2 = "L|-1|AS_CUR_USER:OpenProcessToken():%d, %s|" fullword ascii
      $x3 = "L|-1|CreateProcessAsUser():%d, %s|" fullword ascii
      $x4 = "AS_CUR_USER:OpenProcessToken():%d" fullword ascii
      $x5 = "L|-1|AS_CUR_USER:LogonUser():%d, %s|" fullword ascii
      $x6 = "L|-1|try to run dll %s with user priv|" fullword ascii
      $x7 = "\\\\.\\Global\\PIPE\\sdlrpc" fullword ascii
      $x8 = "\\\\%s\\pipe\\comnode" fullword ascii
      $x9 = "Plugin dll stop failed." fullword ascii
      $x10 = "AS_USER:LogonUser():%d" fullword ascii

      $s1 = "MSIMGHLP.DLL" fullword wide
      $s2 = "msimghlp.dll" fullword ascii
      $s3 = "ximarsh.dll" fullword ascii
      $s4 = "msximl.dll" fullword ascii
      $s5 = "INTERNAL.dll" fullword ascii
      $s6 = "\\\\.\\Global\\PIPE\\" ascii
      $s7 = "ieuser.exe" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and ( 1 of ($x*) or 5 of ($s*) ) )
      or ( 10 of them )
}

rule Turla_APT_Malware_Gen3 {
	meta:
		description = "Detects Turla malware (based on sample used in the RUAG APT case)"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		family = "Turla"
		reference = "https://www.govcert.admin.ch/blog/22/technical-report-about-the-ruag-espionage-case"
		date = "2016-06-09"
		hash1 = "c49111af049dd9746c6b1980db6e150b2a79ca1569b23ed2cba81c85c00d82b4"
		hash2 = "b62a643c96e2e41f639d2a8ce11d61e6b9d7fb3a9baf011120b7fec1b4ee3cf4"
		hash3 = "edb12790b5cd959bc2e53a4b369a4fd747153e6c9d50f6a69ff047f7857a4348"
		hash4 = "8f2ea0f916fda1dfb771f5441e919c561da5b6334b9f2fffcbf53db14063b24a"
		hash5 = "8dddc744bbfcf215346c812aa569e49523996f73a1f22fe4e688084ce1225b98"
		hash6 = "0c69258adcc97632b729e55664c22cd942812336d41e8ea0cff9ddcafaded20f"
		hash7 = "2b4fba1ef06f85d1395945db40a9f2c3b3ed81b56fb9c2d5e5bb693c230215e2"
		hash8 = "7206075cd8f1004e8f1f759d46e98bfad4098b8642412811a214c0155a1f08b9"
		hash9 = "edb12790b5cd959bc2e53a4b369a4fd747153e6c9d50f6a69ff047f7857a4348"
		id = "8cb7d873-e4f9-553e-84e8-dbc0d31f65ab"
	strings:
		$x1 = "\\\\.\\pipe\\sdlrpc" fullword ascii
		$x2 = "WaitMutex Abandoned %p" fullword ascii
		$x3 = "OPER|Wrong config: no port|" fullword ascii
		$x4 = "OPER|Wrong config: no lastconnect|" fullword ascii
		$x5 = "OPER|Wrong config: empty address|" fullword ascii
		$x6 = "Trans task %d obj %s ACTIVE fail robj %s" fullword ascii
		$x7 = "OPER|Wrong config: no auth|" fullword ascii
		$x8 = "OPER|Sniffer '%s' running... ooopppsss...|" fullword ascii

		$s1 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\5.0\\User Agent\\Post Platform" fullword ascii
		$s2 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\5.0\\User Agent\\Pre Platform" fullword ascii
		$s3 = "www.yahoo.com" fullword ascii
		$s4 = "MSXIML.DLL" fullword wide
		$s5 = "www.bing.com" fullword ascii
		$s6 = "%s: http://%s%s" fullword ascii
		$s7 = "/javascript/view.php" fullword ascii
		$s8 = "Task %d failed %s,%d" fullword ascii
		$s9 = "Mozilla/4.0 (compatible; MSIE %d.0; " fullword ascii
	condition:
		( uint16(0) == 0x5a4d and filesize < 2000KB and ( 1 of ($x*) or 6 of ($s*) ) )
		or ( 10 of them )
}

rule Turla_Mal_Script_Jan18_1 {
   meta:
      description = "Detects Turla malicious script"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://ghostbin.com/paste/jsph7"
      date = "2018-01-19"
      hash1 = "180b920e9cea712d124ff41cd1060683a14a79285d960e17f0f49b969f15bfcc"
      id = "4b550b3c-182c-5dc0-b2d2-13925c22be81"
   strings:
      $s1 = ".charCodeAt(i % " ascii
      $s2 = "{WScript.Quit();}" fullword ascii
      $s3 = ".charAt(i)) << 10) |" ascii
      $s4 = " = WScript.Arguments;var " ascii
      $s5 = "= \"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/\";var i;" ascii
   condition:
      filesize < 200KB and 2 of them
}

import "pe"

rule Turla_KazuarRAT {
   meta:
      description = "Detects Turla Kazuar RAT described by DrunkBinary"
      author = "Markus Neis / Florian Roth"
      reference = "https://twitter.com/DrunkBinary/status/982969891975319553"
      date = "2018-04-08"
      hash1 = "6b5d9fca6f49a044fd94c816e258bf50b1e90305d7dab2e0480349e80ed2a0fa"
      hash2 = "7594fab1aadc4fb08fb9dbb27c418e8bc7f08dadb2acf5533dc8560241ecfc1d"
      hash3 = "4e5a86e33e53931afe25a8cb108f53f9c7e6c6a731b0ef4f72ce638d0ea5c198"
      id = "147cc7b7-6dbd-51a2-9501-bcbaec32e20e"
   strings:
      $x1 = "~1.EXE" wide
      $s2 = "dl32.dll" fullword ascii
      $s3 = "HookProc@" ascii
      $s4 = "0`.wtf" fullword ascii
   condition:
      uint16(0) == 0x5a4d and  filesize < 20KB and (
         pe.imphash() == "682156c4380c216ff8cb766a2f2e8817" or
         2 of them )
}


rule MAL_Turla_Agent_BTZ {
   meta:
      description = "Detects Turla Agent.BTZ"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.gdatasoftware.com/blog/2014/11/23937-the-uroburos-case-new-sophisticated-rat-identified"
      date = "2018-04-12"
      modified = "2023-01-06"
      score = 90
      hash1 = "c4a1cd6916646aa502413d42e6e7441c6e7268926484f19d9acbf5113fc52fc8"
      id = "bd642f11-19f6-5178-b978-1215215fea86"
   strings:
      $x1 = "1dM3uu4j7Fw4sjnbcwlDqet4F7JyuUi4m5Imnxl1pzxI6as80cbLnmz54cs5Ldn4ri3do5L6gs923HL34x2f5cvd0fk6c1a0s" fullword ascii
      $x3 = "mstotreg.dat" fullword ascii
      $x4 = "Bisuninst.bin" fullword ascii
      $x5 = "mfc42l00.pdb" fullword ascii
      $x6 = "ielocal~f.tmp" fullword ascii

      $s1 = "%s\\1.txt" fullword ascii
      $s2 = "%windows%" fullword ascii
      $s3 = "%s\\system32" fullword ascii
      $s4 = "\\Help\\SYSTEM32\\" ascii
      $s5 = "%windows%\\mfc42l00.pdb" ascii
      $s6 = "Size of log(%dB) is too big, stop write." fullword ascii
      $s7 = "Log: Size of log(%dB) is too big, stop write." fullword ascii
      $s8 = "%02d.%02d.%04d Log begin:" fullword ascii
      $s9 = "\\system32\\win.com" ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 100KB and (
         1 of ($x*) or
         4 of them
      )
}

rule MAL_Turla_Sample_May18_1 {
   meta:
      description = "Detects Turla samples"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://twitter.com/omri9741/status/991942007701598208"
      date = "2018-05-03"
      hash1 = "4c49c9d601ebf16534d24d2dd1cab53fde6e03902758ef6cff86be740b720038"
      hash2 = "77cbd7252a20f2d35db4f330b9c4b8aa7501349bc06bbcc8f40ae13d01ae7f8f"
      id = "5052838f-a895-55cb-abcf-813465074127"
   strings:
      $x1 = "sc %s create %s binPath= \"cmd.exe /c start %%SystemRoot%%\\%s\">>%s" fullword ascii
      $x2 = "cmd.exe /c start %%SystemRoot%%\\%s" fullword ascii
      $x3 = "cmd.exe /c %s\\%s -s %s:%s:%s -c \"%s %s /wait 1\">>%s" fullword ascii
      $x4 = "Read InjectLog[%dB]********************************" fullword ascii
      $x5 = "%s\\System32\\011fe-3420f-ff0ea-ff0ea.tmp" fullword ascii
      $x6 = "**************************** Begin ini %s [%d]***********************************************" fullword ascii
      $x7 = "%s -o %s -i %s -d exec2 -f %s" fullword ascii
      $x8 = "Logon to %s failed: code %d(User:%s,Pass:%s)" fullword ascii
      $x9 = "system32\\dxsnd32x.exe" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 500KB and 1 of them
}

rule APT_MAL_LNX_Turla_Apr20_1 {
   meta:
      description = "Detects Turla Linux malware"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://twitter.com/Int2e_/status/1246115636331319309"
      date = "2020-04-05"
      hash1 = "67d9556c695ef6c51abf6fbab17acb3466e3149cf4d20cb64d6d34dc969b6502"
      hash2 = "8ccc081d4940c5d8aa6b782c16ed82528c0885bbb08210a8d0a8c519c54215bc"
      id = "f21e7793-a7dd-5195-805d-963827b35808"
   strings:
      $s1 = "/root/.hsperfdata" ascii fullword
      $s2 = "Desc|     Filename     |  size  |state|" ascii fullword
      $s3 = "IPv6 address %s not supported" ascii fullword
      $s4 = "File already exist on remote filesystem !" ascii fullword
      $s5 = "/tmp/.sync.pid" ascii fullword
      $s6 = "'gateway' supported only on ethernet/FDDI/token ring/802.11/ATM LANE/Fibre Channel" ascii fullword
   condition:
      uint16(0) == 0x457f and
      filesize < 5000KB and
      4 of them
}

/* slighly modified rule */
rule APT_MAL_TinyTurla_Sep21_1 {
	meta:
		author = "Cisco Talos"
		description = "Detects Tiny Turla backdoor DLL"
		reference = "https://blog.talosintelligence.com/2021/09/tinyturla.html"
		hash1 = "030cbd1a51f8583ccfc3fa38a28a5550dc1c84c05d6c0f5eb887d13dedf1da01"
		date = "2021-09-21"
		id = "19659ac7-310a-52dd-a94c-022c7add752b"
	strings:
		$a = "Title: " fullword wide
		$b = "Hosts" fullword wide
		$c = "Security" fullword wide
		$d = "TimeLong" fullword wide
		$e = "TimeShort" fullword wide
		$f = "MachineGuid" fullword wide
		$g = "POST" fullword wide
		$h = "WinHttpSetOption" fullword ascii
		$i = "WinHttpQueryDataAvailable" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 25KB and all of them
}
