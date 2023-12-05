rule RAT_AAR
{
	meta:
		author = "Kevin Breen <kevin@techanarchy.net>"
		date = "01.04.2014"
		description = "Detects AAR RAT"
		reference = "http://malwareconfig.com/stats/AAR"
		maltype = "Remote Access Trojan"
		filetype = "exe"

		id = "42c1af80-cff3-505f-a3cb-35b7e34575e1"
	strings:
		$a = "Hashtable"
		$b = "get_IsDisposed"
		$c = "TripleDES"
		$d = "testmemory.FRMMain.resources"
		$e = "$this.Icon" wide
		$f = "{11111-22222-20001-00001}" wide

	condition:
		all of them
}

rule RAT_Adzok
{
	meta:
		author = "Kevin Breen <kevin@techanarchy.net>"
		description = "Detects Adzok RAT"
		Versions = "Free 1.0.0.3,"
		date = "01.05.2015"
		reference = "http://malwareconfig.com/stats/Adzok"
		maltype = "Remote Access Trojan"
		filetype = "jar"

		id = "93807f85-ae4e-5fd2-9010-ed2cf6f57f38"
	strings:
		$a1 = "config.xmlPK"
		$a2 = "key.classPK"
		$a3 = "svd$1.classPK"
		$a4 = "svd$2.classPK"
		$a5 = "Mensaje.classPK"
		$a6 = "inic$ShutdownHook.class"
		$a7 = "Uninstall.jarPK"
		$a8 = "resources/icono.pngPK"

	condition:
		7 of ($a*)
}

rule RAT_Ap0calypse
{
	meta:
		author = "Kevin Breen <kevin@techanarchy.net>"
		description = "Detects Ap0calypse RAT"
		date = "01.04.2014"
		reference = "http://malwareconfig.com/stats/Ap0calypse"
		maltype = "Remote Access Trojan"
		filetype = "exe"

		id = "a2993654-efa0-519b-b6f6-4d722d93adde"
	strings:
		$a = "Ap0calypse"
		$b = "Sifre"
		$c = "MsgGoster"
		$d = "Baslik"
		$e = "Dosyalars"
		$f = "Injecsiyon"

	condition:
		all of them
}
rule RAT_Arcom
{
	meta:
		author = "Kevin Breen <kevin@techanarchy.net>"
		date = "01.04.2014"
		description = "Detects Arcom RAT"
		reference = "http://malwareconfig.com/stats/Arcom"
		maltype = "Remote Access Trojan"
		filetype = "exe"

		id = "a0598340-c4a5-53f0-a810-63e37ec669a5"
	strings:
		$a1 = "CVu3388fnek3W(3ij3fkp0930di"
		$a2 = "ZINGAWI2"
		$a3 = "clWebLightGoldenrodYellow"
		$a4 = "Ancestor for '%s' not found" wide
		$a5 = "Control-C hit" wide
		$a6 = {A3 24 25 21}

	condition:
		all of them
}

rule RAT_Bandook
{
	meta:
		author = "Kevin Breen <kevin@techanarchy.net>"
		date = "01.04.2014"
		description = "Detects Bandook RAT"
		reference = "http://malwareconfig.com/stats/bandook"
		maltype = "Remote Access Trojan"
		filetype = "exe"

		id = "79fb99d8-bd56-5986-9917-e119b51b8303"
	strings:
		$a = "aaaaaa1|"
		$b = "aaaaaa2|"
		$c = "aaaaaa3|"
		$d = "aaaaaa4|"
		$e = "aaaaaa5|"
		$f = "%s%d.exe"
		$g = "astalavista"
		$h = "givemecache"
		$i = "%s\\system32\\drivers\\blogs\\*"
		$j = "bndk13me"

	condition:
		all of them
}

rule RAT_BlackNix
{
	meta:
		author = "Kevin Breen <kevin@techanarchy.net>"
		date = "01.04.2014"
		description = "Detects BlackNix RAT"
		reference = "http://malwareconfig.com/stats/BlackNix"
		maltype = "Remote Access Trojan"
		filetype = "exe"

		id = "d7814184-3ae4-53f1-a602-c3fbc02573c3"
	strings:
		$a1 = "SETTINGS" wide
		$a2 = "Mark Adler"
		$a3 = "Random-Number-Here"
		$a4 = "RemoteShell"
		$a5 = "SystemInfo"

	condition:
		all of them
}

rule RAT_BlackShades
{
	meta:
		author = "Brian Wallace (@botnet_hunter)"
		date = "01.04.2014"
		description = "Detects BlackShades RAT"
		reference = "http://blog.cylance.com/a-study-in-bots-blackshades-net"
		family = "blackshades"

		id = "039f9efd-034d-5088-9a2f-7a63ad170d3d"
	strings:
		$string1 = "bss_server"
		$string2 = "txtChat"
		$string3 = "UDPFlood"

	condition:
		all of them
}

rule RAT_BlueBanana
{
	meta:
		author = "Kevin Breen <kevin@techanarchy.net>"
		date = "01.04.2014"
		description = "Detects BlueBanana RAT"
		reference = "http://malwareconfig.com/stats/BlueBanana"
		maltype = "Remote Access Trojan"
		filetype = "Java"

		id = "f00c7e92-f34c-5666-a1d9-02ac2cf7608c"
	strings:
		$meta = "META-INF"
		$conf = "config.txt"
		$a = "a/a/a/a/f.class"
		$b = "a/a/a/a/l.class"
		$c = "a/a/a/b/q.class"
		$d = "a/a/a/b/v.class"

	condition:
		all of them
}

rule RAT_Bozok
{
	meta:
		author = "Kevin Breen <kevin@techanarchy.net>"
		date = "01.04.2014"
		description = "Detects Bozok RAT"
		reference = "http://malwareconfig.com/stats/Bozok"
		maltype = "Remote Access Trojan"
		filetype = "exe"

		id = "b1d22e8c-39aa-52e7-9ca8-2b35bb82f7de"
	strings:
		$a = "getVer" nocase
		$b = "StartVNC" nocase
		$c = "SendCamList" nocase
		$d = "untPlugin" nocase
		$e = "gethostbyname" nocase

	condition:
		all of them
}

rule RAT_ClientMesh
{
	meta:
		author = "Kevin Breen <kevin@techanarchy.net> (slightly modified by Florian Roth to improve performance)"
		date = "01.06.2014"
		description = "Detects ClientMesh RAT"
		reference = "http://malwareconfig.com/stats/ClientMesh"
		family = "torct"

		id = "351df33e-d3a1-5fe8-be38-edb43bc5d38f"
	strings:
		$string1 = "machinedetails"
		$string2 = "MySettings"
		$string3 = "sendftppasswords"
		$string4 = "sendbrowserpasswords"
		$string5 = "arma2keyMass"
		$string6 = "keylogger"

	condition:
		all of them
}

rule RAT_CyberGate
{

	meta:
		author = "Kevin Breen <kevin@techanarchy.net>"
		date = "01.04.2014"
		description = "Detects CyberGate RAT"
		reference = "http://malwareconfig.com/stats/CyberGate"
		maltype = "Remote Access Trojan"
		filetype = "exe"

		id = "387e7c89-c766-54cf-aac0-3ba03092bc25"
	strings:
		$string1 = {23 23 23 23 40 23 23 23 23 E8 EE E9 F9 23 23 23 23 40 23 23 23 23}
		$string2 = {23 23 23 23 40 23 23 23 23 FA FD F0 EF F9 23 23 23 23 40 23 23 23 23}
		$string3 = "EditSvr"
		$string4 = "TLoader"
		$string5 = "Stroks"
		$string6 = "####@####"
		$res1 = "XX-XX-XX-XX"
		$res2 = "CG-CG-CG-CG"

	condition:
		all of ($string*) and any of ($res*)
}

rule RAT_DarkComet
{
	meta:
		author = "Kevin Breen <kevin@techanarchy.net>"
		date = "01.04.2014"
		description = "Detects DarkComet RAT"
		reference = "http://malwareconfig.com/stats/DarkComet"
		maltype = "Remote Access Trojan"
		filetype = "exe"

		id = "e6fd0269-dd0c-58c0-a1a3-24c2aed916ee"
	strings:
		// Versions 2x
		$a1 = "#BOT#URLUpdate"
		$a2 = "Command successfully executed!"
		$a3 = "MUTEXNAME" wide
		$a4 = "NETDATA" wide
		// Versions 3x & 4x & 5x
		$b1 = "FastMM Borland Edition"
		$b2 = "%s, ClassID: %s"
		$b3 = "I wasn't able to open the hosts file"
		$b4 = "#BOT#VisitUrl"
		$b5 = "#KCMDDC"

	condition:
		all of ($a*) or all of ($b*)
}

rule RAT_DarkRAT
{
	meta:
		author = "Kevin Breen <kevin@techanarchy.net>"
		date = "01.04.2014"
		description = "Detects DarkRAT"
		reference = "http://malwareconfig.com/stats/DarkRAT"
		maltype = "Remote Access Trojan"
		filetype = "exe"

		id = "8283236a-6ed1-5213-8386-a029867b9677"
	strings:
		$a = "@1906dark1996coder@"
		$b = "SHEmptyRecycleBinA"
		$c = "mciSendStringA"
		$d = "add_Shutdown"
		$e = "get_SaveMySettingsOnExit"
		$f = "get_SpecialDirectories"
		$g = "Client.My"

	condition:
		all of them
}

rule RAT_Greame
{
	meta:
		author = "Kevin Breen <kevin@techanarchy.net>"
		date = "01.04.2014"
		description = "Detects Greame RAT"
		reference = "http://malwareconfig.com/stats/Greame"
		maltype = "Remote Access Trojan"
		filetype = "exe"

		id = "b90d3747-407a-5552-971f-78ff78f827a6"
	strings:
		$a = {23 23 23 23 40 23 23 23 23 E8 EE E9 F9 23 23 23 23 40 23 23 23 23}
		$b = {23 23 23 23 40 23 23 23 23 FA FD F0 EF F9 23 23 23 23 40 23 23 23 23}
		$c = "EditSvr"
		$d = "TLoader"
		$e = "Stroks"
		$f = "Avenger by NhT"
		$g = "####@####"
		$h = "GREAME"

	condition:
		all of them
}

rule RAT_HawkEye
{
	meta:
		author = "Kevin Breen <kevin@techanarchy.net>"
		date = "01.06.2015"
		description = "Detects HawkEye RAT"
		reference = "http://malwareconfig.com/stats/HawkEye"
		maltype = "KeyLogger"
		filetype = "exe"

		id = "22b1d1e6-feea-5f84-9564-326ad80bbd8d"
	strings:
		$key = "HawkEyeKeylogger" wide
		$salt = "099u787978786" wide
		$string1 = "HawkEye_Keylogger" wide
		$string2 = "holdermail.txt" wide
		$string3 = "wallet.dat" wide
		$string4 = "Keylog Records" wide
		$string5 = "<!-- do not script -->" wide
		$string6 = "\\pidloc.txt" wide
		$string7 = "BSPLIT" wide

	condition:
		$key and $salt and all of ($string*)
}

rule RAT_Imminent
{
	meta:
		author = "Kevin Breen <kevin@techanarchy.net>"
		date = "01.04.2014"
		description = "Detects Imminent RAT"
		reference = "http://malwareconfig.com/stats/Imminent"
		maltype = "Remote Access Trojan"
		filetype = "exe"

		id = "deddef60-c309-54e0-a488-ce937ed7eae3"
	strings:
		$v1a = "DecodeProductKey"
		$v1b = "StartHTTPFlood"
		$v1c = "CodeKey"
		$v1d = "MESSAGEBOX"
		$v1e = "GetFilezillaPasswords"
		$v1f = "DataIn"
		$v1g = "UDPzSockets"
		$v1h = {52 00 54 00 5F 00 52 00 43 00 44 00 41 00 54 00 41}

		$v2a = "<URL>k__BackingField"
		$v2b = "<RunHidden>k__BackingField"
		$v2c = "DownloadAndExecute"
		$v2d = "-CHECK & PING -n 2 127.0.0.1 & EXIT" wide
		$v2e = "england.png" wide
		$v2f = "Showed Messagebox" wide

	condition:
		all of ($v1*) or all of ($v2*)
}

rule RAT_Infinity
{
	meta:
		author = "Kevin Breen <kevin@techanarchy.net>"
		date = "01.04.2014"
		description = "Detects Infinity RAT"
		reference = "http://malwareconfig.com/stats/Infinity"
		maltype = "Remote Access Trojan"
		filetype = "exe"

		id = "b70f9459-fa84-516f-841d-d9617856eb4d"
	strings:
		$a = "CRYPTPROTECT_PROMPTSTRUCT"
		$b = "discomouse"
		$c = "GetDeepInfo"
		$d = "AES_Encrypt"
		$e = "StartUDPFlood"
		$f = "BATScripting" wide
		$g = "FBqINhRdpgnqATxJ.html" wide
		$i = "magic_key" wide

	condition:
		all of them
}

/* prone to FPs and obsolete 
rule RAT_JavaDropper
{
	meta:
		author = "Kevin Breen <kevin@techanarchy.net> (slightly modified by Florian Roth to improve performance)"
		date = "01.10.2015"
		description = "Detects JavaDropper RAT"
		reference = "http://malwareconfig.com/stats/JavaDropper"
		maltype = "Remote Access Trojan"
		filetype = "exe"

	strings:
		$jar = "META-INF/MANIFEST.MF"

		$b1 = "config.ini"
		$b2 = "password.ini"

		$c1 = "stub/stub.dll"

	condition:
		$jar and (all of ($b*) or all of ($c*))
}
*/

rule RAT_LostDoor
{
	meta:
		author = "Kevin Breen <kevin@techanarchy.net>"
		date = "01.04.2014"
		description = "Detects LostDoor RAT"
		reference = "http://malwareconfig.com/stats/LostDoor"
		maltype = "Remote Access Trojan"
		filetype = "exe"

		id = "f86ae7a1-2182-5b2e-8f9e-9e8456f574bc"
	strings:
		$a0 = {0D 0A 2A 45 44 49 54 5F 53 45 52 56 45 52 2A 0D 0A}
		$a1 = "*mlt* = %"
		$a2 = "*ip* = %"
		$a3 = "*victimo* = %"
		$a4 = "*name* = %"
		$b5 = "[START]"
		$b6 = "[DATA]"
		$b7 = "We Control Your Digital World" wide ascii
		$b8 = "RC4Initialize" wide ascii
		$b9 = "RC4Decrypt" wide ascii

	condition:
		all of ($a*) or all of ($b*)
}

rule RAT_LuminosityLink
{
	meta:
		author = "Kevin Breen <kevin@techanarchy.net>"
		date = "01.04.2014"
		description = "Detects LuminosityLink RAT"
		reference = "http://malwareconfig.com/stats/LuminosityLink"
		maltype = "Remote Access Trojan"
		filetype = "exe"

		id = "163fe10c-38a1-53d3-b3a5-4240229e0306"
	strings:
		$a = "SMARTLOGS" wide
		$b = "RUNPE" wide
		$c = "b.Resources" wide
		$d = "CLIENTINFO*" wide
		$e = "Invalid Webcam Driver Download URL, or Failed to Download File!" wide
		$f = "Proactive Anti-Malware has been manually activated!" wide
		$g = "REMOVEGUARD" wide
		$h = "C0n1f8" wide
		$i = "Luminosity" wide
		$j = "LuminosityCryptoMiner" wide
		$k = "MANAGER*CLIENTDETAILS*" wide

	condition:
		all of them
}

rule RAT_LuxNet
{
	meta:
		author = "Kevin Breen <kevin@techanarchy.net>"
		date = "01.04.2014"
		description = "Detects LuxNet RAT"
		reference = "http://malwareconfig.com/stats/LuxNet"
		maltype = "Remote Access Trojan"
		filetype = "exe"

		id = "277db509-5ba0-5d1b-b17a-d5914f1f1650"
	strings:
		$a = "GetHashCode"
		$b = "Activator"
		$c = "WebClient"
		$d = "op_Equality"
		$e = "dickcursor.cur" wide
		$f = "{0}|{1}|{2}" wide

	condition:
		all of them
}

/* prone to FPs: https://github.com/Neo23x0/signature-base/issues/40
rule RAT_NanoCore
{
	meta:
		author = "Kevin Breen <kevin@techanarchy.net>"
		date = "01.04.2014"
		description = "Detects NanoCore RAT"
		reference = "http://malwareconfig.com/stats/NanoCore"
		maltype = "Remote Access Trojan"
		filetype = "exe"

	strings:
		$a = "NanoCore"
		$b = "ClientPlugin"
		$c = "ProjectData"
		$d = "DESCrypto"
		$e = "KeepAlive"
		$f = "IPNETROW"
		$g = "LogClientMessage"
		$h = "|ClientHost"
		$i = "get_Connected"
		$j = "#=q"
		$key = {43 6f 24 cb 95 30 38 39}

	condition:
		6 of them
}
*/

rule RAT_NetWire
{
	meta:
		author = "Kevin Breen <kevin@techanarchy.net> & David Cannings"
		date = "01.04.2014"
		description = "Detects NetWire RAT"
		reference = "http://malwareconfig.com/stats/NetWire"
		maltype = "Remote Access Trojan"
		filetype = "exe"

		id = "f0077e8c-3e6a-5a98-9171-b0d81f24d27a"
	strings:
		$exe1 = "%.2d-%.2d-%.4d"
		$exe2 = "%s%.2d-%.2d-%.4d"
		$exe3 = "[%s] - [%.2d/%.2d/%d %.2d:%.2d:%.2d]"
		$exe4 = "wcnwClass"
		$exe5 = "[Ctrl+%c]"
		$exe6 = "SYSTEM\\CurrentControlSet\\Control\\ProductOptions"
		$exe7 = "%s\\.purple\\accounts.xml"

	condition:
		all of them
}

rule RAT_Pandora
{
	meta:
		author = "Kevin Breen <kevin@techanarchy.net>"
		date = "01.04.2014"
		description = "Detects Pandora RAT"
		reference = "http://malwareconfig.com/stats/Pandora"
		maltype = "Remote Access Trojan"
		filetype = "exe"

		id = "d31e4366-8911-5c9c-92dc-a99f5233c626"
	strings:
		$a = "Can't get the Windows version"
		$b = "=M=Q=U=Y=]=a=e=i=m=q=u=y=}="
		$c = "JPEG error #%d" wide
		$d = "Cannot assign a %s to a %s" wide
		$g = "%s, ProgID:"
		$h = "clave"
		$i = "Shell_TrayWnd"
		$j = "melt.bat"
		$k = "\\StubPath"
		$l = "\\logs.dat"
		$m = "1027|Operation has been canceled!"
		$n = "466|You need to plug-in! Double click to install... |"
		$0 = "33|[Keylogger Not Activated!]"

	condition:
		all of them
}

rule RAT_Paradox
{
	meta:
		author = "Kevin Breen <kevin@techanarchy.net>"
		date = "01.04.2014"
		description = "Detects Paradox RAT"
		reference = "http://malwareconfig.com/stats/Paradox"
		maltype = "Remote Access Trojan"
		filetype = "exe"

		id = "2f1e6226-799b-54eb-a4a4-6c0f1bf561b4"
	strings:
		$a = "ParadoxRAT"
		$b = "Form1"
		$c = "StartRMCam"
		$d = "Flooders"
		$e = "SlowLaris"
		$f = "SHITEMID"
		$g = "set_Remote_Chat"

	condition:
		all of them
}

rule RAT_Plasma
{
	meta:
		author = "Kevin Breen <kevin@techanarchy.net>"
		date = "01.04.2014"
		description = "Detects Plasma RAT"
		reference = "http://malwareconfig.com/stats/Plasma"
		maltype = "Remote Access Trojan"
		filetype = "exe"

		id = "2a19c0de-0078-5487-869c-1bcabea57300"
	strings:
		$a = "Miner: Failed to Inject." wide
		$b = "Started GPU Mining on:" wide
		$c = "BK: Hard Bot Killer Ran Successfully!" wide
		$d = "Uploaded Keylogs Successfully!" wide
		$e = "No Slowloris Attack is Running!" wide
		$f = "An ARME Attack is Already Running on" wide
		$g = "Proactive Bot Killer Enabled!" wide
		$h = "PlasmaRAT" wide ascii
		$i = "AntiEverything" wide ascii

	condition:
		all of them
}

rule RAT_PoisonIvy
{
	meta:
		author = "Kevin Breen <kevin@techanarchy.net>"
		date = "01.04.2014"
		description = "Detects PoisonIvy RAT"
		reference = "http://malwareconfig.com/stats/PoisonIvy"
		maltype = "Remote Access Trojan"
		filetype = "exe"

		id = "371686d3-878f-56fc-a702-ec49845f486b"
	strings:
		$stub = {04 08 00 53 74 75 62 50 61 74 68 18 04}
		$string1 = "CONNECT %s:%i HTTP/1.0"
		$string2 = "ws2_32"
		$string3 = "cks=u"
		$string4 = "thj@h"
		$string5 = "advpack"

	condition:
		$stub at 0x1620 and all of ($string*) or (all of them)
}

rule RAT_PredatorPain
{
	meta:
		author = "Kevin Breen <kevin@techanarchy.net>"
		date = "01.04.2014"
		description = "Detects PredatorPain RAT"
		reference = "http://malwareconfig.com/stats/PredatorPain"
		maltype = "Remote Access Trojan"
		filetype = "exe"

		id = "c6670179-871d-5a57-983b-d77354e2ede9"
	strings:
		$string1 = "holderwb.txt" wide
		$string3 = "There is a file attached to this email" wide
		$string4 = "screens\\screenshot" wide
		$string5 = "Disablelogger" wide
		$string6 = "\\pidloc.txt" wide
		$string7 = "clearie" wide
		$string8 = "clearff" wide
		$string9 = "emails should be sent to you shortly" wide
		$string10 = "jagex_cache\\regPin" wide
		$string11 = "open=Sys.exe" wide
		$ver1 = "PredatorLogger" wide
		$ver2 = "EncryptedCredentials" wide
		$ver3 = "Predator Pain" wide

	condition:
		7 of ($string*) and any of ($ver*)
}

rule RAT_Punisher
{
	meta:
		author = "Kevin Breen <kevin@techanarchy.net>"
		date = "01.04.2014"
		description = "Detects Punisher RAT"
		reference = "http://malwareconfig.com/stats/Punisher"
		maltype = "Remote Access Trojan"
		filetype = "exe"

		id = "1e16b3c7-9656-5570-afa2-542367aa14d8"
	strings:
		$a = "abccba"
		$b = {5C 00 68 00 66 00 68 00 2E 00 76 00 62 00 73}
		$c = {5C 00 73 00 63 00 2E 00 76 00 62 00 73}
		$d = "SpyTheSpy" wide ascii
		$e = "wireshark" wide
		$f = "apateDNS" wide
		$g = "abccbaDanabccb"

	condition:
		all of them
}

rule RAT_PythoRAT
{
	meta:
		author = "Kevin Breen <kevin@techanarchy.net>"
		date = "01.04.2014"
		description = "Detects Python RAT"
		reference = "http://malwareconfig.com/stats/PythoRAT"
		maltype = "Remote Access Trojan"
		filetype = "exe"

		id = "fc98c513-1abf-5331-b351-f6182e5b19c5"
	strings:
		$a = "TKeylogger"
		$b = "uFileTransfer"
		$c = "TTDownload"
		$d = "SETTINGS"
		$e = "Unknown" wide
		$f = "#@#@#"
		$g = "PluginData"
		$i = "OnPluginMessage"

	condition:
		all of them
}

rule RAT_QRat
{
	meta:
		author = "Kevin Breen @KevTheHermit"
		date = "01.08.2015"
		description = "Detects QRAT"
		reference = "http://malwareconfig.com"
		maltype = "Remote Access Trojan"
		filetype = "jar"

		id = "2ee645a3-1e01-513c-a636-098e445adeca"
	strings:
		$a0 = "e-data"
		$a1 = "quaverse/crypter"
		$a2 = "Qrypt.class"
		$a3 = "Jarizer.class"
		$a4 = "URLConnection.class"

	condition:
		4 of them
}

rule RAT_Sakula
{
	meta:
		date = "2015-10-13"
		description = "Detects Sakula v1.0 RAT"
		author = "Airbus Defence and Space Cybersecurity CSIRT - Yoann Francou / NCC Group David Cannings"
		reference = "http://blog.airbuscybersecurity.com/public/YFR/sakula_v1x.yara"

		id = "4be3179c-3b91-56db-bba9-9ccc42066f96"
	strings:
		$s1 = "%d_of_%d_for_%s_on_%s"
		$s2 = "/c ping 127.0.0.1 & del /q \"%s\""
		$s3 = "=%s&type=%d"
		$s4 = "?photoid="
		$s5 = "iexplorer"
		$s6 = "net start \"%s\""
		$s7 = "cmd.exe /c rundll32 \"%s\""

		$v1_1 = "MicroPlayerUpdate.exe"
		$v1_2 = "CCPUpdate"
		$v1_3 = { 81 3E 78 03 00 00 75 57  8D 54 24 14 52 68 0C 05 41 00 68 01 00 00 80 FF  15 00 F0 40 00 85 C0 74 10 8B 44 24 14 68 2C 31  41 00 50 FF 15 10 F0 40 00 8B 4C 24 14 51 FF 15  24 F0 40 00 E8 0F 09 00 }
		$v1_4 = { 50 E8 CD FC FF FF 83 C4  04 68 E8 03 00 00 FF D7 56 E8 54 12 00 00 E9 AE  FE FF FF E8 13 F5 FF FF }

		$serial01 = { 31 06 2e 48 3e 01 06 b1 8c 98 2f 00 53 18 5c 36 }
		$serial02 = { 01 a5 d9 59 95 19 b1 ba fc fa d0 e8 0b 6d 67 35 }
		$serial03 = { 47 d5 d5 37 2b cb 15 62 b4 c9 f4 c2 bd f1 35 87 }
		$serial04 = { 3a c1 0e 68 f1 ce 51 9e 84 dd cd 28 b1 1f a5 42 }

		$opcodes1 = { 89 FF 55 89 E5 83 EC 20 A1 ?? ?? ?? 00 83 F8 00 }
		$opcodes2 = { 31 C0 8A 04 0B 3C 00 74 09 38 D0 74 05 30 D0 88 04 0B }
		$opcodes3 = { 8B 45 08 8D 0C 02 8A 01 84 C0 74 08 3C ?? 74 04 34 ?? 88 01 }
		$opcodes4 = { 30 14 38 8D 0C 38 40 FE C2 3B C6 }
		$opcodes5 = { 30 14 39 8D 04 39 41 FE C2 3B CE }

		$fp1 = "Symantec Corporation" ascii wide
	condition:
		uint16(0) == 0x5a4d and (
			(3 of ($s*) and any of ($v1_*)) or
			(any of ($serial0*)) or
			(any of ($opcodes*))
		)
      and not 1 of ($fp*)
}

rule RAT_ShadowTech : FILE {
	meta:
		author = "Kevin Breen <kevin@techanarchy.net>"
		date = "01.04.2014"
		description = "Detects ShadowTech RAT"
		reference = "http://malwareconfig.com/stats/ShadowTech"
		maltype = "Remote Access Trojan"
		filetype = "exe"
		id = "1fb15030-b400-5e70-b183-81e2527d5556"
	strings:
		$a = "ShadowTech" nocase
		$b = "DownloadContainer"
		$c = "MySettings"
		$d = "System.Configuration"
		$newline = "#-@NewLine@-#" wide
		$split = "pSIL" wide
		$key = "ESIL" wide

	condition:
		4 of them
}

rule RAT_SmallNet
{
	meta:
		author = "Kevin Breen <kevin@techanarchy.net>"
		date = "01.04.2014"
		description = "Detects SmallNet RAT"
		reference = "http://malwareconfig.com/stats/SmallNet"
		maltype = "Remote Access Trojan"
		filetype = "exe"

		id = "aec1f8fd-2806-527e-9d50-422f212864de"
	strings:
		$split1 = "!!<3SAFIA<3!!"
		$split2 = "!!ElMattadorDz!!"
		$a1 = "stub_2.Properties"
		$a2 = "stub.exe" wide
		$a3 = "get_CurrentDomain"

	condition:
		($split1 or $split2) and (all of ($a*))
}

rule RAT_SpyGate
{
	meta:
		author = "Kevin Breen <kevin@techanarchy.net>"
		date = "01.04.2014"
		description = "Detects SpyGate RAT"
		reference = "http://malwareconfig.com/stats/SpyGate"
		maltype = "Remote Access Trojan"
		filetype = "exe"

		id = "ed015770-81ff-5d9c-8bd0-3c225e400724"
	strings:
		$split = "abccba"
		$a1 = "abccbaSpyGateRATabccba" //$a = Version 0.2.6
		$a2 = "StubX.pdb"
		$a3 = "abccbaDanabccb"
		$b1 = "monikerString" nocase //$b = Version 2.0
		$b2 = "virustotal1"
		$b3 = "get_CurrentDomain"
		$c1 = "shutdowncomputer" wide //$c = Version 2.9
		$c2 = "shutdown -r -t 00" wide
		$c3 = "set cdaudio door closed" wide
		$c4 = "FileManagerSplit" wide
		$c5 = "Chating With >> [~Hacker~]" wide

	condition:
		(all of ($a*) and #split > 40) or (all of ($b*) and #split > 10) or (all of ($c*))
}

rule RAT_Sub7Nation
{
	meta:
		author = "Kevin Breen <kevin@techanarchy.net> (slightly modified by Florian Roth to improve performance)"
		date = "01.04.2014"
		description = "Detects Sub7Nation RAT"
		reference = "http://malwareconfig.com/stats/Sub7Nation"
		maltype = "Remote Access Trojan"
		filetype = "exe"

		id = "4f41d649-4a90-566b-bda8-0a288380aeaa"
	strings:
		$a = "EnableLUA /t REG_DWORD /d 0 /f"
		$i = "HostSettings"
		$verSpecific1 = "sevane.tmp"
		$verSpecific2 = "cmd_.bat"
		$verSpecific3 = "a2b7c3d7e4"
		$verSpecific4 = "cmd.dll"

	condition:
		all of them
}

rule RAT_Vertex
{
	meta:
		author = "Kevin Breen <kevin@techanarchy.net>"
		date = "01.04.2014"
		description = "Detects Vertex RAT"
		reference = "http://malwareconfig.com/stats/Vertex"
		maltype = "Remote Access Trojan"
		filetype = "exe"

		id = "f6f5967e-6b88-5d95-8fe1-a286ee8ce64c"
	strings:
		$string1 = "DEFPATH"
		$string2 = "HKNAME"
		$string3 = "HPORT"
		$string4 = "INSTALL"
		$string5 = "IPATH"
		$string6 = "MUTEX"
		$res1 = "PANELPATH"
		$res2 = "ROOTURL"

	condition:
		all of them
}

rule RAT_VirusRat
{
	meta:
		author = "Kevin Breen <kevin@techanarchy.net>"
		date = "01.04.2014"
		description = "Detects VirusRAT"
		reference = "http://malwareconfig.com/stats/VirusRat"
		maltype = "Remote Access Trojan"
		filetype = "exe"

		id = "ef00cec9-d09b-5010-8e7d-bb391c937f34"
	strings:
		$string0 = "virustotal"
		$string1 = "virusscan"
		$string2 = "abccba"
		$string3 = "pronoip"
		$string4 = "streamWebcam"
		$string5 = "DOMAIN_PASSWORD"
		$string6 = "Stub.Form1.resources"
		$string7 = "ftp://{0}@{1}" wide
		$string8 = "SELECT * FROM moz_logins" wide
		$string9 = "SELECT * FROM moz_disabledHosts" wide
		$string10 = "DynDNS\\Updater\\config.dyndns" wide
		$string11 = "|BawaneH|" wide

	condition:
		all of them
}

rule RAT_Xtreme
{
	meta:
		author = "Kevin Breen <kevin@techanarchy.net>"
		date = "01.04.2014"
		description = "Detects Xtreme RAT"
		reference = "http://malwareconfig.com/stats/Xtreme"
		maltype = "Remote Access Trojan"
		filetype = "exe"
		ver = "2.9, 3.1, 3.2, 3.5"

		id = "02b7bb6a-5d1e-5379-b366-868680844719"
	strings:
		$a = "XTREME" wide
		$b = "ServerStarted" wide
		$c = "XtremeKeylogger" wide
		$d = "x.html" wide
		$e = "Xtreme RAT" wide

	condition:
		all of them
}

rule RAT_adWind
{
	meta:
		author = "Kevin Breen <kevin@techanarchy.net>"
		date = "01.04.2014"
		description = "Detects Adwind RAT"
		reference = "http://malwareconfig.com/stats/adWind"
		maltype = "Remote Access Trojan"
		filetype = "exe"

		id = "95681c07-0e9c-5688-a8a0-899617521c7b"
	strings:
		$meta = "META-INF"
		$conf = "config.xml"
		$a = "Adwind.class"
		$b = "Principal.adwind"

	condition:
		all of them
}

rule RAT_njRat
{
	meta:
		author = "Kevin Breen <kevin@techanarchy.net>"
		date = "01.04.2014"
		description = "Detects njRAT"
		reference = "http://malwareconfig.com/stats/njRat"
		maltype = "Remote Access Trojan"
		filetype = "exe"

		id = "6289b9c8-eef6-5cfb-97bd-b819158d6fdd"
	strings:
		$s1 = {7C 00 27 00 7C 00 27 00 7C} // |'|'|
		$s2 = "netsh firewall add allowedprogram" wide
		$s3 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide
		$s4 = "yyyy-MM-dd" wide

		$v1 = "cmd.exe /k ping 0 & del" wide
		$v2 = "cmd.exe /c ping 127.0.0.1 & del" wide
		$v3 = "cmd.exe /c ping 0 -n 2 & del" wide

	condition:
		all of ($s*) and any of ($v*)
}

rule RAT_unrecom
{
	meta:
		author = "Kevin Breen <kevin@techanarchy.net>"
		date = "01.04.2014"
		description = "Detects unrecom RAT"
		reference = "http://malwareconfig.com/stats/unrecom"
		maltype = "Remote Access Trojan"
		filetype = "exe"

		id = "56b11c22-f43c-5192-9a0a-0ac14b0cd041"
	strings:
		$meta = "META-INF"
		$conf = "load/ID"
		$a = "load/JarMain.class"
		$b = "load/MANIFEST.MF"
		$c = "plugins/UnrecomServer.class"

	condition:
		all of them
}

rule MAL_JRAT_Oct18_1 {
   meta:
      description = "Detects JRAT malware"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2018-10-11"
      hash1 = "ce190c37a6fdb2632f4bc5ea0bb613b3fbe697d04e68e126b41910a6831d3411"
      id = "f211ef1c-8def-55f0-8817-d01ebd9c2947"
   strings:
      $x1 = "/JRat.class" ascii
   condition:
      uint16(0) == 0x4b50 and filesize < 700KB and 1 of them
}
