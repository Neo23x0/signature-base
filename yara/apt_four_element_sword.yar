/*
	Yara Rule Set
	Author: Florian Roth
	Date: 2016-04-18
	Identifier: FourElementSword
	Reference: https://www.arbornetworks.com/blog/asert/four-element-sword-engagement/
*/

/* Rule Set ----------------------------------------------------------------- */

rule FourElementSword_Config_File {
	meta:
		description = "Detects FourElementSword Malware - file f05cd0353817bf6c2cab396181464c31c352d6dea07e2d688def261dd6542b27"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "https://www.arbornetworks.com/blog/asert/four-element-sword-engagement/"
		date = "2016-04-18"
		hash = "f05cd0353817bf6c2cab396181464c31c352d6dea07e2d688def261dd6542b27"
	strings:
		$s0 = "01,,hccutils.dll,2" fullword ascii
		$s1 = "RegisterDlls=OurDll" fullword ascii
		$s2 = "[OurDll]" fullword ascii
		$s3 = "[DefaultInstall]" fullword ascii /* Goodware String - occured 16 times */
		$s4 = "Signature=\"$Windows NT$\"" fullword ascii /* Goodware String - occured 26 times */
	condition:
		4 of them
}

rule FourElementSword_T9000 {
	meta:
		description = "Detects FourElementSword Malware - file 5f3d0a319ecc875cc64a40a34d2283cb329abcf79ad02f487fbfd6bef153943c"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "https://www.arbornetworks.com/blog/asert/four-element-sword-engagement/"
		date = "2016-04-18"
		hash = "5f3d0a319ecc875cc64a40a34d2283cb329abcf79ad02f487fbfd6bef153943c"
	strings:
		$x1 = "D:\\WORK\\T9000\\" ascii
		$x2 = "%s\\temp\\HHHH.dat" fullword wide

		$s1 = "Elevate.dll" fullword wide
		$s2 = "ResN32.dll" fullword wide
		$s3 = "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)" fullword wide
		$s4 = "igfxtray.exe" fullword wide
	condition:
		( uint16(0) == 0x5a4d and filesize < 500KB and 1 of ($x*) ) or ( all of them )
}

rule FourElementSword_32DLL {
	meta:
		description = "Detects FourElementSword Malware - file 7a200c4df99887991c638fe625d07a4a3fc2bdc887112437752b3df5c8da79b6"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "https://www.arbornetworks.com/blog/asert/four-element-sword-engagement/"
		date = "2016-04-18"
		hash = "7a200c4df99887991c638fe625d07a4a3fc2bdc887112437752b3df5c8da79b6"
	strings:
		$x1 = "%temp%\\tmp092.tmp" fullword ascii

		$s1 = "\\System32\\ctfmon.exe" fullword ascii
		$s2 = "%SystemRoot%\\System32\\" fullword ascii
		$s3 = "32.dll" fullword ascii
	condition:
		( uint16(0) == 0x5a4d and filesize < 660KB and $x1 ) or ( all of them )
}

rule FourElementSword_Keyainst_EXE {
	meta:
		description = "Detects FourElementSword Malware - file cf717a646a015ee72f965488f8df2dd3c36c4714ccc755c295645fe8d150d082"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "https://www.arbornetworks.com/blog/asert/four-element-sword-engagement/"
		date = "2016-04-18"
		hash = "cf717a646a015ee72f965488f8df2dd3c36c4714ccc755c295645fe8d150d082"
	strings:
		$x1 = "C:\\ProgramData\\Keyainst.exe" fullword ascii

		$s1 = "ShellExecuteA" fullword ascii /* Goodware String - occured 266 times */
		$s2 = "GetStartupInfoA" fullword ascii /* Goodware String - occured 2573 times */
		$s3 = "SHELL32.dll" fullword ascii /* Goodware String - occured 3233 times */
	condition:
		( uint16(0) == 0x5a4d and filesize < 48KB and $x1 ) or ( all of them )
}

rule FourElementSword_ElevateDLL_2 {
	meta:
		description = "Detects FourElementSword Malware - file 9c23febc49c7b17387767844356d38d5578727ee1150956164883cf555fe7f95"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "https://www.arbornetworks.com/blog/asert/four-element-sword-engagement/"
		date = "2016-04-18"
		hash = "9c23febc49c7b17387767844356d38d5578727ee1150956164883cf555fe7f95"
	strings:
		$s1 = "Elevate.dll" fullword ascii
		$s2 = "GetSomeF" fullword ascii
		$s3 = "GetNativeSystemInfo" fullword ascii /* Goodware String - occured 530 times */
	condition:
		( uint16(0) == 0x5a4d and filesize < 25KB and $s1 ) or ( all of them )
}

rule FourElementSword_fslapi_dll_gui {
	meta:
		description = "Detects FourElementSword Malware - file 2a6ef9dde178c4afe32fe676ff864162f104d85fac2439986de32366625dc083"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "https://www.arbornetworks.com/blog/asert/four-element-sword-engagement/"
		date = "2016-04-18"
		hash = "2a6ef9dde178c4afe32fe676ff864162f104d85fac2439986de32366625dc083"
	strings:
		$s1 = "fslapi.dll.gui" fullword wide
		$s2 = "ImmGetDefaultIMEWnd" fullword ascii /* Goodware String - occured 64 times */
		$s3 = "RichOX" fullword ascii
	condition:
		( uint16(0) == 0x5a4d and filesize < 12KB and all of them )
}

rule FourElementSword_PowerShell_Start {
	meta:
		description = "Detects FourElementSword Malware - file 9b6053e784c5762fdb9931f9064ba6e52c26c2d4b09efd6ff13ca87bbb33c692"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "https://www.arbornetworks.com/blog/asert/four-element-sword-engagement/"
		date = "2016-04-18"
		hash = "9b6053e784c5762fdb9931f9064ba6e52c26c2d4b09efd6ff13ca87bbb33c692"
	strings:
		$s0 = "start /min powershell C:\\\\ProgramData\\\\wget.exe" ascii
		$s1 = "start /min powershell C:\\\\ProgramData\\\\iuso.exe" fullword ascii
	condition:
		1 of them
}

rule FourElementSword_ResN32DLL {
	meta:
		description = "Detects FourElementSword Malware - file bf1b00b7430899d33795ef3405142e880ef8dcbda8aab0b19d80875a14ed852f"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "https://www.arbornetworks.com/blog/asert/four-element-sword-engagement/"
		date = "2016-04-18"
		hash = "bf1b00b7430899d33795ef3405142e880ef8dcbda8aab0b19d80875a14ed852f"
	strings:
		$s1 = "\\Release\\BypassUAC.pdb" ascii
		$s2 = "\\ResN32.dll" fullword wide
		$s3 = "Eupdate" fullword wide
	condition:
		all of them
}

/* Super Rules ------------------------------------------------------------- */

rule FourElementSword_ElevateDLL {
	meta:
		description = "Detects FourElementSword Malware"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "https://www.arbornetworks.com/blog/asert/four-element-sword-engagement/"
		date = "2016-04-18"
		super_rule = 1
		hash1 = "3dfc94605daf51ebd7bbccbb3a9049999f8d555db0999a6a7e6265a7e458cab9"
		hash2 = "5f3d0a319ecc875cc64a40a34d2283cb329abcf79ad02f487fbfd6bef153943c"
	strings:
		$x1 = "Elevate.dll" fullword wide
		$x2 = "ResN32.dll" fullword wide

		$s1 = "Kingsoft\\Antivirus" fullword wide
		$s2 = "KasperskyLab\\protected" fullword wide
		$s3 = "Sophos" fullword wide
	condition:
		( uint16(0) == 0x5a4d and filesize < 500KB and 1 of ($x*) and all of ($s*) )
		or ( all of them )
}
