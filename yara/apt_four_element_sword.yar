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
		description = "Detects FourElementSword Malware"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.arbornetworks.com/blog/asert/four-element-sword-engagement/"
		date = "2016-04-18"
		hash = "f05cd0353817bf6c2cab396181464c31c352d6dea07e2d688def261dd6542b27"
		id = "488a2344-3d8d-5769-aca8-9e14f38f5eb0"
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
		description = "Detects FourElementSword Malware"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.arbornetworks.com/blog/asert/four-element-sword-engagement/"
		date = "2016-04-18"
		hash = "5f3d0a319ecc875cc64a40a34d2283cb329abcf79ad02f487fbfd6bef153943c"
		id = "35ae844e-52e1-5e6f-984d-aa75ebd2f60f"
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
		description = "Detects FourElementSword Malware"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.arbornetworks.com/blog/asert/four-element-sword-engagement/"
		date = "2016-04-18"
		hash = "7a200c4df99887991c638fe625d07a4a3fc2bdc887112437752b3df5c8da79b6"
		id = "fc801364-9f40-50eb-90e1-99f8605014c7"
	strings:
		$x1 = "%temp%\\tmp092.tmp" fullword ascii

		$s1 = "\\System32\\ctfmon.exe" ascii
		$s2 = "%SystemRoot%\\System32\\" ascii
		$s3 = "32.dll" fullword ascii
	condition:
		( uint16(0) == 0x5a4d and filesize < 660KB and $x1 ) or ( all of them )
}

rule FourElementSword_Keyainst_EXE {
	meta:
		description = "Detects FourElementSword Malware"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.arbornetworks.com/blog/asert/four-element-sword-engagement/"
		date = "2016-04-18"
		hash = "cf717a646a015ee72f965488f8df2dd3c36c4714ccc755c295645fe8d150d082"
		id = "175fe2b0-3c76-5464-9a1a-218a09b25a5a"
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
		description = "Detects FourElementSword Malware"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.arbornetworks.com/blog/asert/four-element-sword-engagement/"
		date = "2016-04-18"
		hash = "9c23febc49c7b17387767844356d38d5578727ee1150956164883cf555fe7f95"
		id = "06879d75-18a3-5d49-a963-fa4bee379387"
	strings:
		$s1 = "Elevate.dll" fullword ascii
		$s2 = "GetSomeF" fullword ascii
		$s3 = "GetNativeSystemInfo" fullword ascii /* Goodware String - occured 530 times */
	condition:
		( uint16(0) == 0x5a4d and filesize < 25KB and $s1 ) or ( all of them )
}

rule FourElementSword_fslapi_dll_gui {
	meta:
		description = "Detects FourElementSword Malware"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.arbornetworks.com/blog/asert/four-element-sword-engagement/"
		date = "2016-04-18"
		hash = "2a6ef9dde178c4afe32fe676ff864162f104d85fac2439986de32366625dc083"
		id = "1cc73eaf-7463-5070-97e5-6ea4c7735371"
	strings:
		$s1 = "fslapi.dll.gui" fullword wide
		$s2 = "ImmGetDefaultIMEWnd" fullword ascii /* Goodware String - occured 64 times */
		$s3 = "RichOX" fullword ascii
	condition:
		( uint16(0) == 0x5a4d and filesize < 12KB and all of them )
}

rule FourElementSword_PowerShell_Start {
	meta:
		description = "Detects FourElementSword Malware"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.arbornetworks.com/blog/asert/four-element-sword-engagement/"
		date = "2016-04-18"
		hash = "9b6053e784c5762fdb9931f9064ba6e52c26c2d4b09efd6ff13ca87bbb33c692"
		id = "62affc03-a408-5d8f-99da-58dead8646c5"
	strings:
		$s0 = "start /min powershell C:\\\\ProgramData\\\\wget.exe" ascii
		$s1 = "start /min powershell C:\\\\ProgramData\\\\iuso.exe" fullword ascii
	condition:
		1 of them
}

rule FourElementSword_ResN32DLL {
	meta:
		description = "Detects FourElementSword Malware"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.arbornetworks.com/blog/asert/four-element-sword-engagement/"
		date = "2016-04-18"
		hash = "bf1b00b7430899d33795ef3405142e880ef8dcbda8aab0b19d80875a14ed852f"
		id = "3e1f6d8d-53ea-542f-ba49-39b4c86f3124"
	strings:
		$s1 = "\\Release\\BypassUAC.pdb" ascii
		$s2 = "\\ResN32.dll" wide
		$s3 = "Eupdate" fullword wide
	condition:
		all of them
}

/* Super Rules ------------------------------------------------------------- */

rule FourElementSword_ElevateDLL {
	meta:
		description = "Detects FourElementSword Malware"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.arbornetworks.com/blog/asert/four-element-sword-engagement/"
		date = "2016-04-18"
		super_rule = 1
		hash1 = "3dfc94605daf51ebd7bbccbb3a9049999f8d555db0999a6a7e6265a7e458cab9"
		hash2 = "5f3d0a319ecc875cc64a40a34d2283cb329abcf79ad02f487fbfd6bef153943c"
		id = "06879d75-18a3-5d49-a963-fa4bee379387"
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
