/*
	Yara Rule Set
	Author: Florian Roth
	Date: 2016-06-02
	Identifier: Win Privilege Escalation
*/

/* Rule Set ----------------------------------------------------------------- */

rule Win_PrivEsc_gp3finder_v4_0 {
	meta:
		description = "Detects a tool that can be used for privilege escalation - file gp3finder_v4.0.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://grimhacker.com/2015/04/10/gp3finder-group-policy-preference-password-finder/"
		date = "2016-06-02"
		score = 80
		hash1 = "7d34e214ef2ca33516875fb91a72d5798f89b9ea8964d3990f99863c79530c06"
		id = "3b310c12-ac69-527b-9503-1486ae5f692c"
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
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://www.greyhathacker.net/?p=738"
		date = "2016-06-02"
		score = 80
		hash1 = "1aa87df34826b1081c40bb4b702750587b32d717ea6df3c29715eb7fc04db755"
		id = "131fdb57-f9ca-5247-8bb4-c939eff5b8bf"
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
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://adaclscan.codeplex.com/"
		score = 60
		date = "2016-06-02"
		hash1 = "3473ddb452de7640fab03cad3e8aaf6a527bdd6a7a311909cfef9de0b4b78333"
		id = "15867a9c-9b9b-5d29-bf51-2b3e91af556f"
	strings:
		$s1 = "<Label x:Name=\"lblPort\" Content=\"Port:\"  HorizontalAlignment=\"Left\" Height=\"28\" Margin=\"10,0,0,0\" Width=\"35\"/>" fullword ascii
		$s2 = "(([System.IconExtractor]::Extract(\"mmcndmgr.dll\", 126, $true)).ToBitMap()).Save($env:temp + \"\\Other.png\")    " fullword ascii
		$s3 = "$bolValid = $ctx.ValidateCredentials($psCred.UserName,$psCred.GetNetworkCredential().Password)" fullword ascii
	condition:
		all of them
}
