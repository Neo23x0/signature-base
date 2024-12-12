/*
	THOR Yara Inverse Matches
	> Detect system file manipulations and common APT anomalies

	This is an extract from the THOR signature database

	Reference:
	http://www.bsk-consulting.de/2014/05/27/inverse-yara-signature-matching/
	https://www.bsk-consulting.de/2014/08/28/scan-system-files-manipulations-yara-inverse-matching-22/

	Notice: These rules require an external variable called "filename"

   License: Detetction Rule License 1.1 (https://github.com/SigmaHQ/sigma/blob/master/LICENSE.Detection.Rules.md)

*/

import "pe"

private rule WINDOWS_UPDATE_BDC
{
meta:
   score = 0
condition:
    (uint32be(0) == 0x44434d01 and // magic: DCM PA30
     uint32be(4) == 0x50413330)
    or
    (uint32be(0) == 0x44434401 and
     uint32be(12)== 0x50413330)    // magic: DCD PA30
}

/* Rules -------------------------------------------------------------------- */

rule iexplore_ANOMALY {
   meta:
      author = "Florian Roth (Nextron Systems)"
      description = "Abnormal iexplore.exe - typical strings not found in file"
      date = "23/04/2014"
      score = 55
      nodeepdive = 1
      id = "ea436608-d191-5058-b844-025e48082edc"
   strings:
      $win2003_win7_u1 = "IEXPLORE.EXE" wide nocase
      $win2003_win7_u2 = "Internet Explorer" wide fullword
      $win2003_win7_u3 = "translation" wide fullword nocase
      $win2003_win7_u4 = "varfileinfo" wide fullword nocase
   condition:
      filename == "iexplore.exe"
      and uint16(0) == 0x5a4d
      and not filepath contains "teamviewer"
      and not 1 of ($win*) and not WINDOWS_UPDATE_BDC
      and filepath contains "C:\\"
      and not filepath contains "Package_for_RollupFix"
}

rule svchost_ANOMALY {
	meta:
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		description = "Abnormal svchost.exe - typical strings not found in file"
		date = "23/04/2014"
		score = 55
		id = "5630054d-9fa4-587f-ba78-cda4478f9cc1"
	strings:
		$win2003_win7_u1 = "svchost.exe" wide nocase
		$win2003_win7_u3 = "coinitializesecurityparam" wide fullword nocase
		$win2003_win7_u4 = "servicedllunloadonstop" wide fullword nocase
		$win2000 = "Generic Host Process for Win32 Services" wide fullword
		$win2012 = "Host Process for Windows Services" wide fullword
	condition:
		filename == "svchost.exe"
      and uint16(0) == 0x5a4d
      and not 1 of ($win*) and not WINDOWS_UPDATE_BDC
}

/* removed 1 rule here */

rule explorer_ANOMALY {
	meta:
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		description = "Abnormal explorer.exe - typical strings not found in file"
		date = "27/05/2014"
		score = 55
		id = "ecadd78f-21a1-5a9f-8f3f-cb51e872805b"
	strings:
		$s1 = "EXPLORER.EXE" wide fullword
		$s2 = "Windows Explorer" wide fullword
	condition:
		filename == "explorer.exe"
      and uint16(0) == 0x5a4d
      and not filepath contains "teamviewer"
      and not 1 of ($s*) and not WINDOWS_UPDATE_BDC
}

rule sethc_ANOMALY {
	meta:
		description = "Sethc.exe has been replaced - Indicates Remote Access Hack RDP"
		author = "F. Roth"
		reference = "http://www.emc.com/collateral/white-papers/h12756-wp-shell-crew.pdf"
		date = "2014/01/23"
		score = 70
		id = "9dfbab4e-3dc8-5246-a051-1618f2ca5f39"
	strings:
		$s1 = "stickykeys" fullword nocase
		$s2 = "stickykeys" wide nocase
		$s3 = "Control_RunDLL access.cpl" wide fullword
		$s4 = "SETHC.EXE" wide fullword
	condition:
		filename == "sethc.exe"
      and uint16(0) == 0x5a4d
      and not 1 of ($s*) and not WINDOWS_UPDATE_BDC
}

rule Utilman_ANOMALY {
	meta:
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		description = "Abnormal utilman.exe - typical strings not found in file"
		date = "01/06/2014"
		score = 70
		id = "98daff9b-1600-56b3-87ff-637deaa6808c"
	strings:
		$win7 = "utilman.exe" wide fullword
		$win2000 = "Start with Utility Manager" fullword wide
		$win2012 = "utilman2.exe" fullword wide
	condition:
		( filename == "utilman.exe" or filename == "Utilman.exe" )
      and uint16(0) == 0x5a4d
      and not 1 of ($win*) and not WINDOWS_UPDATE_BDC
}

rule osk_ANOMALY {
	meta:
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		description = "Abnormal osk.exe (On Screen Keyboard) - typical strings not found in file"
		date = "01/06/2014"
		score = 55
		id = "6b78b001-f863-5a24-a9d1-ee5e8305766b"
	strings:
		$s1 = "Accessibility On-Screen Keyboard" wide fullword
		$s2 = "\\oskmenu" wide fullword
		$s3 = "&About On-Screen Keyboard..." wide fullword
		$s4 = "Software\\Microsoft\\Osk" wide
	condition:
		filename == "osk.exe"
      and uint16(0) == 0x5a4d
      and not 1 of ($s*) and not WINDOWS_UPDATE_BDC
}

rule magnify_ANOMALY {
	meta:
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		description = "Abnormal magnify.exe (Magnifier) - typical strings not found in file"
		date = "01/06/2014"
		score = 55
		id = "db75201e-81a3-5f82-bf6f-ba155bfbcf81"
	strings:
		$win7 = "Microsoft Screen Magnifier" wide fullword
		$win2000 = "Microsoft Magnifier" wide fullword
		$winxp = "Software\\Microsoft\\Magnify" wide
	condition:
		filename =="magnify.exe"
      and uint16(0) == 0x5a4d
      and not 1 of ($win*) and not WINDOWS_UPDATE_BDC
}

rule narrator_ANOMALY {
	meta:
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		description = "Abnormal narrator.exe - typical strings not found in file"
		date = "01/06/2014"
		score = 55
		id = "a51f1916-f89a-58a9-b65c-91bf99575b80"
	strings:
		$win7 = "Microsoft-Windows-Narrator" wide fullword
		$win2000 = "&About Narrator..." wide fullword
		$win2012 = "Screen Reader" wide fullword
		$winxp = "Software\\Microsoft\\Narrator"
		$winxp_en = "SOFTWARE\\Microsoft\\Speech\\Voices" wide
	condition:
		filename == "narrator.exe"
      and uint16(0) == 0x5a4d
      and not 1 of ($win*) and not WINDOWS_UPDATE_BDC
}

rule notepad_ANOMALY {
	meta:
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		description = "Abnormal notepad.exe - typical strings not found in file"
		date = "01/06/2014"
		score = 55
		id = "16ddcd9e-ab6f-593e-80e0-a90399cbc3df"
	strings:
		$win7 = "HELP_ENTRY_ID_NOTEPAD_HELP" wide fullword
		$win2000 = "Do you want to create a new file?" wide fullword
		$win2003 = "Do you want to save the changes?" wide
		$winxp = "Software\\Microsoft\\Notepad" wide
		$winxp_de = "Software\\Microsoft\\Notepad" wide
	condition:
		filename == "notepad.exe"
      and uint16(0) == 0x5a4d
      and not 1 of ($win*) and not WINDOWS_UPDATE_BDC
}

/* NEW ---------------------------------------------------------------------- */

rule csrss_ANOMALY {
	meta:
		description = "Anomaly rule looking for certain strings in a system file (maybe false positive on certain systems) - file csrss.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "not set"
		date = "2015/03/16"
		hash = "17542707a3d9fa13c569450fd978272ef7070a77"
		id = "bbd2841a-ec72-5eb4-b34a-5ecbf9c5b517"
	strings:
		$s1 = "Client Server Runtime Process" fullword wide
		$s4 = "name=\"Microsoft.Windows.CSRSS\"" fullword ascii
		$s5 = "CSRSRV.dll" fullword ascii
		$s6 = "CsrServerInitialization" fullword ascii
	condition:
		filename == "csrss.exe"
      and uint16(0) == 0x5a4d
      and not 1 of ($s*) and not WINDOWS_UPDATE_BDC
}

rule conhost_ANOMALY {
	meta:
		description = "Anomaly rule looking for certain strings in a system file (maybe false positive on certain systems) - file conhost.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "not set"
		date = "2015/03/16"
		hash = "1bd846aa22b1d63a1f900f6d08d8bfa8082ae4db"
		id = "9803fa1b-bcaf-5451-831b-fc0dc9d711f2"
	strings:
		$s2 = "Console Window Host" fullword wide
	condition:
		filename == "conhost.exe"
      and uint16(0) == 0x5a4d
      and not 1 of ($s*) and not WINDOWS_UPDATE_BDC
}

rule wininit_ANOMALY {
	meta:
		description = "Anomaly rule looking for certain strings in a system file (maybe false positive on certain systems) - file wininit.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "not set"
		date = "2015/03/16"
		hash = "2de5c051c0d7d8bcc14b1ca46be8ab9756f29320"
		id = "a251984f-c667-55ec-8cc3-3888e80ddf1e"
	strings:
		$s1 = "Windows Start-Up Application" fullword wide
	condition:
		filename == "wininit.exe"
      and uint16(0) == 0x5a4d
      and not 1 of ($s*) and not WINDOWS_UPDATE_BDC
}

rule winlogon_ANOMALY {
	meta:
		description = "Anomaly rule looking for certain strings in a system file (maybe false positive on certain systems) - file winlogon.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "not set"
		date = "2015/03/16"
		hash = "af210c8748d77c2ff93966299d4cd49a8c722ef6"
		id = "ee424459-8048-52b8-ba97-4d09265a881f"
	strings:
		$s1 = "AuthzAccessCheck failed" fullword
		$s2 = "Windows Logon Application" fullword wide
	condition:
		filename == "winlogon.exe"
      and not 1 of ($s*)
      and uint16(0) == 0x5a4d
		and not WINDOWS_UPDATE_BDC
		and not filepath contains "Malwarebytes"
}

rule SndVol_ANOMALY {
	meta:
		description = "Anomaly rule looking for certain strings in a system file (maybe false positive on certain systems) - file SndVol.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "not set"
		date = "2015/03/16"
		hash = "e057c90b675a6da19596b0ac458c25d7440b7869"
		id = "0c4d705f-4b24-55f9-bcf4-3f65eea0b7af"
	strings:
		$s1 = "Volume Control Applet" fullword wide
	condition:
		filename == "sndvol.exe"
      and uint16(0) == 0x5a4d
      and not 1 of ($s*) and not WINDOWS_UPDATE_BDC
}

rule doskey_ANOMALY {
	meta:
		description = "Anomaly rule looking for certain strings in a system file (maybe false positive on certain systems) - file doskey.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "not set"
		date = "2015/03/16"
		hash = "f2d1995325df0f3ca6e7b11648aa368b7e8f1c7f"
		id = "be9c239a-2918-5330-bbd0-33cc17067f70"
	strings:
		$s3 = "Keyboard History Utility" fullword wide
	condition:
		filename == "doskey.exe"
      and uint16(0) == 0x5a4d
      and not 1 of ($s*) and not WINDOWS_UPDATE_BDC
}

rule lsass_ANOMALY {
	meta:
		description = "Anomaly rule looking for certain strings in a system file (maybe false positive on certain systems) - file lsass.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "not set"
		date = "2015/03/16"
		hash = "04abf92ac7571a25606edfd49dca1041c41bef21"
		id = "0c0f6129-3e01-56d3-b297-cee231567759"
	strings:
		$s1 = "LSA Shell" fullword wide
		$s2 = "<description>Local Security Authority Process</description>" fullword ascii
		$s3 = "Local Security Authority Process" fullword wide
		$s4 = "LsapInitLsa" fullword
	condition:
		filename == "lsass.exe"
      and uint16(0) == 0x5a4d
      and not 1 of ($s*) and not WINDOWS_UPDATE_BDC
}

rule taskmgr_ANOMALY {
   meta:
      description = "Anomaly rule looking for certain strings in a system file (maybe false positive on certain systems) - file taskmgr.exe"
      author = "Florian Roth (Nextron Systems)"
      reference = "not set"
      date = "2015/03/16"
      nodeepdive = 1
      hash = "e8b4d84a28e5ea17272416ec45726964fdf25883"
      id = "e1c3a150-6e7e-5ead-a338-0bac6f43185d"
   strings:
      $s0 = "Windows Task Manager" fullword wide
      $s1 = "taskmgr.chm" fullword
      $s2 = "TmEndTaskHandler::" ascii
      $s3 = "CM_Request_Eject_PC" /* Win XP */
      $s4 = "NTShell Taskman Startup Mutex" fullword wide
   condition:
      ( filename == "taskmgr.exe" or filename == "Taskmgr.exe" ) and not 1 of ($s*) and not WINDOWS_UPDATE_BDC
      and uint16(0) == 0x5a4d
      and filepath contains "C:\\"
      and not filepath contains "Package_for_RollupFix"
}

/* removed 22 rules here */

/* APT ---------------------------------------------------------------------- */

rule APT_Cloaked_PsExec
	{
	meta:
		description = "Looks like a cloaked PsExec. This may be APT group activity."
		date = "2014-07-18"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		score = 60
		id = "e389bb76-0d1d-5e0e-9f79-a3117c919da3"
	strings:
		$s0 = "psexesvc.exe" wide fullword
		$s1 = "Sysinternals PsExec" wide fullword
	condition:
		uint16(0) == 0x5a4d and $s0 and $s1
		and not filename matches /(psexec.exe|PSEXESVC.EXE|PsExec64.exe)$/is
		and not filepath matches /RECYCLE.BIN\\S-1/
}

/* removed 6 rules here */

rule APT_Cloaked_SuperScan
	{
	meta:
		description = "Looks like a cloaked SuperScan Port Scanner. This may be APT group activity."
		date = "2014-07-18"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		score = 50
		id = "96027f7d-822c-5c5e-acd9-cde8289c6b50"
	strings:
		$s0 = "SuperScan4.exe" wide fullword
		$s1 = "Foundstone Inc." wide fullword
	condition:
		uint16(0) == 0x5a4d and $s0 and $s1 and not filename contains "superscan"
}

rule APT_Cloaked_ScanLine
	{
	meta:
		description = "Looks like a cloaked ScanLine Port Scanner. This may be APT group activity."
		date = "2014-07-18"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		score = 50
		id = "78041dc0-491b-5a44-a125-3ad72b266cf8"
	strings:
		$s0 = "ScanLine" wide fullword
		$s1 = "Command line port scanner" wide fullword
		$s2 = "sl.exe" wide fullword
	condition:
		uint16(0) == 0x5a4d and $s0 and $s1 and $s2 and not filename == "sl.exe"
}

rule SUSP_Renamed_Dot1Xtray {
   meta:
      description = "Detects a legitimate renamed dot1ctray.exe, which is often used by PlugX for DLL side-loading"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2018-11-15"
      hash1 = "f9ebf6aeb3f0fb0c29bd8f3d652476cd1fe8bd9a0c11cb15c43de33bbce0bf68"
      id = "3685a79e-7dd6-5221-b58a-6ec1c61030cc"
   strings:
      $a1 = "\\Symantec_Network_Access_Control\\"  ascii
      $a2 = "\\dot1xtray.pdb" ascii
      $a3 = "DOT1X_NAMED_PIPE_CONNECT" fullword wide /* Goodware String - occured 2 times */
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and all of them
      and not filename matches /dot1xtray.exe/i
      and not filepath matches /Recycle.Bin/i
}

rule APT_Cloaked_CERTUTIL {
   meta:
      description = "Detects a renamed certutil.exe utility that is often used to decode encoded payloads"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2018-09-14"
      modified = "2022-06-27"
      id = "13943cda-6bb1-5c6c-8e55-e8d4bba1ffef"
   strings:
      $s1 = "-------- CERT_CHAIN_CONTEXT --------" fullword ascii
      $s5 = "certutil.pdb" fullword ascii
      $s3 = "Password Token" fullword ascii
   condition:
      uint16(0) == 0x5a4d and all of them
      and not filename contains "certutil"
      and not filename contains "CertUtil"
      and not filename contains "Certutil"
      and not filepath contains "\\Bromium\\"
}

rule APT_SUSP_Solarwinds_Orion_Config_Anomaly_Dec20 {
   meta:
      description = "Detects a suspicious renamed Afind.exe as used by different attackers"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://twitter.com/iisresetme/status/1339546337390587905?s=12"
      date = "2020-12-15"
      score = 70
      nodeepdive = 1
      id = "440a3eb9-b573-53ea-ab26-c44d9cf62401"
   strings:
      $s1 = "ReportWatcher" fullword wide ascii 
      
      $fp1 = "ReportStatus" fullword wide ascii
   condition:
      filename == "SolarWindows.Orion.Core.BusinessLayer.dll.config"
      and $s1 
      and not $fp1
}

rule PAExec_Cloaked {
   meta:
      description = "Detects a renamed remote access tool PAEXec (like PsExec)"
      author = "Florian Roth (Nextron Systems)"
      reference = "http://researchcenter.paloaltonetworks.com/2017/03/unit42-shamoon-2-delivering-disttrack/"
      date = "2017-03-27"
      score = 70
      hash1 = "01a461ad68d11b5b5096f45eb54df9ba62c5af413fa9eb544eacb598373a26bc"
      id = "fad8417b-bbdb-5a4e-8324-660e27cb39f8"
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

rule SUSP_VULN_DRV_PROCEXP152_May23 {
   meta:
      description = "Detects vulnerable process explorer driver (original file name: PROCEXP152.SYS), often used by attackers to elevate privileges (false positives are possible in cases in which old versions of process explorer are still present on the system)"
      author = "Florian Roth"
      reference = "https://news.sophos.com/en-us/2023/04/19/aukill-edr-killer-malware-abuses-process-explorer-driver/"
      date = "2023-05-05"
		modified = "2023-07-28"
      score = 50
      hash1 = "cdfbe62ef515546f1728189260d0bdf77167063b6dbb77f1db6ed8b61145a2bc"
      id = "748eb390-f320-5045-bed2-24ae70471f43"
   strings:
      $a1 = "\\ProcExpDriver.pdb" ascii
      $a2 = "\\Device\\PROCEXP152" wide fullword
      $a3 = "procexp.Sys" wide fullword
   condition:
      uint16(0) == 0x5a4d 
      and filesize < 200KB 
      and all of them
}

rule SUSP_VULN_DRV_PROCEXP152_Renamed_May23 {
   meta:
      description = "Detects vulnerable process explorer driver (original file name: PROCEXP152.SYS) that has been renamed (often used by attackers to elevate privileges)"
      author = "Florian Roth"
      reference = "https://news.sophos.com/en-us/2023/04/19/aukill-edr-killer-malware-abuses-process-explorer-driver/"
      date = "2023-05-05"
      score = 70
      hash1 = "cdfbe62ef515546f1728189260d0bdf77167063b6dbb77f1db6ed8b61145a2bc"
      id = "af2ec5d5-3453-5d35-8d19-4f37c61fabce"
   strings:
      $a1 = "\\ProcExpDriver.pdb" ascii
      $a2 = "\\Device\\PROCEXP152" wide fullword
      $a3 = "procexp.Sys" wide fullword
   condition:
      uint16(0) == 0x5a4d
      and filesize < 200KB 
      and all of them
      and not filename matches /PROCEXP152\.SYS/i
}

rule SUSP_ANOMALY_Teams_Binary_Nov23 : FILE {
   meta:
      description = "Detects a suspicious binary with the name teams.exe, update.exe or squirrel.exe in the AppData folder of Microsoft Teams that is unsigned or signed by a different CA"
      author = "Florian Roth"
      score = 60
      reference = "https://twitter.com/steve_noel/status/1722698479636476325/photo/1"
      date = "2023-11-11"
      modified = "2024-12-03"
      id = "60557ed1-ac16-5e3b-b105-157dc34f6ad7"
   strings:
      $a1 = "Microsoft Code Signing PCA" ascii
   condition:
      (
         filename iequals "teams.exe" or
         filename iequals "update.exe" or 
         filename iequals "squirrel.exe"
      )
      and filepath icontains "\\AppData\\Local\\Microsoft\\Teams"
      and pe.number_of_signatures == 0
      and not $a1
}

rule SAM_Hive_Backup {
   meta:
      description = "Detects a SAM hive backup file - SAM is the Security Account Manager - contains password hashes"
      author = "Florian Roth"
      reference = "https://www.ired.team/offensive-security/credential-access-and-credential-dumping/dumping-hashes-from-sam-registry"
      score = 60
      nodeepdive = 1
      date = "2015-03-31"
      modified = "2023-12-12"
      id = "31fb6c0c-966d-5002-bf8c-4129964c81ff"
   strings:
      $s1 = "\\SystemRoot\\System32\\Config\\SAM" wide
   condition:
      uint32(0) == 0x66676572 and $s1 in (0..200)
      and not filepath contains "\\System32\\Config"
      and not filepath contains "\\System32\\config"
      and not filepath contains "System Volume Information"
      and not filepath contains "\\config\\RegBack"
}
