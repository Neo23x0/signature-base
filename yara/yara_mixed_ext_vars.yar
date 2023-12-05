/*
	This is a collection of rules that use external variables
	They work with scanners that support the use of external variables, like
	THOR, LOKI or SPARK
	https://www.nextron-systems.com/compare-our-scanners/
*/

import "pe"
import "math" 

rule Acrotray_Anomaly {
	meta:
		description = "Detects an acrotray.exe that does not contain the usual strings"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		score = 75
		id = "e3fef644-e535-5137-ac98-2fd1b7ca4361"
	strings:
		$s1 = "PDF/X-3:2002" fullword wide
		$s2 = "AcroTray - Adobe Acrobat Distiller helper application" fullword wide
		$s3 = "MS Sans Serif" fullword wide
		$s4 = "COOLTYPE.DLL" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 3000KB
		and ( filename == "acrotray.exe" or filename == "AcroTray.exe" )
		and not all of ($s*)
}

rule COZY_FANCY_BEAR_modified_VmUpgradeHelper {
	meta:
		description = "Detects a malicious VmUpgradeHelper.exe as mentioned in the CrowdStrike report"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.crowdstrike.com/blog/bears-midst-intrusion-democratic-national-committee/"
		date = "2016-06-14"
		id = "97b844a4-0fa4-5850-8803-2212a69e3d16"
	strings:
		$s1 = "VMware, Inc." wide fullword
		$s2 = "Virtual hardware upgrade helper service" fullword wide
		$s3 = "vmUpgradeHelper\\vmUpgradeHelper.pdb" ascii
	condition:
		uint16(0) == 0x5a4d and
		filename == "VmUpgradeHelper.exe" and
		not all of ($s*)
}

rule IronTiger_Gh0stRAT_variant
{
	meta:
		author = "Cyber Safety Solutions, Trend Micro"
		description = "This is a detection for a s.exe variant seen in Op. Iron Tiger"
		reference = "http://goo.gl/T5fSJC"
		id = "e7eeee0f-d7a1-5359-bc1f-5a2a883c7227"
	strings:
		$str1 = "Game Over Good Luck By Wind" nocase wide ascii
		$str2 = "ReleiceName" nocase wide ascii
		$str3 = "jingtisanmenxiachuanxiao.vbs" nocase wide ascii
		$str4 = "Winds Update" nocase wide ascii fullword
	condition:
		uint16(0) == 0x5a4d and (any of ($str*))
		and not filename == "UpdateSystemMib.exe"
}

rule OpCloudHopper_Cloaked_PSCP {
   meta:
      description = "Tool used in Operation Cloud Hopper - pscp.exe cloaked as rundll32.exe"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.pwc.co.uk/cyber-security/pdf/cloud-hopper-annex-b-final.pdf"
      date = "2017-04-07"
      score = 90
      id = "c1e2e456-dbdd-54cf-b0e0-b356f291cfcd"
   strings:
      $s1 = "AES-256 SDCTR" ascii
      $s2 = "direct-tcpip" ascii
   condition:
      all of them and filename == "rundll32.exe"
}

rule msi_dll_Anomaly {
   meta:
      description = "Detetcs very small and supicious msi.dll"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://blog.cylance.com/shell-crew-variants-continue-to-fly-under-big-avs-radar"
      date = "2017-02-10"
      hash1 = "8c9048e2f5ea2ef9516cac06dc0fba8a7e97754468c0d9dc1e5f7bce6dbda2cc"
      id = "92cd5c51-ed84-5428-9105-50139f9289c8"
   strings:
      $x1 = "msi.dll.eng" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 15KB and filename == "msi.dll" and $x1
}

rule PoS_Malware_MalumPOS_Config
{
    meta:
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
        date = "2015-06-25"
        description = "MalumPOS Config File"
        reference = "http://blog.trendmicro.com/trendlabs-security-intelligence/trend-micro-discovers-malumpos-targets-hotels-and-other-us-industries/"
        id = "0fd2b9c2-d016-5db2-8fcc-618df6c815de"
    strings:
        $s1 = "[PARAMS]"
        $s2 = "Name="
        $s3 = "InterfacesIP="
        $s4 = "Port="
    condition:
        all of ($s*) and filename == "log.ini" and filesize < 20KB
}

rule Malware_QA_update_test {
	meta:
		description = "VT Research QA uploaded malware - file update_.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "VT Research QA"
		date = "2016-08-29"
		score = 80
		hash1 = "3b3392bc730ded1f97c51e23611740ff8b218abf0a1100903de07819eeb449aa"
		id = "8f319277-1eaf-559e-87ad-f4ab89b04ca5"
	strings:
		$s1 = "test.exe" fullword ascii
		$s2 = "PADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGP" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 1000KB and all of them and filename == "update.exe"
}


/* These only work with external variable "filename" ------------------------ */
/* as used in LOKI, THOR, SPARK --------------------------------------------- */

rule SysInterals_PipeList_NameChanged {
	meta:
		description = "Detects NirSoft PipeList"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://goo.gl/Mr6M2J"
		date = "2016-06-04"
		score = 90
		hash1 = "83f0352c14fa62ae159ab532d85a2b481900fed50d32cc757aa3f4ccf6a13bee"
		id = "01afcf29-a74c-5be2-8b24-694a2802ef34"
	strings:
		$s1 = "PipeList" ascii fullword
		$s2 = "Sysinternals License" ascii fullword
	condition:
		uint16(0) == 0x5a4d and filesize < 170KB and all of them
		and not filename contains "pipelist.exe"
		and not filename contains "PipeList.exe"
}

/*
	Yara Rule Set
	Author: Florian Roth
	Date: 2016-04-26
	Identifier: regsvr32 issue
*/

/* Rule Set ----------------------------------------------------------------- */

rule SCT_Scriptlet_in_Temp_Inet_Files {
	meta:
		description = "Detects a scriptlet file in the temporary Internet files (see regsvr32 AppLocker bypass)"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://goo.gl/KAB8Jw"
		date = "2016-04-26"
		id = "8b729257-3676-59b2-961c-dae1085cbbf6"
	strings:
		$s1 = "<scriptlet>" fullword ascii nocase
		$s2 = "ActiveXObject(\"WScript.Shell\")" ascii
	condition:
		( uint32(0) == 0x4D583F3C or uint32(0) == 0x6D78F3C ) /* <?XM or <?xm */
		and $s1 and $s2
		and filepath contains "Temporary Internet Files"
}


rule GIFCloaked_Webshell_A {
   meta:
      description = "Looks like a webshell cloaked as GIF"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      hash = "f1c95b13a71ca3629a0bb79601fcacf57cdfcf768806a71b26f2448f8c1d5d24"
      score = 60
      id = "4fdef65c-204a-5019-9b4f-c5877c3e39d4"
   strings:
      $s0 = "input type"
      $s1 = "<%eval request"
      $s2 = "<%eval(Request.Item["
      $s3 = "LANGUAGE='VBScript'"
      $s4 = "$_REQUEST" fullword
      $s5 = ";eval("
      $s6 = "base64_decode"

      $fp1 = "<form name=\"social_form\""
   condition:
      uint32(0) == 0x38464947 and ( 1 of ($s*) )
      and not 1 of ($fp*)
}

/* causes FPs and relevancy is limited
rule exploit_ole_stdolelink {
  meta:
    author = "David Cannings"
    description = "StdOleLink, potential 0day in April 2017"
    score = 55
  strings:
    // Parsers will open files without the full 'rtf'
    $header_rtf = "{\\rt" nocase
    $header_office = { D0 CF 11 E0 }
    $header_xml = "<?xml version=" nocase wide ascii

    // Marks of embedded data (reduce FPs)
    // RTF format
    $embedded_object   = "\\object" nocase
    $embedded_objdata  = "\\objdata" nocase
    $embedded_ocx      = "\\objocx" nocase
    $embedded_objclass = "\\objclass" nocase
    $embedded_oleclass = "\\oleclsid" nocase

    // XML Office documents
    $embedded_axocx      = "<ax:ocx"  nocase wide ascii
    $embedded_axclassid  = "ax:classid"  nocase wide ascii

    // OLE format
    $embedded_root_entry = "Root Entry" wide
    $embedded_comp_obj   = "Comp Obj" wide
    $embedded_obj_info   = "Obj Info" wide
    $embedded_ole10      = "Ole10Native" wide

    $data0 = "00000300-0000-0000-C000-000000000046" nocase wide ascii
    $data2 = "OLE2Link" nocase wide ascii
    $data3 = "4f4c45324c696e6b" nocase wide ascii
    $data4 = "StdOleLink" nocase wide ascii
    $data5 = "5374644f6c654c696e6b" nocase wide ascii

  condition:
    // Mandatory header plus sign of embedding, then any of the others
    for any of ($header*) : ( @ == 0 ) and 1 of ($embedded*)
        and (1 of ($data*))
        and extension != ".msi"
}
*/

rule HackTool_Producers {
   meta:
      description = "Hacktool Producers String"
      threat_level = 5
      score = 50
      nodeepdive = 1
      id = "75cb2c86-0eaa-5cf5-96d8-85b91054de36"
   strings:
      $a1 = "www.oxid.it"
      $a2 = "www.analogx.com"
      $a3 = "ntsecurity.nu"
      $a4 = "gentilkiwi.com"
      $a6 = "Marcus Murray"
      $a7 = "Nsasoft US LLC0"
      $a8 = " Nir Sofer"
   condition:
      uint16(0) == 0x5a4d and 1 of ($a*) and
      not extension contains ".ini" and
      not extension contains ".xml" and
      not extension contains ".sqlite"
}

rule Exe_Cloaked_as_ThumbsDb
    {
    meta:
        description = "Detects an executable cloaked as thumbs.db - Malware"
        date = "2014-07-18"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
        score = 50
        id = "ff09f8cf-de5a-50fc-aa0b-c54f7667e246"
    condition:
        uint16(0) == 0x5a4d and filename matches /[Tt]humbs\.db/
}

rule Fake_AdobeReader_EXE
    {
    meta:
      description = "Detects an fake AdobeReader executable based on filesize OR missing strings in file"
      date = "2014-09-11"
      author = "Florian Roth (Nextron Systems)"
      score = 50
      nodeepdive = 1
      nodeepdive = 1
      id = "e3dd9d94-9f4b-5ff9-bfec-29abfb3555bb"
    strings:
      $s1 = "Adobe Systems" ascii

      $fp1 = "Adobe Reader" ascii wide
      $fp2 = "Xenocode Virtual Appliance Runtime" ascii wide
    condition:
      uint16(0) == 0x5a4d and
      filename matches /AcroRd32.exe/i and
      not $s1 in (filesize-2500..filesize)
      and not 1 of ($fp*)
}

rule mimikatz_lsass_mdmp
{
   meta:
      description      = "LSASS minidump file for mimikatz"
      author         = "Benjamin DELPY (gentilkiwi)"
      id = "3d850dbe-1342-55ac-b0f7-91343d88f147"
   strings:
      $lsass         = "System32\\lsass.exe"   wide nocase
   condition:
      (uint32(0) == 0x504d444d) and $lsass and filesize > 50000KB and not filename matches /WER/
}

rule lsadump {
   meta:
      description      = "LSA dump programe (bootkey/syskey) - pwdump and others"
      author         = "Benjamin DELPY (gentilkiwi)"
      score         = 80
      nodeepdive = 1
      id = "3bfa8dd8-720d-5326-ac92-0fb96cf21219"
   strings:
      $str_sam_inc   = "\\Domains\\Account" ascii nocase
      $str_sam_exc   = "\\Domains\\Account\\Users\\Names\\" ascii nocase
      $hex_api_call   = {(41 b8 | 68) 00 00 00 02 [0-64] (68 | ba) ff 07 0f 00 }
      $str_msv_lsa   = { 4c 53 41 53 52 56 2e 44 4c 4c 00 [0-32] 6d 73 76 31 5f 30 2e 64 6c 6c 00 }
      $hex_bkey      = { 4b 53 53 4d [20-70] 05 00 01 00}

      $fp1 = "Sysinternals" ascii
      $fp2 = "Apple Inc." ascii wide
      $fp3 = "Kaspersky Lab" ascii fullword
      $fp4 = "ESET Security" ascii
      $fp5 = "Disaster Recovery Module" wide
      $fp6 = "Bitdefender" wide fullword
   condition:
      uint16(0) == 0x5a4d and
      (($str_sam_inc and not $str_sam_exc) or $hex_api_call or $str_msv_lsa or $hex_bkey )
      and not 1 of ($fp*)
      and not filename contains "Regdat"
      and not filetype == "EXE"
      and not filepath contains "Dr Watson"
      and not extension == "vbs"
}

rule SUSP_ServU_SSH_Error_Pattern_Jul21_1 {
   meta:
      description = "Detects suspicious SSH component exceptions that could be an indicator of exploitation attempts as described in advisory addressing CVE-2021-35211 in ServU services"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.solarwinds.com/trust-center/security-advisories/cve-2021-35211#FAQ"
      date = "2021-07-12"
      score = 60
      id = "1a89f0b0-445c-5867-94cd-f07ba1becad6"
   strings:
      $s1 = "EXCEPTION: C0000005;" ascii
      $s2 = "CSUSSHSocket::ProcessReceive();" ascii
   condition:
      filename == "DebugSocketlog.txt"
      and all of ($s*)
}

rule SUSP_ServU_Known_Mal_IP_Jul21_1 {
   meta:
      description = "Detects suspicious IP addresses used in exploitation of ServU services CVE-2021-35211 and reported by Solarwinds"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.solarwinds.com/trust-center/security-advisories/cve-2021-35211#FAQ"
      date = "2021-07-12"
      score = 60
      id = "118272a7-7ec9-568b-99e0-8cfe97f3f64e"
   strings:
      $xip1 = "98.176.196.89" ascii fullword 
      $xip2 = "68.235.178.32" ascii fullword
      $xip3 = "208.113.35.58" ascii fullword
      $xip4 = "144.34.179.162" ascii fullword
      $xip5 = "97.77.97.58" ascii fullword
   condition:
      filename == "DebugSocketlog.txt"
      and 1 of them
}

rule SUSP_EXPL_Confluence_RCE_CVE_2021_26084_Indicators_Sep21 {
   meta:
      description = "Detects ELF binaries owner by the confluence user but outside usual confluence directories"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://attackerkb.com/topics/Eu74wdMbEL/cve-2021-26084-confluence-server-ognl-injection/rapid7-analysis"
      date = "2021-09-01"
      score = 55
      id = "395d37ea-1986-5fdd-b58c-562ae0d8be35"
   condition:
      uint32be(0) == 0x7f454c46 /* ELF binary */
      and owner == "confluence"
      and not filepath contains "/confluence/"
}

rule SUSP_Blocked_Download_Proxy_Replacement_Jan23_1 {
   meta:
      description = "Detects a file that has been replaced with a note by a security solution like an Antivirus or a filtering proxy server"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.virustotal.com/gui/search/filename%253A*.exe%2520tag%253Ahtml%2520size%253A10kb-%2520size%253A2kb%252B/files"
      date = "2023-01-28"
      score = 60
      id = "58bc8288-6bdb-57d5-9de5-a54a39584838"
   strings:
      $x01 = "Web Filter Violation"
      $x02 = "Google Drive can't scan this file for viruses."
      $x03 = " target=\"_blank\">Cloudflare <img "
      $x04 = "Sorry, this file is infected with a virus.</p>"
      $x05 = "-- Sophos Warn FileType Page -->"
      $x06 = "<p>Certain Sophos products may not be exported for use by government end-users" // accept EULA 
      $x07 = "<p class=\"content-list\">Bitly displays this warning when a link has been flagged as suspect. There are many"
      $x08 = "Something went wrong. Don't worry, your files are still safe and the Dropbox team has been notified."
      $x09 = "<p>sinkhole</p>"
      $x10 = "The requested short link is blocked by website administration due to violation of the website policy terms."
      $x11 = "<img src=\"https://www.malwarebytes.com/images/"
      $x12 = "<title>Malwarebytes</title>"
      $x13 = "<title>Blocked by VIPRE</title>"
      $x14 = "<title>Your request appears to be from an automated process</title>"
      $x15 = "<p>Advanced Security blocked access to"
      $x16 = "<title>Suspected phishing site | Cloudflare</title>"
      $x17 = ">This link has been flagged "
      $x18 = "<h1>Trend Micro Apex One</h1>"
      $x19 = "Hitachi ID Identity and Access Management Suite"
      $x20 = ">http://www.fortinet.com/ve?vn="
      $x21 = "access to URL with fixed IP not allowed" // FritzBox
      $x23 = "<title>Web Page Blocked</title>"
      $x24 = "<title>Malicious Website Blocked</title>"
      $x25 = "<h2>STOPzilla has detected"
      $x26 = ">Seqrite Endpoint Security</span>"
      $x27 = "<TITLE>K7 Safe Surf</TITLE>"
      $x28 = "<title>Blocked by VIPRE</title>"

      $g01 = "blocked access" fullword
      $g02 = "policy violation" fullword
      $g03 = "violation of " 
      $g04 = "blocked by" fullword
      $g05 = "Blocked by" fullword
      $g07 = "Suspected Phishing"
      $g08 = "ile quarantined"
      $g09 = " is infected "
      $g10 = "Blocked</title>"
      $g11 = "site blocked" fullword
      $g12 = "Site Blocked" fullword
      $g13 = "blocked for" fullword
      $g14 = "is blocked" fullword
      $g15 = "potentially harmful"
      $g16 = "Page Blocked" fullword
      $g17 = "page blocked" fullword
   condition:
      extension == ".exe" and not uint16(0) == 0x5a4d and 1 of them
      or (
         extension == ".rar" or 
         extension == ".ps1" or 
         extension == ".vbs" or
         extension == ".bat"
      )
      and 1 of ($x*)
}

/* too many FPs
rule APT_MAL_RU_WIN_Snake_Malware_PeIconSizes_May23_1 {
   meta:
      description = "Detects Comadmin file that houses Snake's kernel driver and the driver's loader"
      author = "CSA"
      reference = "https://media.defense.gov/2023/May/09/2003218554/-1/-1/0/JOINT_CSA_HUNTING_RU_INTEL_SNAKE_MALWARE_20230509.PDF"
      date = "2023-05-10"
      score = 75
   condition:
      uint16(0) == 0x5a4d
      and ( 
         filename == "WerFault.exe"
         or filename == "werfault.exe"
      )
      and filepath contains "\\WinSxS\\"
      and for any rsrc in pe.resources: (
         rsrc.type == pe.RESOURCE_TYPE_ICON and rsrc.length == 3240
      ) 
      and for any rsrc in pe.resources: (
         rsrc.type == pe.RESOURCE_TYPE_ICON and rsrc.length == 1384 
      ) 
      and for any rsrc in pe.resources: (
         rsrc.type == pe.RESOURCE_TYPE_ICON and rsrc.length == 7336
      )
}
*/

rule APT_MAL_RU_Snake_Malware_Queue_File_May23_1 {
   meta:
      description = "Detects Queue files used by Snake malware"
      author = "Florian Roth"
      reference = "https://media.defense.gov/2023/May/09/2003218554/-1/-1/0/JOINT_CSA_HUNTING_RU_INTEL_SNAKE_MALWARE_20230509.PDF"
      date = "2023-05-10"
      score = 80
      id = "c7ed554e-b55e-5c3f-aa8b-231cb1073f34"
   condition:
      filename matches /(\{[0-9A-Fa-f]{8}\-([0-9A-Fa-f]{4}\-){3}[0-9A-Fa-f]{12}\}\.){2}crmlog/
      /* and filepath contains "\\Registration\\" // not needed - already specific enough */
      // we reduce the range for the entropy calculation to the first 1024 for performance
      // reasons. In a fully encrypted file - as used by Snake - this should already be specific enough
      //and math.entropy(0, filesize) >= 7.0
      and math.entropy(0, 1024) >= 7.0
}


rule SUSP_Password_XLS_Unencrypted {
   meta:
      description = "Detects files named e.g. password.xls, which might contain unportected clear text passwords"
      author = "Arnim Rupp (https://github.com/ruppde)"
      reference = "Internal Research"
      date = "2023-10-04"
      score = 60
      id = "41096ef1-dd02-5956-9053-3d7fb1a5092c"
   condition:
      // match password and the german passwort:
      (
         filename istartswith "passwor" or        /* EN / DE */
         filename istartswith "contrase" or       /* ES */
         filename istartswith "mot de pass" or   /* FR */
         filename istartswith "mot_de_pass" or   /* FR */
         filename istartswith "motdepass" or     /* FR */
         filename istartswith "wachtwoord"        /* NL */
      )
      and (
          // no need to check if an xls is password protected, because it's trivial to break
          (
              filename iendswith ".xls"
              and uint32be(0) == 0xd0cf11e0 // xls
          )
          or
          (
              filename iendswith ".xlsx"
              and uint32be(0) == 0x504b0304 // unencrypted xlsx = pkzip
          )
      )
}

rule SUSP_Password_XLS_Encrypted {
   meta:
      description = "Detects files named e.g. password.xlsx, which might contain clear text passwords, but are password protected from MS Office"
      author = "Arnim Rupp (https://github.com/ruppde)"
      reference = "Internal Research"
      date = "2023-10-04"
      score = 50
      id = "d3334923-3396-524d-9111-8ccb754ab99e"
   condition:
      // match password and the german passwort:
      (
         filename istartswith "passwor" or        /* EN / DE */
         filename istartswith "contrase" or       /* ES */
         filename istartswith "mot de pass" or   /* FR */
         filename istartswith "mot_de_pass" or   /* FR */
         filename istartswith "motdepass" or     /* FR */
         filename istartswith "wachtwoord"        /* NL */
      )
      and filename iendswith ".xlsx"
      and uint32be(0) == 0xd0cf11e0 // encrypted xlsx = CDFV2
}
