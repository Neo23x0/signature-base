/*
	This is a collection of rules that use external vriables
	They work with scanners that support the use of external variabls, like
	THOR, LOKI or SPARK
	https://www.nextron-systems.com/compare-our-scanners/
*/

rule Acrotray_Anomaly {
	meta:
		description = "Detects an acrotray.exe that does not contain the usual strings"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		score = 75
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
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "https://www.crowdstrike.com/blog/bears-midst-intrusion-democratic-national-committee/"
		date = "2016-06-14"
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
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://www.pwc.co.uk/cyber-security/pdf/cloud-hopper-annex-b-final.pdf"
      date = "2017-04-07"
      score = 90
   strings:
      $s1 = "AES-256 SDCTR" ascii
      $s2 = "direct-tcpip" ascii
   condition:
      all of them and filename == "rundll32.exe"
}

rule msi_dll_Anomaly {
   meta:
      description = "Detetcs very small and supicious msi.dll"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://blog.cylance.com/shell-crew-variants-continue-to-fly-under-big-avs-radar"
      date = "2017-02-10"
      hash1 = "8c9048e2f5ea2ef9516cac06dc0fba8a7e97754468c0d9dc1e5f7bce6dbda2cc"
   strings:
      $x1 = "msi.dll.eng" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 15KB and filename == "msi.dll" and $x1
}

rule PoS_Malware_MalumPOS_Config
{
    meta:
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
        date = "2015-06-25"
        description = "MalumPOS Config File"
        reference = "http://blog.trendmicro.com/trendlabs-security-intelligence/trend-micro-discovers-malumpos-targets-hotels-and-other-us-industries/"
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
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "VT Research QA"
		date = "2016-08-29"
		score = 80
		hash1 = "3b3392bc730ded1f97c51e23611740ff8b218abf0a1100903de07819eeb449aa"
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
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "https://goo.gl/Mr6M2J"
		date = "2016-06-04"
		score = 90
		hash1 = "83f0352c14fa62ae159ab532d85a2b481900fed50d32cc757aa3f4ccf6a13bee"
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
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "http://goo.gl/KAB8Jw"
		date = "2016-04-26"
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
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      hash = "f1c95b13a71ca3629a0bb79601fcacf57cdfcf768806a71b26f2448f8c1d5d24"
      score = 60
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

rule HackTool_Producers {
   meta:
      description = "Hacktool Producers String"
      threat_level = 5
      score = 50
      nodeepdive = 1
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
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
        score = 50
    condition:
        uint16(0) == 0x5a4d and filename matches /[Tt]humbs\.db/
}

rule Fake_AdobeReader_EXE
    {
    meta:
      description = "Detects an fake AdobeReader executable based on filesize OR missing strings in file"
      date = "2014-09-11"
      author = "Florian Roth"
      score = 50
      nodeepdive = 1
      nodeepdive = 1
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

rule Fake_FlashPlayerUpdaterService_EXE
    {
    meta:
        description = "Detects an fake AdobeReader executable based on filesize OR missing strings in file"
        date = "2014-09-11"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
        score = 50
    strings:
        $s1 = "Adobe Systems Incorporated" ascii wide
    condition:
        uint16(0) == 0x5a4d and
        filename matches /FlashPlayerUpdateService.exe/i and
        not $s1
}

rule mimikatz_lsass_mdmp
{
   meta:
      description      = "LSASS minidump file for mimikatz"
      author         = "Benjamin DELPY (gentilkiwi)"
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
