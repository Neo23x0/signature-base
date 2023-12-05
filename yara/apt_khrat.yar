/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-08-31
   Identifier: KHRAT RAT
   Reference: https://researchcenter.paloaltonetworks.com/2017/08/unit42-updated-khrat-malware-used-in-cambodia-attacks/
*/

import "pe"

/* Rule Set ----------------------------------------------------------------- */

rule KHRAT_Malware {
   meta:
      description = "Detects an Imphash of KHRAT malware"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://researchcenter.paloaltonetworks.com/2017/08/unit42-updated-khrat-malware-used-in-cambodia-attacks/"
      date = "2017-08-31"
      hash1 = "53e27fd13f26462a58fa5587ecd244cab4da23aa80cf0ed6eb5ee9f9de2688c1"
      id = "3e6a5aca-9898-5864-8974-ca4adf272893"
   condition:
      uint16(0) == 0x5a4d and filesize < 100KB and pe.imphash() == "6a8478ad861f98f8428a042f74de1944"
}

rule MAL_KHRAT_script {
   meta:
      description = "Rule derived from KHRAT script but can match on other malicious scripts as well"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://researchcenter.paloaltonetworks.com/2017/08/unit42-updated-khrat-malware-used-in-cambodia-attacks/"
      date = "2017-08-31"
      hash1 = "8c88b4177b59f4cac820b0019bcc7f6d3d50ce4badb689759ab0966780ae32e3"
      id = "fd345647-4887-560e-a6b2-129a880026aa"
   strings:
      $x1 = "CreateObject(\"WScript.Shell\").Run \"schtasks /create /sc MINUTE /tn" ascii
      $x2 = "CreateObject(\"WScript.Shell\").Run \"rundll32.exe javascript:\"\"\\..\\mshtml,RunHTMLApplication" ascii
      $x3 = "<registration progid=\"ff010f\" classid=\"{e934870c-b429-4d0d-acf1-eef338b92c4b}\" >" fullword ascii
   condition:
      1 of them
}

rule MAL_KHRAT_scritplet {
   meta:
      description = "Rule derived from KHRAT scriptlet"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://researchcenter.paloaltonetworks.com/2017/08/unit42-updated-khrat-malware-used-in-cambodia-attacks/"
      date = "2017-08-31"
      hash1 = "cdb9104636a6f7c6018fe99bc18fb8b542689a84c23c10e9ea13d5aa275fd40e"
      id = "f72d68a3-0409-5401-b6a1-ca8f188d7409"
   strings:
      $x1 = "http.open \"POST\", \"http://update.upload-dropbox[.]com/docs/tz/GetProcess.php\",False,\"\",\"\" " fullword ascii
      $x2 = "Process=Process & Chr(32) & Chr(32) & Chr(32) & Obj.Description" fullword ascii

      $s1 = "http.SetRequestHeader \"Content-Type\", \"application/json\" " fullword ascii
      $s2 = "Dim http,WMI,Objs,Process" fullword ascii
      $s3 = "Set Objs=WMI.InstancesOf(\"Win32_Process\")" fullword ascii
      $s4 = "'WScript.Echo http.responseText " fullword ascii
   condition:
      uint16(0) == 0x3f3c and filesize < 1KB and ( 1 of ($x*) or 4 of them )
}
