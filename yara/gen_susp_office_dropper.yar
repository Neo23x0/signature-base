rule SUSP_Office_Dropper_Strings {
   meta:
      description = "Detects Office droppers that include a notice to enable active content"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2018-09-13"
      id = "6560fdf7-46e8-5c16-8263-a36f1dec7868"
   strings:
      $a1 = "_VBA_PROJECT" wide

      $s1 = "click enable editing" fullword ascii
      $s2 = "click enable content" fullword ascii
      $s3 = "\"Enable Editing\"" fullword ascii
      $s4 = "\"Enable Content\"" fullword ascii
   condition:
      uint16(0) == 0xcfd0 and filesize < 500KB and $a1 and 1 of ($s*)
}

rule SUSP_EnableContent_String_Gen {
   meta:
      description = "Detects suspicious string that asks to enable active content in Office Doc"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2019-02-12"
      hash1 = "525ba2c8d35f6972ac8fcec8081ae35f6fe8119500be20a4113900fe57d6a0de"
      id = "d763bc21-2925-55df-85e0-1ee857e921ca"
   strings:
      $e1 = "Enable Editing" fullword ascii
      $e2 = "Enable Content" fullword ascii
      $e3 = "Enable editing" fullword ascii
      $e4 = "Enable content" fullword ascii
   condition:
      uint16(0) == 0xcfd0 and (
            $e1 in (0..3000) or
            $e2 in (0..3000) or
            $e3 in (0..3000) or
            $e4 in (0..3000) or
            2 of them
      )
}

rule SUSP_WordDoc_VBA_Macro_Strings {
   meta:
      description = "Detects suspicious strings in Word Doc that indcate malicious use of VBA macros"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2019-02-12"
      score = 60
      hash1 = "525ba2c8d35f6972ac8fcec8081ae35f6fe8119500be20a4113900fe57d6a0de"
      id = "210baf6e-ec67-5bc4-ba27-6a6de0c11a73"
   strings:
      $a1 = "\\Microsoft Shared\\" ascii
      $a2 = "\\VBA\\" ascii
      $a3 = "Microsoft Office Word" fullword ascii
      $a4 = "PROJECTwm" fullword wide

      $s1 = "AppData" fullword ascii
      $s2 = "Document_Open" fullword ascii
      $s3 = "Project1" fullword ascii
      $s4 = "CreateObject" fullword ascii
   condition:
      uint16(0) == 0xcfd0 and filesize < 800KB and all of them
}

rule SUSP_OfficeDoc_VBA_Base64Decode {
   meta:
      description = "Detects suspicious VBA code with Base64 decode functions"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://github.com/cpaton/Scripting/blob/master/VBA/Base64.bas"
      date = "2019-06-21"
      score = 70
      hash1 = "52262bb315fa55b7441a04966e176b0e26b7071376797e35c80aa60696b6d6fc"
      id = "99690116-fc89-53d7-8f29-575d75d53fc9"
   strings:
      $s1 = "B64_CHAR_DICT" ascii
      $s2 = "Base64Decode" ascii
      $s3 = "Base64Encode" ascii
   condition:
      uint16(0) == 0xcfd0 and filesize < 60KB and 2 of them
}

rule SUSP_VBA_FileSystem_Access {
   meta:
      description = "Detects suspicious VBA that writes to disk and is activated on document open"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2019-06-21"
      score = 60
      hash1 = "52262bb315fa55b7441a04966e176b0e26b7071376797e35c80aa60696b6d6fc"
      id = "91241b91-ca3f-5817-bf78-550fe015b467"
   strings:
      $s1 = "\\Common Files\\Microsoft Shared\\" wide
      $s2 = "Scripting.FileSystemObject" ascii

      $a1 = "Document_Open" ascii
      $a2 = "WScript.Shell" ascii
      $a3 = "AutoOpen" fullword ascii
   condition:
      uint16(0) == 0xcfd0 and filesize < 100KB and all of ($s*) and 1 of ($a*)
}

rule SUSP_Excel_IQY_RemoteURI_Syntax {
   meta:
      description = "Detects files with Excel IQY RemoteURI syntax"
      author = "Nick Carr"
      reference = "https://twitter.com/ItsReallyNick/status/1030330473954897920"
      date = "2018-08-17"
      modified = "2023-11-25"
      score = 55
      id = "ea3427da-9cce-5ad9-9c78-e3cee802ba80"
   strings:
      $URL = "http"

      $fp1 = "https://go.microsoft.com"
   condition:
      uint32(0) == 0x0d424557 and uint32(4) == 0x0a0d310a
      and filesize < 1MB
      and $URL
      and not 1 of ($fp*)
}

rule SUSP_Macro_Sheet_Obfuscated_Char {
   meta:
      description = "Finding hidden/very-hidden macros with many CHAR functions"
      author = "DissectMalware"
      date = "2020-04-07"
      score = 65
      hash1 = "0e9ec7a974b87f4c16c842e648dd212f80349eecb4e636087770bc1748206c3b"
      reference = "https://twitter.com/DissectMalware/status/1247595433305800706"
      id = "791e9bba-3e4e-5efd-a800-a612c6f92cfb"
   strings:
      $ole_marker = {D0 CF 11 E0 A1 B1 1A E1}  
      $s1 = "Excel" fullword ascii
      $macro_sheet_h1 = {85 00 ?? ?? ?? ?? ?? ?? 01 01}
      $macro_sheet_h2 = {85 00 ?? ?? ?? ?? ?? ?? 02 01}    
      $char_func = {06 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 1E 3D  00 41 6F 00}
   condition:
      $ole_marker at 0 and 1 of ($macro_sheet_h*) and #char_func > 10 and $s1
}
