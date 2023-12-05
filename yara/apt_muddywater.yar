/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2018-02-26
   Identifier: MuddyWater samples
*/

/* Rule Set ----------------------------------------------------------------- */

rule MuddyWater_Mal_Doc_Feb18_1 {
   meta:
      description = "Detects malicious document used by MuddyWater"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research - TI2T"
      date = "2018-02-26"
      hash1 = "3d96811de7419a8c090a671d001a85f2b1875243e5b38e6f927d9877d0ff9b0c"
      id = "5f275ee8-c6a9-532b-bc82-b109195171da"
   strings:
      /* iex([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String( */
      $x1 = "aWV4KFtTeXN0ZW0uVGV4dC5FbmNvZGluZ106OlVuaWNvZGUuR2V0U3RyaW5nKFtTeXN0ZW0uQ29udmVydF06OkZyb21CYXNlNjRTdHJpbmco" ascii
      /* Double Base64 encoded : Invoke-Expression */
      $x2 = "U1FCdUFIWUFid0JyQUdVQUxRQkZBSGdBY0FCeUFHVUFjd0J6QUdrQWJ3QnVBQ0FBS"
   condition:
      uint16(0) == 0xcfd0 and filesize < 3000KB and 1 of them
}

rule MuddyWater_Mal_Doc_Feb18_2 {
   meta:
      description = "Detects malicious document used by MuddyWater"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research - TI2T"
      date = "2018-02-26"
      hash1 = "3d96811de7419a8c090a671d001a85f2b1875243e5b38e6f927d9877d0ff9b0c"
      hash2 = "366d8b84a43a528e6aaf9ecfc38980b148f983967803914471ccf011b9bb0832"
      id = "117e1d33-63a3-52c8-acf6-bc61959193db"
   strings:
      $s1 = "*\\G{00020430-0000-0000-C000-000000000046}#2.0#0#C:\\Windows\\System32\\stdole2.tlb#OLE Automation" fullword wide
      $s2 = "*\\G{2DF8D04C-5BFA-101B-BDE5-00AA0044DE52}#2.8#0#C:\\Program Files\\Common Files\\Microsoft Shared\\OFFICE16\\MSO.DLL#Microsoft " wide
      $s3 = "*\\G{00020905-0000-0000-C000-000000000046}#8.7#0#C:\\Program Files\\Microsoft Office\\Office16\\MSWORD.OLB#Microsoft Word 16.0 O" wide
      $s4 = "scripting.filesystemobject$" fullword ascii
      $s5 = "ID=\"{00000000-0000-0000-0000-000000000000}\"" fullword ascii
   condition:
      uint16(0) == 0xcfd0 and filesize < 6000KB and all of them
}

rule MAL_MuddyWater_DroppedTask_Jun18_1 {
   meta:
      description = "Detects a dropped Windows task as used by MudyWater in June 2018"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://app.any.run/tasks/719c94eb-0a00-47cc-b583-ad4f9e25ebdb"
      date = "2018-06-12"
      hash1 = "7ecc2e1817f655ece2bde39b7d6633f4f586093047ec5697a1fab6adc7e1da54"
      id = "d9ef379d-161f-59f1-873e-3af12b24b76b"
   strings:
      $x1 = "%11%\\scrobj.dll,NI,c:" wide

      $s1 = "AppAct = \"SOFTWARE\\Microsoft\\Connection Manager\"" fullword wide
      $s2 = "[DefenderService]" fullword wide
      $s3 = "UnRegisterOCXs=EventManager" fullword wide
      $s4 = "ShortSvcName=\" \"" fullword wide
   condition:
      uint16(0) == 0xfeff and filesize < 1KB and ( 1 of ($x*) or 3 of them )
}
