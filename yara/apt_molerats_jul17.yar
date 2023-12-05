/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-07-07
   Identifier: Molerats Jul17
   Reference: https://mymalwareparty.blogspot.de/2017/07/operation-desert-eagle.html
*/

/* Rule Set ----------------------------------------------------------------- */

rule Molerats_Jul17_Sample_1 {
   meta:
      description = "Detects Molerats sample - July 2017"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://mymalwareparty.blogspot.de/2017/07/operation-desert-eagle.html"
      date = "2017-07-07"
      hash1 = "ebf2423b9de131eab1c61ac395cbcfc2ac3b15bd9c83b96ae0a48619a4a38d0a"
      id = "b5277255-3ced-5dc5-9490-c5829a0c248b"
   strings:
      /* {11804ce4-930a-4b09-bf70-9f1a95d0d70d}, Culture=neutral, PublicKeyToken=3e56350693f7355e */
      $s1 = "ezExODA0Y2U0LTkzMGEtNGIwOS1iZjcwLTlmMWE5NWQwZDcwZH0sIEN1bHR1cmU9bmV1dHJhbCwgUHVibGljS2V5VG9rZW49M2U1NjM1MDY5M2Y3MzU1ZQ==,[z]{c00" wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 200KB and all of them )
}

rule Molerats_Jul17_Sample_2 {
   meta:
      description = "Detects Molerats sample - July 2017"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://mymalwareparty.blogspot.de/2017/07/operation-desert-eagle.html"
      date = "2017-07-07"
      hash1 = "7e122a882d625f4ccac019efb7bf1b1024b9e0919d205105e7e299fb1a20a326"
      id = "7ef02003-83d1-5ec7-952d-1e693375dd4b"
   strings:
      $s1 = "Folder.exe" fullword ascii
      $s2 = "Notepad++.exe" fullword wide
      $s3 = "RSJLRSJOMSJ" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 1000KB and all of them )
}

rule Molerats_Jul17_Sample_3 {
   meta:
      description = "Detects Molerats sample - July 2017"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://mymalwareparty.blogspot.de/2017/07/operation-desert-eagle.html"
      date = "2017-07-07"
      hash1 = "995eee4122802c2dc83bb619f8c53173a5a9c656ad8f43178223d78802445131"
      hash2 = "fec657a19356753008b0f477083993aa5c36ebaf7276742cf84bfe614678746b"
      id = "e1a3323e-fe84-59e5-86d9-dca0c261e3c3"
   strings:
      $s1 = "ccleaner.exe" fullword wide
      $s2 = "Folder.exe" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 600KB and all of them )
}

rule Molerats_Jul17_Sample_4 {
   meta:
      description = "Detects Molerats sample - July 2017"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://mymalwareparty.blogspot.de/2017/07/operation-desert-eagle.html"
      date = "2017-07-07"
      hash1 = "512a14130a7a8b5c2548aa488055051ab7e725106ddf2c705f6eb4cfa5dc795c"
      id = "cad0c6a2-d286-52fa-b9b8-793ab9ae048f"
   strings:
      $x1 = "get-itemproperty -path 'HKCU:\\SOFTWARE\\Microsoft\\' -name 'KeyName')" wide
      $x2 = "O.Run C & chrw(34) & \"[System.IO.File]::" wide
      $x3 = "HKCU\\SOFTWARE\\Microsoft\\\\KeyName\"" fullword wide
   condition:
      ( filesize < 700KB and 1 of them )
}

rule Molerats_Jul17_Sample_5 {
   meta:
      description = "Detects Molerats sample - July 2017"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://mymalwareparty.blogspot.de/2017/07/operation-desert-eagle.html"
      date = "2017-07-07"
      hash1 = "ebf2423b9de131eab1c61ac395cbcfc2ac3b15bd9c83b96ae0a48619a4a38d0a"
      id = "c9dd4f4a-a980-5339-b238-9f53360b89ae"
   strings:
      $x1 = "powershell.exe -nop -c \"iex" nocase ascii
      $x2 = ".run('%windir%\\\\SysWOW64\\\\WindowsPowerShell\\\\" ascii

      $a1 = "Net.WebClient).DownloadString" nocase ascii
      $a2 = "gist.githubusercontent.com" nocase ascii
   condition:
      filesize < 200KB and ( 1 of ($x*) or 2 of them )
}

rule Molerats_Jul17_Sample_Dropper {
   meta:
      description = "Detects Molerats sample dropper SFX - July 2017"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://mymalwareparty.blogspot.de/2017/07/operation-desert-eagle.html"
      date = "2017-07-07"
      hash1 = "ad0b3ac8c573d84c0862bf1c912dba951ec280d31fe5b84745ccd12164b0bcdb"
      id = "b4622373-b496-51de-abaa-caa665b558b3"
   strings:
      $s1 = "Please remove %s from %s folder. It is unsecure to run %s until it is done." fullword wide
      $s2 = "sfxrar.exe" fullword ascii
      $s3 = "attachment.hta" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 1000KB and all of them )
}
