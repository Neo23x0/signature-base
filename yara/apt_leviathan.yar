/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-10-18
   Identifier: Leviathan Phishing Attacks
   Reference: https://goo.gl/MZ7dRg
*/

/* Rule Set ----------------------------------------------------------------- */

rule SeDLL_Javascript_Decryptor {
   meta:
      description = "Detects SeDll - DLL is used for decrypting and executing another JavaScript backdoor such as Orz"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://goo.gl/MZ7dRg"
      date = "2017-10-18"
      hash1 = "146aa9a0ec013aa5bdba9ea9d29f59d48d43bc17c6a20b74bb8c521dbb5bc6f4"
   strings:
      $x1 = "SEDll_Win32.dll" fullword ascii
      $x2 = "regsvr32 /s \"%s\" DR __CIM__" fullword wide

      $s1 = "WScriptW" fullword ascii
      $s2 = "IWScript" fullword ascii
      $s3 = "%s\\%s~%d" fullword wide
      $s4 = "PutBlockToFileWW" fullword ascii
      $s5 = "CheckUpAndDownWW" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 40KB and ( 1 of ($x*) or 4 of them )
}

rule Leviathan_CobaltStrike_Sample_1 {
   meta:
      description = "Detects Cobalt Strike sample from Leviathan report"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://goo.gl/MZ7dRg"
      date = "2017-10-18"
      hash1 = "5860ddc428ffa900258207e9c385f843a3472f2fbf252d2f6357d458646cf362"
   strings:
      $x1 = "a54c81.dll" fullword ascii
      $x2 = "%d is an x64 process (can't inject x86 content)" fullword ascii
      $x3 = "Failed to impersonate logged on user %d (%u)" fullword ascii

      $s1 = "powershell -nop -exec bypass -EncodedCommand \"%s\"" fullword ascii
      $s2 = "IEX (New-Object Net.Webclient).DownloadString('http://127.0.0.1:%u/'); %s" fullword ascii
      $s3 = "could not run command (w/ token) because of its length of %d bytes!" fullword ascii
      $s4 = "could not write to process memory: %d" fullword ascii
      $s5 = "%s.4%08x%08x%08x%08x%08x.%08x%08x%08x%08x%08x%08x%08x.%08x%08x%08x%08x%08x%08x%08x.%08x%08x%08x%08x%08x%08x%08x.%x%x.%s" fullword ascii
      $s6 = "Could not connect to pipe (%s): %d" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 600KB and ( 1 of ($x*) or 3 of them )
}

rule MockDll_Gen {
   meta:
      description = "Detects MockDll - regsvr DLL loader"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://goo.gl/MZ7dRg"
      date = "2017-10-18"
      hash1 = "bfc5c6817ff2cc4f3cd40f649e10cc9ae1e52139f35fdddbd32cb4d221368922"
      hash2 = "80b931ab1798d7d8a8d63411861cee07e31bb9a68f595f579e11d3817cfc4aca"
   strings:
      $x1 = "mock_run_ini_Win32.dll" fullword ascii
      $x2 = "mock_run_ini_x64.dll" fullword ascii

      $s1 = "RealCmd=%s %s" fullword ascii
      $s2 = "MockModule=%s" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 20KB and ( 1 of ($x*) or 2 of them )
}

rule VBScript_Favicon_File {
   meta:
      description = "VBScript cloaked as Favicon file used in Leviathan incident"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://goo.gl/MZ7dRg"
      date = "2017-10-18"
      hash1 = "39c952c7e14b6be5a9cb1be3f05eafa22e1115806e927f4e2dc85d609bc0eb36"
   strings:
      $x1 = "myxml = '<?xml version=\"\"1.0\"\" encoding=\"\"UTF-8\"\"?>';myxml = myxml +'<root>" ascii
      $x2 = ".Run \"taskkill /im mshta.exe" ascii
      $x3 = "<script language=\"VBScript\">Window.ReSizeTo 0, 0 : Window.moveTo -2000,-2000 :" ascii

      $s1 = ".ExpandEnvironmentStrings(\"%ALLUSERSPROFILE%\") &" fullword ascii
      $s2 = ".ExpandEnvironmentStrings(\"%temp%\") & " ascii
   condition:
      filesize < 100KB and ( uint16(0) == 0x733c and 1 of ($x*) )
      or ( 3 of them )
}
