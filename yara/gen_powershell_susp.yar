/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-02-23
   Identifier: Suspicious PowerShell Script Code
*/

/* Rule Set ----------------------------------------------------------------- */

rule WordDoc_PowerShell_URLDownloadToFile {
   meta:
      description = "Detects Word Document with PowerShell URLDownloadToFile"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://www.arbornetworks.com/blog/asert/additional-insights-shamoon2/"
      date = "2017-02-23"
      super_rule = 1
      hash1 = "33ee8a57e142e752a9c8960c4f38b5d3ff82bf17ec060e4114f5b15d22aa902e"
      hash2 = "388b26e22f75a723ce69ad820b61dd8b75e260d3c61d74ff21d2073c56ea565d"
      hash3 = "71e584e7e1fb3cf2689f549192fe3a82fd4cd8ee7c42c15d736ebad47b028087"
   strings:
      $w1 = "Microsoft Forms 2.0 CommandButton" fullword ascii
      $w2 = "Microsoft Word 97-2003 Document" fullword ascii

      $p1 = "powershell.exe" fullword ascii
      $p2 = "URLDownloadToFile" fullword ascii
   condition:
      ( uint16(0) == 0xcfd0 and 1 of ($w*) and all of ($p*) )
}

rule Suspicious_PowerShell_Code_1 {
   meta:
      description = "Detects suspicious PowerShell code"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
		score = 60
      reference = "Internal Research"
      date = "2017-02-22"
      type = "file"
   strings:
      $s1 = /$[a-z]=new-object net.webclient/ ascii
      $s2 = /$[a-z].DownloadFile\("http:/ ascii
      $s3 = /IEX $[a-zA-Z]{1,8}.downloadstring\(["']http/ ascii nocase
		$s4 = "powershell.exe -w hidden -ep bypass -Enc" ascii
		$s5 = "-w hidden -noni -nop -c \"iex(New-Object" ascii
		$s6 = "powershell.exe reg add HKCU\\software\\microsoft\\windows\\currentversion\\run" nocase
   condition:
      1 of them
}

rule Suspicious_PowerShell_WebDownload_1 {
   meta:
      description = "Detects suspicious PowerShell code that downloads from web sites"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
		score = 60
      reference = "Internal Research"
      date = "2017-02-22"
      type = "file"
   strings:
      $s1 = "System.Net.WebClient).DownloadString(\"http" ascii nocase
		$s2 = "System.Net.WebClient).DownloadString('http" ascii nocase

      $fp1 = "NuGet.exe" ascii fullword
      $fp2 = "chocolatey.org" ascii
   condition:
      1 of ($s*) and not 1 of ($fp*)
}


/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-06-27
   Identifier: Misc
   Reference: Internal Research
*/

/* Rule Set ----------------------------------------------------------------- */

rule PowerShell_in_Word_Doc {
   meta:
      description = "Detects a powershell and bypass keyword in a Word document"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "Internal Research - ME"
      date = "2017-06-27"
      score = 50
      hash1 = "4fd4a7b5ef5443e939015276fc4bf8ffa6cf682dd95845ef10fdf8158fdd8905"
   strings:
      $s1 = "POwErSHELl.ExE" fullword ascii nocase
      $s2 = "BYPASS" fullword ascii nocase
   condition:
      ( uint16(0) == 0xcfd0 and filesize < 1000KB and all of them )
}

/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-09-30
   Identifier: PowerShell with VBS and JS
   Reference: Internal Research
*/

/* Rule Set ----------------------------------------------------------------- */

rule Susp_PowerShell_Sep17_1 {
   meta:
      description = "Detects suspicious PowerShell script in combo with VBS or JS "
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-09-30"
      score = 60
      hash1 = "8e28521749165d2d48bfa1eac685c985ac15fc9ca5df177d4efadf9089395c56"
   strings:
      $x1 = "Process.Create(\"powershell.exe -nop -w hidden" fullword ascii nocase
      $x2 = ".Run\"powershell.exe -nop -w hidden -c \"\"IEX " ascii

      $s1 = "window.resizeTo 0,0" fullword ascii
   condition:
      ( filesize < 2KB and 1 of them )
}

rule Susp_PowerShell_Sep17_2 {
   meta:
      description = "Detects suspicious PowerShell script in combo with VBS or JS "
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-09-30"
      hash1 = "e387f6c7a55b85e0675e3b91e41e5814f5d0ae740b92f26ddabda6d4f69a8ca8"
   strings:
      $x1 = ".Run \"powershell.exe -nop -w hidden -e " ascii
      $x2 = "FileExists(path + \"\\..\\powershell.exe\")" fullword ascii
      $x3 = "window.moveTo -4000, -4000" fullword ascii

      $s1 = "= CreateObject(\"Wscript.Shell\")" fullword ascii
   condition:
      filesize < 20KB and (
         ( uint16(0) == 0x733c and 1 of ($x*) )
          or 2 of them
      )
}

rule WScript_Shell_PowerShell_Combo {
   meta:
      description = "Detects malware from Middle Eastern campaign reported by Talos"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "http://blog.talosintelligence.com/2018/02/targeted-attacks-in-middle-east.html"
      date = "2018-02-07"
      score = 50
      hash1 = "15f5aaa71bfa3d62fd558a3e88dd5ba26f7638bf2ac653b8d6b8d54dc7e5926b"
   strings:
      $s1 = ".CreateObject(\"WScript.Shell\")" ascii

      $p1 = "powershell.exe" fullword ascii
      $p2 = "-ExecutionPolicy Bypass" fullword ascii
      $p3 = "[System.Convert]::FromBase64String(" ascii

      $fp1 = "Copyright: Microsoft Corp." ascii
   condition:
      filesize < 400KB and $s1 and 1 of ($p*)
      and not 1 of ($fp*)
}

rule SUSP_PowerShell_String_K32_RemProcess {
   meta:
      description = "Detects suspicious PowerShell code that uses Kernel32, RemoteProccess handles or shellcode"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://github.com/nccgroup/redsnarf"
      date = "2018-03-31"
      hash3 = "54a8dd78ec4798cf034c7765d8b2adfada59ac34d019e77af36dcaed1db18912"
      hash4 = "6d52cdd74edea68d55c596554f47eefee1efc213c5820d86e64de0853a4e46b3"
   strings:
      $x1 = "Throw \"Unable to allocate memory in the remote process for shellcode\"" fullword ascii
      $x2 = "$Kernel32Handle = $Win32Functions.GetModuleHandle.Invoke(\"kernel32.dll\")" fullword ascii
      $s3 = "$RSCAddr = $Win32Functions.VirtualAllocEx.Invoke($RemoteProcHandle, [IntPtr]::Zero, [UIntPtr][UInt64]$SCLength, $Win32Constants." ascii
      $s7 = "if ($RemoteProcHandle -eq [IntPtr]::Zero)" fullword ascii
      $s8 = "if (($Success -eq $false) -or ([UInt64]$NumBytesWritten -ne [UInt64]$SCLength))" fullword ascii
      $s9 = "$Success = $Win32Functions.WriteProcessMemory.Invoke($RemoteProcHandle, $RSCAddr, $SCPSMemOriginal, [UIntPtr][UInt64]$SCLength, " ascii
      $s15 = "$TypeBuilder.DefineField('Characteristics', [UInt32], 'Public') | Out-Null" fullword ascii
   condition:
      uint16(0) == 0x7566 and filesize < 6000KB and 1 of them
}

rule PowerShell_JAB_B64 {
   meta:
      description = "Detects base464 encoded $ sign at the beginning of a string"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://twitter.com/ItsReallyNick/status/980915287922040832"
      date = "2018-04-02"
      score = 60
   strings:
      $s1 = "('JAB" ascii wide
      $s2 = "powershell" nocase
   condition:
      filesize < 30KB and all of them
}
