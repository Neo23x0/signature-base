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
      author = "Florian Roth"
		score = 60
      reference = "Internal Research"
      date = "2017-02-22"
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
      author = "Florian Roth"
		score = 60
      reference = "Internal Research"
      date = "2017-02-22"
   strings:
      $s1 = "System.Net.WebClient).DownloadString(\"http" ascii nocase
		$s2 = "System.Net.WebClient).DownloadString('http" ascii nocase
      
      $fp1 = "NuGet.exe" ascii fullword
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
