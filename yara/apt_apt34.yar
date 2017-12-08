
/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-12-07
   Identifier: APT 34
   Reference: https://www.fireeye.com/blog/threat-research/2017/12/targeted-attack-in-middle-east-by-apt34.html
*/

/* Rule Set ----------------------------------------------------------------- */

rule APT34_Malware_HTA {
   meta:
      description = "Detects APT 34 malware"
      author = "Florian Roth"
      reference = "https://www.fireeye.com/blog/threat-research/2017/12/targeted-attack-in-middle-east-by-apt34.html"
      date = "2017-12-07"
      hash1 = "f6fa94cc8efea0dbd7d4d4ca4cf85ac6da97ee5cf0c59d16a6aafccd2b9d8b9a"
   strings:
      $x1 = "WshShell.run \"cmd.exe /C C:\\ProgramData\\" ascii
      $x2 = ".bat&ping 127.0.0.1 -n 6 > nul&wscript  /b" ascii
      $x3 = "cmd.exe /C certutil -f  -decode C:\\ProgramData\\" ascii
      $x4 = "a.WriteLine(\"set Shell0 = CreateObject(" ascii
      $x5 = "& vbCrLf & \"Shell0.run" ascii

      $s1 = "<title>Blog.tkacprow.pl: HTA Hello World!</title>" fullword ascii
      $s2 = "<body onload=\"test()\">" fullword ascii
   condition:
      filesize < 60KB and ( 1 of ($x*) or all of ($s*) )
}

rule APT34_Malware_Exeruner {
   meta:
      description = "Detects APT 34 malware"
      author = "Florian Roth"
      reference = "https://www.fireeye.com/blog/threat-research/2017/12/targeted-attack-in-middle-east-by-apt34.html"
      date = "2017-12-07"
      hash1 = "c75c85acf0e0092d688a605778425ba4cb2a57878925eee3dc0f4dd8d636a27a"
   strings:
      $x1 = "\\obj\\Debug\\exeruner.pdb" ascii
      $x2 = "\"wscript.shell`\")`nShell0.run" wide
      $x3 = "powershell.exe -exec bypass -enc \" + ${global:$http_ag} +" wide
      $x4 = "/c powershell -exec bypass -window hidden -nologo -command " fullword wide
      $x5 = "\\UpdateTasks\\JavaUpdatesTasksHosts\\" wide
      $x6 = "schtasks /create /F /ru SYSTEM /sc minute /mo 1 /tn" wide
      $x7 = "UpdateChecker.ps1 & ping 127.0.0.1" wide
      $s8 = "exeruner.exe" fullword wide
      $s9 = "${global:$address1} = $env:ProgramData + \"\\Windows\\Microsoft\\java\";" fullword wide
      $s10 = "C:\\ProgramData\\Windows\\Microsoft\\java" fullword wide
      $s11 = "function runByVBS" fullword wide
      $s12 = "$84e31856-683b-41c0-81dd-a02d8b795026" fullword ascii
      $s13 = "${global:$dns_ag} = \"aQBmACAAKAAoAEcAZQB0AC0AVwBtAGk" wide
   condition:
      uint16(0) == 0x5a4d and filesize < 100KB and 1 of them
}