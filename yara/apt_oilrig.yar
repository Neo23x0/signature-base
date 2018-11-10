/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2016-10-12
   Identifier: OilRig Malware Campaign
*/

import "pe"

/* Rule Set ----------------------------------------------------------------- */

rule OilRig_Malware_Campaign_Gen1 {
   meta:
      description = "Detects malware from OilRig Campaign"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://goo.gl/QMRZ8K"
      date = "2016-10-12"
      hash1 = "d808f3109822c185f1d8e1bf7ef7781c219dc56f5906478651748f0ace489d34"
      hash2 = "80161dad1603b9a7c4a92a07b5c8bce214cf7a3df897b561732f9df7920ecb3e"
      hash3 = "662c53e69b66d62a4822e666031fd441bbdfa741e20d4511c6741ec3cb02475f"
      hash4 = "903b6d948c16dc92b69fe1de76cf64ab8377893770bf47c29bf91f3fd987f996"
      hash5 = "c4fbc723981fc94884f0f493cb8711fdc9da698980081d9b7c139fcffbe723da"
      hash6 = "57efb7596e6d9fd019b4dc4587ba33a40ab0ca09e14281d85716a253c5612ef4"
      hash7 = "1b2fee00d28782076178a63e669d2306c37ba0c417708d4dc1f751765c3f94e1"
      hash8 = "9f31a1908afb23a1029c079ee9ba8bdf0f4c815addbe8eac85b4163e02b5e777"
      hash9 = "0cd9857a3f626f8e0c07495a4799c59d502c4f3970642a76882e3ed68b790f8e"
      hash10 = "4b5112f0fb64825b879b01d686e8f4d43521252a3b4f4026c9d1d76d3f15b281"
      hash11 = "4e5b85ea68bf8f2306b6b931810ae38c8dff3679d78da1af2c91032c36380353"
      hash12 = "c3c17383f43184a29f49f166a92453a34be18e51935ddbf09576a60441440e51"
      hash13 = "f3856c7af3c9f84101f41a82e36fc81dfc18a8e9b424a3658b6ba7e3c99f54f2"
      hash14 = "0c64ab9b0c122b1903e8063e3c2c357cbbee99de07dc535e6c830a0472a71f39"
      hash15 = "d874f513a032ccb6a5e4f0cd55862b024ea0bee4de94ccf950b3dd894066065d"
      hash16 = "8ee628d46b8af20c4ba70a2fe8e2d4edca1980583171b71fe72455c6a52d15a9"
      hash17 = "55d0e12439b20dadb5868766a5200cbbe1a06053bf9e229cf6a852bfcf57d579"
      hash18 = "528d432952ef879496542bc62a5a4b6eee788f60f220426bd7f933fa2c58dc6b"
      hash19 = "93940b5e764f2f4a2d893bebef4bf1f7d63c4db856877020a5852a6647cb04a0"
      hash20 = "e2ec7fa60e654f5861e09bbe59d14d0973bd5727b83a2a03f1cecf1466dd87aa"
      hash21 = "9c0a33a5dc62933f17506f20e0258f877947bdcd15b091a597eac05d299b7471"
      hash22 = "a787c0e42608f9a69f718f6dca5556607be45ec77d17b07eb9ea1e0f7bb2e064"
      hash23 = "3772d473a2fe950959e1fd56c9a44ec48928f92522246f75f4b8cb134f4713ff"
      hash24 = "3986d54b00647b507b2afd708b7a1ce4c37027fb77d67c6bc3c20c3ac1a88ca4"
      hash25 = "f5a64de9087b138608ccf036b067d91a47302259269fb05b3349964ca4060e7e"

   strings:
      $x1 = "Get-Content $env:Public\\Libraries\\update.vbs) -replace" ascii
      $x2 = "wss.Run \"powershell.exe \" & Chr(34) & \"& {waitfor haha /T 2}\" & Chr(34), 0" fullword ascii
      $x3 = "Call Extract(UpdateVbs, wss.ExpandEnvironmentStrings(\"%PUBLIC%\") & \"\\Libraries\\update.vbs\")" fullword ascii
      $s4 = "CreateObject(\"WScript.Shell\").Run cmd, 0o" fullword ascii

      /* Base64 encode config */
      /* $global:myhost = */
      $b1 = "JGdsb2JhbDpteWhvc3QgP" ascii
      /* HOME="%public%\Libraries\" */
      $b2 = "SE9NRT0iJXB1YmxpYyVcTGlicmFyaWVzX" ascii
      /* Set wss = CreateObject("wScript.Shell") */
      $b3 = "U2V0IHdzcyA9IENyZWF0ZU9iamVjdCgid1NjcmlwdC5TaGV" ascii
      /* $scriptdir = Split-Path -Parent -Path $ */
      $b4 = "JHNjcmlwdGRpciA9IFNwbGl0LVBhdGggLVBhcmVudCAtUGF0aCA" ascii
      /* \x0aSet wss = CreateObject("wScript.Shell") */
      $b5 = "DQpTZXQgd3NzID0gQ3JlYXRlT2JqZWN" ascii
      /* whoami & hostname */
      $b6 = "d2hvYW1pICYgaG9zdG5hb" ascii
   condition:
      ( uint16(0) == 0xcfd0 and filesize < 700KB and 1 of them )
}

rule OilRig_Malware_Campaign_Mal1 {
   meta:
      description = "Detects malware from OilRig Campaign"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://goo.gl/QMRZ8K"
      date = "2016-10-12"
      hash1 = "e17e1978563dc10b73fd54e7727cbbe95cc0b170a4e7bd0ab223e059f6c25fcc"
   strings:
      $x1 = "DownloadExecute=\"powershell \"\"&{$r=Get-Random;$wc=(new-object System.Net.WebClient);$wc.DownloadFile(" ascii
      $x2 = "-ExecutionPolicy Bypass -File \"&HOME&\"dns.ps1\"" fullword ascii
      $x3 = "CreateObject(\"WScript.Shell\").Run Replace(DownloadExecute,\"-_\",\"bat\")" fullword ascii
      $x4 = "CreateObject(\"WScript.Shell\").Run DnsCmd,0" fullword ascii
      $s1 = "http://winodwsupdates.me" ascii
   condition:
      ( uint16(0) == 0x4f48 and filesize < 4KB and 1 of them ) or ( 2 of them )
}

rule OilRig_Malware_Campaign_Gen2 {
   meta:
      description = "Detects malware from OilRig Campaign"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://goo.gl/QMRZ8K"
      date = "2016-10-12"
      hash1 = "c6437f57a8f290b5ec46b0933bfa8a328b0cb2c0c7fbeea7f21b770ce0250d3d"
      hash2 = "293522e83aeebf185e653ac279bba202024cedb07abc94683930b74df51ce5cb"
   strings:
      $s1 = "%userprofile%\\AppData\\Local\\Microsoft\\ " fullword ascii
      $s2 = "$fdn=[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('" fullword ascii
      $s3 = "&{$rn = Get-Random; $id = 'TR" fullword ascii
      $s4 = "') -replace '__',('DNS'+$id) | " fullword ascii
      $s5 = "\\upd.vbs" fullword ascii
      $s6 = "schtasks /create /F /sc minute /mo " fullword ascii
      $s7 = "') -replace '__',('HTP'+$id) | " fullword ascii
      $s8 = "&{$rn = Get-Random -minimum 1 -maximum 10000; $id = 'AZ" fullword ascii
      $s9 = "http://www.israirairlines.com/?mode=page&page=14635&lang=eng<" fullword ascii
   condition:
      ( uint16(0) == 0xcfd0 and filesize < 4000KB and 2 of ($s*) ) or ( 4 of them )
}

rule OilRig_Malware_Campaign_Gen3 {
   meta:
      description = "Detects malware from OilRig Campaign"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://goo.gl/QMRZ8K"
      date = "2016-10-12"
      hash1 = "5e9ddb25bde3719c392d08c13a295db418d7accd25d82d020b425052e7ba6dc9"
      hash2 = "bd0920c8836541f58e0778b4b64527e5a5f2084405f73ee33110f7bc189da7a9"
      hash3 = "90639c7423a329e304087428a01662cc06e2e9153299e37b1b1c90f6d0a195ed"
   strings:
      $x1 = "source code from https://www.fireeye.com/blog/threat-research/2016/05/targeted_attacksaga.htmlrrrr" fullword ascii
      $x2 = "\\Libraries\\fireueye.vbs" fullword ascii
      $x3 = "\\Libraries\\fireeye.vbs&" fullword wide
   condition:
      ( uint16(0) == 0xcfd0 and filesize < 100KB and 1 of them )
}

rule OilRig_Malware_Campaign_Mal2 {
   meta:
      description = "Detects malware from OilRig Campaign"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://goo.gl/QMRZ8K"
      date = "2016-10-12"
      hash1 = "65920eaea00764a245acb58a3565941477b78a7bcc9efaec5bf811573084b6cf"
   strings:
      $x1 = "wss.Run \"powershell.exe \" & Chr(34) & \"& {(Get-Content $env:Public\\Libraries\\update.vbs) -replace '__',(Get-Random) | Set-C" ascii
      $x2 = "Call Extract(UpdateVbs, wss.ExpandEnvironmentStrings(\"%PUBLIC%\") & \"\\Libraries\\update.vbs\")" fullword ascii
      $x3 = "mailto:Mohammed.sarah@gratner.com" fullword wide
      $x4 = "mailto:Tarik.Imam@gartner.com" fullword wide
      $x5 = "Call Extract(DnsPs1, wss.ExpandEnvironmentStrings(\"%PUBLIC%\") & \"\\Libraries\\dns.ps1\")" fullword ascii
      $x6 = "2dy53My5vcmcvMjAw" fullword wide /* base64 encoded string 'w.w3.org/200' */
   condition:
      ( uint16(0) == 0xcfd0 and filesize < 200KB and 1 of them )
}

rule OilRig_Campaign_Reconnaissance {
   meta:
      description = "Detects Windows discovery commands - known from OilRig Campaign"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://goo.gl/QMRZ8K"
      date = "2016-10-12"
      hash1 = "5893eae26df8e15c1e0fa763bf88a1ae79484cdb488ba2fc382700ff2cfab80c"
   strings:
      $s1 = "whoami & hostname & ipconfig /all" ascii
      $s2 = "net user /domain 2>&1 & net group /domain 2>&1" ascii
      $s3 = "net group \"domain admins\" /domain 2>&1 & " ascii
   condition:
      ( filesize < 1KB and 1 of them )
}

rule OilRig_Malware_Campaign_Mal3 {
   meta:
      description = "Detects malware from OilRig Campaign"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://goo.gl/QMRZ8K"
      date = "2016-10-12"
      hash1 = "02226181f27dbf59af5377e39cf583db15200100eea712fcb6f55c0a2245a378"
   strings:
      $x1 = "(Get-Content $env:Public\\Libraries\\dns.ps1) -replace ('#'+'##'),$botid | Set-Content $env:Public\\Libraries\\dns.ps1" fullword ascii
      $x2 = "Invoke-Expression ($global:myhome+'tp\\'+$global:filename+'.bat > '+$global:myhome+'tp\\'+$global:filename+'.txt')" fullword ascii
      $x3 = "('00000000'+(convertTo-Base36(Get-Random -Maximum 46655)))" fullword ascii
   condition:
      ( filesize < 10KB and 1 of them )
}

rule OilRig_Malware_Nov17_13 {
   meta:
      description = ""
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://twitter.com/ClearskySec/status/933280188733018113"
      date = "2017-11-22"
      hash1 = "4f1e2df85c538875a7da877719555e21c33a558ac121eb715cf4e779d77ab445"
   strings:
      $x1 = "\\Release\\dnscat2.pdb" ascii
      $x2 = "cscript.exe //T:20 //Nologo " fullword ascii

      $a1 = "taskkill /F /IM cscript.exe" fullword ascii
      $a2 = "cmd.exe /c " fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and (
        pe.imphash() == "0160250adfc97f9d4a12dd067323ec61" or
        1 of ($x*) or
        all of ($a*)
      )
}

rule Oilrig_IntelSecurityManager_macro {
   meta:
      description = "Detects OilRig malware"
      author = "Eyal Sela (slightly modified by Florian Roth)"
      reference = "Internal Research"
      date = "2018-01-19"
   strings:
      $one1 = "$c$m$$d$.$$" ascii wide
      $one2 = "$C$$e$r$$t$u$$t$i$$l$" ascii wide
      $one3 = "$$%$a$$p$p$$d$a$" ascii wide
      $one4 = ".$t$$x$t$$" ascii wide
      $one5 = "cu = Replace(cu, \"$\", \"\")" ascii wide
      $one6 = "Shell Environ$(\"COMSPEC\") & \" /c"
      $one7 = "echo \" & Chr(32) & cmd & Chr(32) & \" > \" & Chr(34)" ascii wide

      $two1 = "& SchTasks /Delete /F /TN " ascii wide
      $two2 = "SecurityAssist" ascii wide
      $two3 = "vbs = \"cmd.exe /c SchTasks" ascii wide
      $two4 = "/Delete /F /TN Conhost & del" ascii wide
      $two5 = "NullRefrencedException" ascii wide
      $two6 = "error has occurred in user32.dll by" ascii wide
      $two7 = "NullRefrencedException" ascii wide
   condition:
      filesize < 300KB and 1 of ($one*) or 2 of ($two*)
}

rule Oilrig_IntelSecurityManager {
   meta:
      description = "Detects OilRig malware"
      author = "Eyal Sela"
      reference = "Internal Research"
      date = "2018-01-19"
   strings:
      $one1 = "srvResesponded" ascii wide fullword
      $one2 = "InetlSecurityAssistManager" ascii wide fullword
      $one3 = "srvCheckresponded" ascii wide fullword
      $one4 = "IntelSecurityManager" ascii wide
      $one5 = "msoffice365cdn.com" ascii wide
      $one6 = "\\tmpCa.vbs" ascii wide
      $one7 = "AAZFinish" ascii wide fullword
      $one8 = "AAZUploaded" ascii wide fullword
      $one9 = "ABZFinish" ascii wide fullword
      $one10 = "\\tmpCa.vbs" ascii wide
   condition:
      filesize < 300KB and any of them
}
