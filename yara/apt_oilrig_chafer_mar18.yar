/*
   Yara Rule Set
   Author: Markus Neis, Florian Roth
   Date: 2018-03-21
   Identifier: OilRig / Chafer activity
   Reference: https://nyotron.com/nyotron-discovers-next-generation-oilrig-attacks/
*/

/* Rule Set ----------------------------------------------------------------- */

rule Chafer_Mimikatz_Custom  {
   meta:
      description = "Detects Custom Mimikatz Version"
      author = "Florian Roth / Markus Neis"
      reference = "https://nyotron.com/wp-content/uploads/2018/03/Nyotron-OilRig-Malware-Report-March-2018b.pdf"
      date = "2018-03-22"
      hash1 = "9709afeb76532566ee3029ecffc76df970a60813bcac863080cc952ad512b023"
   strings:
      $x1 = "C:\\Users\\win7p\\Documents\\mi-back\\" ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and 1 of them
}

rule Chafer_Exploit_Copyright_2017 {
   meta:
      description = "Detects Oilrig Internet Server Extension with Copyright (C) 2017 Exploit"
      author = "Markus Neis"
      reference = "https://nyotron.com/wp-content/uploads/2018/03/Nyotron-OilRig-Malware-Report-March-2018b.pdf"
      date = "2018-03-22"
      hash1 = "cdac69caad8891c5e1b8eabe598c869674dee30af448ce4e801a90eb79973c66"
   strings:
      $x1 = "test3 Internet Server Extension" fullword wide
      $x2 = "Copyright (C) 2017 Exploit" fullword wide

      $a1 = "popen() failed!" fullword ascii
      $a2 = "cmd2cmd=" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 700KB and (
         1 of ($x*) or all of ($a*)
      )
}

rule Chafer_Portscanner {
   meta:
      description = "Detects Custom Portscanner used by Oilrig"
      author = "Markus Neis"
      reference = "https://nyotron.com/wp-content/uploads/2018/03/Nyotron-OilRig-Malware-Report-March-2018b.pdf"
      date = "2018-03-22"
      hash1 = "88274a68a6e07bdc53171641e7349d6d0c71670bd347f11dcc83306fe06656e9"
   strings:
      $x1 = "C:\\Users\\RS01204N\\Documents\\" ascii
      $x2 = "PortScanner /ip:google.com  /port:80 /t:500 /tout:2" fullword ascii
      $x3 = "open ports of host/hosts" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and 1 of them
}

rule Oilrig_Myrtille {
   meta:
      description = "Detects Oilrig Myrtille RDP Browser"
      author = "Markus Neis"
      reference = "https://nyotron.com/wp-content/uploads/2018/03/Nyotron-OilRig-Malware-Report-March-2018b.pdf"
      date = "2018-03-22"
      hash1 = "67945f2e65a4a53e2339bd361652c6663fe25060888f18e681418e313d1292ca"
   strings:
      $x1 = "\\obj\\Release\\Myrtille.Services.pdb" fullword ascii
      $x2 = "Failed to notify rdp client process exit (MyrtilleAppPool down?), remote session {0} ({1})" fullword wide
      $x3 = "Started rdp client process, remote session {0}" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 50KB and 1 of them
}

rule Chafer_Packed_Mimikatz {
   meta:
      description = "Detects Oilrig Packed Mimikatz also detected as Chafer_WSC_x64 by FR"
      author = "Florian Roth / Markus Neis"
      reference = "https://nyotron.com/wp-content/uploads/2018/03/Nyotron-OilRig-Malware-Report-March-2018b.pdf"
      date = "2018-03-22"
      hash1 = "5f2c3b5a08bda50cca6385ba7d84875973843885efebaff6a482a38b3cb23a7c"
   strings:
      $s1 = "Windows Security Credentials" fullword wide
      $s2 = "Minisoft" fullword wide
      $x1 = "Copyright (c) 2014 - 2015 Minisoft" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and ( all of ($s*) or $x1 )
}

rule Oilrig_PS_CnC {
   meta:
      description = "Powershell CnC using DNS queries"
      author = "Markus Neis"
      reference = "https://nyotron.com/wp-content/uploads/2018/03/Nyotron-OilRig-Malware-Report-March-2018b.pdf"
      date = "2018-03-22"
      hash1 = "9198c29a26f9c55317b4a7a722bf084036e93a41ba4466cbb61ea23d21289cfa"
   strings:
      $x1 = "(-join $base32filedata[$uploadedCompleteSize..$($uploadedCompleteSize" fullword ascii
      $s2 = "$hostname = \"D\" + $fileID + (-join ((65..90) + (48..57) + (97..122)|" ascii
   condition:
      filesize < 40KB and 1 of them
}
