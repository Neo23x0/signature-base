/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-04-03
   Identifier: ROKRAT
*/

rule ROKRAT_Malware {
   meta:
      description = "Detects ROKRAT Malware"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "http://blog.talosintelligence.com/2017/04/introducing-rokrat.html"
      date = "2017-04-03"
      modified = "2021-09-14"
      hash1 = "051463a14767c6477b6dacd639f30a8a5b9e126ff31532b58fc29c8364604d00"
      hash2 = "cd166565ce09ef410c5bba40bad0b49441af6cfb48772e7e4a9de3d646b4851c"
      id = "52e7e144-b704-5254-9a0f-928fbc96f877"
   strings:
      $x1 = "c:\\users\\appdata\\local\\svchost.exe" fullword ascii
      $x2 = "c:\\temp\\episode3.mp4" fullword ascii
      $x3 = "MAC-SIL-TED-FOO-YIM-LAN-WAN-SEC-BIL-TAB" ascii
      $x4 = "c:\\temp\\%d.tmp" ascii fullword

      $s1 = "%s%s%04d%02d%02d%02d%02d%02d.jar" fullword ascii
      $s2 = "\\Aboard\\Acm%c%c%c.exe" ascii

      $a1 = "ython" ascii fullword
      $a2 = "iddler" ascii fullword
      $a3 = "egmon" ascii fullword
      $a6 = "iresha" ascii fullword
   condition:
      uint16(0) == 0x5a4d and filesize < 25000KB and ( 1 of ($x*) or ( 5 of them ) )
}

/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-11-28
   Identifier: ROKRAT
   Reference: http://blog.talosintelligence.com/2017/11/ROKRAT-Reloaded.html
*/

/* Rule Set ----------------------------------------------------------------- */

import "pe"

rule ROKRAT_Dropper_Nov17 {
   meta:
      description = "Detects dropper for ROKRAT malware"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "http://blog.talosintelligence.com/2017/11/ROKRAT-Reloaded.html"
      date = "2017-11-28"
      hash1 = "eb6d25e08b2b32a736b57f8df22db6d03dc82f16da554f4e8bb67120eacb1d14"
      hash2 = "a29b07a6fe5d7ce3147dd7ef1d7d18df16e347f37282c43139d53cce25ae7037"
      id = "4f3156a2-6b1b-5c65-b8fa-84c0b739d703"
   condition:
      uint16(0) == 0x5a4d and filesize < 2500KB and
      pe.imphash() == "c6187b1b5f4433318748457719dd6f39"
}

rule Freeenki_Infostealer_Nov17 {
   meta:
      description = "Detects Freenki infostealer malware"
      author = "Florian Roth (Nextron Systems)"
      reference = "http://blog.talosintelligence.com/2017/11/ROKRAT-Reloaded.html"
      date = "2017-11-28"
      modified = "2023-01-06"
      hash1 = "99c1b4887d96cb94f32b280c1039b3a7e39ad996859ffa6dd011cf3cca4f1ba5"
      id = "01365093-e40a-524a-8a13-217742542f1e"
   strings:
      $x1 = "base64Encoded=\"TVqQAAMAAAAEAAAA" ascii
      $x2 = "command =outFile &\" sysupdate\"" fullword ascii
      $x3 = "outFile=sysDir&\"\\rundll32.exe\"" fullword ascii

      $s1 = "SOFTWARE\\Clients\\StartMenuInternet\\firefox.exe\\shell\\open\\command" fullword wide
      $s2 = "c:\\TEMP\\CrashReports\\" ascii
      $s3 = "objShell.run command, 0, True" fullword ascii
      $s4 = "sysDir = shell.ExpandEnvironmentStrings(\"%windir%\")" fullword ascii
      $s5 = "'Wscript.echo \"Base64 encoded: \" + base64Encoded" fullword ascii
      $s6 = "set shell = WScript.CreateObject(\"WScript.Shell\")" fullword ascii

      $a1 = "\\Google\\Chrome\\User Data\\Default\\Login Data" ascii
      $a2 = "SELECT username_value, password_value, signon_realm FROM logins" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and (
        1 of ($x*) or
        3 of them or
        all of ($a*)
      )
}

rule Freeenki_Infostealer_Nov17_Export_Sig_Testing {
   meta:
      description = "Detects Freenki infostealer malware"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "http://blog.talosintelligence.com/2017/11/ROKRAT-Reloaded.html"
      date = "2017-11-28"
      hash1 = "99c1b4887d96cb94f32b280c1039b3a7e39ad996859ffa6dd011cf3cca4f1ba5"
      id = "929f9d41-2e71-5a86-b12f-489355bdf88d"
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      pe.exports("getUpdate") and pe.number_of_exports == 1
}

/* Further Investigations */

rule ROKRAT_Nov17_1 {
   meta:
      description = "Detects ROKRAT malware"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2017-11-28"
      id = "6bf3653b-1f96-5060-b6fd-82ccc83fad77"
   strings:
      $s1 = "\\T+M\\Result\\DocPrint.pdb" ascii
      $s2 = "d:\\HighSchool\\version 13\\2ndBD" ascii
      $s3 = "e:\\Happy\\Work\\Source\\version" ascii

      $x1 = "\\appdata\\local\\svchost.exe" ascii
      $x2 = "c:\\temp\\esoftscrap.jpg" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 15000KB and 1 of them )
}
