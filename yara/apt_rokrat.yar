/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-04-03
   Identifier: ROKRAT
*/

rule ROKRAT_Malware {
   meta:
      description = "Detects ROKRAT Malware"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "http://blog.talosintelligence.com/2017/04/introducing-rokrat.html"
      date = "2017-04-03"
      hash1 = "051463a14767c6477b6dacd639f30a8a5b9e126ff31532b58fc29c8364604d00"
      hash2 = "cd166565ce09ef410c5bba40bad0b49441af6cfb48772e7e4a9de3d646b4851c"
   strings:
      $x1 = "c:\\users\\appdata\\local\\svchost.exe" fullword ascii
      $x2 = "c:\\temp\\episode3.mp4" fullword ascii
      $x3 = "MAC-SIL-TED-FOO-YIM-LAN-WAN-SEC-BIL-TAB" ascii
      $x4 = "c:\\temp\\%d.tmp" ascii fullword

      $s1 = "%s%s%04d%02d%02d%02d%02d%02d.jar" fullword ascii
      $s2 = "\\Aboard\\Acm%c%c%c.exe" fullword ascii

      $a1 = "ython" ascii fullword
      $a2 = "iddler" ascii fullword
      $a3 = "egmon" ascii fullword
      $a6 = "iresha" ascii fullword
   condition:
      ( uint16(0) == 0x5a4d and filesize < 25000KB and ( 1 of ($x*) or all of ($a*) ) ) or ( 5 of them )
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
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "http://blog.talosintelligence.com/2017/11/ROKRAT-Reloaded.html"
      date = "2017-11-28"
      hash1 = "eb6d25e08b2b32a736b57f8df22db6d03dc82f16da554f4e8bb67120eacb1d14"
      hash2 = "a29b07a6fe5d7ce3147dd7ef1d7d18df16e347f37282c43139d53cce25ae7037"
   condition:
      uint16(0) == 0x5a4d and filesize < 2500KB and
      pe.imphash() == "c6187b1b5f4433318748457719dd6f39"
}

rule Freeenki_Infostealer_Nov17 {
   meta:
      description = "Detects Freenki infostealer malware"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "http://blog.talosintelligence.com/2017/11/ROKRAT-Reloaded.html"
      date = "2017-11-28"
      hash1 = "99c1b4887d96cb94f32b280c1039b3a7e39ad996859ffa6dd011cf3cca4f1ba5"
   strings:
      $x1 = "base64Encoded=\"TVqQAAMAAAAEAAAA" ascii
      $x2 = "command =outFile &\" sysupdate\"" fullword ascii
      $x3 = "outFile=sysDir&\"\\rundll32.exe\"" fullword ascii

      $s1 = "SOFTWARE\\Clients\\StartMenuInternet\\firefox.exe\\shell\\open\\command" fullword wide
      $s2 = "c:\\TEMP\\CrashReports\\" fullword ascii
      $s3 = "objShell.run command, 0, True" fullword ascii
      $s4 = "sysDir = shell.ExpandEnvironmentStrings(\"%windir%\")" fullword ascii
      $s5 = "'Wscript.echo \"Base64 encoded: \" + base64Encoded" fullword ascii
      $s6 = "set shell = WScript.CreateObject(\"WScript.Shell\")" fullword ascii

      $a1 = "\\Google\\Chrome\\User Data\\Default\\Login Data" fullword ascii
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
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "http://blog.talosintelligence.com/2017/11/ROKRAT-Reloaded.html"
      date = "2017-11-28"
      hash1 = "99c1b4887d96cb94f32b280c1039b3a7e39ad996859ffa6dd011cf3cca4f1ba5"
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      pe.exports("getUpdate") and pe.number_of_exports == 1
}

/* Further Investigations */

rule ROKRAT_Nov17_1 {
   meta:
      description = "Detects ROKRAT malware"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-11-28"
   strings:
      $s1 = "\\T+M\\Result\\DocPrint.pdb" ascii
      $s2 = "d:\\HighSchool\\version 13\\2ndBD" ascii
      $s3 = "e:\\Happy\\Work\\Source\\version" ascii

      $x1 = "\\appdata\\local\\svchost.exe" ascii
      $x2 = "c:\\temp\\esoftscrap.jpg" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 15000KB and 1 of them )
}
