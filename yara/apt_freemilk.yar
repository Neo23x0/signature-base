/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-10-05
   Identifier: FreeMilk
   Reference: https://researchcenter.paloaltonetworks.com/2017/10/unit42-freemilk-highly-targeted-spear-phishing-campaign/
*/

import "pe"

/* Rule Set ----------------------------------------------------------------- */

rule FreeMilk_APT_Mal_1 {
   meta:
      description = "Detects malware from FreeMilk campaign"
      author = "Florian Roth"
      reference = "https://researchcenter.paloaltonetworks.com/2017/10/unit42-freemilk-highly-targeted-spear-phishing-campaign/"
      date = "2017-10-05"
      hash1 = "34478d6692f8c28332751b31fd695b799d4ab36a8c12f7b728e2cb99ae2efcd9"
      hash2 = "35273d6c25665a19ac14d469e1436223202be655ee19b5b247cb1afef626c9f2"
      hash3 = "0f82ea2f92c7e906ee9ffbbd8212be6a8545b9bb0200eda09cce0ba9d7cb1313"
   strings:
      $x1 = "\\milk\\Release\\milk.pdb" ascii
      $x2 = "E:\\BIG_POOH\\Project\\" ascii
      $x3 = "Windows-KB271854-x86.exe" fullword wide

      $s1 = "Windows-KB275122-x86.exe" fullword wide
      $s2 = "\\wsatra.tmp" fullword wide
      $s3 = "%s\\Rar0tmpExtra%d.rtf" fullword wide
      $s4 = "\"%s\" help" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and (
            pe.imphash() == "108aa007b3d1b4817ff4c04d9b254b39" or
            1 of ($x*) or
            4 of them
         )
}

rule FreeMilk_APT_Mal_2 {
   meta:
      description = "Detects malware from FreeMilk campaign"
      author = "Florian Roth"
      reference = "https://researchcenter.paloaltonetworks.com/2017/10/unit42-freemilk-highly-targeted-spear-phishing-campaign/"
      date = "2017-10-05"
      hash1 = "7f35521cdbaa4e86143656ff9c52cef8d1e5e5f8245860c205364138f82c54df"
   strings:
      $s1 = "failed to take the screenshot. err: %d" fullword ascii
      $s2 = "runsample" fullword wide
      $s3 = "%s%02X%02X%02X%02X%02X%02X:" fullword wide
      $s4 = "win-%d.%d.%d-%d" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 400KB and (
         pe.imphash() == "b86f7d2c1c182ec4c074ae1e16b7a3f5" or
         all of them
      )
}

rule FreeMilk_APT_Mal_3 {
   meta:
      description = "Detects malware from FreeMilk campaign"
      author = "Florian Roth"
      reference = "https://researchcenter.paloaltonetworks.com/2017/10/unit42-freemilk-highly-targeted-spear-phishing-campaign/"
      date = "2017-10-05"
      hash1 = "ef40f7ddff404d1193e025081780e32f88883fa4dd496f4189084d772a435cb2"
   strings:
      $s1 = "CMD.EXE /C \"%s\"" fullword wide
      $s2 = "\\command\\start.exe" fullword wide
      $s3 = ".bat;.com;.cmd;.exe" fullword wide
      $s4 = "Unexpected failure opening HKCR key: %d" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 900KB and all of them )
}

rule FreeMilk_APT_Mal_4 {
   meta:
      description = "Detects malware from FreeMilk campaign"
      author = "Florian Roth"
      reference = "https://researchcenter.paloaltonetworks.com/2017/10/unit42-freemilk-highly-targeted-spear-phishing-campaign/"
      date = "2017-10-05"
      hash1 = "99c1b4887d96cb94f32b280c1039b3a7e39ad996859ffa6dd011cf3cca4f1ba5"
   strings:
      $x1 = "base64Encoded=\"TVqQAAMAAAAE" ascii

      $s1 = "SOFTWARE\\Clients\\StartMenuInternet\\firefox.exe\\shell\\open\\command" fullword wide
      $s2 = "'Wscript.echo \"Base64 encoded: \" + base64Encoded" fullword ascii
      $s3 = "\\Google\\Chrome\\User Data\\Default\\Login Data" fullword ascii
      $s4 = "outFile=sysDir&\"\\rundll32.exe\"" fullword ascii
      $s5 = "set shell = WScript.CreateObject(\"WScript.Shell\")" fullword ascii
      $s6 = "command =outFile &\" sysupdate\"" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and (
         ( pe.exports("getUpdate") and pe.number_of_exports == 1 ) or
         1 of ($x*) or
         3 of them
      )
}
