/*
   Yara Rule Set
   Author: Cylance
   Date: 2017-02-09
   Identifier: StreamEx Shell Crew (Cylance Report)
*/

/* Rule Set ----------------------------------------------------------------- */


rule StreamEx_ShellCrew {
   meta:
      description = "Detects a "
      author = "Cylance"
      reference = "https://blog.cylance.com/shell-crew-variants-continue-to-fly-under-big-avs-radar"
      date = "2017-02-09"
      score = 80
      id = "217077bb-71b7-5cbf-8adf-68a16688c415"
   strings:
      $a = "0r+8DQY97XGB5iZ4Vf3KsEt61HLoTOuIqJPp2AlncRCgSxUWyebhMdmzvFjNwka="
      $b = {34 ?? 88 04 11 48 63 C3 48 FF C1 48 3D D8 03 00 00}
      $bb = {81 86 ?? ?? 00 10 34 ?? 88 86 ?? ?? 00 10 46 81 FE D8 03 00 00}
      $c = "greendll"
      $d = "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/39.0.2171.95 Safari/537.36" wide
      $f = {26 5E 25 24 23 91 91 91 91}
      $g = "D:\\pdb\\ht_d6.pdb"
   condition:
      $a or $b or $bb or ($c and $d) or $f or $g
}

/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-02-10
   Identifier: ShellCrew StreamEx
*/

/* Rule Set ----------------------------------------------------------------- */

rule ShellCrew_StreamEx_1 {
   meta:
      description = "Auto-generated rule"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://blog.cylance.com/shell-crew-variants-continue-to-fly-under-big-avs-radar"
      date = "2017-02-10"
      modified = "2022-12-21"
      hash1 = "81f411415aefa5ad7f7ed2365d9a18d0faf33738617afc19215b69c23f212c07"
      id = "26b4cac0-3f2b-5637-86f5-16b7f8afa0e6"
   strings:
      $x1 = "cmd.exe /c  \"%s\"" fullword wide
      $s3 = "uac\\bin\\install_test.pdb" ascii
      $s5 = "uncompress error:%d %s" fullword ascii
      $s7 = "%s\\AdobeBak\\Proc.dat" fullword wide
      $s8 = "e:\\workspace\\boar" fullword ascii
      $s12 = "$\\data.ini" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 1000KB and 4 of them )
}

rule ShellCrew_StreamEx_1_msi {
   meta:
      description = "Auto-generated rule"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://blog.cylance.com/shell-crew-variants-continue-to-fly-under-big-avs-radar"
      date = "2017-02-10"
      hash1 = "8c9048e2f5ea2ef9516cac06dc0fba8a7e97754468c0d9dc1e5f7bce6dbda2cc"
      id = "8cf5dad5-0737-56bf-8cef-7bcf7e7e5a78"
   strings:
      $x1 = "msi.dll.eng" fullword wide

      $s2 = "ahinovx" fullword ascii
      $s3 = "jkpsxy47CDEMNSTYbhinqrwx56" fullword ascii
      $s4 = "PVYdejmrsy12" fullword ascii
      $s6 = "FLMTUZaijkpsxy45CD" fullword ascii
      $s7 = "afhopqvw34ABIJOPTYZehmo" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 20KB and 3 of them )
}

rule ShellCrew_StreamEx_1_msi_dll {
   meta:
      description = "Auto-generated rule"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://blog.cylance.com/shell-crew-variants-continue-to-fly-under-big-avs-radar"
      date = "2017-02-10"
      hash1 = "883108119d2f4db066fa82e37aa49ecd2dbdacda67eb936b96720663ed6565ce"
      hash2 = "5311f862d7c824d13eea8293422211e94fb406d95af0ae51358accd4835aaef8"
      hash3 = "191cbeffa36657ab1ef3939da023cacbc9de0285bbe7775069c3d6e18b372c3f"
      id = "56586e0b-010a-5ad5-8822-5d370475aa06"
   strings:
      $s1 = "NDOGDUA" fullword ascii
      $s2 = "NsrdsrN" fullword ascii
   condition:
      ( uint16(0) == 0x4d9d and filesize < 300KB and all of them )
}
