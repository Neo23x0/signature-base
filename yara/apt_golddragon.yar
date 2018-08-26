/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2018-02-03
   Identifier: Gold Dragon
   Reference: https://goo.gl/rW1yvZ
*/

import "pe"

/* Rule Set ----------------------------------------------------------------- */

rule GoldDragon_malware_Feb18_1 {
   meta:
      description = "Detects malware from Gold Dragon report"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://securingtomorrow.mcafee.com/mcafee-labs/gold-dragon-widens-olympics-malware-attacks-gains-permanent-presence-on-victims-systems/"
      date = "2018-02-03"
      score = 90
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and (
         pe.imphash() == "168c2f7752511dfd263a83d5d08a90db" or
         pe.imphash() == "0606858bdeb129de33a2b095d7806e74" or
         pe.imphash() == "51d992f5b9e01533eb1356323ed1cb0f" or
         pe.imphash() == "bb801224abd8562f9ee8fb261b75e32a"
      )
}

rule GoldDragon_Aux_File {
   meta:
      description = "Detects export from Gold Dragon - February 2018"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://securingtomorrow.mcafee.com/mcafee-labs/gold-dragon-widens-olympics-malware-attacks-gains-permanent-presence-on-victims-systems/"
      date = "2018-02-03"
      score = 90
   strings:
      $x1 = "/////////////////////regkeyenum////////////" ascii
   condition:
      filesize < 500KB and 1 of them
}

rule GoldDragon_Ghost419_RAT {
   meta:
      description = "Detects Ghost419 RAT from Gold Dragon report"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://goo.gl/rW1yvZ"
      date = "2018-02-03"
      hash1 = "45bfa1327c2c0118c152c7192ada429c6d4ae03b8164ebe36ab5ba9a84f5d7aa"
      hash2 = "ee7a9a7589cbbcac8b6bf1a3d9c5d1c1ada98e68ac2f43ff93f768661b7e4a85"
      hash3 = "dee482e5f461a8e531a6a7ea4728535aafdc4941a8939bc3c55f6cb28c46ad3d"
      hash4 = "2df9e274ce0e71964aca4183cec01fb63566a907981a9e7384c0d73f86578fe4"
      hash5 = "111ab6aa14ef1f8359c59b43778b76c7be5ca72dc1372a3603cd5814bfb2850d"
      hash6 = "0ca12b78644f7e4141083dbb850acbacbebfd3cfa17a4849db844e3f7ef1bee5"
      hash7 = "ae1b32aac4d8a35e2c62e334b794373c7457ebfaaab5e5e8e46f3928af07cde4"
      hash8 = "c54837d0b856205bd4ae01887aae9178f55f16e0e1a1e1ff59bd18dbc8a3dd82"
      hash9 = "db350bb43179f2a43a1330d82f3afeb900db5ff5094c2364d0767a3e6b97c854"
   strings:
      $x1 = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/4.0; .NET CLR 1.1.4322)" fullword ascii
      $x2 = "WebKitFormBoundarywhpFxMBe19cSjFnG" ascii
      $x3 = "\\Microsoft\\HNC\\" fullword ascii
      $x4 = "\\anternet abplorer" fullword ascii
      $x5 = "%s\\abxplore.exe" fullword ascii
      $x6 = "GHOST419" fullword ascii
      $x7 = "I,m Online. %04d - %02d - %02d - %02d - %02d" fullword ascii
      $x8 = "//////////////////////////regkeyenum//////////////" fullword ascii

      $s1 = "www.GoldDragon.com" fullword ascii
      $s2 = "/c systeminfo >> %s" fullword ascii
      $s3 = "/c dir %s\\ >> %s" fullword ascii
      $s4 = "DownLoading %02x, %02x, %02x" fullword ascii
      $s5 = "Tran_dll.dll" fullword ascii
      $s6 = "MpCmdRunkr.dll" fullword ascii
      $s7 = "MpCmdRun.dll" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 200KB and (
         pe.exports("ExportFunction") or
         1 of ($x*) or
         2 of them
      )
}

rule GoldDragon_RunningRAT {
   meta:
      description = "Detects Running RAT from Gold Dragon report"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://goo.gl/rW1yvZ"
      date = "2018-02-03"
      hash1 = "0852f2c5741997d8899a34bb95c349d7a9fb7277cd0910656c3ce37a6f11cb88"
      hash2 = "2981e1a1b3c395cee6e4b9e6c46d062cf6130546b04401d724750e4c8382c863"
      hash3 = "7aa99ebc49a130f07304ed25655862a04cc20cb59d129e1416a7dfa04f7d3e51"
   strings:
      $x1 = "C:\\USERS\\WIN7_x64\\result.log" fullword wide
      $x2 = "rundll32.exe %s RunningRat" fullword ascii
      $x3 = "SystemRat.dll" fullword ascii
      $x4 = "rundll32.exe %s ExportFunction" fullword ascii
      $x5 = "rundll32.exe \"%s\" RunningRat" fullword ascii
      $x6 = "ixeorat.bin" fullword ascii
      $x7 = "C:\\USERS\\Public\\result.log" fullword ascii

      $a1 = "emanybtsohteg" fullword ascii /* reversed goodware string 'gethostbyname' */
      $a2 = "tekcosesolc" fullword ascii /* reversed goodware string 'closesocket' */
      $a3 = "emankcosteg" fullword ascii /* reversed goodware string 'getsockname' */
      $a4 = "emantsohteg" fullword ascii /* reversed goodware string 'gethostname' */
      $a5 = "tpokcostes" fullword ascii /* reversed goodware string 'setsockopt' */
      $a6 = "putratSASW" fullword ascii /* reversed goodware string 'WSAStartup' */

      $s1 = "ParentDll.dll" fullword ascii
      $s2 = "MR - Already Existed" fullword ascii
      $s3 = "MR First Started, Registed OK!" fullword ascii
      $s4 = "RM-M : LoadResource OK!" fullword ascii
      $s5 = "D:\\result.log" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and (
        pe.imphash() == "c78ccc8f02286648c4373d3bf03efc43" or
        pe.exports("RunningRat") or
        1 of ($x*) or
        5 of ($a*) or
        3 of ($s*)
      )
}

rule GoldDragon_RunnignRAT {
   meta:
      description = "Detects Running RAT malware from Gold Dragon report"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://goo.gl/rW1yvZ"
      date = "2018-02-03"
      hash1 = "94aa827a514d7aa70c404ec326edaaad4b2b738ffaea5a66c0c9f246738df579"
      hash2 = "5cbc07895d099ce39a3142025c557b7fac41d79914535ab7ffc2094809f12a4b"
      hash3 = "98ccf3a463b81a47fdf4275e228a8f2266e613e08baae8bdcd098e49851ed49a"
   strings:
      $s1 = "cmd.exe /c systeminfo " fullword ascii
      $s2 = "ieproxy.dll" fullword ascii
      $s3 = "taskkill /f /im daumcleaner.exe" fullword ascii
      $s4 = "cmd.exe /c tasklist " fullword ascii
      $s5 = "rundll32.exe \"%s\" Run" fullword ascii
      $s6 = "Mozilla/5.0 (Windows NT 5.2; rv:12.0) Gecko/20100101 Firefox/12.0" fullword ascii
      $s7 = "%s\\%s_%03d" fullword wide
      $s8 = "\\PI_001.dat" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and (
         3 of them
      )
}
