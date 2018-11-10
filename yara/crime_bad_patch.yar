/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-10-20
   Identifier: BadPatch
   Reference: https://goo.gl/RvDwwA
*/

/* Rule Set ----------------------------------------------------------------- */

rule WinAgent_BadPatch_1 {
   meta:
      description = "Detects samples mentioned in BadPatch report"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://goo.gl/RvDwwA"
      date = "2017-10-20"
      hash1 = "285998bce9692e46652529685775aa05e3a5cb93ee4e65d021d2231256e92813"
   strings:
      $x1 = "J:\\newPatch\\downloader\\" wide
      $x2 = "L:\\rashed\\New code\\" wide
      $x3 = ":\\newPatch\\last version\\" wide
      $x4 = "\\Microsoft\\Microsoft\\Microsoft1.log" fullword wide
      $x5 = "\\Microsoft\\Microsoft\\Microsoft.log" fullword wide
      $x6 = "\\Microsoft\\newPP.exe" fullword wide
      $x7 = " (this is probably a proxy server error)." fullword wide
      $x8 = " :Old - update patch and check anti-virus.. " fullword wide
      $x9 = "PatchNotExit-- download now.. " fullword wide
      $x10 = "PatchNotExit-- Check Version" fullword wide
      $x11 = "PatchNotExit-- Version Patch" fullword wide

      $s1 = "downloader " fullword wide
      $s2 = "DelDownloadFile" fullword ascii
      $s3 = "downloadFile" fullword ascii
      $s4 = "downloadUpdate" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 600KB and ( 1 of ($x*) or 4 of them ) )
}

rule WinAgent_BadPatch_2 {
   meta:
      description = "Detects samples mentioned in BadPatch report"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://goo.gl/RvDwwA"
      date = "2017-10-20"
      hash1 = "106deff16a93c4a4624fe96e3274e1432921c56d5a430834775e5b98861c00ea"
      hash2 = "ece76fdf7e33d05a757ef5ed020140d9367c7319022a889923bbfacccb58f4d7"
      hash3 = "cf53fc8c9ce4e5797cc5ac6f71d4cbc0f2b15f2ed43f38048a5273f40bc09876"
      hash4 = "802a39b22dfacdc2325f8a839377c903b4a7957503106ce6f7aed67e824b82c2"
      hash5 = "278dba3857367824fc2d693b7d96cef4f06cb7fdc52260b1c804b9c90d43646d"
      hash6 = "2941f75da0574c21e4772f015ef38bb623dd4d0c81c263523d431b0114dd847e"
      hash7 = "46f3afae22e83344e4311482a9987ed851b2de282e8127f64d5901ac945713c0"
      hash8 = "27752bbb01abc6abf50e1da3a59fefcce59618016619d68690e71ad9d4a3c247"
      hash9 = "050610cfb3d3100841685826273546c829335a5f4e2e4260461b88367ad9502c"
   strings:
      $s1 = "myAction=shell_result&serialNumber=" fullword wide
      $s2 = "\\Appdata\\Local\\Google\\Chrome\\User Data\\Default\\Login Data.*" fullword wide
      $s3 = "\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles" fullword wide
      $s4 = "\\Appdata\\Local\\Google\\Chrome\\User Data\\Default\\Cookies.*" fullword wide
      $s5 = "newSHELL[" fullword wide
      $s6 = "\\file1.txt" fullword wide
      $s7 = "myAction=newGIF&serialNumber=" fullword wide
      $s8 = "\\Storege1" fullword wide
      $s9 = "\\Microsoft\\mac.txt" fullword wide
      $s10 = "spytube____:" fullword ascii
      $s11 = "0D0700045F5C5B0312045A04041F40014B1D11004A1F19074A141100011200154B031C04" fullword wide
      $s12 = "16161A1000012B162503151851065A1A0007" fullword wide
      $s13 = "-- SysFile...." fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 700KB and 3 of them )
}
