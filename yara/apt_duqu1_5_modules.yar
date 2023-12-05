
rule Duqu1_5_modules {
   meta:
      author = "Silas Cutler (havex@chronicle.security)"
      desc = "Detection for Duqu 1.5 modules"
      hash = "bb3961e2b473c22c3d5939adeb86819eb846ccd07f5736abb5e897918580aace"
      reference = "https://medium.com/chronicle-blog/who-is-gossipgirl-3b4170f846c0"
      id = "7239f5e1-c08f-566c-8998-f7dacc2c4a29"
   strings:
      $c1 = "%s(%d)disk(%d)fdisk(%d)"
      $c2 = "\\Device\\Floppy%d" wide
      $c3 = "BrokenAudio" wide
      $m1 = { 81 3F E9 18 4B 7E}
      $m2 = { 81 BC 18 F8 04 00 00 B3 20 EA B4 }
   condition:
      all of them
}
