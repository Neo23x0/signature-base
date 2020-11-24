
/* modified by Florian Roth */

rule APT_SideWinder_NET_Loader_Aug_2020_1 {
   meta:
      description = "Detected the NET loader used by SideWinder group (August 2020)"
      author = "Arkbird_SOLG"
      reference = "https://twitter.com/ShadowChasing1/status/1297902086747598852"
      date = "2020-08-24"
      hash1 = "4a0947dd9148b3d5922651a6221afc510afcb0dfa69d08ee69429c4c75d4c8b4"
   strings:
      $a1 = "DUSER.dll" fullword wide
      
      $s1 = "UHJvZ3JhbQ==" fullword wide // base64 encoded string -> 'Program' -> Invoke call decoded PE
      $s2 = "U3RhcnQ=" fullword wide 
      $s3 = ".tmp           " fullword wide
      $s4 = "FileRipper" fullword ascii
      $s5 = "copytight @" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 4KB and $a1 and 3 of ($s*)
}