
/* modified by Florian Roth */

rule APT_SideWinder_NET_Loader_Aug_2020_1 {
   meta:
      description = "Detected the NET loader used by SideWinder group (August 2020)"
      author = "Arkbird_SOLG"
      reference = "https://twitter.com/ShadowChasing1/status/1297902086747598852"
      date = "2020-08-24"
      hash1 = "4a0947dd9148b3d5922651a6221afc510afcb0dfa69d08ee69429c4c75d4c8b4"
      id = "61d96e2a-3a43-586f-85bc-a2c53b1318e6"
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

rule APT_MAL_SideWinder_implant {
   meta:
      author = "AT&T Alien Labs"
      description = "Detects SideWinder final payload"
      hash1 = "c568238dcf1e30d55a398579a4704ddb8196b685"
      reference = "https://cybersecurity.att.com/blogs/labs-research/a-global-perspective-of-the-sidewinder-apt"
      id = "3a420c9c-7821-5405-8d4d-6931d0f311ba"
   strings:
      $code= { 1B 30 05 00 C7 00 00 00 00 00 00 00 02 28 03 00
               00 06 7D 12 00 00 04 02 02 FE 06 23 00 00 06 73
               5B 00 00 0A 14 20 88 13 00 00 15 73 5C 00 00 0A
               7D 13 00 00 04 02 02 FE 06 24 00 00 06 73 5B 00
               00 0A 14 20 88 13 00 00 15 73 5C 00 00 0A 7D 15
               00 00 04 02 7B 12 00 00 04 6F 0E 00 00 06 2C 1D
               02 28 1F 00 00 06 02 7B 12 00 00 04 16 6F 0F 00
               00 06 02 7B 12 00 00 04 6F 06 00 00 06 02 7B 12
               00 00 04 6F 10 00 00 06 2C 23 02 28 20 00 00 06
               02 28 21 00 00 06 02 7B 12 00 00 04 16 }

      $strings = { 
         2E 00 73 00 69 00 66 00 00 09 2E 00 66 00 6C 00
         63 00 00 1B 73 00 65 00 6C 00 65 00 63 00 74 00
         65 00 64 00 46 00 69 00 6C 00 65 00 73
      }
   condition:
      uint16(0) == 0x5A4D and all of them
}
