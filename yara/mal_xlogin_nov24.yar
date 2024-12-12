
rule MAL_ELF_Xlogin_Nov24_1 {
   meta:
      description = "Detects xlogin backdoor samples"
      author = "Florian Roth"
      reference = "https://blog.sekoia.io/solving-the-7777-botnet-enigma-a-cybersecurity-quest/"
      date = "2024-11-11"
      score = 80
      hash1 = "2b09a6811a9d0447f8c6480430eb0f7e3ff64fa933d0b2e8cd6117f38382cc6a"
      hash2 = "d1cbf80786b1ca1ba2e5c31ec09159be276ad3d10fc0a8a0dbff229d8263ca0a"
      hash3 = "ff17e9bcc1ed16985713405b95745e47674ec98e3c6c889df797600718a35b2c"
      id = "e8940660-ecf8-5616-9cb1-fc0a02d35689"
   strings:
      $xc1 = { 6C 6F 67 69 6E 3A 00 25 73 00 00 2F 62 69 6E 2F 73 68 00 2F 74 6D 70 2F 6C 6F 67 69 6E }
      
      $s1 = "/tmp/login" ascii fullword
      $s2 = "npxXoudifFeEgGaACSnmcs[" ascii fullword

      $sc1 = { 28 6E 69 6C 29 00 00 00 28 6E 75 6C 6C 29 }
   condition:
      uint16(0) == 0x457f
      and filesize < 500KB
      and ( 1 of ($x*) or 2 of them )
}
