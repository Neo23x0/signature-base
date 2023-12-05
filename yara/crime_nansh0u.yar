/*
   YARA Rule Set
   Author: Florian Roth
   Date: 2019-05-31
   Identifier: Nansh0u
   Reference: https://www.guardicore.com/2019/05/nansh0u-campaign-hackers-arsenal-grows-stronger/
   License = CC BY-NC 4.0 https://creativecommons.org/licenses/by-nc/4.0/
*/

/* Rule Set ----------------------------------------------------------------- */


import "pe"

rule MAL_XMR_Miner_May19_1 : HIGHVOL {
   meta:
      description = "Detects Monero Crypto Coin Miner"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.guardicore.com/2019/05/nansh0u-campaign-hackers-arsenal-grows-stronger/"
      date = "2019-05-31"
      score = 85
      hash1 = "d6df423efb576f167bc28b3c08d10c397007ba323a0de92d1e504a3f490752fc"
      id = "233d1d47-de67-55a9-ae7e-46b5dd34e6ce"
   strings:
      $x1 = "donate.ssl.xmrig.com" fullword ascii
      $x2 = "* COMMANDS     'h' hashrate, 'p' pause, 'r' resume" fullword ascii

      $s1 = "[%s] login error code: %d" fullword ascii
      $s2 = "\\\\?\\pipe\\uv\\%p-%lu" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 14000KB and (
         pe.imphash() == "25d9618d1e16608cd5d14d8ad6e1f98e" or
         1 of ($x*) or
         2 of them
      )
}

rule HKTL_CN_ProcHook_May19_1 {
   meta:
      description = "Detects hacktool used by Chinese threat groups"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.guardicore.com/2019/05/nansh0u-campaign-hackers-arsenal-grows-stronger/"
      date = "2019-05-31"
      hash1 = "02ebdc1ff6075c15a44711ccd88be9d6d1b47607fea17bef7e5e17f8da35293e"
      id = "ae4e2613-8254-5ea6-af88-2f08ebe4da33"
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and
      pe.imphash() == "343d580dd50ee724746a5c28f752b709"
}


rule SUSP_PDB_CN_Threat_Actor_May19_1 {
   meta:
      description = "Detects PDB path user name used by Chinese threat actors"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.guardicore.com/2019/05/nansh0u-campaign-hackers-arsenal-grows-stronger/"
      date = "2019-05-31"
      score = 65
      hash1 = "01c3882e8141a25abe37bb826ab115c52fd3d109c4a1b898c0c78cee8dac94b4"
      id = "fc6969ed-5fc1-5b3b-9659-c6fc1c9e2f9c"
   strings:
      $x1 = "C:\\Users\\zcg\\Desktop\\" ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 400KB and 1 of them
}

rule MAL_Ramnit_May19_1 {
   meta:
      description = "Detects Ramnit malware"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.guardicore.com/2019/05/nansh0u-campaign-hackers-arsenal-grows-stronger/"
      date = "2019-05-31"
      hash1 = "d7ec3fcd80b3961e5bab97015c91c843803bb915c13a4a35dfb5e9bdf556c6d3"
      id = "f8fa3557-556e-5680-9f1a-2ecf118ade75"
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB
      and pe.imphash() == "500cd02578808f964519eb2c85153046"
}

rule MAL_Parite_Malware_May19_1 {
   meta:
      description = "Detects Parite malware"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.guardicore.com/2019/05/nansh0u-campaign-hackers-arsenal-grows-stronger/"
      date = "2019-05-31"
      score = 80
      hash1 = "c9d8852745e81f3bfc09c0a3570d018ae8298af675e3c6ee81ba5b594ff6abb8"
      hash2 = "8d47b08504dcf694928e12a6aa372e7fa65d0d6744429e808ff8e225aefa5af2"
      hash3 = "285e3f21dd1721af2352196628bada81050e4829fb1bb3f8757a45c221737319"
      hash4 = "b987dcc752d9ceb3b0e6cd4370c28567be44b789e8ed8a90c41aa439437321c5"
      id = "f4c9da17-9894-5243-828a-827accb0bac5"
   strings:
      $s1 = "taskkill /im cmd.exe /f" fullword ascii
      $s2 = "LOADERX64.dll" fullword ascii

      $x1 = "\\dllhot.exe" ascii
      $x2 = "dllhot.exe --auto --any --forever --keepalive" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 10000KB and ( 1 of ($x*) or 2 of them )
}

rule MAL_Parite_Malware_May19_2 {
   meta:
      description = "Detects Parite malware based on Imphash"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.guardicore.com/2019/05/nansh0u-campaign-hackers-arsenal-grows-stronger/"
      date = "2019-05-31"
      hash1 = "c9d8852745e81f3bfc09c0a3570d018ae8298af675e3c6ee81ba5b594ff6abb8"
      hash2 = "8d47b08504dcf694928e12a6aa372e7fa65d0d6744429e808ff8e225aefa5af2"
      hash3 = "285e3f21dd1721af2352196628bada81050e4829fb1bb3f8757a45c221737319"
      hash4 = "b987dcc752d9ceb3b0e6cd4370c28567be44b789e8ed8a90c41aa439437321c5"
      id = "33970268-610c-5abf-9e9e-83dae0c81064"
   condition:
      uint16(0) == 0x5a4d and filesize < 18000KB and (
         pe.imphash() == "b132a2719be01a6ef87d9939d785e19e" or
         pe.imphash() == "78f4f885323ffee9f8fa011455d0523d"
      )
}

rule EXPL_Strings_CVE_POC_May19_1 {
   meta:
      description = "Detects strings used in CVE POC noticed in May 2019"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.guardicore.com/2019/05/nansh0u-campaign-hackers-arsenal-grows-stronger/"
      date = "2019-05-31"
      score = 80
      hash1 = "01c3882e8141a25abe37bb826ab115c52fd3d109c4a1b898c0c78cee8dac94b4"
      id = "df11e0b1-e907-5a24-a3e7-0e78acb379f7"
   strings:
      $x1 = "\\Debug\\poc_cve_20" ascii
      $x2 = "\\Release\\poc_cve_20" ascii
      $x3 = "alloc fake fail: %x!" fullword ascii
      $x4 = "Allocate fake tagWnd fail!" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 400KB and 1 of them
}
