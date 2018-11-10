
/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-11-11
   Identifier: SunOrcal
   Reference: https://researchcenter.paloaltonetworks.com/2017/11/unit42-new-malware-with-ties-to-sunorcal-discovered/
*/

import "pe"

/* Rule Set ----------------------------------------------------------------- */

rule Reaver3_Malware_Nov17_1 {
   meta:
      description = "Detects Reaver malware mentioned in PaloAltoNetworks report"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://researchcenter.paloaltonetworks.com/2017/11/unit42-new-malware-with-ties-to-sunorcal-discovered/"
      date = "2017-11-11"
      hash1 = "1813f10bcf74beb582c824c64fff63cb150d178bef93af81d875ca84214307a1"
   strings:
      $s1 = "CPL.dll" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 100KB and pe.imphash() == "e722dd50a0e2bc0cab8ca35fc4bf6d99" and all of them )
}

rule Reaver3_Malware_Nov17_2 {
   meta:
      description = "Detects Reaver malware mentioned in PaloAltoNetworks report"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://researchcenter.paloaltonetworks.com/2017/11/unit42-new-malware-with-ties-to-sunorcal-discovered/"
      date = "2017-11-11"
      hash1 = "9213f70bce491991c4cbbbd7dc3e67d3a3d535b965d7064973b35c50f265e59b"
      hash2 = "98eb5465c6330b9b49df2e7c9ad0b1164aa5b35423d9e80495a178eb510cdc1c"
   strings:
      $x1 = "WindowsUpdateReaver" fullword wide

      $s1 = "\\WUpdate.~tmp" fullword ascii
      $s2 = "\\~WUpdate.lnk" fullword ascii
      $s3 = "\\services\\" fullword ascii
      $s4 = "moomjufps" fullword ascii
      $s5 = "gekmomkege" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 100KB and (
         pe.imphash() == "837cc5062a0758335b257ea3b27972b2" or
         1 of ($x*) or
         3 of them
      )
}

rule Reaver3_Malware_Nov17_3 {
   meta:
      description = "Detects Reaver malware mentioned in PaloAltoNetworks report"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://researchcenter.paloaltonetworks.com/2017/11/unit42-new-malware-with-ties-to-sunorcal-discovered/"
      date = "2017-11-11"
      hash1 = "18ac3b14300ecfeed4b64a844c16dccb06b0e3513d0954d6c6182f2ea14e4c92"
      hash2 = "c0f8bb77284b96e07cab1c3fab8800b1bbd030720c74628c4ee5666694ef903d"
      hash3 = "c906250e0a4c457663e37119ebe1efa1e4b97eef1d975f383ac3243f9f09908c"
      hash4 = "1fcda755e8fa23d27329e4bc0443a82e1c1e9a6c1691639db256a187365e4db1"
      hash5 = "d560f44188fb56d3abb11d9508e1167329470de19b811163eb1167534722e666"
   strings:
      $s1 = "winhelp.dat" fullword ascii
      $s2 = "\\microsoft\\Credentials\\" fullword ascii
      $s3 = "~Update.lnk" fullword ascii
      $s4 = "winhelp.cpl" fullword ascii
      $s5 = "\\services\\" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 200KB and (
         pe.imphash() == "8ee521b2316ddd6af1679eac9f5ed77b" or
         4 of them
      )
}

rule SunOrcal_Malware_Nov17_1 {
   meta:
      description = "Detects Reaver malware mentioned in PaloAltoNetworks report"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://researchcenter.paloaltonetworks.com/2017/11/unit42-new-malware-with-ties-to-sunorcal-discovered/"
      date = "2017-11-11"
      hash1 = "cb7c0cf1750baaa11783e93369230ee666b9f3da7298e4d1bb9a07af6a439f2f"
      hash2 = "799139b5278dc2ac24279cc6c3db44f4ef0ea78ee7b721b0ace38fd8018c51ac"
      hash3 = "38ea33dab0ba2edd16ecd98cba161c550d1036b253c8666c4110d198948329fb"
   strings:
      $x1 = "kQZ6l5t1kAlsjmBzsCZPrSpQn5tFrChLtTdsgTlOsClKt5pBsDdFrSVshnxMr6ZOpn9slndBsy1jq6lIr216rSNApn9P" fullword ascii
      /* $x2 = "!!!system" fullword ascii - more specific: */
      $x2 = { 00 00 00 00 00 00 00 00 00 00 00 00 21 21 21 73
              79 73 74 65 6D 00 00 00 00 00 00 00 00 00 00 00 }
      $x3 = "!!!url!!!" fullword ascii
      $x4 = "h4NcbkdLrCpFpPQ=" fullword ascii
      $x5 = "GloablCryptNv1" fullword ascii
      $x6 = "Gloabl\\CryptNv1" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 200KB and 1 of them
}
