/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2018-05-24
   Identifier: VPNFilter
   Reference: https://blog.talosintelligence.com/2018/05/VPNFilter.html
*/

/* Rule Set ----------------------------------------------------------------- */

rule MAL_ELF_VPNFilter_1 {
   meta:
      description = "dropzone - file f8286e29faa67ec765ae0244862f6b7914fcdde10423f96595cb84ad5cc6b344"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2018-05-24"
      hash1 = "f8286e29faa67ec765ae0244862f6b7914fcdde10423f96595cb84ad5cc6b344"
   strings:
      $s1 = "Login=" fullword ascii
      $s2 = "Password=" fullword ascii
      $s3 = "%s/rep_%u.bin" fullword ascii
      $s4 = "%s:%uh->%s:%hu" fullword ascii
      $s5 = "Password required" fullword ascii /* Goodware String - occured 1 times */
      $s6 = "password=" fullword ascii /* Goodware String - occured 2 times */
      $s7 = "Authorization: Basic" fullword ascii /* Goodware String - occured 2 times */
      $s8 = "/tmUnblock.cgi" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 100KB and all of them
}

rule MAL_ELF_VPNFilter_2 {
   meta:
      description = "dropzone - file 50ac4fcd3fbc8abcaa766449841b3a0a684b3e217fc40935f1ac22c34c58a9ec"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2018-05-24"
      hash1 = "50ac4fcd3fbc8abcaa766449841b3a0a684b3e217fc40935f1ac22c34c58a9ec"
   strings:
      $s1 = "User-Agent: Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 5.2; Trident/4.0)" fullword ascii
      $s2 = "passwordPASSWORDpassword" fullword ascii
      $s3 = "/tmp/client.key" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 1000KB and all of them
}

rule MAL_ELF_VPNFilter_3 {
   meta:
      description = "dropzone - file 0e0094d9bd396a6594da8e21911a3982cd737b445f591581560d766755097d92"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2018-05-24"
      hash1 = "0e0094d9bd396a6594da8e21911a3982cd737b445f591581560d766755097d92"
      hash2 = "9683b04123d7e9fe4c8c26c69b09c2233f7e1440f828837422ce330040782d17"
      hash3 = "37e29b0ea7a9b97597385a12f525e13c3a7d02ba4161a6946f2a7d978cc045b4"
      hash4 = "0649fda8888d701eb2f91e6e0a05a2e2be714f564497c44a3813082ef8ff250b"
      hash5 = "4b03288e9e44d214426a02327223b5e516b1ea29ce72fa25a2fcef9aa65c4b0b"
      hash6 = "8a20dc9538d639623878a3d3d18d88da8b635ea52e5e2d0c2cce4a8c5a703db1"
      hash7 = "776cb9a7a9f5afbaffdd4dbd052c6420030b2c7c3058c1455e0a79df0e6f7a1d"
   strings:
      $sx1 = "User-Agent: Mozilla/6.1 (compatible; MSIE 9.0; Windows NT 5.3; Trident/5.0)" fullword ascii
      $sx2 = "Execute by shell[%d]:" fullword ascii
      $sx3 = "CONFIG.TOR.name:" fullword ascii

      $s1 = "Executing command:  %s %s..." fullword ascii
      $s2 = "/proc/%d/cmdline" fullword ascii

      $a1 = "Mozilla/5.0 Firefox/50.0" fullword ascii
      $a2 = "Mozilla/5.0 (X11; Ubuntu; Linux i686; rv:52.0) Gecko/20100101 Firefox/52.0" fullword ascii
      $a3 = "Mozilla/5.0 (Windows NT 6.1; rv:52.0) Gecko/20100101 Firefox/52.0" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 1000KB and ( 1 of ($sx*) or 2 of ($s*) or 2 of ($a*) )
}

rule SUSP_ELF_Tor_Client {
   meta:
      description = "dropzone - file afd281639e26a717aead65b1886f98d6d6c258736016023b4e59de30b7348719"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2018-05-24"
      hash1 = "afd281639e26a717aead65b1886f98d6d6c258736016023b4e59de30b7348719"
   strings:
      $x1 = "We needed to load a secret key from %s, but it was encrypted. Try 'tor --keygen' instead, so you can enter the passphrase." fullword ascii
      $x2 = "Received a VERSION cell with odd payload length %d; closing connection." fullword ascii
      $x3 = "Please upgrade! This version of Tor (%s) is %s, according to the directory authorities. Recommended versions are: %s" fullword ascii
   condition:
      uint16(0) == 0x457f and 1 of them
}
