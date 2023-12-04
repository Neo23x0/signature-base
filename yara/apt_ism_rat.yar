/*
   Yara Rule Set
   Author: Ahmed Zaki
   Date: 2017-05-04
   Identifier: ISM RAT
   Reference: https://www.nccgroup.trust/us/about-us/newsroom-and-events/blog/2017/february/ism-rat/
*/

rule Trojan_ISMRAT_gen {
   meta:
      description = "ISM RAT"
      author = "Ahmed Zaki"
      reference = "https://www.nccgroup.trust/us/about-us/newsroom-and-events/blog/2017/february/ism-rat/"
      hash1 = "146a112cb01cd4b8e06d36304f6bdf7b"
      hash2 = "fa3dbe37108b752c38bf5870b5862ce5"
      hash3 = "bf4b07c7b4a4504c4192bd68476d63b5"
   strings:
      $s1 = "WinHTTP Example/1.0" wide
      $s2 = "Mozilla/5.0 (Windows NT 6.3; Trident/7.0; rv:11.0" wide
      $s3 = "|||Command executed successfully"
      $dir = /Microsoft\\Windows\\Tmpe[a-z0-9]{2,8}/
   condition:
      uint16(0) == 0x5A4D and all of them
}
