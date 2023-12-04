/*
   Yara Rule Set
   Author: ESET
   Date: 2017-08-30
   Identifier: Turla Gazer
   Reference: https://www.welivesecurity.com/2017/08/30/eset-research-cyberespionage-gazer/
*/


import "pe"

rule Gazer_certificate_subject {
   meta:
      description = "Detects Tura's Gazer malware"
      author = "ESET"
      reference = "https://www.welivesecurity.com/2017/08/30/eset-research-cyberespionage-gazer/"
      date = "30.08.2017"
   condition:
      for any i in (0..pe.number_of_signatures - 1):
         (
            pe.signatures[i].subject contains "Solid Loop" or
            pe.signatures[i].subject contains "Ultimate Computer Support"
         )
}

rule Gazer_certificate {
   meta:
      description = "Detects Tura's Gazer malware"
      author = "ESET"
      reference = "https://www.welivesecurity.com/2017/08/30/eset-research-cyberespionage-gazer/"
      date = "30.08.2017"
   strings:
      $certif1 = { 52 76 a4 53 cd 70 9c 18 da 65 15 7e 5f 1f de 02 }
      $certif2 = { 12 90 f2 41 d9 b2 80 af 77 fc da 12 c6 b4 96 9c }
   condition:
      uint16(0) == 0x5a4d and 1 of them and filesize < 2MB
}

rule Gazer_logfile_name {
   meta:
      description = "Detects Tura's Gazer malware"
      author = "ESET"
      reference = "https://www.welivesecurity.com/2017/08/30/eset-research-cyberespionage-gazer/"
      date = "30.08.2017"
   strings:
      $s1 = "CVRG72B5.tmp.cvr"
      $s2 = "CVRG1A6B.tmp.cvr"
      $s3 = "CVRG38D9.tmp.cvr"
   condition:
      uint16(0) == 0x5a4d and 1 of them
}
