/* requires YARA 3.8 or higher */
import "pe"

rule SUSP_XORed_URL_In_EXE {
   meta:
      description = "Detects an XORed URL in an executable"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://twitter.com/stvemillertime/status/1237035794973560834"
      date = "2020-03-09"
      modified = "2022-09-16"
      score = 50
      id = "f83991c8-f2d9-5583-845a-d105034783ab"
   strings:
      $s1 = "http://" xor
      $s2 = "https://" xor
      $f1 = "http://" ascii
      $f2 = "https://" ascii

      $fp01 = "3Com Corporation" ascii  /* old driver */
      $fp02 = "bootloader.jar" ascii  /* DeepGit */
      $fp03 = "AVAST Software" ascii wide
      $fp04 = "smartsvn" wide ascii fullword
      $fp05 = "Avira Operations GmbH" wide fullword
      $fp06 = "Perl Dev Kit" wide fullword
      $fp07 = "Digiread" wide fullword
      $fp08 = "Avid Editor" wide fullword
      $fp09 = "Digisign" wide fullword
      $fp10 = "Microsoft Corporation" wide fullword
      $fp11 = "Microsoft Code Signing" ascii wide
      $fp12 = "XtraProxy" wide fullword
      $fp13 = "A Sophos Company" wide
      $fp14 = "http://crl3.digicert.com/" ascii
      $fp15 = "http://crl.sectigo.com/SectigoRSACodeSigningCA.crl" ascii
      $fp16 = "HitmanPro.Alert" wide fullword
   condition:
      uint16(0) == 0x5a4d and
      filesize < 2000KB and (
         ( $s1 and #s1 > #f1 ) or
         ( $s2 and #s2 > #f2 )
      )
      and not 1 of ($fp*)
      and not pe.number_of_signatures > 0
}

