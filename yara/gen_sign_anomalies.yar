
import "pe"

rule SUSP_Unsigned_OSPPSVC {
   meta:
      description = "Detects a suspicious unsigned office software protection platform service binary"
      author = "Florian Roth"
      reference = "https://www.welivesecurity.com/2019/09/24/no-summer-vacations-zebrocy/"
      date = "2019-09-26"
      hash1 = "5294a730f1f0a176583b9ca2b988b3f5ec65dad8c6ebe556b5135566f2c16a56"
   strings:
      /* FileDescription Microsoft Office Software Protection Platform Service */
      $sc1 = { 00 46 00 69 00 6C 00 65 00 44 00 65 00 73 00 63
               00 72 00 69 00 70 00 74 00 69 00 6F 00 6E 00 00
               00 00 00 4D 00 69 00 63 00 72 00 6F 00 73 00 6F
               00 66 00 74 00 20 00 4F 00 66 00 66 00 69 00 63
               00 65 00 20 00 53 00 6F 00 66 00 74 00 77 00 61
               00 72 00 65 00 20 00 50 00 72 00 6F 00 74 00 65
               00 63 00 74 00 69 00 6F 00 6E 00 20 00 50 00 6C
               00 61 00 74 00 66 00 6F 00 72 00 6D 00 20 00 53
               00 65 00 72 00 76 00 69 00 63 00 65 }
   condition:
      uint16(0) == 0x5a4d and filesize < 8000KB and $sc1 and pe.number_of_signatures < 1
}
