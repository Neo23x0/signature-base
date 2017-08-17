/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-07-15
   Identifier: CHAOS
   Reference: https://github.com/tiagorlampert/CHAOS
*/

/* Rule Set ----------------------------------------------------------------- */

rule CHAOS_Payload {
   meta:
      description = "Detects a CHAOS back connect payload"
      author = "Florian Roth"
      reference = "https://github.com/tiagorlampert/CHAOS"
      date = "2017-07-15"
      score = 80
      hash1 = "0962fcfcb1b52df148720c2112b036e75755f09279e3ebfce1636739af9b4448"
      hash2 = "5c3553345f824b7b6de09ccb67d834e428b8df17443d98816471ca28f5a11424"
   strings:
      $x1 = { 2F 43 48 41 4F 53 00 02 73 79 6E 63 2F 61 74 6F 6D 69 63 }
   condition:
      ( uint16(0) == 0x5a4d and filesize < 15000KB and all of them )
}