
rule SUSP_VHD_Suspicious_Small_Size {
   meta:
      description = "Detects suspicious VHD files"
      author = "Florian Roth"
      reference = "https://twitter.com/MeltX0R/status/1208095892877774850"
      date = "2019-12-21"
      score = 50
   strings:
      /* VHD */
      $hc1 = { 63 6F 6E 65 63 74 69 78 }
   condition:
      uint16(0) == 0x6f63 and $hc1 at 0 and
      filesize <= 4000KB
}
