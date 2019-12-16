
rule SUSP_RAR_NtdsDIT {
   meta:
      description = "Detects suspicious RAR file that contains ntds.dit"
      author = "Florian Roth"
      reference = "https://www.cybereason.com/blog/operation-soft-cell-a-worldwide-campaign-against-telecommunications-providers"
      date = "2019-12-16"
      score = 70
   strings:
      $x1 = "ntds.dit0" ascii fullword
   condition:
      uint32(0) == 0x21726152 // Rar!
      and $x1
}
