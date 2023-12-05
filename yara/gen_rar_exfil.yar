
rule SUSP_RAR_NtdsDIT {
   meta:
      description = "Detects suspicious RAR file that contains ntds.dit or SAM export"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.cybereason.com/blog/operation-soft-cell-a-worldwide-campaign-against-telecommunications-providers"
      date = "2019-12-16"
      modified = "2022-11-15" // only synced the name with our internal rule
      score = 70
      id = "da9e160f-3213-5027-bb0f-bf80ab3d5318"
   strings:
      $x1 = "ntds.dit0" ascii fullword
      $x2 = { 0? 53 41 4D 30 01 00 03 }  // SAM0
      $x3 = { 0? 73 61 6D 30 01 00 03 }  // sam0
   condition:
      uint32(0) == 0x21726152 // Rar!
      and 1 of them
}
