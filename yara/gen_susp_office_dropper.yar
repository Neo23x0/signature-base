rule SUSP_Office_Dropper_Strings {
   meta:
      description = "Detects Office droppers that include a notice to enable active content"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2018-09-13"
   strings:
      $a1 = "_VBA_PROJECT" fullword wide

      $s1 = "click enable editing" fullword ascii
      $s2 = "click enable content" fullword ascii
      $s3 = "\"Enable Editing\"" fullword ascii
      $s4 = "\"Enable Content\"" fullword ascii
   condition:
      uint16(0) == 0xcfd0 and filesize < 500KB and $a1 and 1 of ($s*)
}

rule SUSP_EnableContent_String {
   meta:
      description = "Detects strings in macro enabled malicious documents"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2018-11-19"
      score = 60
      hash1 = "65bd49d9f6d9b92478e3653362c0031919607302db6cfb3a7c1994d20be18bcc"
   strings:
      $s1 = "Enable Content" fullword ascii
      $s2 = "Enable Editing" fullword ascii
   condition:
      uint16(0) == 0xcfd0 and filesize < 5000KB and 2 of them
}
