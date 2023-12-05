
rule SUSP_ZIP_LNK_PhishAttachment_Pattern_Jun22_1 {
   meta:
      description = "Detects suspicious tiny ZIP files with phishing attachment characteristics"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2022-06-23"
      score = 65
      hash1 = "4edb41f4645924d8a73e7ac3e3f39f4db73e38f356bc994ad7d03728cd799a48"
      hash2 = "c4fec375b44efad2d45c49f30133efbf6921ce82dbb2d1a980f69ea6383b0ab4"
      hash3 = "9c70eeac97374213355ea8fa019a0e99e0e57c8efc43daa3509f9f98fa71c8e4"
      hash4 = "ddc20266e38a974a28af321ab82eedaaf51168fbcc63ac77883d8be5200dcaf9"
      hash5 = "b59788ae984d9e70b4f7f5a035b10e6537063f15a010652edd170fc6a7e1ea2f"
      id = "3537c4ea-a51d-5100-97d7-71a24da5ff43"
   strings:
      $sl1 = ".lnk" 
   condition:
      uint16(0) == 0x4b50 and 
      filesize < 2KB and 
      $sl1 in (filesize-256..filesize)
}

rule SUSP_ZIP_ISO_PhishAttachment_Pattern_Jun22_1 {
   meta:
      description = "Detects suspicious small base64 encoded ZIP files (MIME email attachments) with .iso files as content as often used in phishing attacks"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2022-06-23"
      score = 65
      id = "638541a6-d2d4-513e-978c-9d1b9f5e3b71"
   strings:
      $pkzip_base64_1 = { 0A 55 45 73 44 42 }
      $pkzip_base64_2 = { 0A 55 45 73 44 42 }
      $pkzip_base64_3 = { 0A 55 45 73 48 43 }

      $iso_1 = "Lmlzb1BL"
      $iso_2 = "5pc29QS"
      $iso_3 = "uaXNvUE"
   condition:
      filesize < 2000KB and 1 of ($pk*) and 1 of ($iso*)
}

rule SUSP_Archive_Phishing_Attachment_Characteristics_Jun22_1 {
   meta:
      description = "Detects characteristics of suspicious file names or double extensions often found in phishing mail attachments"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://twitter.com/0xtoxin/status/1540524891623014400?s=12&t=IQ0OgChk8tAIdTHaPxh0Vg"
      date = "2022-06-29"
      score = 65
      hash1 = "caaa5c5733fca95804fffe70af82ee505a8ca2991e4cc05bc97a022e5f5b331c"
      hash2 = "a746d8c41609a70ce10bc69d459f9abb42957cc9626f2e83810c1af412cb8729"
      id = "3cb8c371-f40b-5773-84d1-3bce37da529e"
   strings:
      $sa01 = "INVOICE.exePK" ascii
      $sa02 = "PAYMENT.exePK" ascii
      $sa03 = "REQUEST.exePK" ascii
      $sa04 = "ORDER.exePK" ascii
      $sa05 = "invoice.exePK" ascii
      $sa06 = "payment.exePK" ascii
      $sa07 = "_request.exePK" ascii
      $sa08 = "_order.exePK" ascii
      $sa09 = "-request.exePK" ascii
      $sa10 = "-order.exePK" ascii
      $sa11 = " request.exePK" ascii
      $sa12 = " order.exePK" ascii
      $sa14 = ".doc.exePK" ascii
      $sa15 = ".docx.exePK" ascii
      $sa16 = ".xls.exePK" ascii
      $sa17 = ".xlsx.exePK" ascii
      $sa18 = ".pdf.exePK" ascii
      $sa19 = ".ppt.exePK" ascii
      $sa20 = ".pptx.exePK" ascii
      $sa21 = ".rtf.exePK" ascii
      $sa22 = ".txt.exePK" ascii

      $sb01 = "SU5WT0lDRS5leGVQS"
      $sb02 = "lOVk9JQ0UuZXhlUE"
      $sb03 = "JTlZPSUNFLmV4ZVBL"
      $sb04 = "UEFZTUVOVC5leGVQS"
      $sb05 = "BBWU1FTlQuZXhlUE"
      $sb06 = "QQVlNRU5ULmV4ZVBL"
      $sb07 = "UkVRVUVTVC5leGVQS"
      $sb08 = "JFUVVFU1QuZXhlUE"
      $sb09 = "SRVFVRVNULmV4ZVBL"
      $sb10 = "T1JERVIuZXhlUE"
      $sb11 = "9SREVSLmV4ZVBL"
      $sb12 = "PUkRFUi5leGVQS"
      $sb13 = "aW52b2ljZS5leGVQS"
      $sb14 = "ludm9pY2UuZXhlUE"
      $sb15 = "pbnZvaWNlLmV4ZVBL"
      $sb16 = "cGF5bWVudC5leGVQS"
      $sb17 = "BheW1lbnQuZXhlUE"
      $sb18 = "wYXltZW50LmV4ZVBL"
      $sb19 = "X3JlcXVlc3QuZXhlUE"
      $sb20 = "9yZXF1ZXN0LmV4ZVBL"
      $sb21 = "fcmVxdWVzdC5leGVQS"
      $sb22 = "X29yZGVyLmV4ZVBL"
      $sb23 = "9vcmRlci5leGVQS"
      $sb24 = "fb3JkZXIuZXhlUE"
      $sb25 = "LXJlcXVlc3QuZXhlUE"
      $sb26 = "1yZXF1ZXN0LmV4ZVBL"
      $sb27 = "tcmVxdWVzdC5leGVQS"
      $sb28 = "LW9yZGVyLmV4ZVBL"
      $sb29 = "1vcmRlci5leGVQS"
      $sb30 = "tb3JkZXIuZXhlUE"
      $sb31 = "IHJlcXVlc3QuZXhlUE"
      $sb32 = "ByZXF1ZXN0LmV4ZVBL"
      $sb33 = "gcmVxdWVzdC5leGVQS"
      $sb34 = "IG9yZGVyLmV4ZVBL"
      $sb35 = "BvcmRlci5leGVQS"
      $sb36 = "gb3JkZXIuZXhlUE"
      $sb37 = "LmRvYy5leGVQS"
      $sb38 = "5kb2MuZXhlUE"
      $sb39 = "uZG9jLmV4ZVBL"
      $sb40 = "LmRvY3guZXhlUE"
      $sb41 = "5kb2N4LmV4ZVBL"
      $sb42 = "uZG9jeC5leGVQS"
      $sb43 = "Lnhscy5leGVQS"
      $sb44 = "54bHMuZXhlUE"
      $sb45 = "ueGxzLmV4ZVBL"
      $sb46 = "Lnhsc3guZXhlUE"
      $sb47 = "54bHN4LmV4ZVBL"
      $sb48 = "ueGxzeC5leGVQS"
      $sb49 = "LnBkZi5leGVQS"
      $sb50 = "5wZGYuZXhlUE"
      $sb51 = "ucGRmLmV4ZVBL"
      $sb52 = "LnBwdC5leGVQS"
      $sb53 = "5wcHQuZXhlUE"
      $sb54 = "ucHB0LmV4ZVBL"
      $sb55 = "LnBwdHguZXhlUE"
      $sb56 = "5wcHR4LmV4ZVBL"
      $sb57 = "ucHB0eC5leGVQS"
      $sb58 = "LnJ0Zi5leGVQS"
      $sb59 = "5ydGYuZXhlUE"
      $sb60 = "ucnRmLmV4ZVBL"
      $sb61 = "LnR4dC5leGVQS"
      $sb62 = "50eHQuZXhlUE"
      $sb63 = "udHh0LmV4ZVBL"
   condition:
      uint16(0) == 0x4b50 and 1 of ($sa*) or 1 of ($sb*)
}
