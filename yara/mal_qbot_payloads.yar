
rule MAL_QBot_HTML_Smuggling_Indicators_Oct22_1 {
   meta:
      description = "Detects double encoded PKZIP headers as seen in HTML files used by QBot"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://twitter.com/ankit_anubhav/status/1578257383133876225?s=20&t=Bu3CCJCzImpTGOQX_KGsdA"
      date = "2022-10-07"
      score = 75
      hash1 = "4f384bcba31fda53e504d0a6c85cee0ce3ea9586226633d063f34c53ddeaca3f"
      hash2 = "8e61c2b751682becb4c0337f5a79b2da0f5f19c128b162ec8058104b894cae9b"
      hash3 = "c5d23d991ce3fbcf73b177bc6136d26a501ded318ccf409ca16f7c664727755a"
      hash4 = "5072d91ee0d162c28452123a4d9986f3df6b3244e48bf87444ce88add29dd8ed"
      hash5 = "ff4e21f788c36aabe6ba870cf3b10e258c2ba6f28a2d359a25d5a684c92a0cad"
      id = "8034d6af-4dae-5ff6-b635-efb5175fe4d1"
   strings:
      /* Double base64 encoded - as seen in HTML */
      $sd1 = "VUVzREJCUUFBUUFJQ"
      $sd2 = "VFc0RCQlFBQVFBSU"
      $sd3 = "VRXNEQkJRQUFRQUlB"
      /* reversed */
      $sdr1 = "QJFUUBFUUCJERzVUV"
      $sdr2 = "USBFVQBFlQCR0cFV"
      $sdr3 = "BlUQRFUQRJkQENXRV"

      /* Triple base64 encoded - to detect the double encoded versions in email attachments */
      $st1 = "VlVWelJFSkNVVUZCVVVGSl"
      $st2 = "ZVVnpSRUpDVVVGQlVVRkpR"
      $st3 = "WVVZ6UkVKQ1VVRkJVVUZKU"
      $st4 = "VkZjMFJDUWxGQlFWRkJTV"
      $st5 = "ZGYzBSQ1FsRkJRVkZCU1"
      $st6 = "WRmMwUkNRbEZCUVZGQlNV"
      $st7 = "VlJYTkVRa0pSUVVGUlFVbE"
      $st8 = "ZSWE5FUWtKUlFVRlJRVWxC"
      $st9 = "WUlhORVFrSlJRVUZSUVVsQ"
      /* reversed */
      $str1 = "UUpGVVVCRlVVQ0pFUnpWVV"
      $str2 = "FKRlVVQkZVVUNKRVJ6VlVW"
      $str3 = "RSkZVVUJGVVVDSkVSelZVV"
      $str4 = "VVNCRlZRQkZsUUNSMGNGV"
      $str5 = "VTQkZWUUJGbFFDUjBjRl"
      $str6 = "VU0JGVlFCRmxRQ1IwY0ZW"
      $str7 = "QmxVUVJGVVFSSmtRRU5YUl"
      $str8 = "JsVVFSRlVRUkprUUVOWFJW"
      $str9 = "CbFVRUkZVUVJKa1FFTlhSV"

      /* HTML */
      $htm = "<html" ascii
      /* avoid matches in emails with double encoding - because email attachments get base64 encoded */
      $eml = "Content-Transfer-Encoding:" ascii
   condition:
      filesize < 10MB and ( 
         ( 1 of ($sd*) and $htm and not $eml ) /* double encoded in HTML */
         or ( 1 of ($st*) and $eml )           /* triple encoded in EML */
      )
}
