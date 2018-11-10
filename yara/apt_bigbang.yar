import "pe"

rule APT_ME_BigBang_Gen_Jul18_1 {
   meta:
      description = "Detects malware from Big Bang campaign against Palestinian authorities"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://research.checkpoint.com/apt-attack-middle-east-big-bang/"
      date = "2018-07-09"
      hash1 = "4db68522600f2d8aabd255e2da999a9d9c9f1f18491cfce9dadf2296269a172b"
      hash2 = "ac6462e9e26362f711783b9874d46fefce198c4c3ca947a5d4df7842a6c51224"
      hash3 = "e1f52ea30d25289f7a4a5c9d15be97c8a4dfe10eb68ac9d031edcc7275c23dbc"
   strings:
      $x2 = "%@W@%S@c@ri%@p@%t.S@%he@%l%@l" ascii
      $x3 = "S%@h%@e%l%@l." ascii
      $x4 = "(\"S@%t@%a%@rt%@up\")" ascii
      $x5 = "aW5zdGFsbCBwcm9nOiBwcm9nIHdpbGwgZGVsZXRlIG9sZCB0bXAgZmlsZQ==" fullword ascii /* base64 encoded string 'install prog: prog will delete old tmp file' */
      $x6 = "aW5zdGFsbCBwcm9nOiBUaGVyZSBpcyBubyBvbGQgZmlsZSBpbiB0ZW1wLg==" fullword ascii /* base64 encoded string 'install prog: There is no old file in temp.' */
      $x7 = "VXBkYXRlIHByb2c6IFRoZXJlIGlzIG5vIG9sZCBmaWxlIGluIHRlbXAu" fullword ascii /* base64 encoded string 'Update prog: There is no old file in temp.' */
      $x8 = "aW5zdGFsbCBwcm9nOiBDcmVhdGUgVGFzayBhZnRlciA1IG1pbiB0byBydW4gRmlsZSBmcm9tIHRtcA==" fullword ascii /* base64 encoded string 'install prog: Create Task after 5 min to run File from tmp' */
      $x9 = "UnVuIEZpbGU6IE15IHByb2cgaXMgRXhpdC4=" fullword ascii /* base64 encoded string 'Run File: My prog is Exit.' */
      $x10 = "li%@%@nk.W%@%@indo@%%@%@%wS%@%@tyle = 3" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and (
         1 of them or
         pe.imphash() == "0f09ea2a68d04f331df9a5d0f8641332"
      )
}

rule APT_ME_BigBang_Mal_Jul18_1 {
   meta:
      description = "Detects malware from Big Bang report"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://research.checkpoint.com/apt-attack-middle-east-big-bang/"
      date = "2018-07-09"
      hash1 = "ac6462e9e26362f711783b9874d46fefce198c4c3ca947a5d4df7842a6c51224"
      hash2 = "e1f52ea30d25289f7a4a5c9d15be97c8a4dfe10eb68ac9d031edcc7275c23dbc"
   strings:
      $s1 = "%Y%m%d-%I-%M-%S" fullword ascii
      $s2 = "/api/serv/requests/%s/runfile/delete" fullword ascii
      $s3 = "\\part.txt" fullword ascii
      $s4 = "\\ALL.txt" fullword ascii
      $s5 = "\\sat.txt" fullword ascii
      $s6 = "runfile.proccess_name" fullword ascii
      $s7 = "%s%s%p%s%zd%s%d%s%s%s%s%s" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and 4 of them
}
