

rule SUSP_SVG_JS_Payload_Mar25 {
   meta:
      description = "Detects a suspicious SVG file that contains a JavaScript payload. This rule is a generic rule that might generate false positives. A match should be further investigated."
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2025-03-20"
      modified = "2025-03-21"
      score = 60
      hash = "7b4b8e42d4df56412969cd1c38dcb750d21b10a54d257a9b918bd6ae0e0f8d11"
      hash = "4ae2ebc103f5de7ccfd75603b543d602b5c793e1ef7db19fbb60ff2e42611f75"
      hash = "b92e9d6f8a516e78b3e848c4b5b2815b406c9478e6be3777f3e784ceedc66f4a"
      hash = "23ea832d503b02e9edbdbf9ed8ce0b19376d44580d21906d9da834de69f7dfcb"
      hash = "4f33dff59753773a596798ee58fb899c5382c6ec2951b457554aebe5c05ec0cd"
      hash = "b8be8e009b08c04857dc2388544d61db57c0dd1841371aa7e4bf3ee2010ef1a8"
      hash = "cdcbe23f284067c4e863f76370f8612d85bef0410ca0bb5684112a8c16eff21c"
      hash = "5b3d11109e0d10b9266cbfbb6906e728c4470d752f95769280666d1166df4b43"
      hash = "a7620155da2a576823dbe7963ff4a5f79702645edb8b2ae67b8af8ba7eac697b"
      hash = "52e1c6279dc151616bbd85ac7d0abc42cab5850deb6da2e2b20e339f79c3536a"
      id = "cdb22283-8427-5c25-b653-d6d76dd27dc6"
   strings:
      $a1 = "<svg xmlns=" ascii fullword

      $sx1 = "src=\"data:application/ecmascript;base64,"
      $sx2 = "=\"></script>"

      $ss1 = "<script type=\"application/ecmascript\">"
      $ss2 = "<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"100%\" height=\"100%\">"
   condition:
      $a1 in (0..1024)
      and (
         filesize < 100KB and 1 of ($sx*)
         or 
         filesize < 1MB and 2 of ($s*)
      )
}
