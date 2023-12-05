import "pe"

rule MAL_GandCrab_Apr18_1 {
   meta:
      description = "Detects GandCrab malware"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://twitter.com/MarceloRivero/status/988455516094550017"
      date = "2018-04-23"
      hash1 = "6fafe7bb56fd2696f2243fc305fe0c38f550dffcfc5fca04f70398880570ffff"
      id = "ef7983cd-a7b3-5ce2-8cff-1bcf35bc6140"
   condition:
      uint16(0) == 0x5a4d and filesize < 800KB and pe.imphash() == "7936b0e9491fd747bf2675a7ec8af8ba"
}
