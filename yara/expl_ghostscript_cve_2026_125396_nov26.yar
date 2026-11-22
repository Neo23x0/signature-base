rule EXPL_Ghostscript_CVE_2026_125396_POC_Nov26 {
   meta:
      description = "Detects the public proof-of-concept exploit for CVE-2026-125396 (Upload2Shell), a use-after-free in the Ghostscript font loader that lets a crafted document bypass the -dSAFER sandbox and run commands as the rendering process"
      author = "Florian Roth"
      date = "2026-11-21"
      reference = "https://pwn.ai/upload2shell/research.html"
      hash = "7685dc0e5608a7da449937e476dc4b43cf7e481a0b5c396936a9a3585fc5b25c"
      score = 80
      id = "aa4ccc7b-1e41-552f-8302-6bd92bf866af"
   strings:
      // core: handler, stack, type
      $sa1 = "errordict /typecheck {" ascii
      $sa2 = "count array astore" ascii
      $sa3 = "get type /stringtype eq" ascii

      // context
      $sb1 = "Fontmap" ascii fullword
      $sb2 = "setglobal" ascii fullword
      $sb3 = "/FontType 1 def" ascii

      // parts that vary between variants
      $sc1 = " (%ram%" ascii
      $sc2 = " (%!PS-AdobeFont-1.0: " ascii
   condition:
      all of them
}
