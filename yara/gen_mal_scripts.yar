
/* Various rules - see the references */

rule PS_AMSI_Bypass {
   meta:
      description = "Detects PowerShell AMSI Bypass"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://gist.github.com/mattifestation/46d6a2ebb4a1f4f0e7229503dc012ef1"
      date = "2017-07-19"
      score = 65
      type = "file"
   strings:
      $s1 = ".GetField('amsiContext',[Reflection.BindingFlags]'NonPublic,Static')." ascii nocase
   condition:
      1 of them
}

rule JS_Suspicious_Obfuscation_Dropbox {
   meta:
      description = "Detects PowerShell AMSI Bypass"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://twitter.com/ItsReallyNick/status/887705105239343104"
      date = "2017-07-19"
      score = 70
   strings:
      $x1 = "j\"+\"a\"+\"v\"+\"a\"+\"s\"+\"c\"+\"r\"+\"i\"+\"p\"+\"t\""
      $x2 = "script:https://www.dropbox.com" ascii
   condition:
      2 of them
}

rule JS_Suspicious_MSHTA_Bypass {
   meta:
      description = "Detects MSHTA Bypass"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://twitter.com/ItsReallyNick/status/887705105239343104"
      date = "2017-07-19"
      score = 70
   strings:
      $s1 = "mshtml,RunHTMLApplication" ascii
      $s2 = "new ActiveXObject(\"WScript.Shell\").Run(" ascii
      $s3 = "/c start mshta j" ascii nocase
   condition:
      2 of them
}

rule JavaScript_Run_Suspicious {
   meta:
      description = "Detects a suspicious Javascript Run command"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://twitter.com/craiu/status/900314063560998912"
      score = 60
      date = "2017-08-23"
   strings:
      $s1 = "w = new ActiveXObject(" ascii
      $s2 = " w.Run(r);" fullword ascii
   condition:
      all of them
}

/* Certutil Rule Improved */

private rule MSI {
   strings:
      $r1 = "SummaryInformation" wide
   condition:
      uint16(0) == 0xCFD0 and $r1
}

rule Certutil_Decode_OR_Download {
   meta:
      description = "Certutil Decode"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "Internal Research"
      score = 40
      date = "2017-08-29"
   strings:
      $a1 = "certutil -decode " ascii wide
      $a2 = "certutil  -decode " ascii wide
      $a3 = "certutil.exe -decode " ascii wide
      $a4 = "certutil.exe  -decode " ascii wide
      $a5 = "certutil -urlcache -split -f http" ascii wide
      $a6 = "certutil.exe -urlcache -split -f http" ascii wide
   condition:
      ( not MSI and filesize < 700KB and 1 of them )
}

rule Suspicious_JS_script_content {
   meta:
      description = "Detects suspicious statements in JavaScript files"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "Research on Leviathan https://goo.gl/MZ7dRg"
      date = "2017-12-02"
      score = 70
      hash1 = "fc0fad39b461eb1cfc6be57932993fcea94fca650564271d1b74dd850c81602f"
   strings:
      $x1 = "new ActiveXObject('WScript.Shell')).Run('cmd /c " ascii
      $x2 = ".Run('regsvr32 /s /u /i:" ascii
      $x3 = "new ActiveXObject('WScript.Shell')).Run('regsvr32 /s" fullword ascii
      $x4 = "args='/s /u /i:" ascii
   condition:
      ( filesize < 10KB and 1 of them )
}

rule Universal_Exploit_Strings {
   meta:
      description = "Detects a group of strings often used in exploit codes"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "not set"
      date = "2017-12-02"
      score = 50
      hash1 = "9b07dacf8a45218ede6d64327c38478640ff17d0f1e525bd392c002e49fe3629"
   strings:
      $s1 = "Exploit" fullword ascii
      $s2 = "Payload" fullword ascii
      $s3 = "CVE-201" ascii
      $s4 = "bindshell"
   condition:
      ( filesize < 2KB and 3 of them )
}

rule VBS_Obfuscated_Mal_Feb18_1  {
   meta:
      description = "Detects malicious obfuscated VBS observed in February 2018"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://goo.gl/zPsn83"
      date = "2018-02-12"
      hash1 = "06960cb721609fe5a857fe9ca3696a84baba88d06c20920370ddba1b0952a8ab"
      hash2 = "c5c0e28093e133d03c3806da0061a35776eed47d351e817709d2235b95d3a036"
      hash3 = "e1765a2b10e2ff10235762b9c65e9f5a4b3b47d292933f1a710e241fe0417a74"
   strings:
      $x1 = "A( Array( (1* 2^1 )+" ascii
      $x2 = ".addcode(A( Array(" ascii
      $x3 = "false:AA.send:Execute(AA.responsetext):end" ascii
      $x4 = "& A( Array(  (1* 2^1 )+" ascii

      $s1 = ".SYSTEMTYPE:NEXT:IF (UCASE(" ascii
      $s2 = "A = STR:next:end function" ascii
      $s3 = "&WSCRIPT.SCRIPTFULLNAME&CHR" fullword ascii
   condition:
      filesize < 600KB and ( 1 of ($x*) or 3 of them )
}
