rule EXPL_React_Server_CVE_2025_55182_POC_Dec25 {
   meta:
      description = "Detects in-memory webshell indicators related to the proof-of-concept code for the React Server Remote Code Execution Vulnerability (CVE-2025-55182)"
      author = "Florian Roth"
      reference = "https://x.com/pyn3rd/status/1996840827897954542/photo/1"
      date = "2025-12-05"
      score = 70
   strings:
      $xs1 = "{const cmd=p.query.cmd;if(!cmd)(s.writeHead(400);"

      $s1 = ";if(p.pathname=="
      $s2 = ".writeHead(400);"
      $s3 = ".writeHead(200,{'Content-Type':"
      $s4 = ".execSync("
      $s5 = ",stdio:'pipe'})"
   condition:
      1 of ($x*)
      or all of ($s*)
}

rule SUSP_WEBSHELL_LOG_Signatures_Dec25 {
   meta:
      description = "Detects indicators related simple webshells that use the same exec/cmd pattern"
      author = "Florian Roth"
      reference = "https://x.com/pyn3rd/status/1996840827897954542/photo/1"
      date = "2025-12-05"
      score = 60
   strings:
      $xa1 = "/exec?cmd=ls"
      $xa2 = "/exec?cmd=whoami"
      $xa3 = "/exec?cmd=id"
      $xa4 = "/exec?cmd=uname%20-a"
   condition:
      1 of them
      // not XML
      and not uint16(0) == 0x3c3f
}

rule EXPL_RCE_React_Server_CVE_2025_55182_POC_Dec25 {
   meta:
      description = "Detects RCE indicators related to the proof-of-concept code for the React Server Remote Code Execution Vulnerability (CVE-2025-55182)"
      author = "Florian Roth"
      reference = "https://www.youtube.com/watch?v=MmdwakT-Ve8"
      date = "2025-12-05"
      score = 70
   strings:
      $s1 = "process.mainModule.require('child_process').execSync("
      $s2 = "$1:constructor:constructor"
   condition:
      all of them
      // not XML
      and not uint16(0) == 0x3c3f
}

rule EXPL_RCE_React_Server_Next_JS_CVE_2025_66478_Tracebacks_Dec25 {
   meta:
      description = "Detects traceback indicators caused by the exploitation of the React Server Remote Code Execution Vulnerability (CVE-2025-55182) in Next.js applications (CVE-2025-66478). This can also be caused by vulnerability scanning."
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2025-12-05"
      score = 55
   strings:
      $s1 = "Unexpected end of form"
      $s2 = "/next-server/app-page.runtime.dev.js:2:457"
      $s3 = "/app-page.runtime.dev.js:2:472"
   condition:
      all of them
}

rule EXPL_RCE_React_Server_Next_JS_CVE_2025_66478_Errors_Dec25 {
   meta:
      description = "Detects error messages caused by the exploitation of the React Server Remote Code Execution Vulnerability (CVE-2025-55182) in Next.js applications (CVE-2025-66478). This can also be caused by vulnerability scanning."
      author = "Florian Roth"
      reference = "https://github.com/Malayke/Next.js-RSC-RCE-Scanner-CVE-2025-66478"
      date = "2025-12-05"
      score = 65
   strings:
      $s1 = "[Error: NEXT_REDIRECT]"
      $s2 = "digest: 'uid=0(root) gid=0(root)"
   condition:
      all of them
}

rule EXPL_SUSP_JS_POC_Dec25 {
   meta:
      description = "Detects RCE indicators related to the proof-of-concept code for the React Server Remote Code Execution Vulnerability (CVE-2025-55182) but could be used in other JavaScript based PoC code as well"
      author = "Florian Roth"
      reference = "https://github.com/msanft/CVE-2025-55182/blob/main/poc.py"
      date = "2025-12-05"
      modified = "2025-12-06"
      score = 70
   strings:
      $xr1 = /process\.mainModule\.require\(["']child_process["']\).{5,40}\(["'](whoami|powershell|\/bin\/sh|\/bin\/bash|wget|curl|cat \/etc\/passwd|uname -a)/
   condition:
      1 of them
}

rule EXPL_SUSP_JS_POC_RSC_Detector_Payloads_Dec25 {
   meta:
      description = "Detects RCE indicators related to the proof-of-concept code for the React Server Remote Code Execution Vulnerability (CVE-2025-55182) as used in the RSC Detector browser extension but could be used in other JavaScript based PoC code as well"
      author = "Florian Roth"
      reference = "https://github.com/mrknow001/RSC_Detector"
      date = "2025-12-06"
      score = 70
   strings:
      $s1 = "process.mainModule.require('child_process').execSync("
      $s2 = ").toString('base64');"

      // harmless test cases - we only want to match real command execution attempts
      $f1 = "echo vulnerability_test"
   condition:
      all of ($s*)
      and not 1 of ($f*)
}
