
rule APT_UTA028_ForensicArtefacts_PaloAlto_CVE_2024_3400_Apr24_1 : SCRIPT {
   meta:
      description = "Detects forensic artefacts of APT UTA028 as found in a campaign exploiting the Palo Alto CVE-2024-3400 vulnerability"
      author = "Florian Roth"
      reference = "https://www.volexity.com/blog/2024/04/12/zero-day-exploitation-of-unauthenticated-remote-code-execution-vulnerability-in-globalprotect-cve-2024-3400/"
      date = "2024-04-15"
      modified = "2024-04-18"
      score = 70
      id = "32cf18ff-784d-5849-87f8-14ede7315188"
   strings:
      $x1 = "cmd = base64.b64decode(rst.group"
      $x2 = "f.write(\"/*\"+output+\"*/\")"

      $x3 = "* * * * * root wget -qO- http://"
      $x4 = "rm -f /var/appweb/sslvpndocs/global-protect/*.css"

      $x5a = "failed to unmarshal session(../" // https://security.paloaltonetworks.com/CVE-2024-3400
      $x5b = "failed to unmarshal session(./../" // customer data

      $x6 = "rm -rf /opt/panlogs/tmp/device_telemetry/minute/*" base64
      $x7 = "$(uname -a) > /var/" base64
   condition:
      1 of them
}

rule EXPL_PaloAlto_CVE_2024_3400_Apr24_1 {
   meta:
      description = "Detects characteristics of the exploit code used in attacks against Palo Alto GlobalProtect CVE-2024-3400"
      author = "Florian Roth"
      reference = "https://www.volexity.com/blog/2024/04/12/zero-day-exploitation-of-unauthenticated-remote-code-execution-vulnerability-in-globalprotect-cve-2024-3400/"
      date = "2024-04-15"
      score = 70
      id = "1bcf0415-5351-5e09-ab93-496e8dc47c92"
   strings:
      $x1 = "SESSID=../../../../opt/panlogs/"
      $x2 = "SESSID=./../../../../opt/panlogs/"
      
      $sa1 = "SESSID=../../../../"
      $sa2 = "SESSID=./../../../../"
      
      $sb2 = "${IFS}"
   condition:
      1 of ($x*)
      or (1 of ($sa*) and $sb2)
}

rule SUSP_LNX_Base64_Download_Exec_Apr24 : SCRIPT {
   meta:
      description = "Detects suspicious base64 encoded shell commands used for downloading and executing further stages"
      author = "Paul Hager"
      date = "2024-04-18"
      reference = "Internal Research"
      score = 75
      id = "df8dddef-3c49-500c-abc8-7f7de5aa69ae"
   strings:
      $sa1 = "curl http" base64
      $sa2 = "wget http" base64
      
      $sb1 = "chmod 777 " base64
      $sb2 = "/tmp/" base64
   condition:
      1 of ($sa*)
      and all of ($sb*)
}

rule SUSP_PY_Import_Statement_Apr24_1 {
   meta:
      description = "Detects suspicious Python import statement and socket usage often found in Python reverse shells"
      author = "Florian Roth"
      reference = "https://www.volexity.com/blog/2024/04/12/zero-day-exploitation-of-unauthenticated-remote-code-execution-vulnerability-in-globalprotect-cve-2024-3400/"
      date = "2024-04-15"
      score = 65
      id = "8e05f9a1-40a8-5d01-9e45-8779b0ff7a45"
   strings:
      $x1 = "import sys,socket,os,pty;s=socket.socket("
   condition:
      1 of them
}

rule SUSP_LNX_Base64_Exec_Apr24 : SCRIPT {
   meta:
      description = "Detects suspicious base64 encoded shell commands (as seen in Palo Alto CVE-2024-3400 exploitation)"
      author = "Christian Burkard"
      date = "2024-04-18"
      modified = "2025-03-21"
      reference = "Internal Research"
      score = 75
      id = "2da3d050-86b0-5903-97eb-c5f39ce4f3a3"
   strings:
      $s1 = "curl http://" base64
      $s2 = "wget http://" base64
      $s3 = ";chmod 777 " base64
      // $s4 = "/tmp/" base64 // prone to FPs
      
      $mirai = "country="

      $fp1 = "<html"
      $fp2 = "<?xml"
   condition:
      filesize < 800KB
      and 1 of ($s*) 
      and not $mirai
      and not 1 of ($fp*)
}
