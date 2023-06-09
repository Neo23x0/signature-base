
rule HKTL_EXPL_POC_LibSSH_Auth_Bypass_CVE_2023_2283_Jun23_1 {
   meta:
      description = "Detects POC code used in attacks against libssh vulnerability CVE-2023-2283"
      author = "Florian Roth"
      reference = "https://github.com/github/securitylab/tree/1786eaae7f90d87ce633c46bbaa0691d2f9bf449/SecurityExploits/libssh/pubkey-auth-bypass-CVE-2023-2283"
      date = "2023-06-08"
      score = 85
   strings:
      $s1 = "nprocs = %d" ascii fullword
      $s2 = "fork failed: %s" ascii fullword
   condition:
      uint16(0) == 0x457f and all of them
}

rule LOG_LibSSH_Auth_Bypass_CVE_2023_2283_Jun23_1 {
   meta:
      description = "Detects error message generated when exploiting the libssh vulnerability CVE-2023-2283"
      author = "Florian Roth"
      reference = "https://twitter.com/kevin_backhouse/status/1666459308941357056?s=20"
      date = "2023-06-09"
      score = 70
   strings:
      $s1 = "Failed to generate curve25519 keys" ascii fullword

      $fp1 = "ssh_set_error(" // avoid detection of source code
   condition:
      $s1 and not 1 of ($fp*)
}
