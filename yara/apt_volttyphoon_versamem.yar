
rule WEBSHELL_JAVA_VersaMem_JAR_Aug24_1 {
   meta:
      description = "Detects VersaMem Java webshell samples (as used by Volt Typhoon)"
      author = "blacklotuslabs (modified by Florian Roth)"
      reference = "https://x.com/ryanaraine/status/1828440883315999117"
      date = "2024-08-27"
      modified = "2024-08-29"
      score = 75
   strings:
      $s1 = "com.versa.vnms.ui.TestMain"
      $s2 = "/tmp/.java_pid"
      $s3 = "captureLoginPasswordCode"
      $s4 = "com/versa/vnms/ui/services/impl/VersaAuthenticationServiceImpl"
      $s5 = "/tmp/.temp.data"
      $s6 = "getInsertCode"
      $s7 = "VersaMem"
      $s8 = "Versa-Auth"
   condition:
      filesize < 5MB and 3 of them
}

rule WEBSHELL_JAVA_VersaMem_JAR_Aug24_2 {
   meta:
      description = "Detects VersaMem Java webshell samples (as used by Volt Typhoon)"
      author = "Florian Roth"
      reference = "https://x.com/craiu/status/1828687700884336990"
      date = "2024-08-29"
      score = 75
      hash1 = "4bcedac20a75e8f8833f4725adfc87577c32990c3783bf6c743f14599a176c37"
   strings:
      $x1 = "tomcat_memShell" ascii
      $x2 = "versa/vnms/ui/config/" ascii fullword
   condition:
      uint16(0) == 0x4b50
      and filesize < 3000KB
      and 1 of them
}
