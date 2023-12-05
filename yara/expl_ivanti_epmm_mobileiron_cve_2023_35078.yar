
rule LOG_EXPL_Ivanti_EPMM_MobileIron_Core_CVE_2023_35078_Jul23_1 {
   meta:
      description = "Detects the successful exploitation of Ivanti Endpoint Manager Mobile (EPMM) / MobileIron Core CVE-2023-35078"
      author = "Florian Roth"
      reference = "Ivanti Endpoint Manager Mobile (EPMM) CVE-2023-35078 - Analysis Guidance"
      date = "2023-07-25"
      score = 75
      id = "44cca0b5-3851-5786-82fd-ce3ccb566453"
   strings:
      $xr1 = /\/mifs\/aad\/api\/v2\/[^\n]{1,300} 200 [1-9][0-9]{0,60} /
   condition:
      $xr1
}

rule MAL_WAR_Ivanti_EPMM_MobileIron_Mi_War_Aug23 {
   meta:
      description = "Detects WAR file found in the Ivanti EPMM / MobileIron Core compromises exploiting CVE-2023-35078"
      author = "Florian Roth"
      reference = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-213a"
      date = "2023-08-01"
      score = 85
      hash1 = "6255c75e2e52d779da39367e7a7d4b8d1b3c9c61321361952dcc05819251a127"
      id = "cd16cf29-a90d-5c3f-b66f-e9264dbf79fb"
   strings:
      $s1 = "logsPaths.txt" ascii fullword
      $s2 = "keywords.txtFirefox" ascii
   condition:
      uint16(0) == 0x4b50 and
      filesize < 20KB and
      all of them
}

rule MAL_WAR_Ivanti_EPMM_MobileIron_LogClear_JAVA_Aug23 {
   meta:
      description = "Detects LogClear.class found in the Ivanti EPMM / MobileIron Core compromises exploiting CVE-2023-35078"
      author = "Florian Roth"
      reference = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-213a"
      date = "2023-08-01"
      score = 80
      hash1 = "deb381c25d7a511b9eb936129eeba2c0341cff7f4bd2168b05e40ab2ee89225e"
      id = "e1ef3bf3-0107-5ba6-a49f-71e079851a4f"
   strings:
      $s1 = "logsPaths.txt" ascii fullword
      $s2 = "log file: %s, not read" ascii fullword
      $s3 = "/tmp/.time.tmp" ascii fullword
      $s4 = "readKeywords" ascii fullword
      $s5 = "\"----------------  ----------------" ascii fullword
   condition:
      uint16(0) == 0xfeca and
      filesize < 20KB and
      4 of them or all of them
}
