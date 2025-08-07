rule SUSP_Scheduled_Task_Java_JAR_Aug25 {
   meta:
      description = "Detects scheduled tasks that execute Java JAR files, which is suspicious but not necessarily malicious"
      author = "Florian Roth"
      date = "2025-08-07"
      score = 60
      reference = "Internal Research"
      hash = "7c5999082d9c5f3dd342ca05191311ddd1e24ba7675d1e9763fb4d962be3a933"
   strings:
      $a0 = "<Task version=" wide
      $a1 = "xmlns=\"http://schemas.microsoft.com/windows/" wide

      $sa1 = "java.exe</Command>" wide
      $sa2 = "javaw.exe</Command>" wide

      $sb1 = "<Arguments>-jar " wide
   condition:
      uint16(0) == 0xfeff
      and filesize < 500KB
      and all of ($a*)
      and 1 of ($sa*)
      and 1 of ($sb*)
}

rule SUSP_JAVA_Loader_Indicators_Aug25 {
   meta:
      description = "Detects indicators of a Java loader used in phishing campaigns"
      author = "Florian Roth"
      reference = "https://www.malwation.com/blog/technical-analysis-of-a-stealth-java-loader-used-in-phishing-campaigns-targeting-turkiye"
      date = "2025-08-07"
      score = 70
      hash1 = "c4cf746fce283878dde567e5457a8ebdbb7ff3414be46569ecdd57338bd96fa1"
   strings:
      $s1 = "Loader.classPK" ascii fullword
      $s2 = "stubPK" ascii
      $s3 = "META-INF/MANIFEST.MFPK" ascii
   condition:
      uint16(0) == 0x4b50
      and filesize < 500KB
      and $s1 in (filesize - 224..filesize)
      and $s2 in (filesize - 224..filesize)
      and $s3 in (filesize - 224..filesize)
}

rule MAL_JAVA_Loader_Final_Jar_Aug25 {
   meta:
      description = "Detects a final Java loader JAR file used in phishing campaigns"
      author = "Florian Roth"
      reference = "https://www.malwation.com/blog/technical-analysis-of-a-stealth-java-loader-used-in-phishing-campaigns-targeting-turkiye"
      date = "2025-08-07"
      score = 85
      hash1 = "0a7fddd91b332c8daee2c0727b884fc92cfaede02883dbad75f7efc299e884e3"
   strings:
      $s1 = "Obfuscation by Allatori Obfuscator" ascii fullword
      $s2 = "MANIFEST.MFM" ascii fullword
      $s3 = "GetCpu.classPK" ascii fullword
      $s4 = "extra/spreader" ascii fullword
   condition:
      all of them
}

rule SUSP_JAVA_Class_Allatori_Obfuscator_Aug25 {
   meta:
      description = "Detects a relatively small Java class file obfuscated by Allatori Obfuscator"
      author = "Florian Roth"
      reference = "https://www.malwation.com/blog/technical-analysis-of-a-stealth-java-loader-used-in-phishing-campaigns-targeting-turkiye"
      date = "2025-08-07"
      score = 50
      hash1 = "0a7fddd91b332c8daee2c0727b884fc92cfaede02883dbad75f7efc299e884e3"
   strings:
      $x1 = "Obfuscation by Allatori Obfuscator" ascii fullword
   condition:
      uint16(0) == 0x4b50
      and filesize < 500KB
      and $x1
}
