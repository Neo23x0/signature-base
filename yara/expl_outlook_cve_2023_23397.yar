
rule SUSP_EXPL_Msg_CVE_2023_23397_Mar23 {
   meta:
      description = "MSG file with a PidLidReminderFileParameter property, potentially exploiting CVE-2023-23397"
      author = "delivr.to, modified by Florian Roth / Nils Kuhnert"
      date = "2023-03-15"
      modified = "2023-03-16"
      score = 60
      reference = "https://www.mdsec.co.uk/2023/03/exploiting-cve-2023-23397-microsoft-outlook-elevation-of-privilege-vulnerability/"
   strings:
      /* https://interoperability.blob.core.windows.net/files/MS-OXPROPS/%5bMS-OXPROPS%5d.pdf */
      /* PSETID_Appointment */
      $app = { 02 20 06 00 00 00 00 00 C0 00 00 00 00 00 00 46 }
      /* PSETID_Meeting */
      $meeting = { 90 DA D8 6E 0B 45 1B 10 98 DA 00 AA 00 3F 13 05 }
      /* PidLidReminderFileParameter */
      $rfp = { 1F 85 00 00 }
      /* not MSI */
      $fp_msi1 = {84 10 0C 00 00 00 00 00 C0 00 00 00 00 00 00 46}
   condition:
      uint32be(0) == 0xD0CF11E0 and
      uint32be(4) == 0xA1B11AE1 and (
         ( $app in (0..10000) ) or
         ( $meeting in (0..10000) )
      ) 
      and $rfp in (0..10000)
      and not 1 of ($fp*)
}

rule EXPL_SUSP_Outlook_CVE_2023_23397_Exfil_IP_Mar23 {
   meta:
      description = "Detects suspicious .msg file with a PidLidReminderFileParameter property exploiting CVE-2023-23397 (modified delivr.to rule - more specific = less FPs but limited to exfil using IP addresses, not FQDNs)"
      author = "delivr.to, Florian Roth, Nils Kuhnert"
      date = "2023-03-15"
      modified = "2023-03-16"
      score = 75
      reference = "https://www.mdsec.co.uk/2023/03/exploiting-cve-2023-23397-microsoft-outlook-elevation-of-privilege-vulnerability/"
   strings:
      /* https://interoperability.blob.core.windows.net/files/MS-OXPROPS/%5bMS-OXPROPS%5d.pdf */
      /* PSETID_Appointment */
      $app = { 02 20 06 00 00 00 00 00 C0 00 00 00 00 00 00 46 }
      /* PSETID_Meeting */
      $meeting = { 90 DA D8 6E 0B 45 1B 10 98 DA 00 AA 00 3F 13 05 }
      /* PidLidReminderFileParameter */
      $rfp = { 1F 85 00 00 }
      /* \\ + IP UNC path prefix - wide formatted */
      $u1 = { 00 00 5C 00 5C 00 (3? 00 2E|3? 00 3? 00 2E|3? 00 3? 00 3? 00 2E) 00 (3? 00 2E|3? 00 3? 00 2E|3? 00 3? 00 3? 00 2E) 00 (3? 00 2E|3? 00 3? 00 2E|3? 00 3? 00 3? 00 2E) 00 (3? 00|3? 00 3? 00|3? 00 3? 00 3? 00) }
      /* not MSI */
      $fp_msi1 = {84 10 0C 00 00 00 00 00 C0 00 00 00 00 00 00 46}
   condition:
      uint16(0) == 0xCFD0 and (
         ( $app in (0..8000) ) or
         ( $meeting in (0..8000) )
      ) 
      and $rfp in (0..8000)
      and $u1 in (0..8000)
      and not 1 of ($fp*)
}


