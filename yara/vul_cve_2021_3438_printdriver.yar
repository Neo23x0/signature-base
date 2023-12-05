
import "pe"

rule VULN_PrinterDriver_PrivEsc_CVE_2021_3438_Jul21 {
   meta:
      description = "Detects affected drivers with PE timestamps older than the date of the initial report"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://labs.sentinelone.com/cve-2021-3438-16-years-in-hiding-millions-of-printers-worldwide-vulnerable/"
      date = "2021-07-20"
      score = 70
      hash1 = "7cc9ba2df7b9ea6bb17ee342898edd7f54703b93b6ded6a819e83a7ee9f938b4"
      id = "34cd648a-3e3f-5832-8abe-18507931eb3d"
   strings:
      $s1 = "This String is from Device Driver@@@@@ !!!" ascii 
      $s2 = "\\DosDevices\\ssportc" wide fullword
   condition:
      uint16(0) == 0x5a4d
      and filesize < 400KB
      and all of ($s*)
      /* date of the initial report by SentinelOne */
      and 1613606400 >= pe.timestamp
}
