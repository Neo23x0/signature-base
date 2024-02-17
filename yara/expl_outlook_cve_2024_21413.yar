
rule EXPL_CVE_2024_21413_Microsoft_Outlook_RCE_Feb24 {
   meta:
      description = "Detects emails that contain signs of a method to exploit CVE-2024-21413 in Microsoft Outlook"
      author = "Florian Roth"
      reference = "https://github.com/xaitax/CVE-2024-21413-Microsoft-Outlook-Remote-Code-Execution-Vulnerability/"
      date = "2024-02-17"
      score = 75
   strings:
      $a1 = "Subject: "
      $a2 = "Received: "

      $xr1 = /href[\s=3D"']{2,20}file:\/\/\/\\\\[^"']{6,200}!/
   condition:
      filesize < 800KB
      and all of ($a*)
      and 1 of ($xr*)
}
