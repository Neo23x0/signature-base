
/*
   Yara Rule Set
   Author: Florian Roth
   Date: 2017-07-10
   Identifier: Hacking Attempts
   Reference: https://blogs.rsa.com/wp-content/uploads/2017/07/Fig8-netstat_dropped_more.png
*/

/* Rule Set ----------------------------------------------------------------- */

rule Recon_Commands_Windows_Gen1 {
   meta:
      description = "Detects a set of reconnaissance commands on Windows systems"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-07-10"
      score = 60
      reference = "https://goo.gl/MSJCxP"
   strings:
      $s1 = "netstat -an" ascii
      $s2 = "net view" ascii fullword
      $s3 = "net user" ascii fullword
      $s4 = "whoami" ascii
      $s5 = "tasklist /v" ascii
      $s6 = "systeminfo" ascii
      $s7 = "net localgroup administrators" ascii
      $s8 = "net user administrator" ascii
      $s9 = "regedit -e " ascii
      $s10 = "tasklist /svc" ascii
      $s11 = "regsvr32 /s /u " ascii
      $s12 = "CreateObject(\"WScript.Shell\").RegWrite" ascii
      $s13 = "bitsadmin /rawreturn /transfer getfile" ascii
      $s14 = "wmic qfe list full" ascii
      $s15 = "schtasks.exe /create " ascii nocase
      $s16 = "wmic share get" ascii
      $s17 = "wmic nteventlog get" ascii
      $s18 = "wevtutil cl " ascii
      $s19 = "sc query type= service" ascii
      $s20 = "arp -a " ascii

      $fp1 = "avdapp.dll" fullword wide
   condition:
      filesize < 1000KB and 4 of them
      and not 1 of ($fp*)
}
