
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
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2017-07-10"
      score = 60
      reference = "https://goo.gl/MSJCxP"
      id = "bc95265c-780d-5451-bd12-d14495877e46"
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
      $fp2 = "keyword.command.batchfile" ascii
      $fp3 = ".sublime-settings" ascii
   condition:
      filesize < 1000KB and 4 of them
      and not 1 of ($fp*)
}

rule SUSP_Recon_Outputs_Jun20_1 {
   meta:
      description = "Detects outputs of many different commands often used for reconnaissance purposes"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://securelist.com/cycldek-bridging-the-air-gap/97157/"
      date = "2020-06-04"
      score = 60
      id = "ec3759aa-212f-52ce-9f38-636accd35749"
   strings:
      /* ipconfig /all */
      $s1 = ". . . . : Yes" ascii 
      /* ping */
      $s2 = "with 32 bytes of data:" ascii
      /* arp -a */
      $s3 = "ff-ff-ff-ff-ff-ff     static" ascii
      /* netstat */ 
      $s4 = "  TCP    0.0.0.0:445" ascii 
      /* tasklist */ 
      $s5 = "System Idle Process" ascii
   condition:
      filesize < 150KB and
      4 of them
}
