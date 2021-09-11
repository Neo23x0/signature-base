/*
   Modified rule of Jeremy Brown
   see my video: https://www.youtube.com/watch?v=53gpfmKFxr4
*/

rule EXPL_CVE_2021_40444_Document_Rels_XML {
   meta:
      description = "Detects indicators found in weaponized documents that exploit CVE-2021-40444"
      author = "Jeremy Brown / @alteredbytes"
      reference = "https://twitter.com/AlteredBytes/status/1435811407249952772"
      date = "2021-09-10"
   strings:
      $b1 = "/relationships/oleObject" ascii 
      $b2 = "/relationships/attachedTemplate" ascii

      $c1 = "Target=\"mhtml:http" nocase
      $c2 = "!x-usc:http" nocase
      $c3 = "TargetMode=\"External\"" nocase
   condition:
      uint32(0) == 0x6D783F3C
      and filesize < 5KB
      and 1 of ($b*)
      and all of ($c*)
}
