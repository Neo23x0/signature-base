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

rule MAL_MalDoc_OBFUSCT_MHTML_Sep21_1 {
   meta:
      description = "Detects suspicious office reference files including an obfuscated MHTML reference exploiting CVE-2021-40444"
      author = "Florian Roth"
      reference = "https://twitter.com/decalage2/status/1438946225190014984?s=20"
      date = "2021-09-18"
      score = 90
      hash = "84674acffba5101c8ac518019a9afe2a78a675ef3525a44dceddeed8a0092c69"
   strings:
      $h1 = "<?xml " ascii
      $s1 = "109;&#104;&#116;&#109;&#108;&#58;&#104;&#116;&#109;&#108" ascii
   condition:
      filesize < 25KB and all of them
}
