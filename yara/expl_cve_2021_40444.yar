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
      id = "812bb68e-71ea-5a9a-8d39-ab99fdaa6c58"
   strings:
      $b1 = "/relationships/oleObject" ascii 
      $b2 = "/relationships/attachedTemplate" ascii

      $c1 = "Target=\"mhtml:http" nocase
      $c2 = "!x-usc:http" nocase
      $c3 = "TargetMode=\"External\"" nocase
   condition:
      uint32(0) == 0x6D783F3C
      and filesize < 10KB
      and 1 of ($b*)
      and all of ($c*)
}

rule EXPL_MAL_MalDoc_OBFUSCT_MHTML_Sep21_1 {
   meta:
      description = "Detects suspicious office reference files including an obfuscated MHTML reference exploiting CVE-2021-40444"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://twitter.com/decalage2/status/1438946225190014984?s=20"
      date = "2021-09-18"
      score = 90
      hash = "84674acffba5101c8ac518019a9afe2a78a675ef3525a44dceddeed8a0092c69"
      id = "781cfd61-d5ac-58e5-868f-dbd2a2df3500"
   strings:
      $h1 = "<?xml " ascii wide
      $s1 = "109;&#104;&#116;&#109;&#108;&#58;&#104;&#116;&#109;&#108" ascii wide
   condition:
      filesize < 25KB and all of them
}


rule EXPL_XML_Encoded_CVE_2021_40444 {
   meta:
      author = "James E.C, Proofpoint"
      description = "Detects possible CVE-2021-40444 with no encoding, HTML/XML entity (and hex notation) encoding, or all 3"
      reference = "https://twitter.com/sudosev/status/1439205606129377282"
      date = "2021-09-18"
      modified = "2021-09-19"
      score = 70
      hash = "13DE9F39B1AD232E704B5E0B5051800FCD844E9F661185ACE8287A23E9B3868E" // document.xml
      hash = "84674ACFFBA5101C8AC518019A9AFE2A78A675EF3525A44DCEDDEED8A0092C69" // original .docx
      id = "4bf9ec64-c662-5c8f-9e58-12a7412ef07d"
   strings:
      $h1 = "<?xml " ascii wide
      $t_xml_r = /Target[\s]{0,20}=[\s]{0,20}\["']([Mm]|&#(109|77|x6d|x4d);)([Hh]|&#(104|72|x68|x48);)([Tt]|&#(116|84|x74|x54);)([Mm]|&#(109|77|x6d|x4d);)([Ll]|&#(108|76|x6c|x4c);)(:|&#58;|&#x3a)/
      $t_mode_r = /TargetMode[\s]{0,20}=[\s]{0,20}\["']([Ee]|&#(x45|x65|69|101);)([Xx]|&#(x58|x78|88|120);)([Tt]|&#(x74|x54|84|116);)/
   condition:
      filesize < 500KB and $h1 and all of ($t_*)
}

/* not directly related to CVE-2021-40444 */
rule SUSP_OBFUSC_Indiators_XML_OfficeDoc_Sep21_1 : Windows CVE {
   meta:
      author = "Florian Roth (Nextron Systems)"
      description = "Detects suspicious encodings in fields used in reference files found in weaponized MS Office documents"
      reference = "https://twitter.com/sudosev/status/1439205606129377282"
      date = "2021-09-18"
      score = 65
      hash = "13DE9F39B1AD232E704B5E0B5051800FCD844E9F661185ACE8287A23E9B3868E" // document.xml
      hash = "84674ACFFBA5101C8AC518019A9AFE2A78A675EF3525A44DCEDDEED8A0092C69" // original .docx
      id = "ffcaf270-f574-5692-90e5-6776c34eb71b"
   strings:
      $h1 = "<?xml " ascii wide

      $xml_e = "Target=\"&#" ascii wide
      $xml_mode_1 = "TargetMode=\"&#" ascii wide
   condition:
      filesize < 500KB and $h1 and 1 of ($xml*)
}

rule SUSP_OBFUSC_Indiators_XML_OfficeDoc_Sep21_2 : Windows CVE {
   meta:
      author = "Florian Roth (Nextron Systems)"
      description = "Detects suspicious encodings in fields used in reference files found in weaponized MS Office documents"
      reference = "https://twitter.com/sudosev/status/1439205606129377282"
      date = "2021-09-18"
      score = 65
      id = "c3c5ec4f-5d2a-523c-bd4b-b75c04bac87d"
   strings:
      $h1 = "<?xml " ascii wide
      $a1 = "Target" ascii wide
      $a2 = "TargetMode" ascii wide
      $xml_e = "&#x0000" ascii wide
   condition:
      filesize < 500KB and all of them
}
