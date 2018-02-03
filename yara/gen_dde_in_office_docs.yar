
// YARA rules Office DDE
// NVISO 2017/10/10 - 2017/10/12
// https://sensepost.com/blog/2017/macro-less-code-exec-in-msword/

/* slowing down scanning
rule Office_DDEAUTO_field {
   meta:
      description = "Detects DDE in MS Office documents"
      author = "NVISO Labs"
      reference = "https://blog.nviso.be/2017/10/11/detecting-dde-in-ms-office-documents/"
      date = "2017-10-12"
      score = 60
   strings:
      $a = /<w:fldChar\s+?w:fldCharType="begin"\/>.{1,1000}?\b[Dd][Dd][Ee][Aa][Uu][Tt][Oo]\b.{1,1000}?<w:fldChar\s+?w:fldCharType="end"\/>/
   condition:
      $a
}

rule Office_DDE_field {
   meta:
      description = "Detects DDE in MS Office documents"
      author = "NVISO Labs"
      reference = "https://blog.nviso.be/2017/10/11/detecting-dde-in-ms-office-documents/"
      date = "2017-10-12"
      score = 40
   strings:
      $a = /<w:fldChar\s+?w:fldCharType="begin"\/>.+?\b[Dd][Dd][Ee]\b.+?<w:fldChar\s+?w:fldCharType="end"\/>/
   condition:
      $a
}
*/

rule Office_OLE_DDEAUTO {
   meta:
      description = "Detects DDE in MS Office documents"
      author = "NVISO Labs"
      reference = "https://blog.nviso.be/2017/10/11/detecting-dde-in-ms-office-documents/"
      date = "2017-10-12"
      score = 50
   strings:
      $a = /\x13\s*DDEAUTO\b[^\x14]+/ nocase
   condition:
      uint32be(0) == 0xD0CF11E0 and $a
}

rule Office_OLE_DDE {
   meta:
      description = "Detects DDE in MS Office documents"
      author = "NVISO Labs"
      reference = "https://blog.nviso.be/2017/10/11/detecting-dde-in-ms-office-documents/"
      date = "2017-10-12"
      score = 50
   strings:
      $a = /\x13\s*DDE\b[^\x14]+/ nocase
   condition:
      uint32be(0) == 0xD0CF11E0 and $a
}
