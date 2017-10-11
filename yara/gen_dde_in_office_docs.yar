// YARA rules Office DDE
// NVISO 2017/10/10
// https://sensepost.com/blog/2017/macro-less-code-exec-in-msword/

rule Office_DDEAUTO_field {
   meta:
      description = "Detects DDE in MS Office documents"
      author = "NVISO Labs"
      reference = "https://blog.nviso.be/2017/10/11/detecting-dde-in-ms-office-documents/"
      date = "2017-10-11"
      score = 50
   strings:
      $a = /<w:fldChar\s+?w:fldCharType="begin"\/>.+?DDEAUTO.+?<w:fldChar\s+?w:fldCharType="end"\/>/
   condition:
      $a
}

rule Office_DDE_field {
   meta:
      description = "Detects DDE in MS Office documents"
      author = "NVISO Labs"
      reference = "https://blog.nviso.be/2017/10/11/detecting-dde-in-ms-office-documents/"
      date = "2017-10-11"
      score = 30
   strings:
      $a = /<w:fldChar\s+?w:fldCharType="begin"\/>.+?DDE[^A].+?<w:fldChar\s+?w:fldCharType="end"\/>/
   condition:
      $a
}
