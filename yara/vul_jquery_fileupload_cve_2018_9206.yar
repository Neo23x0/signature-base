rule VUL_JQuery_FileUpload_CVE_2018_9206 {
   meta:
      description = "Detects JQuery File Upload vulnerability CVE-2018-9206"
      author = "Florian Roth"
      reference = "https://www.zdnet.com/article/zero-day-in-popular-jquery-plugin-actively-exploited-for-at-least-three-years/"
      reference2 = "https://github.com/blueimp/jQuery-File-Upload/commit/aeb47e51c67df8a504b7726595576c1c66b5dc2f"
      reference3 = "https://blogs.akamai.com/sitr/2018/10/having-the-security-rug-pulled-out-from-under-you.html"
      date = "2018-10-19"
   strings:
      $s1 = "error_reporting(E_ALL | E_STRICT);" fullword ascii
      $s2 = "require('UploadHandler.php');" fullword ascii
      $s3 = "$upload_handler = new UploadHandler();" fullword ascii
   condition:
      all of them
}
