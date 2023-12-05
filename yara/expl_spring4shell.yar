/* Old webshell rule from THOR's signature set - donation to the community */ 
rule WEBSHELL_JSP_Nov21_1 {
   meta:
      description = "Detects JSP webshells"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.ic3.gov/Media/News/2021/211117-2.pdf"
      date = "2021-11-23"
      score = 70
      id = "117eed28-c44e-5983-b4c7-b555fc06d923"
   strings:
      $x1 = "request.getParameter(\"pwd\")" ascii
      $x2 = "excuteCmd(request.getParameter(" ascii
      $x3 = "getRuntime().exec (request.getParameter(" ascii
      $x4 = "private static final String PW = \"whoami\"" ascii
   condition:
      filesize < 400KB and 1 of them
}

rule EXPL_POC_SpringCore_0day_Indicators_Mar22_1 {
   meta:
      description = "Detects indicators found after SpringCore exploitation attempts and in the POC script"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://twitter.com/vxunderground/status/1509170582469943303"
      date = "2022-03-30"
      score = 70
      id = "297e4b57-f831-56e0-a391-1ffbc9a4d438"
   strings:
      $x1 = "java.io.InputStream%20in%20%3D%20%25%7Bc1%7Di"
      $x2 = "?pwd=j&cmd=whoami"
      $x3 = ".getParameter(%22pwd%22)"
      $x4 = "class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7B"
   condition:
      1 of them
}

rule EXPL_POC_SpringCore_0day_Webshell_Mar22_1 {
   meta:
      description = "Detects webshell found after SpringCore exploitation attempts POC script"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://twitter.com/vxunderground/status/1509170582469943303"
      date = "2022-03-30"
      score = 70
      id = "e7047c98-3c60-5211-9ad5-2bfdfb35d493"
   strings:
      $x1 = ".getInputStream(); int a = -1; byte[] b = new byte[2048];"
      $x2 = "if(\"j\".equals(request.getParameter(\"pwd\")"
      $x3 = ".getRuntime().exec(request.getParameter(\"cmd\")).getInputStream();"
   condition:
     filesize < 200KB and 1 of them
}
