
rule PowerShell_Susp_Parameter_Combo {
   meta:
      description = "Detects PowerShell invocation with suspicious parameters"
      author = "Florian Roth"
      reference = "https://goo.gl/uAic1X"
      date = "2017-03-12"
      score = 60
      type = "file"
   strings:
      /* Encoded Command */
      $sa1 = " -enc " ascii nocase
      $sa2 = " -EncodedCommand " ascii nocase

      /* Window Hidden */
      $sb1 = " -w hidden " ascii nocase
      $sb2 = " -window hidden " ascii nocase
      $sb3 = " -windowstyle hidden " ascii nocase

      /* Non Profile */
      $sc1 = " -nop " ascii nocase
      $sc2 = " -noprofile " ascii nocase

      /* Non Interactive */
      $sd1 = " -noni " ascii nocase
      $sd2 = " -noninteractive " ascii nocase

      /* Exec Bypass */
      $se1 = " -ep bypass " ascii nocase
      $se2 = " -exec bypass " ascii nocase
      $se3 = " -executionpolicy bypass " ascii nocase
      $se4 = " -exec bypass " ascii nocase

      /* Single Threaded - PowerShell Empire */
      $sf1 = " -sta " ascii

      $fp1 = "Chocolatey Software"
      $fp2 = "VBOX_MSI_INSTALL_PATH"
   condition:
      filesize < 3000KB and 4 of ($s*) and not 1 of ($fp*)
}
