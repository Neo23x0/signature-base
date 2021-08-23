rule WEBSHELL_ASPX_XslTransform_Aug21 {
   meta:
      author = "Max Altgelt"
      reference = "https://gist.github.com/JohnHammond/cdae03ca5bc2a14a735ad0334dcb93d6"
      date = "2020-02-23"
      description = "Detects an ASPX webshell utilizing XSL Transformations"
   strings:
      $csharpshell = "Language=\"C#\"" nocase

      $x1 = "<root>1</root>"
      $x2 = ".LoadXml(System.Text.Encoding.UTF8.GetString(System.Convert.FromBase64String("

      $s1 = "XsltSettings.TrustedXslt"
      $s2 = "Xml.XmlUrlResolver"
      $s3 = "FromBase64String(Request[\""
   condition:
      filesize < 500KB and $csharpshell and (1 of ($x*) or all of ($s*))
}
