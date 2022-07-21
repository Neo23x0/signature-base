
rule VULN_Confluence_Questions_Plugin_CVE_2022_26138_Jul22_1 {
   meta:
      description = "Detects properties file of Confluence Questions plugin with static user name and password (backdoor) CVE-2022-26138"
      author = "Florian Roth"
      reference = "https://www.bleepingcomputer.com/news/security/atlassian-fixes-critical-confluence-hardcoded-credentials-flaw/"
      date = "2022-07-21"
      score = 50
   strings:
      $ = "predefined.user.password=disabled1system1user6708"
   condition:
      filesize < 30000KB and 1 of them
}
