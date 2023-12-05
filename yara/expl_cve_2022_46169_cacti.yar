rule EXPL_LOG_Cacti_CommandInjection_CVE_2022_46169_Dec22_1 {
   meta:
      description = "Detects potential exploitation attempts that target the Cacti Command Injection CVE-2022-46169"
      author = "Nasreddine Bencherchali"
      score = 70
      reference = "https://github.com/Cacti/cacti/security/advisories/GHSA-6p93-p743-35gf"
      date = "2022-12-27"
      id = "c799a419-87ed-55ea-8ebb-d4da901be4ad"
   strings:
      $xr1 = /\/remote_agent\.php.{1,300}(whoami|\/bin\/bash|\/bin\/sh|\bwget\b|powershell|cmd \/c|cmd\.exe \/c).{1,300} 200 / ascii
   condition:
      $xr1
}
