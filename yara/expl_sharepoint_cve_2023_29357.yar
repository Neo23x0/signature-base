
rule LOG_EXPL_SharePoint_CVE_2023_29357_Sep23_1 {
   meta:
      description = "Detects log entries that could indicate a successful exploitation of CVE-2023-29357 on Microsoft SharePoint servers with the published Python POC"
      author = "Florian Roth (with help from @LuemmelSec)"
      reference = "https://twitter.com/Gi7w0rm/status/1706764212704591953?s=20"
      date = "2023-09-28"
      modified = "2023-09-29"
      score = 70
   strings:
      /* 
         references:
         https://x.com/TH3C0DEX/status/1707503935596925048?s=20 
         https://x.com/theluemmel/status/1707653715627311360?s=20 (plus private chat)
      */
      $xr1 = /GET \/_vti_bin\/client\.svc\/web\/(siteusers|currentuser) - (80|443) .{10,200} python-requests\/[0-9\.]{3,8} - [^4]/
   condition:
      $xr1
}
