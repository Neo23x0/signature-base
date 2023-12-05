
rule LOG_EXPL_SharePoint_CVE_2023_29357_Sep23_1 {
   meta:
      description = "Detects log entries that could indicate a successful exploitation of CVE-2023-29357 on Microsoft SharePoint servers with the published Python POC"
      author = "Florian Roth (with help from @LuemmelSec)"
      reference = "https://twitter.com/Gi7w0rm/status/1706764212704591953?s=20"
      date = "2023-09-28"
      modified = "2023-10-01"
      score = 70
      id = "9fa77216-c0d6-55e5-bbcc-adb9438ca456"
   strings:
      /* 
         references:
         https://x.com/TH3C0DEX/status/1707503935596925048?s=20 
         https://x.com/theluemmel/status/1707653715627311360?s=20 (plus private chat)
      */
      $xr1 = /GET [a-z\.\/_]{0,40}\/web\/(siteusers|currentuser) - (80|443) .{10,200} (python-requests\/[0-9\.]{3,8}|-) [^ ]{1,160} [^4]0[0-9] /
   condition:
      $xr1
}

rule HKTL_EXPL_POC_PY_SharePoint_CVE_2023_29357_Sep23_1 {
   meta:
      description = "Detects a Python POC to exploit CVE-2023-29357 on Microsoft SharePoint servers"
      author = "Florian Roth"
      reference = "https://github.com/Chocapikk/CVE-2023-29357"
      date = "2023-10-01"
      modified = "2023-10-01"
      score = 80
      id = "2be524ab-f360-56b8-9ce3-e15036855c67"
   strings:
      $x1 = "encoded_payload = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b'=')"
   condition:
      filesize < 30KB and $x1
}

rule HKTL_EXPL_POC_NET_SharePoint_CVE_2023_29357_Sep23_1 {
   meta:
      description = "Detects a C# POC to exploit CVE-2023-29357 on Microsoft SharePoint servers"
      author = "Florian Roth"
      reference = "https://github.com/LuemmelSec/CVE-2023-29357"
      date = "2023-10-01"
      score = 80
      id = "aa6aeb00-b162-538c-a670-cbff525dd8f1"
   strings:
      $x1 = "{f22d2de0-606b-4d16-98d5-421f3f1ba8bc}" ascii wide
      $x2 = "{F22D2DE0-606B-4D16-98D5-421F3F1BA8BC}" ascii wide

      $s1 = "Bearer"
      $s2 = "hashedprooftoken"
      $s3 = "/_api/web/"
      $s4 = "X-PROOF_TOKEN"
      $s5 = "00000003-0000-0ff1-ce00-000000000000"
      $s6 = "IsSiteAdmin"
   condition:
      uint16(0) == 0x5a4d
      and filesize < 800KB 
      and (
         1 of ($x*)
         or all of ($s*)
      )
}


