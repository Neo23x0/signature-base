
rule MAL_XWorm_Client_Stub_Oct26 {
   meta:
      description = "Detects the XWorm RAT client stub by four plaintext status messages from its own code, including a fixed Content-length header value"
      license = "CC BY 4.0 - https://creativecommons.org/licenses/by/4.0/"
      author = "The Hunters Ledger"
      reference = "https://the-hunters-ledger.com/reports/zerotrace-74-0-42-25-20260316/"
      date = "2026-10-17"
      score = 75
      hash1 = "427f818131c9beb7f8a487cb28fe13e2699db844ac3c9e9ae613fd35113fe77f"
      hash2 = "b7fa1e5cefb7f5ad367271f29bde8558566c17da169b5dac797c79beb3fc4531"
      id = "79ef84ad-1811-5229-81b9-2bc0c0921e1e"
   strings:
      $s1 = "Plugins Removed!" wide
      $s2 = "Modified successfully!" wide
      $s3 = "Plugin Error! " wide
      $s4 = "Content-length: 5235" wide
   condition:
      uint16(0) == 0x5a4d
      and filesize < 150KB
      and all of them
}
