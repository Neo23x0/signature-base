
rule HKTL_SentinelOne_RemotePotato0_PrivEsc {
   meta:
      author = "SentinelOne"    
      description = "Detects RemotePotato0 binary"
      reference = "https://labs.sentinelone.com/relaying-potatoes-dce-rpc-ntlm-relay-eop"
      date = "2021-04-26"
      id = "f6dffd6b-e794-5c4a-9700-5c2022168f44"
   strings:    
      $import1 = "CoGetInstanceFromIStorage"
      $istorage_clsid = "{00000306-0000-0000-c000-000000000046}" nocase wide ascii    
      $meow_header = { 4d 45 4f 57 }
      $clsid1 = "{11111111-2222-3333-4444-555555555555}" wide ascii
      $clsid2 = "{5167B42F-C111-47A1-ACC4-8EABE61B0B54}" nocase wide ascii
   condition:       
      (uint16(0) == 0x5A4D) and $import1 and $istorage_clsid and $meow_header and 1 of ($clsid*)
}
