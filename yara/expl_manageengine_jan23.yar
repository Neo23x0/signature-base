
rule EXPL_ManageEngine_CVE_2022_47966_Jan23_1 {
   meta:
      description = "Detects indicators of exploitation of ManageEngine vulnerability as described by Horizon3"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.horizon3.ai/manageengine-cve-2022-47966-iocs/"
      date = "2023-01-13"
      score = 75
      id = "07535b9c-8611-5a46-bcd7-f94070de2aea"
   strings:
      $ = "]: com.adventnet.authentication.saml.SamlException: Signature validation failed. SAML Response rejected|"
   condition:
      1 of them
}

