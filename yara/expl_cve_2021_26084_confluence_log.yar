
rule LOG_EXPL_Confluence_RCE_CVE_2021_26084_Sep21 : LOG {
   meta:
      description = "Detects exploitation attempts against Confluence servers abusing a RCE reported as CVE-2021-26084"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://github.com/httpvoid/writeups/blob/main/Confluence-RCE.md"
      date = "2021-09-01"
      score = 55
      id = "bbf98ce4-d32b-541a-b727-bc35c9aaef53"
   strings:
      $xr1 = /isSafeExpression Unsafe clause found in \['[^\n]{1,64}\\u0027/ ascii wide
      $xs1 = "[util.velocity.debug.DebugReferenceInsertionEventHandler] referenceInsert resolving reference [$!queryString]"
      $xs2 = "userName: anonymous | action: createpage-entervariables ognl.ExpressionSyntaxException: Malformed OGNL expression: '\\' [ognl.TokenMgrError: Lexical error at line 1"

      $sa1 = "GET /pages/doenterpagevariables.action"
      $sb1 = "%5c%75%30%30%32%37"
      $sb2 = "\\u0027"

      $sc1 = " ERROR "
      $sc2 = " | userName: anonymous | action: createpage-entervariables"
      $re1 = /\[confluence\.plugins\.synchrony\.SynchronyContextProvider\] getContextMap (\n )?-- url: \/pages\/createpage-entervariables\.action/
   condition:
      1 of ($x*) or ( $sa1 and 1 of ($sb*) ) or (all of ($sc*) and $re1)
}
