rule MAL_APT_BlueNoroff_FakeMeeting_JS_Kit {
   meta:
      author = "farbodghasemlu"
      description = "Detects the BlueNoroff (DPRK) fake Zoom/Teams meeting ClickFix kit JavaScript bundle"
      reference = "https://www.jumpsec.com/guides/inside-a-dprk-bluenoroff-clickfix-kit/"
      date = "2026-09-01"
      score = 75
      id = "a48d4cb6-e955-4aa8-8bb8-ebce684987f2"
      hash1 = "e2ac3ee6366d38ae0f87d72cec86044516d41f8bbfbc853d0275315cfc598f6e"
      hash2 = "0e69a1cc83d85f4c9fe0c6845b7db007435613c4353260685077186073006233"
      hash3 = "423fef87e61c62b8a07e21f501114881858c8a90464a01db44d94066791e177c"
   strings:
      $tok  = "sahfuehf29385hsdfuiewhf" ascii wide
      $pwd  = "9jXK14VFM8fObdKxfkake8tD" ascii wide
      $mod1 = "executeLinkFromDownUrl" ascii wide
      $mod2 = "refreshRoomExecuteUrlFromDownUrl" ascii wide
      $mod3 = "room-down-url" ascii wide
      $env1 = "MEETING_SDK_VERSION" ascii wide
      $env2 = "AUTH_API_TOKEN" ascii wide
      $ha   = "host-action" ascii wide
      $ms   = "mediasoup" ascii wide
   condition:
      filesize > 100KB and filesize < 8MB
      and (
         any of ($tok, $pwd)
         or ( 2 of ($mod*) and 1 of ($env*) )
         or ( all of ($env*) and $ha and $ms )
      )
}
