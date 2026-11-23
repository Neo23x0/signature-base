/*
    PamStealer "Wavel" variant (macOS infostealer) YARA rules
    Based on: Jamf Threat Labs, "New PamStealer variant targets macOS via fake crypto wallet"
              (published 2026-09-22, analyzed by Thijs Xhaflaire)

    Rule 1 covers the zsh dropper chain (JXA -> zsh -> pkgunpack utility ->
    X25519 key exchange with the C2, magic-tagged DEK wrap).
    Rule 2 covers the rewritten Swift second-stage stealer (r8afup9un0).

    Distinctive anchors (never mixed with generic strings):
      - SNWK1 / SNP1 magic bytes of the DEK wrap / payload envelope
      - "sn-dek-wrap-v1" SHA-256 KDF domain separator
      - "pkgunpack" purpose-built decryption utility
      - "daemon_function" zsh dropper function
      - "# sysnotif-repair" persistence marker comment
      - "_pam_verify_login", "_kc_grab_storage_item", "_sqlite_backup_database"
        exported symbols of the Swift stealer
*/

rule Mal_PamStealer_Wavel_Dropper_Sep26 {
   meta:
      description = "Detects PamStealer 'Wavel' variant (Sept 2026) zsh dropper: pkgunpack X25519 key-exchange chain, SNWK1 DEK wrap, sysnotif-repair persistence markers"
      author = "Haroon Arshad"
      date = "2026-10-16"
      reference = "https://www.jamf.com/blog/pamstealer-wavel-macos-infostealer/"
      score = 85
   strings:
      // Highly distinctive anchors from the dropper / crypto chain
      $m1 = "SNWK1" ascii
      $m2 = "sn-dek-wrap-v1" ascii
      // Dropper logic and markers
      $s1 = "pkgunpack" ascii
      $s2 = "daemon_function" ascii
      $s3 = "wavel.apple03cloudstore.com" ascii
      $s4 = "dek_wrap_b64" ascii
      $s5 = "/v1/loader/dek" ascii
      $s6 = "sysnotif-repair" ascii
      $s7 = "X-Upload-Token" ascii
      $s8 = "JsOsaDAS1.001.00" ascii
      $s9 = ".5ffa071d.zip.lockdir" ascii
      $s10 = "y32me8.com" ascii
   condition:
      filesize < 10MB
      and 1 of ($m*)         // at least one crypto anchor, then
      and 3 of them           // 3 total of all strings keeps FP risk low
}

rule Mal_PamStealer_Wavel_Stage2_Sep26 {
   meta:
      description = "Detects PamStealer 'Wavel' variant (Sept 2026) Swift second-stage stealer r8afup9un0 via exported PAM/keychain symbols and build markers"
      author = "Haroon Arshad"
      date = "2026-10-16"
      reference = "https://www.jamf.com/blog/pamstealer-wavel-macos-infostealer/"
      score = 85
   strings:
      // Exported symbols unique to the rewritten Swift stealer
      $s1 = "_pam_verify_login" ascii
      $s2 = "_kc_grab_storage_item" ascii
      $s3 = "_sqlite_backup_database" ascii
      $s4 = "_MacClient_main" ascii
      $s5 = "r8afup9un0" ascii
      $s6 = "KC_PERSIST_PROMPT" ascii
      $s7 = "SONOMA_DISPLAY_NAME" ascii
      $s8 = "KcHelper" ascii
   condition:
      // FAT Mach-O binary (arm64/x86_64), magic 0xCAFEBABE at offset 0
      uint32(0) == 0xBEBAFECA
      and filesize < 100MB
      and 5 of them
}
