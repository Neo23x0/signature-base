rule MAL_JS_NPM_SupplyChain_Attack_Nov25 {
   meta:
      description = "Detects malicious JavaScript worm bun_environment.js"
      author = "Marius Benthin"
      date = "2025-11-24"
      reference = "https://www.aikido.dev/blog/shai-hulud-strikes-again-hitting-zapier-ensdomains"
      hash = "62ee164b9b306250c1172583f138c9614139264f889fa99614903c12755468d0"
      score = 80
   strings:
      $sa1 = "npm publish"

      $sb1 = "iamcredentials"
      $sb2 = "secretmanager"
      $sb3 = "secretsmanager"
      $sb4 = "-fips."
   condition:
      filesize < 20MB
      and $sa1
      and 2 of ($sb*)
}

rule SUSP_JS_NPM_Sha1_Hulud_Nov25 {
   meta:
      description = "Detects suspicious indicators for Sha1 Hulud worm"
      author = "Marius Benthin"
      date = "2025-11-24"
      reference = "https://www.aikido.dev/blog/shai-hulud-strikes-again-hitting-zapier-ensdomains"
      hash = "62ee164b9b306250c1172583f138c9614139264f889fa99614903c12755468d0"
      score = 60
   strings:
      $x1 = "Sha1-Hulud:"
      $x2 = "SHA1HULUD"
   condition:
      filesize < 20MB
      and 1 of them
}

rule SUSP_JS_NPM_SetupScript_Nov25 {
   meta:
      description = "Detects suspicious JavaScript which exits silently and checks operating system"
      author = "Marius Benthin"
      date = "2025-11-24"
      reference = "https://www.aikido.dev/blog/shai-hulud-strikes-again-hitting-zapier-ensdomains"
      hash = "a3894003ad1d293ba96d77881ccd2071446dc3f65f434669b49b3da92421901a"
      score = 70
   strings:
      $s1 = "require('child_process')"
      $s2 = "process.exit(0)"
      $s3 = "process.platform ==="
      $s4 = "().catch((e"
   condition:
      filesize < 100KB
      and all of them
}

rule MAL_NPM_SupplyChain_Attack_PreInstallScript_Nov25 {
   meta:
      description = "Detects known malicious preinstall script in package.json"
      author = "Marius Benthin"
      date = "2025-11-24"
      reference = "https://www.aikido.dev/blog/shai-hulud-strikes-again-hitting-zapier-ensdomains"
      hash = "c4bc2afd133916f064f2fb7d1e2e067ea65db33463eeae2fa54a9860a6303865"
      score = 80
   strings:
      $x1 = "\"preinstall\": \"node setup_bun.js\""
   condition:
      filesize < 10KB
      and all of them
}
