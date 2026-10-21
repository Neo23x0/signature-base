/*
   DPRK "Contagious Interview" (WaterPlum / UNC5342 cluster) - fake take-home interview chain
   observed 2026-10-21: Vercel-hosted dropper -> EtherHiding loader (Polygon eth_call) ->
   JS RAT/stealer -> key agents, MMC wallet backdoor, NetSupport "Take PC", PrintHost collector,
   App-Bound-Encryption bypass DLL.

   String selection favours artefacts that survive obfuscator.io re-runs (regex literals,
   object property names, destructured identifiers, environment variable names, PE strings)
   over string-array chunks, which change with every obfuscation pass.
*/

rule MAL_APT_NK_ContagiousInterview_JS_Dropper_Stage1_Oct26 {
   meta:
      description = "Detects the obfuscated stage-1 Node.js dropper of a DPRK Contagious Interview chain that writes ~/.vs_cache/{main.js,package.json,main.vbs}, installs dependencies with npm and relaunches through wscript //B or a detached node process"
      author = "Kirill Popov"
      reference = "Internal Research"
      date = "2026-10-21"
      hash1 = "677b85d56283a7c22f7f32350c6d81a7873c6c6afe1ff6b0d5a9608ba9614068"
      score = 80
      id = "70bd70d1-63af-4455-946f-50297de0b35e"
   strings:
      /* argument parsing regex literals - kept verbatim by the obfuscator */
      $r1 = "/^--source=(.*)$/"
      $r2 = "/^[A-Za-z0-9._-]{1,32}$/"

      /* dependency map written into the generated package.json */
      $d1 = "'node-machine-id':'1.1.12'"
      $d2 = "'better-sqlite3':"
      $d3 = "'socket.io-client':"

      /* spawn options / wscript launch */
      $o1 = "'windowsVerbatimArguments':!![]"
      $o2 = "'//B'"

      /* string-array chunks of this build (weak, supporting only) */
      $c1 = ".vs_cach"
      $c2 = "main.vbs"
      $c3 = "@primno/"
      $c4 = "npm-cli."
   condition:
      filesize < 100KB
      and 1 of ($r*)
      and 2 of ($d*)
      and 2 of ($o*, $c*)
}

rule MAL_APT_NK_ContagiousInterview_JS_EtherHiding_Loader_Stage2_Oct26 {
   meta:
      description = "Detects the obfuscated stage-2 EtherHiding loader (~/.vs_cache/main.js) of a DPRK Contagious Interview chain that resolves its C2 through a Polygon eth_call (selector 0x8eaa6ac0) and runs the returned 'sessions' JavaScript through new Function"
      author = "Kirill Popov"
      reference = "Internal Research"
      date = "2026-10-21"
      hash1 = "ada39027d2db8512d4ff2624e827b1ab6ffe3e7e281b1c1325aed85a89364e1f"
      score = 85
      id = "0afb8a01-d0c8-440c-9714-1432145ba524"
   strings:
      /* JSON-RPC eth_call body built as an object literal */
      $rpc1 = "{'jsonrpc':'2.0','id':0x1,'method':"
      $rpc2 = "'params':[{'to':"
      $rpc3 = "'latest'"

      /* zero-address check on the decoded contract result */
      $z1 = "/^0x0{40}$/i"

      /* in-memory execution of the C2 response */
      $x1 = "new Function("
      $x2 = "(require,module,exports,__dirname,__filename)"

      /* function selector, full or as obfuscator chunk */
      $sel1 = "0x8eaa6ac0"
      $sel2 = "'0x8eaa6a'"

      /* RPC host fragments and axios options of this build */
      $h1 = "tenderly"
      $h2 = "1rpc.io/"
      $h3 = "drpc.org"
      $h4 = "polygon-"
      $h5 = ".quiknod"
      $a1 = "'validateStatus':()=>!![]"
      $a2 = "'timeout':0x1388"
      $a3 = "'/session"
   condition:
      filesize < 50KB
      and 1 of ($rpc1, $rpc2)
      and 1 of ($x*)
      and (1 of ($sel*) or $z1)
      and 3 of ($h*, $a*, $rpc3)
}

rule MAL_APT_NK_ContagiousInterview_JSON_VSCodeManifest_Wrapper_Stage3_Oct26 {
   meta:
      description = "Detects the stage-3 C2 response of a DPRK Contagious Interview chain: a JSON document disguised as a VS Code extension manifest whose 'sessions' member carries the obfuscated JavaScript RAT/stealer"
      author = "Kirill Popov"
      reference = "Internal Research"
      date = "2026-10-21"
      hash1 = "7c0074797f21226600cb9acdf558507d3e61bec771762c16fe104faf7aea13bc"
      score = 80
      id = "fa880f4c-077f-4412-b35a-096e9860cccc"
   strings:
      /* the member stage 2 extracts and executes */
      $w1 = /"sessions"\s*:\s*"\(function\(/

      /* VS Code manifest disguise */
      $m1 = "\"publisher\":"
      $m2 = "\"engines\":"
      $m3 = "\"vscode\":"
      $m4 = "\"contributes\":"
      $m5 = "\"activationEvents\":"

      /* stage-3 identifiers that do not depend on backslash escaping */
      $s1 = "VS_BACKUP_CHILD"
      $s2 = "VS_IO_WORKER"
      $s3 = "allowVsCache"
      $s4 = "keyDatasUploaded"
      $s5 = "needsCookieRetry"
      $s6 = "appBoundPresent"
      $s7 = "KEYBOARD_AGENT_NO_AUTO_START"
      $s8 = "allowBrowserExtension"
      $s9 = "hypervisorPresent"
      $s10 = "X-Client-OS"
      $s11 = "/api/mmc"
      $s12 = "ss_nsm"
   condition:
      uint8(0) == 0x7B
      and filesize < 3MB
      and $w1
      and 3 of ($m*)
      and 4 of ($s*)
}

rule MAL_APT_NK_ContagiousInterview_JS_RAT_Stealer_Stage3_Oct26 {
   meta:
      description = "Detects the stage-3 Node.js RAT/credential and wallet stealer of a DPRK Contagious Interview chain, as raw JavaScript or embedded in its JSON wrapper"
      author = "Kirill Popov"
      reference = "Internal Research"
      date = "2026-10-21"
      hash1 = "761e0adb34e6f89ba43fcd65cf861593bfee9319e38e6175394921309e83a254"
      hash2 = "7c0074797f21226600cb9acdf558507d3e61bec771762c16fe104faf7aea13bc"
      score = 85
      id = "c942b9df-c63d-431c-968c-34797eea3610"
   strings:
      /* environment markers for child processes */
      $e1 = "VS_BACKUP_CHILD"
      $e2 = "VS_IO_WORKER"
      $e3 = "KEYBOARD_AGENT_NO_AUTO_START"

      /* state / config property names (survive obfuscation) */
      $p1 = "allowVsCache"
      $p2 = "keyDatasUploaded"
      $p3 = "needsCookieRetry"
      $p4 = "needsLoginRetry"
      $p5 = "appBoundPresent"
      $p6 = "harvestEmitted"
      $p7 = "priorityKeywords"
      $p8 = "allowBrowserExtension"
      $p9 = "envConfidence"
      $p10 = "bigFilesOnly"
      $p11 = "cookieUploaded"
      $p12 = "loginUploaded"
      $p13 = "hypervisorPresent"
      $p14 = "chassisVendor"

      /* operator command names and C2 protocol */
      $c1 = "ss_nsm"
      $c2 = "ss_avc"
      $c3 = "ss_cam"
      $c4 = "X-Client-OS"
      $c5 = "X-Client-Id"
      $c6 = "/api/mmc"

      /* regex bodies used for VM / adapter / SSH / lock detection */
      $r1 = "vmware|vbox|virtualbox|vethernet|hyper-?v|docker|npcap|loopback|bluetooth|vpn|tap-win|tun|virtio|pseudo"
      $r2 = "permission denied|host key verification failed|could not resolve|connection refused"
      $r3 = "MacBook|iMac|Macmini|MacPro|Mac[0-9]|iMacPro|MacStudio"
      $r4 = "S-1-16-12288|High Mandatory Level"
      $r5 = "EBUSY|EPERM|EACCES|EAGAIN|locked|busy|being used"
   condition:
      filesize < 3MB
      and (
         1 of ($e*) and 6 of ($p*) and 2 of ($c*, $r*)
         or 10 of them
      )
}

rule MAL_APT_NK_ContagiousInterview_JS_KeyAgent_Stage4_Oct26 {
   meta:
      description = "Detects the stage-4 Node.js keylogger / clipboard agents (Windows, macOS and Linux builds) of a DPRK Contagious Interview chain"
      author = "Kirill Popov"
      reference = "Internal Research"
      date = "2026-10-21"
      hash1 = "05c138ea816f4ceed7e59be54b7bfe029d6d6c188008657b742f6b0734a5991a"
      hash2 = "9c059cb372e26258d8c5868265a97dc65daf01009521e558ed0fc450171c4ac4"
      hash3 = "e499e99aa0c8e1eaf6363ccb77eef74dcaa21f2e8d29bfbfc6c67f8afaf63a58"
      score = 80
      id = "ad285f1a-9bcc-464a-96c0-e6a3b3f876c6"
   strings:
      /* build-time placeholder for the campaign/client id, default 999 */
      $id1 = "typeof __CLIENT_ID__"
      $id2 = "?__CLIENT_ID__:0x3e7"

      /* exported API and protocol field names */
      $s1 = "'agentIdentityFields':"
      $s2 = "'getClipboardContent':"
      $s3 = "'clipboard_monitoring':"
      $s4 = "'stopCapture':"
      $s5 = "'startCapture'"
      $s6 = "process.env.KEYBOARD_AGENT_NO_AUTO_START"
      $s7 = "instance_username"
      $s8 = "os_version_label"
      $s9 = "instanceUsername"
      $s10 = "osVersionLabel"
      $s11 = "AGENT_TOKEN"
      $s12 = "AGENT_LABEL"
      $s13 = "no_auto_start"

      /* OS-specific capture helpers */
      $w1 = "applicationframehost"
      $w2 = "KBDLLHOO"
      $w3 = "hwndCaret"
      $m1 = "MAC_KEY_TEST_HOOKS"
      $m2 = "clipwatcherDownloadBinary"
      $m3 = "open_accessibility_settings"
      $l1 = "KEYBOARD_AGENT_QUIET"
      $l2 = "NEEDRESTART_MODE"
      $l3 = "wl-paste"
   condition:
      filesize < 300KB
      and 1 of ($id*)
      and 7 of ($s*)
      and 1 of ($w*, $m*, $l*)
}

rule MAL_APT_NK_ContagiousInterview_JS_MMC_WalletBackdoor_Oct26 {
   meta:
      description = "Detects the MMC wallet-backdoor JavaScript of a DPRK Contagious Interview chain that patches browser-wallet Service Worker ScriptCache entries to POST wallet passwords to /api/mmc/report"
      author = "Kirill Popov"
      reference = "Internal Research"
      date = "2026-10-21"
      hash1 = "655669d80237628859534fd5b69ba0cee33a85cd81ed458c196760644304970c"
      score = 85
      id = "a663dc79-cef1-4be5-b7e8-97c6ca9af1f2"
   strings:
      /* code constructs - required so that IOC lists and write-ups do not match */
      $k1 = "function patchScriptCacheFile("
      $k2 = "function _maskCrc("
      $k3 = "'.vs_cache', 'mmc.log'"
      $k4 = "headers:{\"content-type\":\"application/json\"},method:\"POST\",body:JSON.stringify({t:"

      $x1 = "/api/mmc/report"
      $x2 = "/api/mmc/progress"

      $s1 = "classic-level.tgz"
      $s2 = "'.mmc.bak'"
      $s3 = "mmc-cdp"
      $s4 = "submitPasswordOrEncryptionKey"
      $s5 = "legacyBackgroundApiService"
      $s6 = "_crc32c"
      $s7 = "\"<trlk>\""
      $s8 = "cache-only payload started"
      $s9 = "MMC_WATCH"
      $s10 = "ScriptCache"

      /* wallet extension ids targeted (MetaMask, Rabby, Trust, Phantom, TronLink per the sample EXT_NAME map) */
      $e1 = "nkbihfbeogaeaoehlefnkodbefgpgknn"
      $e2 = "acmacodkjbdgmoleebolmdjonilkdbch"
      $e3 = "egjidjbpglichdcondbcbdnbeeppgdph"
      $e4 = "bfnaelmomeimhlpmgjnjophhpkkoljpa"
      $e5 = "ibnejdfjmmkpcnlpebklmnkoeoihofec"
   condition:
      filesize < 1MB
      and 2 of ($k*)
      and 1 of ($x*)
      and 4 of ($s*, $e*)
}

rule MAL_APT_NK_ContagiousInterview_NetSupport_Client32_INI_Oct26 {
   meta:
      description = "Detects the NetSupport Manager client32.ini used by a DPRK Contagious Interview chain for silent remote control, either as delivered (SettingSync\\Caches\\...\\Win32\\ResCache masquerade path) or after the gateways of this campaign were written into it"
      author = "Kirill Popov"
      reference = "Internal Research"
      date = "2026-10-21"
      hash1 = "f690697aa10cef4ac647fff4d2672e93a1a19d1a3db723530e1eebec04a16ce7"
      score = 75
      id = "bf402bf1-48f6-4edb-aca8-74faa49a4b0c"
   strings:
      $h1 = "[Client]"
      $h2 = "[HTTP]"

      /* silent, no tray, no disconnect */
      $c1 = "silent=1"
      $c2 = "SysTray=0"
      $c3 = "DisableDisconnect=1"
      $c4 = "DisableClientConnect=1"
      $c5 = "ShowUIOnConnect=0"
      $c6 = "Usernames=*"

      /* masquerade install path */
      $p1 = "\\SettingSync\\Caches\\"
      $p2 = "\\Win32\\ResCache\\client32.ini"

      /* gateways and gateway security key served by /nsm-config */
      $g1 = "80.190.79.39"
      $g2 = "147.124.202.170"
      $g3 = "FC;J@EEJ9O?EDH9L>DBIGJ=ABCGF<A"
   condition:
      filesize < 20KB
      and all of ($h*)
      and 4 of ($c*)
      and 1 of ($p*, $g*)
}

rule MAL_APT_NK_ContagiousInterview_NetSupport_NSM_LIC_Oct26 {
   meta:
      description = "Detects the cracked NetSupport Manager licence file (licensee and serial NSM1234) shipped in the nsm-portable.zip of a DPRK Contagious Interview chain"
      author = "Kirill Popov"
      reference = "Internal Research"
      date = "2026-10-21"
      hash1 = "53b4a9603905e7838842694a90549362d9ec25b6d22e1c4f3d6c14e040c7a76c"
      score = 70
      id = "4d7ea96d-3c1e-4cf7-b443-e343632f3920"
   strings:
      $a1 = "NetSupport License File"
      $a2 = "[_License]"
      $s1 = "licensee=NSM1234"
      $s2 = "serial_no=NSM1234"
      $s3 = "maxslaves=9999"
      $s4 = "; Generated on 11:59 - 11/02/2026"
   condition:
      filesize < 4KB
      and all of ($a*)
      and 2 of ($s*)
}

rule MAL_APT_NK_ContagiousInterview_PrintHost_Collector_Oct26 {
   meta:
      description = "Detects the native 'Print Spool Host' collector (PrintHost.exe / SpoolHelp.exe) of a DPRK Contagious Interview chain, which resolves its C2 through a Polygon contract (EtherHiding) and uploads keylog, clipboard and screenshot buffers"
      author = "Kirill Popov"
      reference = "Internal Research"
      date = "2026-10-21"
      hash1 = "365315e31354b811f8ea537417ff4e0938862a409be434c9a3ff821d57dff384"
      score = 85
      id = "801e8e6a-c249-4304-99f3-91a439072349"
   strings:
      /* campaign-unique values */
      $x1 = "0xb5a3db644aad5124b17BF96c3782D5d7623b89fD" wide
      $x2 = "0Sq7K3M7XX6H6L5okChXUbPr-iTQAZdg38ptPFtHJ3I" wide
      $x3 = "summer-bitter-slug.matic.quiknode.pro" ascii wide

      /* EtherHiding resolver */
      $e1 = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"eth_call\",\"params\":[{\"to\":\"" ascii wide
      $e2 = "0x8eaa6ac0" ascii wide
      $e3 = "TeamEndpoint lookup failed on all nodes" wide

      /* masquerade identity and synchronisation objects */
      $s1 = "Print Spool Host v%s" wide
      $s2 = "PrintSpoolHostWnd" wide
      $s3 = "Local\\PrintSpoolHost_Running" wide
      $s4 = "Local\\PrintSpoolHost_Stop2" wide
      $s5 = "Local\\PrintSpoolHost_Flush" wide
      $s6 = "Microsoft\\Windows\\PrintHost" wide
      $s7 = "PrintSpoolHost/1.0" wide
      $s8 = "PrintSpoolInputSvc" wide
      $s9 = "name=\"Harborline.PrintHost\""

      /* collector protocol */
      $c1 = "X-Collector-Token: " wide
      $c2 = "X-Machine-Id: " wide
      $c3 = "/api/client/identify" wide
      $c4 = "/api/client/upload-screenshot" wide
      $c5 = "/api/client/collect-progress" wide
      $c6 = "\\buffer\\keylog" wide
      $c7 = "\\buffer\\clipboard" wide
   condition:
      uint16(0) == 0x5A4D
      and filesize < 5MB
      and (
         1 of ($x*) and 2 of ($e*, $s*, $c*)
         or 1 of ($e*) and 3 of ($s*) and 3 of ($c*)
         or 4 of ($s*) and 4 of ($c*)
      )
}

rule MAL_APT_NK_ContagiousInterview_ABE_Bypass_DLL_Oct26 {
   meta:
      description = "Detects the Chromium App-Bound-Encryption bypass DLL (abe_payload.dll) of a DPRK Contagious Interview chain, which calls the browser elevation-service COM object from inside the browser process and reports through ABE_* environment variables and a .status.txt file"
      author = "Kirill Popov"
      reference = "Internal Research"
      date = "2026-10-21"
      hash1 = "47a76888121a06bf9d56313b21be269a3b5acb32a7c25c0ef8c4739e219c27ce"
      score = 80
      id = "3ba512c6-ed28-44de-b80e-583bbd4126b0"
   strings:
      /* hand-off environment variables and status file */
      $v1 = "ABE_IN" ascii fullword
      $v2 = "ABE_OUT" ascii fullword
      $v3 = "ABE_CLSID" ascii fullword
      $v4 = "ABE_IID" ascii fullword
      $v5 = ".status.txt" ascii

      /* status-line formats */
      $f1 = "stage=cocreate edge=%d" ascii
      $f2 = "decrypt_fail iid=%d slot=%d lastErr=%u" ascii
      $f3 = "qi_fail iid=%d hr=0x%08X try_direct" ascii
      $f4 = "ok iid=%d slot=%d lastErr=%u" ascii
      $f5 = "err=bad_clsid" ascii

      /* Chrome / Edge elevation-service CLSIDs as strings (shared with public ABE tools) */
      $g1 = "708860E0-F641-4611-8895-7D867DD3675B" ascii
      $g2 = "1FCBE96C-1697-43AF-9140-2897C7C69767" ascii
   condition:
      uint16(0) == 0x5A4D
      and filesize < 200KB
      and (
         2 of ($f*) and 2 of ($v*)
         or 1 of ($f*) and 3 of ($v*) and 1 of ($g*)
      )
}
