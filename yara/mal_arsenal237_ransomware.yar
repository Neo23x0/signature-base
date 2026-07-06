/*
   Yara Rule Set
   Identifier: Arsenal-237 Ransomware Suite (enc_c2, new_enc, full_test_enc, dec_fixed, nethost, chromelevator)
   Author: The Hunters Ledger
   Source: https://pixelatedcontinuum.github.io/Threat-Intel-Reports/
   License: CC BY-NC 4.0 - https://creativecommons.org/licenses/by-nc/4.0/
*/

rule Chromelevator_Browser_Credential_Extraction {
   meta:
      description = "Detects Arsenal-237 chromelevator.exe browser credential extraction tool targeting Chrome, Brave, and Edge via reflective DLL injection"
      license = "CC BY-NC 4.0 - https://creativecommons.org/licenses/by-nc/4.0/"
      author = "The Hunters Ledger"
      reference = "https://pixelatedcontinuum.github.io/Threat-Intel-Reports/hunting-detections/arsenal-237-chromelevator-exe/"
      date = "2026-01-26"
      family = "Arsenal-237"
      id = "6b23aa0e-8604-538e-9dbd-5b70fd18bd65"
   strings:
      $filename = "chromelevator.exe" nocase ascii
      $payload = "PAYLOAD_DLL" nocase ascii
      $chrome = "chrome.exe" nocase ascii
      $brave = "brave.exe" nocase ascii
      $edge = "msedge.exe" nocase ascii
      $named_pipe = "Named pipe server created" nocase ascii
      $reflective = "ReflectiveLoader" nocase ascii
      $extraction = "Extracted" nocase ascii
      $cookies = "cookies" nocase ascii
      $passwords = "passwords" nocase ascii
      $payments = "payments" nocase ascii
      $verbose = "--verbose" nocase ascii
      $fingerprint = "--fingerprint" nocase ascii
      $output = "--output-path" nocase ascii
      $create_pipe = "CreateNamedPipeW" nocase ascii
      $connect_pipe = "ConnectNamedPipe" nocase ascii
      $find_resource = "FindResourceW" nocase ascii
      $load_resource = "LoadResource" nocase ascii
   condition:
      ($filename and $payload and ($extraction or ($cookies and $passwords))) or
      (3 of ($chrome, $brave, $edge) and 2 of ($extraction, $cookies, $passwords, $payments)) or
      ($reflective and $named_pipe and any of ($chrome, $brave, $edge) and 2 of ($create_pipe, $connect_pipe, $find_resource, $load_resource)) or
      (2 of ($verbose, $fingerprint, $output) and any of ($chrome, $brave, $edge))
}

rule Arsenal237_Direct_Syscall_Framework {
   meta:
      description = "Detects Arsenal-237 direct syscall EDR bypass framework using Zw* Native API calls to avoid EDR hooking"
      license = "CC BY-NC 4.0 - https://creativecommons.org/licenses/by-nc/4.0/"
      author = "The Hunters Ledger"
      reference = "https://pixelatedcontinuum.github.io/Threat-Intel-Reports/hunting-detections/arsenal-237-chromelevator-exe/"
      date = "2026-01-26"
      family = "Arsenal-237"
      id = "4eb2e9e0-7633-5af4-8a6e-ee93245b6f23"
   strings:
      $zw_alloc = "ZwAllocateVirtualMemory" nocase ascii
      $zw_write = "ZwWriteVirtualMemory" nocase ascii
      $zw_read = "ZwReadVirtualMemory" nocase ascii
      $zw_protect = "ZwProtectVirtualMemory" nocase ascii
      $zw_create_thread = "ZwCreateThreadEx" nocase ascii
      $zw_open_proc = "ZwOpenProcess" nocase ascii
      $zw_query_proc = "ZwQueryInformationProcess" nocase ascii
      $zw_context = "ZwGetContextThread" nocase ascii
      $zw_set_context = "ZwSetContextThread" nocase ascii
      $zw_resume = "ZwResumeThread" nocase ascii
      $zw_pattern = /Zw[A-Z][a-zA-Z]+/
   condition:
      (5 of ($zw_alloc, $zw_write, $zw_protect, $zw_create_thread, $zw_open_proc)) or
      (all of them and #zw_pattern >= 10)
}

rule Reflective_DLL_Injection_Framework {
   meta:
      description = "Detects reflective DLL injection implementation using ReflectiveLoader with direct syscall or Win32 API injection pattern"
      license = "CC BY-NC 4.0 - https://creativecommons.org/licenses/by-nc/4.0/"
      author = "The Hunters Ledger"
      reference = "https://pixelatedcontinuum.github.io/Threat-Intel-Reports/hunting-detections/arsenal-237-chromelevator-exe/"
      date = "2026-01-26"
      family = "Arsenal-237"
      id = "4a88262f-f5b3-568c-b25a-3f54412b4ffc"
   strings:
      $dos_header = "MZ"
      $reflective_loader = "ReflectiveLoader" nocase ascii
      $reflective_export = "reflective" nocase ascii wide
      $alloc = "VirtualAllocEx" nocase ascii
      $write = "WriteProcessMemory" nocase ascii
      $protect = "VirtualProtectEx" nocase ascii
      $create_remote = "CreateRemoteThread" nocase ascii
      $zw_alloc = "ZwAllocateVirtualMemory" nocase ascii
      $zw_write = "ZwWriteVirtualMemory" nocase ascii
      $zw_protect = "ZwProtectVirtualMemory" nocase ascii
      $zw_create = "ZwCreateThreadEx" nocase ascii
   condition:
      (($reflective_loader or $reflective_export) and $dos_header at 0) or
      ($reflective_loader and all of ($zw_alloc, $zw_write, $zw_protect, $zw_create)) or
      ($reflective_loader and all of ($alloc, $write, $protect, $create_remote))
}

rule Arsenal237_Victim_Key_Decryptor {
   meta:
      description = "Detects Arsenal-237 dec_fixed.exe victim-specific hardcoded ChaCha20 decryption key matching new_enc.exe encryption key"
      license = "CC BY-NC 4.0 - https://creativecommons.org/licenses/by-nc/4.0/"
      author = "The Hunters Ledger"
      reference = "https://pixelatedcontinuum.github.io/Threat-Intel-Reports/hunting-detections/arsenal-237-dec_fixed-exe/"
      date = "2026-01-26"
      family = "Arsenal-237"
      malware_type = "Ransomware Decryptor"
      id = "e63e8167-3810-595e-a52d-1d85251278aa"
   strings:
      $key1 = "1e0d8597856270d1926cfcf252af1b14a776c20b3b50168df9311314202e73ba" nocase ascii
      $key2 = "67e6096a85ae67bb72f36e3c3af54fa57f520e518c68059babd9831f19cde05b" nocase ascii
   condition:
      1 of them
}

rule Arsenal237_ChaCha20_Decryption {
   meta:
      description = "Detects Arsenal-237 dec_fixed.exe ChaCha20-Poly1305 AEAD decryption implementation with key validation error strings"
      license = "CC BY-NC 4.0 - https://creativecommons.org/licenses/by-nc/4.0/"
      author = "The Hunters Ledger"
      reference = "https://pixelatedcontinuum.github.io/Threat-Intel-Reports/hunting-detections/arsenal-237-dec_fixed-exe/"
      date = "2026-01-26"
      family = "Arsenal-237"
      malware_type = "Ransomware Decryptor"
      id = "fd58d054-fcba-5acb-9fc2-3b8760897fba"
   strings:
      $constant1 = "expand 32-byte k" ascii nocase
      $error1 = "Decryption failed - wrong key or corrupted file" ascii
      $error2 = "File corrupted - encrypted size mismatch" ascii
   condition:
      $constant1 and any of ($error1, $error2)
}

rule Arsenal237_Decryptor_Tool {
   meta:
      description = "Detects Arsenal-237 dec_fixed.exe batch file decryptor with --folder-a parameter and characteristic error message strings"
      license = "CC BY-NC 4.0 - https://creativecommons.org/licenses/by-nc/4.0/"
      author = "The Hunters Ledger"
      reference = "https://pixelatedcontinuum.github.io/Threat-Intel-Reports/hunting-detections/arsenal-237-dec_fixed-exe/"
      date = "2026-01-26"
      family = "Arsenal-237"
      malware_type = "Ransomware Decryptor"
      id = "1eaf0468-4677-509b-b617-76b521e34965"
   strings:
      $cmd1 = "--folder-a" ascii
      $error1 = "File too small" ascii
      $error2 = "Could not find filename" ascii
      $error3 = "Invalid victim key hex" ascii
      $cleanup = "readme.txt" ascii nocase
   condition:
      $cmd1 and 2 of ($error1, $error2, $error3) and $cleanup
}

rule Arsenal237_Rust_Compiled_Tools {
   meta:
      description = "Detects Arsenal-237 Rust-compiled ransomware tools (encryptors and decryptors) by ChaCha20-Poly1305 library strings and file size"
      license = "CC BY-NC 4.0 - https://creativecommons.org/licenses/by-nc/4.0/"
      author = "The Hunters Ledger"
      reference = "https://pixelatedcontinuum.github.io/Threat-Intel-Reports/hunting-detections/arsenal-237-dec_fixed-exe/"
      date = "2026-01-26"
      family = "Arsenal-237"
      malware_type = "Ransomware"
      id = "2d681148-fb9f-57ed-9cb7-b5e46330976c"
   strings:
      $chacha20_lib = "chacha20" ascii nocase
      $poly1305_lib = "poly1305" ascii nocase
      $rust_constant = "expand 32-byte k" ascii
      $rust_error = "Decryption failed" ascii nocase
   condition:
      filesize > 900KB and filesize < 1MB and
      $chacha20_lib and $poly1305_lib and
      $rust_constant and $rust_error
}

rule Arsenal237_nethost_C2_Strings {
   meta:
      description = "Detects Arsenal-237 nethost.dll by hardcoded C2 target strings and environment variable discovery concatenation artifact"
      license = "CC BY-NC 4.0 - https://creativecommons.org/licenses/by-nc/4.0/"
      author = "The Hunters Ledger"
      reference = "https://pixelatedcontinuum.github.io/Threat-Intel-Reports/hunting-detections/arsenal-237-nethost-dll/"
      date = "2026-01-26"
      family = "Arsenal-237"
      malware_type = "C2 Communication Module"
      id = "93e82bff-7142-5af5-9328-ed4a5beb337c"
   strings:
      $c2_targets = "8.8.8.8:53127.0.0.1ntdll.dll" ascii
      $env_discovery = "COMPUTERNAMEUSERNAME" ascii
      $rust_panic = "runtime error" ascii
      $winsock_init = "WSAStartup" ascii
   condition:
      ($c2_targets or ($env_discovery and $rust_panic and $winsock_init)) and uint16(0) == 0x5A4D
}

rule Arsenal237_nethost_PowerShell_Templates {
   meta:
      description = "Detects Arsenal-237 nethost.dll embedded PowerShell command templates for service enumeration, file download, and C2 response parsing"
      license = "CC BY-NC 4.0 - https://creativecommons.org/licenses/by-nc/4.0/"
      author = "The Hunters Ledger"
      reference = "https://pixelatedcontinuum.github.io/Threat-Intel-Reports/hunting-detections/arsenal-237-nethost-dll/"
      date = "2026-01-26"
      family = "Arsenal-237"
      malware_type = "C2 Communication Module"
      id = "635cb72c-b596-58ad-b496-fa3bfc721760"
   strings:
      $ps_service = "Get-Service|?{$_.Status -eq ''}" ascii
      $ps_download = "Invoke-WebRequest -Uri '' -OutFile ''" ascii
      $upload_prefix = "pathB64:" ascii
      $response_keywords = "resultmachine_idsuccess" ascii
   condition:
      3 of them and uint16(0) == 0x5A4D
}

rule Arsenal237_nethost_Winsock_Init {
   meta:
      description = "Detects Arsenal-237 nethost.dll Winsock 2.2 initialization pattern with WSASocket and environment variable enumeration"
      license = "CC BY-NC 4.0 - https://creativecommons.org/licenses/by-nc/4.0/"
      author = "The Hunters Ledger"
      reference = "https://pixelatedcontinuum.github.io/Threat-Intel-Reports/hunting-detections/arsenal-237-nethost-dll/"
      date = "2026-01-26"
      family = "Arsenal-237"
      malware_type = "C2 Communication Module"
      id = "b4d7182c-cf4c-539e-80fc-c083b175e543"
   strings:
      $ws_startup = { C7 ?? ?? 02 02 00 }
      $wsa_socket = "WSASocket" ascii
      $connect_api = "connect" ascii
      $env_vars = "COMPUTERNAME" ascii
   condition:
      all of them and uint16(0) == 0x5A4D
}

rule Arsenal237_nethost_Rust_Indicators {
   meta:
      description = "Detects Arsenal-237 nethost.dll Rust compilation indicators including panic handler and standard library artifacts"
      license = "CC BY-NC 4.0 - https://creativecommons.org/licenses/by-nc/4.0/"
      author = "The Hunters Ledger"
      reference = "https://pixelatedcontinuum.github.io/Threat-Intel-Reports/hunting-detections/arsenal-237-nethost-dll/"
      date = "2026-01-26"
      family = "Arsenal-237"
      malware_type = "C2 Communication Module"
      id = "4620a235-bc72-5683-8f84-3d0f1a499364"
   strings:
      $rust_panic = "rust_panic" ascii
      $rustc_artifact = ".rustc_artifact" ascii
      $rust_std = "std::panic" ascii
      $assertion_fail = "assertion `left  right` failed" ascii
   condition:
      2 of them and uint16(0) == 0x5A4D
}

rule Arsenal237_ChaCha20_Encryption_Constants {
   meta:
      description = "Detects ChaCha20 cipher constants alongside Arsenal-237's specific aead-0.5.2 Rust crate version — combination distinguishes Arsenal-237 from generic ChaCha20 implementations (Tor, WireGuard, OpenSSL, etc.)"
      license = "CC BY-NC 4.0 - https://creativecommons.org/licenses/by-nc/4.0/"
      author = "The Hunters Ledger"
      reference = "https://pixelatedcontinuum.github.io/Threat-Intel-Reports/hunting-detections/arsenal-237-enc_c2-exe/"
      date = "2026-01-26"
      family = "Arsenal-237"
      malware_type = "Ransomware"
      id = "b7c172f4-76e9-52ec-a00c-2d8e5e960766"
   strings:
      $chacha_constant_1 = "expand 32-byte k" ascii
      $chacha_constant_2 = "Chacha_256_constant" ascii
      $chacha_library = "aead-0.5.2" ascii
      $chacha_function = "chacha20" ascii nocase
   condition:
      uint16(0) == 0x5A4D and
      filesize < 20MB and
      $chacha_library and
      2 of them
}

rule Arsenal237_Tor_C2_Infrastructure {
   meta:
      description = "Detects Arsenal-237 enc_c2.exe Tor hidden service C2 — either by the specific onion address or by the /c2/beacon.php endpoint pattern in a PE context (avoids FP on generic Tor-aware binaries)"
      license = "CC BY-NC 4.0 - https://creativecommons.org/licenses/by-nc/4.0/"
      author = "The Hunters Ledger"
      reference = "https://pixelatedcontinuum.github.io/Threat-Intel-Reports/hunting-detections/arsenal-237-enc_c2-exe/"
      date = "2026-01-26"
      family = "Arsenal-237"
      malware_type = "Ransomware C2"
      id = "c43947ba-6b5e-56a6-9187-c59ee9ec5ad2"
   strings:
      $c2_domain = "rustydl5ak6p6ajqnja6qzkxvp5huhe4olpdsq5oy75ea4o34aalpkqd.onion" ascii
      $c2_endpoint = "/c2/beacon.php" ascii
      $c2_protocol = "POST /c2/beacon.php" ascii
      $onion_tld = ".onion" ascii
   condition:
      uint16(0) == 0x5A4D and
      filesize < 20MB and
      ($c2_domain or
       ($c2_endpoint and $c2_protocol) or
       ($c2_endpoint and $onion_tld) or
       ($c2_protocol and $onion_tld))
}

rule Arsenal237_Ransomware_Operations {
   meta:
      description = "Detects Arsenal-237 enc_c2.exe ransomware operational strings including encryption markers and ransom note generation"
      license = "CC BY-NC 4.0 - https://creativecommons.org/licenses/by-nc/4.0/"
      author = "The Hunters Ledger"
      reference = "https://pixelatedcontinuum.github.io/Threat-Intel-Reports/hunting-detections/arsenal-237-enc_c2-exe/"
      date = "2026-01-26"
      family = "Arsenal-237"
      malware_type = "Ransomware"
      id = "0fce6789-e5c8-5645-bb11-5469d4059a78"
   strings:
      $ransom_msg = "YOUR FILES HAVE BEEN ENCRYPTED!" ascii
      $ransom_note = "README.txt" ascii
      $encrypted_extension = ".locked" ascii
      $enc_c2_executable = "enc_c2.exe" ascii
      $http_client = "ureq" ascii
   condition:
      3 of them
}

rule Arsenal237_TEB_AntiDebug {
   meta:
      description = "Detects TEB-based anti-debugging technique used by Arsenal-237 enc_c2.exe with sleep-based sandbox evasion"
      license = "CC BY-NC 4.0 - https://creativecommons.org/licenses/by-nc/4.0/"
      author = "The Hunters Ledger"
      reference = "https://pixelatedcontinuum.github.io/Threat-Intel-Reports/hunting-detections/arsenal-237-enc_c2-exe/"
      date = "2026-01-26"
      family = "Arsenal-237"
      id = "d4cfca14-ca09-571f-9ba8-7a11250d51bc"
   strings:
      $teb_api = "NtCurrentTeb" ascii
      $stack_base = "StackBase" ascii
      $sleep_loop = { 68 88 13 00 00 FF 15 }
      $sleep_1000 = { 68 E8 03 00 00 FF 15 }
   condition:
      ($teb_api and $stack_base and ($sleep_loop or $sleep_1000))
}

rule Arsenal237_Rust_Compilation_Artifacts {
   meta:
      description = "Detects Rust compilation artifacts unique to Arsenal-237 build environment — /root/.cargo path indicates root-built (rare in legitimate Rust binaries) combined with index.crates.io presence"
      license = "CC BY-NC 4.0 - https://creativecommons.org/licenses/by-nc/4.0/"
      author = "The Hunters Ledger"
      reference = "https://pixelatedcontinuum.github.io/Threat-Intel-Reports/hunting-detections/arsenal-237-enc_c2-exe/"
      date = "2026-01-26"
      family = "Arsenal-237"
      id = "f58d1418-f733-5cdb-b069-ce296e254486"
   strings:
      $rust_lib_path = "/root/.cargo/registry/src/" ascii
      $crates_io = "index.crates.io" ascii
      $rustc_marker = "rustc-1." ascii
      $cargo_marker = "/.cargo/registry/" ascii
   condition:
      uint16(0) == 0x5A4D and
      filesize < 20MB and
      $rust_lib_path and
      1 of ($crates_io, $rustc_marker, $cargo_marker)
}

rule Arsenal237_RaaS_Builder_Tracking {
   meta:
      description = "Detects Arsenal-237 RaaS builder ID strings and affiliate tracking markers in ransomware samples"
      license = "CC BY-NC 4.0 - https://creativecommons.org/licenses/by-nc/4.0/"
      author = "The Hunters Ledger"
      reference = "https://pixelatedcontinuum.github.io/Threat-Intel-Reports/hunting-detections/arsenal-237-enc_c2-exe/"
      date = "2026-01-26"
      family = "Arsenal-237"
      malware_type = "RaaS"
      id = "151bd2c3-586a-5444-9d66-62bfddd9df33"
   strings:
      $builder_id_default = "TEST_BUILD_001" ascii
      $builder_id_generic = "builder_id" ascii
      $victim_id = "victim_id" ascii
      $encryption_key = "encryption_key" ascii
      $machine_info = "machine_info" ascii
   condition:
      (($builder_id_default and $builder_id_generic) or
      ($builder_id_generic and $encryption_key and $victim_id and $machine_info))
}

rule Arsenal237_RustCrypto_ChaCha20_RSA {
   meta:
      description = "Detects Arsenal-237 full_test_enc.exe Rust ChaCha20 + RSA cryptographic library combination used for file encryption"
      license = "CC BY-NC 4.0 - https://creativecommons.org/licenses/by-nc/4.0/"
      author = "The Hunters Ledger"
      reference = "https://pixelatedcontinuum.github.io/Threat-Intel-Reports/hunting-detections/arsenal-237-full_test_enc-exe/"
      date = "2026-01-27"
      family = "Arsenal-237"
      malware_type = "Ransomware"
      id = "2ab0cbdb-35a1-57d0-a044-bc09d26820b2"
   strings:
      $chacha20 = "/chacha20-0.9.1/src/lib.rs" ascii
      $rsa = "/rsa-0.9.9/src/algorithms/" ascii
      $aead = "/aead-0.5.2/src/lib.rs" ascii
      $cipher = "/cipher-0.4.4/" ascii
      $digest = "/digest-0.10.7/" ascii
      $rand = "/rand-0.8.5/" ascii
   condition:
      uint16(0) == 0x5A4D and
      filesize > 10MB and
      3 of them
}

rule Arsenal237_Ransomware_Lockbox_Strings {
   meta:
      description = "Detects Arsenal-237 full_test_enc.exe ransom messaging, .lockbox file extension, and encryption operation log strings"
      license = "CC BY-NC 4.0 - https://creativecommons.org/licenses/by-nc/4.0/"
      author = "The Hunters Ledger"
      reference = "https://pixelatedcontinuum.github.io/Threat-Intel-Reports/hunting-detections/arsenal-237-full_test_enc-exe/"
      date = "2026-01-27"
      family = "Arsenal-237"
      malware_type = "Ransomware"
      id = "225bc362-de16-57fd-b8e4-7a1bb6ca6b5b"
   strings:
      $ransom1 = "YOUR FILES HAVE BEEN ENCRYPTED!" ascii wide
      $ransom2 = "Ransom ID:" ascii wide
      $lockbox = ".lockbox" ascii wide
      $log1 = "[*] Encryptor starting..." ascii
      $log2 = "[*] Encrypting all drives..." ascii
      $log3 = "[+] Encryption complete!" ascii
   condition:
      uint16(0) == 0x5A4D and
      filesize > 10MB and filesize < 20MB and
      (2 of ($ransom1, $ransom2) and $lockbox) or
      (all of ($log1, $log2, $log3))
}

rule Arsenal237_Rayon_AntiAnalysis {
   meta:
      description = "Detects Arsenal-237 full_test_enc.exe Rayon parallel processing library and anti-analysis techniques including VM detection"
      license = "CC BY-NC 4.0 - https://creativecommons.org/licenses/by-nc/4.0/"
      author = "The Hunters Ledger"
      reference = "https://pixelatedcontinuum.github.io/Threat-Intel-Reports/hunting-detections/arsenal-237-full_test_enc-exe/"
      date = "2026-01-27"
      family = "Arsenal-237"
      malware_type = "Ransomware"
      id = "c2193fd2-fa04-53d6-bc9d-a60963366ea2"
   strings:
      $rayon = "/rayon-1.11.0/src/" ascii
      $walkdir = "/walkdir-2.5.0/" ascii
      $sysinfo = "/sysinfo-0.29.11/" ascii
      $vm_detect = "VMware" ascii nocase
      $vbox_detect = "VirtualBox" ascii nocase
      $encrypt_error1 = "Failed to encrypt nonce" ascii
      $encrypt_error2 = "Failed to encrypt key" ascii
      $encrypt_error3 = "Block encryption failed" ascii
   condition:
      uint16(0) == 0x5A4D and
      filesize > 10MB and
      (all of ($rayon, $walkdir, $sysinfo)) or
      (2 of ($vm_detect, $vbox_detect, $encrypt_error1, $encrypt_error2, $encrypt_error3))
}

rule Arsenal237_NetworkShare_Enumeration {
   meta:
      description = "Detects Arsenal-237 full_test_enc.exe network share enumeration via net use for lateral movement and network drive encryption"
      license = "CC BY-NC 4.0 - https://creativecommons.org/licenses/by-nc/4.0/"
      author = "The Hunters Ledger"
      reference = "https://pixelatedcontinuum.github.io/Threat-Intel-Reports/hunting-detections/arsenal-237-full_test_enc-exe/"
      date = "2026-01-27"
      family = "Arsenal-237"
      malware_type = "Ransomware"
      id = "c8dba0dd-b6b8-5811-8014-e05aa2cd501a"
   strings:
      $netuse = "net use" ascii
      $smb = "SMB" ascii nocase
      $netuse_error = "Failed to execute net use" ascii
      $folder_option = "--folder" ascii
   condition:
      uint16(0) == 0x5A4D and
      filesize > 10MB and
      ($netuse or $netuse_error) and
      ($folder_option or $smb)
}

rule Arsenal237_FullTestEnc_Comprehensive {
   meta:
      description = "Comprehensive detection for Arsenal-237 full_test_enc.exe combining Rust crypto libraries, ransom strings, and parallel encryption indicators"
      license = "CC BY-NC 4.0 - https://creativecommons.org/licenses/by-nc/4.0/"
      author = "The Hunters Ledger"
      reference = "https://pixelatedcontinuum.github.io/Threat-Intel-Reports/hunting-detections/arsenal-237-full_test_enc-exe/"
      date = "2026-01-27"
      family = "Arsenal-237"
      malware_type = "Ransomware"
      id = "b0241755-d615-59f9-a689-f6c5e3d141d1"
   strings:
      $chacha = "/chacha20-" ascii
      $rsa_lib = "/rsa-" ascii
      $ransom = "YOUR FILES HAVE BEEN ENCRYPTED!" ascii wide
      $rayon = "/rayon-" ascii
      $walkdir = "/walkdir-" ascii
      $sysinfo = "/sysinfo-" ascii
      $lockbox = ".lockbox" ascii
      $netuse = "net use" ascii
      $ransom_id = "Ransom ID" ascii
   condition:
      uint16(0) == 0x5A4D and
      filesize > 10MB and filesize < 20MB and
      $chacha and $rsa_lib and $ransom and
      (1 of ($rayon, $walkdir, $sysinfo)) and
      ($lockbox or $netuse or $ransom_id)
}

rule Arsenal237_ChaCha20_Key {
   meta:
      description = "Detects Arsenal-237 hardcoded ChaCha20 encryption key shared between new_enc.exe and dec_fixed.exe"
      license = "CC BY-NC 4.0 - https://creativecommons.org/licenses/by-nc/4.0/"
      author = "The Hunters Ledger"
      reference = "https://pixelatedcontinuum.github.io/Threat-Intel-Reports/hunting-detections/arsenal-237-new_enc-exe/"
      date = "2026-01-26"
      family = "Arsenal-237"
      malware_type = "Ransomware"
      id = "e21098a7-bae4-524b-8eb5-d9352b03e15a"
   strings:
      $key_hex = "67e6096a85ae67bb72f36e3c3af54fa57f520e518c68059babd9831f19cde05b" nocase ascii wide
      $key_partial = "67e60" nocase
   condition:
      $key_hex or $key_partial
}

rule Arsenal237_Campaign_Identifiers {
   meta:
      description = "Detects Arsenal-237 new_enc.exe by campaign ID or RustRansomNoteTask scheduled-task name (version string alone is too generic to anchor)"
      license = "CC BY-NC 4.0 - https://creativecommons.org/licenses/by-nc/4.0/"
      author = "The Hunters Ledger"
      reference = "https://pixelatedcontinuum.github.io/Threat-Intel-Reports/hunting-detections/arsenal-237-new_enc-exe/"
      date = "2026-01-26"
      family = "Arsenal-237"
      malware_type = "Ransomware"
      id = "98ea8e65-ed23-5695-a8ed-204ccc624356"
   strings:
      $campaign_id = "ICIIXGD1X8ZJ4T1MTQ6TLQIDJEMDE7U4" ascii wide
      $version = "v0.5-beta" ascii wide
      $ransom_task = "RustRansomNoteTask" ascii wide fullword
   condition:
      uint16(0) == 0x5A4D and
      filesize < 20MB and
      ($campaign_id or $ransom_task or
       ($version and ($campaign_id or $ransom_task)))
}

rule Arsenal237_Veritas_Backup_Targeting {
   meta:
      description = "Detects Arsenal-237 new_enc.exe enterprise targeting of Veritas Backup Exec and Veeam backup service processes for pre-encryption termination"
      license = "CC BY-NC 4.0 - https://creativecommons.org/licenses/by-nc/4.0/"
      author = "The Hunters Ledger"
      reference = "https://pixelatedcontinuum.github.io/Threat-Intel-Reports/hunting-detections/arsenal-237-new_enc-exe/"
      date = "2026-01-26"
      family = "Arsenal-237"
      malware_type = "Ransomware"
      id = "d301b67a-2a37-5c7f-bdc3-1b9e78ce260d"
   strings:
      $gxvss = "GxVss" ascii wide
      $gxblr = "GxBlr" ascii wide
      $gxfwd = "GxFWD" ascii wide
      $gxcvd = "GxCVD" ascii wide
      $gxcimgr = "GxCIMgr" ascii wide
      $veeam = "veeam" ascii wide nocase
   condition:
      (3 of ($gxvss, $gxblr, $gxfwd, $gxcvd, $gxcimgr)) or $veeam
}

rule Arsenal237_AntiRecovery_VSS {
   meta:
      description = "Detects Arsenal-237 new_enc.exe Volume Shadow Copy deletion commands to prevent ransomware recovery"
      license = "CC BY-NC 4.0 - https://creativecommons.org/licenses/by-nc/4.0/"
      author = "The Hunters Ledger"
      reference = "https://pixelatedcontinuum.github.io/Threat-Intel-Reports/hunting-detections/arsenal-237-new_enc-exe/"
      date = "2026-01-26"
      family = "Arsenal-237"
      malware_type = "Ransomware"
      id = "b85772b5-03cc-551e-8475-6241ea6fcb26"
   strings:
      $vss_delete = "vssadmin delete shadows /all /quiet" ascii wide nocase
      $vss_pattern = "vssadmin" ascii wide nocase
      $delete_shadows = "delete shadows" ascii wide nocase
   condition:
      ($vss_delete) or ($vss_pattern and $delete_shadows)
}

rule Arsenal237_AntiAnalysis_VM_Detection {
   meta:
      description = "Detects Arsenal-237 new_enc.exe anti-analysis strings targeting VM environments, sandboxes, and analysis tools"
      license = "CC BY-NC 4.0 - https://creativecommons.org/licenses/by-nc/4.0/"
      author = "The Hunters Ledger"
      reference = "https://pixelatedcontinuum.github.io/Threat-Intel-Reports/hunting-detections/arsenal-237-new_enc-exe/"
      date = "2026-01-26"
      family = "Arsenal-237"
      malware_type = "Ransomware"
      id = "0b1b39a6-c9b3-5462-896e-fad27cf93f9e"
   strings:
      $vm_vbox = "VBOX" ascii wide nocase
      $vm_vmware = "VMWARE" ascii wide nocase
      $vm_qemu = "QEMU" ascii wide nocase
      $vm_xen = "XEN" ascii wide nocase
      $vm_hyperv = "HYPERV" ascii wide nocase
      $sandbox_cuckoo = "cuckoo" ascii wide nocase
      $bios_registry = "HARDWARE\\DESCRIPTION\\System\\BIOS" ascii wide nocase
      $debugger_check = "IsDebuggerPresent" ascii wide
   condition:
      (3 of ($vm_vbox, $vm_vmware, $vm_qemu, $vm_xen, $vm_hyperv)) or
      $sandbox_cuckoo or $bios_registry or $debugger_check
}

rule Arsenal237_HexEncoded_RansomNote {
   meta:
      description = "Detects Arsenal-237 new_enc.exe hex-encoded ransom note header containing v0.5-beta version and Ransom-ID marker"
      license = "CC BY-NC 4.0 - https://creativecommons.org/licenses/by-nc/4.0/"
      author = "The Hunters Ledger"
      reference = "https://pixelatedcontinuum.github.io/Threat-Intel-Reports/hunting-detections/arsenal-237-new_enc-exe/"
      date = "2026-01-26"
      family = "Arsenal-237"
      malware_type = "Ransomware"
      id = "ede4cc35-bc9a-5f5e-a9d5-fdf4931202de"
   strings:
      $hex_header = "76302e352d626574610d0a0d0a52616e736f6d2d4944" ascii wide
   condition:
      $hex_header
}
