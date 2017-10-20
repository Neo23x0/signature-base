/*
   Yara Rule Set
   Author: (see the author field in the rules)
   Date: 2017-10-20
   Sync Date: 2017-10-20
   Identifier: Binary Alert Rules
   Reference: https://github.com/airbnb/binaryalert

   Note: Applied some modifications to avoid false positives during full disk file system scans
*/

/* Private Rules */

private rule MachO
{
    meta:
        description = "Mach-O binaries"
    condition:
        uint32(0) == 0xfeedface or uint32(0) == 0xcefaedfe or uint32(0) == 0xfeedfacf or uint32(0) == 0xcffaedfe or uint32(0) == 0xcafebabe or uint32(0) == 0xbebafeca
}

/* ./rules/public/hacktool/macos */

rule hacktool_macos_exploit_cve_5889
{
    meta:
        description = "http://www.cvedetails.com/cve/cve-2015-5889"
        reference = "https://www.exploit-db.com/exploits/38371/"
        author = "@mimeframe"
    strings:
        $a1 = "/etc/sudoers" fullword wide ascii
        $a2 = "/etc/crontab" fullword wide ascii
        $a3 = "* * * * * root echo" wide ascii
        $a4 = "ALL ALL=(ALL) NOPASSWD: ALL" wide ascii
        $a5 = "/usr/bin/rsh" fullword wide ascii
        $a6 = "localhost" fullword wide ascii
    condition:
        all of ($a*)
}

rule hacktool_macos_exploit_tpwn
{
    meta:
        description = "tpwn exploits a null pointer dereference in XNU to escalate privileges to root."
        reference = "https://www.rapid7.com/db/modules/exploit/osx/local/tpwn"
        author = "@mimeframe"
    strings:
        $a1 = "[-] Couldn't find a ROP gadget, aborting." wide ascii
        $a2 = "leaked kaslr slide," wide ascii
        $a3 = "didn't get root, but this system is vulnerable." wide ascii
        $a4 = "Escalating privileges! -qwertyoruiop" wide ascii
    condition:
        2 of ($a*)
}

rule hacktool_macos_juuso_keychaindump
{
    meta:
        description = "For reading OS X keychain passwords as root."
        reference = "https://github.com/juuso/keychaindump"
        author = "@mimeframe"
    strings:
        $a1 = "[-] Too many candidate keys to fit in memory" wide ascii
        $a2 = "[-] Could not allocate memory for key search" wide ascii
        $a3 = "[-] Too many credentials to fit in memory" wide ascii
        $a4 = "[-] The target file is not a keychain file" wide ascii
        $a5 = "[-] Could not find the securityd process" wide ascii
        $a6 = "[-] No root privileges, please run with sudo" wide ascii
    condition:
        4 of ($a*)
}

rule hacktool_macos_keylogger_b4rsby_swiftlog
{
    meta:
        description = "Dirty user level command line keylogger hacked together in Swift."
        reference = "https://github.com/b4rsby/SwiftLog"
        author = "@mimeframe"
    strings:
        $a1 = "You need to enable the keylogger in the System Prefrences" wide ascii
    condition:
        all of ($a*)
}

rule hacktool_macos_keylogger_caseyscarborough
{
    meta:
        description = "A simple and easy to use keylogger for macOS."
        reference = "https://github.com/caseyscarborough/keylogger"
        author = "@mimeframe"
    strings:
        $a1 = "/var/log/keystroke.log" wide ascii
        $a2 = "ERROR: Unable to create event tap." wide ascii
        $a3 = "Keylogging has begun." wide ascii
        $a4 = "ERROR: Unable to open log file. Ensure that you have the proper permissions." wide ascii
    condition:
        2 of ($a*)
}

rule hacktool_macos_keylogger_dannvix
{
    meta:
        description = "A simple keylogger for macOS."
        reference = "https://github.com/dannvix/keylogger-osx"
        author = "@mimeframe"
    strings:
        $a1 = "/var/log/keystroke.log" wide ascii
        $a2 = "<forward-delete>" wide ascii
        $a3 = "<unknown>" wide ascii
    condition:
        all of ($a*)
}

rule hacktool_macos_keylogger_eldeveloper_keystats
{
    meta:
        description = "A simple keylogger for macOS."
        reference = "https://github.com/ElDeveloper/keystats"
        author = "@mimeframe"
    strings:
        $a1 = "YVBKeyLoggerPerishedNotification" wide ascii
        $a2 = "YVBKeyLoggerPerishedByLackOfResponseNotification" wide ascii
        $a3 = "YVBKeyLoggerPerishedByUserChangeNotification" wide ascii
    condition:
        2 of ($a*)
}

rule hacktool_macos_keylogger_giacomolaw
{
    meta:
        description = "A simple keylogger for macOS."
        reference = "https://github.com/GiacomoLaw/Keylogger"
        author = "@mimeframe"
    strings:
        $a1 = "ERROR: Unable to access keystroke log file. Please make sure you have the correct permissions." wide ascii
        $a2 = "ERROR: Unable to create event tap." wide ascii
        $a3 = "Keystrokes are now being recorded" wide ascii
    condition:
        2 of ($a*)
}

rule hacktool_macos_keylogger_logkext
{
    meta:
        description = "LogKext is an open source keylogger for Mac OS X, a product of FSB software."
        reference = "https://github.com/SlEePlEs5/logKext"
        author = "@mimeframe"
    strings:
        // daemon
        $a1 = "logKextPassKey" wide ascii
        $a2 = "Couldn't get system keychain:" wide ascii
        $a3 = "Error finding secret in keychain" wide ascii
        $a4 = "com_fsb_iokit_logKext" wide ascii
        // client
        $b1 = "logKext Password:" wide ascii
        $b2 = "Logging controls whether the daemon is logging keystrokes (default is on)." wide ascii
        // logkextkeygen
        $c1 = "logKextPassKey" wide ascii
        $c2 = "Error: couldn't create secAccess" wide ascii
        // logkext
        $d1 = "IOHIKeyboard" wide ascii
        $d2 = "Clear keyboards called with kextkeys" wide ascii
        $d3 = "Added notification for keyboard" wide ascii
    condition:
        3 of ($a*) or all of ($b*) or all of ($c*) or all of ($d*)
}

rule hacktool_macos_keylogger_roxlu_ofxkeylogger
{
    meta:
        description = "ofxKeylogger keylogger."
        reference = "https://github.com/roxlu/ofxKeylogger"
        author = "@mimeframe"
    strings:
        $a1 = "keylogger_init" wide ascii
        $a2 = "install_keylogger_hook function not found in dll." wide ascii
        $a3 = "keylogger_set_callback" wide ascii
    condition:
        all of ($a*)
}

rule hacktool_macos_keylogger_skreweverything_swift
{
    meta:
        description = "It is a simple and easy to use keylogger for macOS written in Swift."
        reference = "https://github.com/SkrewEverything/Swift-Keylogger"
        author = "@mimeframe"
    strings:
        $a1 = "Can't create directories!" wide ascii
        $a2 = "Can't create manager" wide ascii
        $a3 = "Can't open HID!" wide ascii
        $a4 = "PRINTSCREEN" wide ascii
        $a5 = "LEFTARROW" wide ascii
    condition:
        4 of ($a*)
}

rule hacktool_macos_macpmem
{
    meta:
        description = "MacPmem enables read/write access to physical memory on macOS. Can be used by CSIRT teams and attackers."
        reference = "https://github.com/google/rekall/tree/master/tools/osx/MacPmem"
        author = "@mimeframe"
    strings:
        // osxpmem
        $a1 = "%s/MacPmem.kext" wide ascii
        $a2 = "The Pmem physical memory imager." wide ascii
        $a3 = "The OSXPmem memory imager." wide ascii
        $a4 = "These AFF4 Volumes will be loaded and their metadata will be parsed before the program runs." wide ascii
        $a5 = "Pmem driver version incompatible. Reported" wide ascii
        $a6 = "Memory access driver left loaded since you specified the -l flag." wide ascii
        // kext
        $b1 = "Unloading MacPmem" wide ascii
        $b2 = "MacPmem load tag is" wide ascii
    condition:
        MachO and 2 of ($a*) or all of ($b*)
}

rule hacktool_macos_manwhoami_icloudcontacts
{
    meta:
        description = "Pulls iCloud Contacts for an account. No dependencies. No user notification."
        reference = "https://github.com/manwhoami/iCloudContacts"
        author = "@mimeframe"
    strings:
        $a1 = "https://setup.icloud.com/setup/authenticate/" wide ascii
        $a2 = "https://p04-contacts.icloud.com/" wide ascii
        $a3 = "HTTP Error 401: Unauthorized. Are you sure the credentials are correct?" wide ascii
        $a4 = "HTTP Error 404: URL not found. Did you enter a username?" wide ascii
    condition:
        3 of ($a*)
}

rule hacktool_macos_manwhoami_mmetokendecrypt
{
    meta:
        description = "This program decrypts / extracts all authorization tokens on macOS / OS X / OSX."
        reference = "https://github.com/manwhoami/MMeTokenDecrypt"
        author = "@mimeframe"
    strings:
        $a1 = "security find-generic-password -ws 'iCloud'" wide ascii
        $a2 = "ERROR getting iCloud Decryption Key" wide ascii
        $a3 = "Could not find MMeTokenFile. You can specify the file manually." wide ascii
        $a4 = "Decrypting token plist ->" wide ascii
        $a5 = "Successfully decrypted token plist!" wide ascii
    condition:
        3 of ($a*)
}

rule hacktool_macos_manwhoami_osxchromedecrypt
{
    meta:
        description = "Decrypt Google Chrome / Chromium passwords and credit cards on macOS / OS X."
        reference = "https://github.com/manwhoami/OSXChromeDecrypt"
        author = "@mimeframe"
    strings:
        $a1 = "Credit Cards for Chrome Profile" wide ascii
        $a2 = "Passwords for Chrome Profile" wide ascii
        $a3 = "Unknown Card Issuer" wide ascii
        $a4 = "ERROR getting Chrome Safe Storage Key" wide ascii
        $b1 = "select name_on_card, card_number_encrypted, expiration_month, expiration_year from credit_cards" wide ascii
        $b2 = "select username_value, password_value, origin_url, submit_element from logins" wide ascii
    condition:
        3 of ($a*) or all of ($b*)
}

rule hacktool_macos_n0fate_chainbreaker
{
    meta:
        description = "chainbreaker can extract user credential in a Keychain file with Master Key or user password in forensically sound manner."
        reference = "https://github.com/n0fate/chainbreaker"
        author = "@mimeframe"
    strings:
        $a1 = "[!] Private Key Table is not available" wide ascii
        $a2 = "[!] Public Key Table is not available" wide ascii
        $a3 = "[-] Decrypted Private Key" wide ascii
    condition:
        all of ($a*)
}

rule hacktool_macos_ptoomey3_keychain_dumper
{
    meta:
        description = "Keychain dumping utility."
        reference = "https://github.com/ptoomey3/Keychain-Dumper"
        author = "@mimeframe"
    strings:
        $a1 = "keychain_dumper" wide ascii
        $a2 = "/var/Keychains/keychain-2.db" wide ascii
        $a3 = "<key>keychain-access-groups</key>" wide ascii
        $a4 = "SELECT DISTINCT agrp FROM genp UNION SELECT DISTINCT agrp FROM inet" wide ascii
        $a5 = "dumpEntitlements" wide ascii
    condition:
        all of ($a*)
}

/* ./rules/public/hacktool/multi */

rule hacktool_multi_bloodhound_owned
{
    meta:
        description = "Bloodhound: Custom queries to document a compromise, find collateral spread of owned nodes, and visualize deltas in privilege gains"
        reference = "https://github.com/porterhau5/BloodHound-Owned/"
        author = "@fusionrace"
    strings:
        $s1 = "Find all owned Domain Admins" fullword ascii wide
        $s2 = "Find Shortest Path from owned node to Domain Admins" fullword ascii wide
        $s3 = "List all directly owned nodes" fullword ascii wide
        $s4 = "Set owned and wave properties for a node" fullword ascii wide
        $s5 = "Find spread of compromise for owned nodes in wave" fullword ascii wide
        $s6 = "Show clusters of password reuse" fullword ascii wide
        $s7 = "Something went wrong when creating SharesPasswordWith relationship" fullword ascii wide
        $s8 = "reference doc of custom Cypher queries for BloodHound" fullword ascii wide
        $s9 = "Created SharesPasswordWith relationship between" fullword ascii wide
        $s10 = "Skipping finding spread of compromise due to" fullword ascii wide
    condition:
        any of them
}

rule hacktool_multi_jtesta_ssh_mitm
{
    meta:
        description = "intercepts ssh connections to capture credentials"
        reference = "https://github.com/jtesta/ssh-mitm"
        author = "@fusionrace"
    strings:
        $a1 = "INTERCEPTED PASSWORD:" wide ascii
        $a2 = "more sshbuf problems." wide ascii
    condition:
        all of ($a*)
}

rule hacktool_multi_masscan
{
    meta:
        description = "masscan is a performant port scanner, it produces results similar to nmap"
        reference = "https://github.com/robertdavidgraham/masscan"
        author = "@mimeframe"
    strings:
        $a1 = "EHLO masscan" fullword wide ascii
        $a2 = "User-Agent: masscan/" wide ascii
        $a3 = "/etc/masscan/masscan.conf" fullword wide ascii
        $b1 = "nmap(%s): unsupported. This code will never do DNS lookups." wide ascii
        $b2 = "nmap(%s): unsupported, we do timing WAY different than nmap" wide ascii
        $b3 = "[hint] I've got some local priv escalation 0days that might work" wide ascii
        $b4 = "[hint] VMware on Macintosh doesn't support masscan" wide ascii
    condition:
        all of ($a*) or any of ($b*)
}

rule hacktool_multi_ncc_ABPTTS
{
    meta:
        description = "Allows for TCP tunneling over HTTP"
        reference = "https://github.com/nccgroup/ABPTTS"
        author = "@mimeframe"
    strings:
        $s1 = "---===[[[ A Black Path Toward The Sun ]]]===---" ascii wide
        $s2 = "https://vulnerableserver/EStatus/" ascii wide
        $s3 = "Error: no ABPTTS forwarding URL was specified. This utility will now exit." ascii wide
        // access key
        $s4 = "tQgGur6TFdW9YMbiyuaj9g6yBJb2tCbcgrEq" fullword ascii wide
        // encryption key
        $s5 = "63688c4f211155c76f2948ba21ebaf83" fullword ascii wide
        // log file
        $s6 = "ABPTTSClient-log.txt" fullword ascii wide
    condition:
        any of them
}

rule hacktool_multi_ntlmrelayx
{
    meta:
        description = "https://www.fox-it.com/en/insights/blogs/blog/inside-windows-network/"
        reference = "https://github.com/CoreSecurity/impacket/blob/master/examples/ntlmrelayx.py"
        author = "@mimeframe"
    strings:
        $a1 = "Started interactive SMB client shell via TCP" wide ascii
        $a2 = "Service Installed.. CONNECT!" wide ascii
        $a3 = "Done dumping SAM hashes for host:" wide ascii
        $a4 = "DA already added. Refusing to add another" wide ascii
        $a5 = "Domain info dumped into lootdir!" wide ascii
    condition:
        any of ($a*)
}

rule hacktool_multi_pyrasite_py
{
    meta:
        description = "A tool for injecting arbitrary code into running Python processes."
        reference = "https://github.com/lmacken/pyrasite"
        author = "@fusionrace"
    strings:
        $s1 = "WARNING: ptrace is disabled. Injection will not work." fullword ascii wide
        $s2 = "A payload that connects to a given host:port and receives commands" fullword ascii wide
        $s3 = "A reverse Python connection payload." fullword ascii wide
        $s4 = "pyrasite - inject code into a running python process" fullword ascii wide
        $s5 = "The ID of the process to inject code into" fullword ascii wide
        $s6 = "This file is part of pyrasite." fullword ascii wide
        $s7 = "https://github.com/lmacken/pyrasite" fullword ascii wide
        $s8 = "Setup a communication socket with the process by injecting" fullword ascii wide
        $s9 = "a reverse subshell and having it connect back to us." fullword ascii wide
        $s10 = "Write out a reverse python connection payload with a custom port" fullword ascii wide
        $s11 = "Wait for the injected payload to connect back to us" fullword ascii wide
        $s12 = "PyrasiteIPC" fullword ascii wide
        $s13 = "A reverse Python shell that behaves like Python interactive interpreter." fullword ascii wide
        $s14 = "pyrasite cannot establish reverse" fullword ascii wide
    condition:
        any of them
}

rule hacktool_multi_responder_py
{
    meta:
        description = "Responder is a LLMNR, NBT-NS and MDNS poisoner, with built-in HTTP/SMB/MSSQL/FTP/LDAP rogue authentication server"
        reference = "http://www.c0d3xpl0it.com/2017/02/compromising-domain-admin-in-internal-pentest.html"
        author = "@fusionrace"
    strings:
        $s1 = "Poison all requests with another IP address than Responder's one." fullword ascii wide
        $s2 = "Responder is in analyze mode. No NBT-NS, LLMNR, MDNS requests will be poisoned." fullword ascii wide
        $s3 = "Enable answers for netbios wredir suffix queries. Answering to wredir will likely break stuff on the network." fullword ascii wide
        $s4 = "This option allows you to fingerprint a host that issued an NBT-NS or LLMNR query." fullword ascii wide
        $s5 = "Upstream HTTP proxy used by the rogue WPAD Proxy for outgoing requests (format: host:port)" fullword ascii wide
        $s6 = "31mOSX detected, -i mandatory option is missing" fullword ascii wide
        $s7 = "This option allows you to fingerprint a host that issued an NBT-NS or LLMNR query." fullword ascii wide
    condition:
        any of them
}

/* ./rules/public/hacktool/windows */

rule hacktool_windows_hot_potato
{
    meta:
        description = "https://foxglovesecurity.com/2016/01/16/hot-potato/"
        reference = "https://github.com/foxglovesec/Potato"
        author = "@mimeframe"
    strings:
        $a1 = "Parsing initial NTLM auth..." wide ascii
        $a2 = "Got PROPFIND for /test..." wide ascii
        $a3 = "Starting NBNS spoofer..." wide ascii
        $a4 = "Exhausting UDP source ports so DNS lookups will fail..." wide ascii
        $a5 = "Usage: potato.exe -ip" wide ascii
    condition:
        any of ($a*)
}

rule hacktool_windows_moyix_creddump
{
    meta:
        description = "creddump is a python tool to extract credentials and secrets from Windows registry hives."
        reference = "https://github.com/moyix/creddump"
        author = "@mimeframe"
    strings:
        $a1 = "!@#$%^&*()qwertyUIOPAzxcvbnmQQQQQQQQQQQQ)(*@&%" wide ascii
        $a2 = "0123456789012345678901234567890123456789" wide ascii
        $a3 = "NTPASSWORD" wide ascii
        $a4 = "LMPASSWORD" wide ascii
        $a5 = "aad3b435b51404eeaad3b435b51404ee" wide ascii
        $a6 = "31d6cfe0d16ae931b73c59d7e0c089c0" wide ascii
    condition:
        all of ($a*)
}

rule hacktool_windows_ncc_wmicmd
{
    meta:
        description = "Command shell wrapper for WMI"
        reference = "https://github.com/nccgroup/WMIcmd"
        author = "@mimeframe"
    strings:
        $a1 = "Need to specify a username, domain and password for non local connections" wide ascii
        $a2 = "WS-Management is running on the remote host" wide ascii
        $a3 = "firewall (if enabled) allows connections" wide ascii
        $a4 = "WARNING: Didn't see stdout output finished marker - output may be truncated" wide ascii
        $a5 = "Command sleep in milliseconds - increase if getting truncated output" wide ascii
        $b1 = "0x800706BA" wide ascii
        $b2 = "NTLMDOMAIN:" wide ascii
        $b3 = "cimv2" wide ascii
    condition:
        any of ($a*) or all of ($b*)
}

rule hacktool_windows_rdp_cmd_delivery
{
    meta:
        description = "Delivers a text payload via RDP (rubber ducky)"
        reference = "https://github.com/nopernik/mytools/blob/master/rdp-cmd-delivery.sh"
        author = "@fusionrace"
    strings:
        $s1 = "Usage: rdp-cmd-delivery.sh OPTIONS" ascii wide
        $s2 = "[--tofile 'c:\\test.txt' local.ps1 #will copy contents of local.ps1 to c:\\test.txt" ascii wide
        $s3 = "-cmdfile local.bat                #will execute everything from local.bat" ascii wide
        $s4 = "To deliver powershell payload, use '--cmdfile script.ps1' but inside powershell console" ascii wide
    condition:
        any of them
}

rule hacktool_windows_wmi_implant
{
    meta:
        description = "A PowerShell based tool that is designed to act like a RAT"
        reference = "https://www.fireeye.com/blog/threat-research/2017/03/wmimplant_a_wmi_ba.html"
        author = "@fusionrace"
    strings:
        $s1 = "This really isn't applicable unless you are using WMImplant interactively." fullword ascii wide
        $s2 = "What command do you want to run on the remote system? >" fullword ascii wide
        $s3 = "Do you want to [create] or [delete] a string registry value? >" fullword ascii wide
        $s4 = "Do you want to run a WMImplant against a list of computers from a file? [yes] or [no] >" fullword ascii wide
        $s5 = "What is the name of the service you are targeting? >" fullword ascii wide
        $s6 = "This function enables the user to upload or download files to/from the attacking machine to/from the targeted machine" fullword ascii wide
        $s7 = "gen_cli - Generate the CLI command to execute a command via WMImplant" fullword ascii wide
        $s8 = "exit - Exit WMImplant" fullword ascii wide
        $s9 = "Lateral Movement Facilitation" fullword ascii wide
        $s10 = "vacant_system - Determine if a user is away from the system." fullword ascii wide
        $s11 = "Please provide the ProcessID or ProcessName flag to specify the process to kill!" fullword ascii wide
    condition:
        any of them
}

rule hacktool_windows_mimikatz_copywrite
{
    meta:
        description = "Mimikatz credential dump tool: Author copywrite"
        reference = "https://github.com/gentilkiwi/mimikatz"
        author = "@fusionrace"
        md5_1 = "0c87c0ca04f0ab626b5137409dded15ac66c058be6df09e22a636cc2bcb021b8"
        md5_2 = "0c91f4ca25aedf306d68edaea63b84efec0385321eacf25419a3050f2394ee3b"
        md5_3 = "0fee62bae204cf89d954d2cbf82a76b771744b981aef4c651caab43436b5a143"
        md5_4 = "004c07dcd04b4e81f73aacd99c7351337f894e4dac6c91dcfaadb4a1510a967c"
        md5_5 = "09c542ff784bf98b2c4899900d4e699c5b2e2619a4c5eff68f6add14c74444ca"
        md5_6 = "09054be3cc568f57321be32e769ae3ccaf21653e5d1e3db85b5af4421c200669"
    strings:
        $s1 = "Kiwi en C" fullword ascii wide
        $s2 = "Benjamin DELPY `gentilkiwi`" fullword ascii wide
        $s3 = "http://blog.gentilkiwi.com/mimikatz" fullword ascii wide
        $s4 = "Build with love for POC only" fullword ascii wide
        $s5 = "gentilkiwi (Benjamin DELPY)" fullword wide
        $s6 = "KiwiSSP" fullword wide
        $s7 = "Kiwi Security Support Provider" fullword wide
        $s8 = "kiwi flavor !" fullword wide
    condition:
        uint16(0) == 0x5a4d and filesize < 800KB and /* Added by Florian Roth to avoid false positives */
        any of them
}

rule hacktool_windows_mimikatz_errors
{
    meta:
        description = "Mimikatz credential dump tool: Error messages"
        reference = "https://github.com/gentilkiwi/mimikatz"
        author = "@fusionrace"
        md5_1 = "09054be3cc568f57321be32e769ae3ccaf21653e5d1e3db85b5af4421c200669"
        md5_2 = "004c07dcd04b4e81f73aacd99c7351337f894e4dac6c91dcfaadb4a1510a967c"
    strings:
        $s1 = "[ERROR] [LSA] Symbols" fullword ascii wide
        $s2 = "[ERROR] [CRYPTO] Acquire keys" fullword ascii wide
        $s3 = "[ERROR] [CRYPTO] Symbols" fullword ascii wide
        $s4 = "[ERROR] [CRYPTO] Init" fullword ascii wide
    condition:
        all of them
}

rule hacktool_windows_mimikatz_files
{
    meta:
        description = "Mimikatz credential dump tool: Files"
        reference = "https://github.com/gentilkiwi/mimikatz"
        author = "@fusionrace"
        md5_1 = "09054be3cc568f57321be32e769ae3ccaf21653e5d1e3db85b5af4421c200669"
        md5_2 = "004c07dcd04b4e81f73aacd99c7351337f894e4dac6c91dcfaadb4a1510a967c"
    strings:
        $s1 = "kiwifilter.log" fullword wide
        $s2 = "kiwissp.log" fullword wide
        $s3 = "mimilib.dll" fullword ascii wide
    condition:
        uint16(0) == 0x5a4d and filesize < 800KB and /* Added by Florian Roth to avoid false positives */
        any of them
}

rule hacktool_windows_mimikatz_modules
{
    meta:
        description = "Mimikatz credential dump tool: Modules"
        reference = "https://github.com/gentilkiwi/mimikatz"
        author = "@fusionrace"
        md5_1 = "0c87c0ca04f0ab626b5137409dded15ac66c058be6df09e22a636cc2bcb021b8"
        md5_2 = "0c91f4ca25aedf306d68edaea63b84efec0385321eacf25419a3050f2394ee3b"
        md5_3 = "09054be3cc568f57321be32e769ae3ccaf21653e5d1e3db85b5af4421c200669"
        md5_4 = "004c07dcd04b4e81f73aacd99c7351337f894e4dac6c91dcfaadb4a1510a967c"
        md5_5 = "0fee62bae204cf89d954d2cbf82a76b771744b981aef4c651caab43436b5a143"
    strings:
        $s1 = "mimilib" fullword ascii wide
        $s2 = "mimidrv" fullword ascii wide
        $s3 = "mimilove" fullword ascii wide
    condition:
        uint16(0) == 0x5a4d and filesize < 800KB and /* Added by Florian Roth to avoid false positives */
        any of them
}

rule hacktool_windows_mimikatz_sekurlsa
{
    meta:
        description = "Mimikatz credential dump tool"
        reference = "https://github.com/gentilkiwi/mimikatz"
        author = "@fusionrace"
        SHA256_1 = "09054be3cc568f57321be32e769ae3ccaf21653e5d1e3db85b5af4421c200669"
        SHA256_2 = "004c07dcd04b4e81f73aacd99c7351337f894e4dac6c91dcfaadb4a1510a967c"
    strings:
        $s1 = "dpapisrv!g_MasterKeyCacheList" fullword ascii wide
        $s2 = "lsasrv!g_MasterKeyCacheList" fullword ascii wide
        $s3 = "!SspCredentialList" ascii wide
        $s4 = "livessp!LiveGlobalLogonSessionList" fullword ascii wide
        $s5 = "wdigest!l_LogSessList" fullword ascii wide
        $s6 = "tspkg!TSGlobalCredTable" fullword ascii wide
    condition:
        all of them
}
