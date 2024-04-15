
/* 
	Rules which detect vulnerabilities in configuration files.
	External variables are used so they only work with YARA scanners, that pass them on (e.g. Thor, Loki and Spyre)
*/


rule VULN_Linux_Sudoers_Commands {
	meta:
		description = "Detects sudoers config with commands which might allow privilege escalation to root"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp"
		reference = "https://gtfobins.github.io/"
		date = "2022-11-22"
		modified = "2024-04-15"
		score = 50
		id = "221d90c8-e70e-5214-a03b-57ecabcdd480"
	strings:
		$command1 = "/sh " ascii
		$command2 = "/bash " ascii
		$command3 = "/ksh " ascii
		$command4 = "/csh " ascii
		$command5 = "/tcpdump " ascii
		//$command6 = "/cat " ascii
		//$command7 = "/head " ascii
		$command8 = "/nano " ascii
		$command9 = "/pico " ascii
		$command10 = "/rview " ascii
		$command11 = "/vi " ascii
		$command12 = "/vim " ascii
		$command13 = "/rvi " ascii
		$command14 = "/rvim " ascii
		//$command15 = "/more " ascii
		$command16 = "/less " ascii
		$command17 = "/dd " ascii
		/* $command18 = "/mount " ascii prone to FPs */ 

	condition:
		( filename == "sudoers" or filepath contains "/etc/sudoers.d" ) and 
		any of ($command*)
}

rule VULN_Linux_NFS_Exports {
	meta:
		description = "Detects insecure /etc/exports NFS config which might allow privilege escalation to root or other users. The parameter insecure allows any non-root user to mount NFS shares via e.g. an SSH-tunnel. With no_root_squash SUID root binaries are allowed."
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		reference = "https://www.errno.fr/nfs_privesc.html"
		author = "Arnim Rupp"
		date = "2022-11-22"
		score = 50
		id = "4b7d81d8-1ae1-5fcf-a91c-271477a839db"
	strings:
		// line has to start with / to avoid triggering on #-comment lines
		$conf1 = /\n\/.{2,200}?\binsecure\b/ ascii
		$conf2 = /\n\/.{2,200}?\bno_root_squash\b/ ascii

	condition:
		filename == "exports" and 
		filepath contains "/etc" and 
		any of ($conf*)
}

rule SUSP_AES_Key_in_MySql_History {
	meta:
		description = "Detects AES key outside of key management in .mysql_history"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp"
		date = "2022-11-22"
		score = 50
		id = "28acef39-8606-5d3d-b395-0d8db13f6c9c"
	strings:
		$c1 = /\bAES_(DE|EN)CRYPT\(.{1,128}?,.??('|").{1,128}?('|")\)/ ascii
		$c2 = /\baes_(de|en)crypt\(.{1,128}?,.??('|").{1,128}?('|")\)/ ascii

	condition:
		filename == ".mysql_history" and 
		any of ($c*)
}

rule VULN_Slapd_Conf_with_Default_Password {
	meta:
		description = "Detects an openldap slapd.conf with the default password test123"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp"
		date = "2022-11-22"
		reference = "https://www.openldap.org/doc/admin21/slapdconfig.html"
		score = 70
		id = "1d1319da-125b-5373-88f1-27a23c85729e"
	strings:
		/* \nrootpw \{SSHA\}fsAEyxlFOtvZBwPLAF68zpUhth8lERoR */
		$c1 = { 0A 72 6f 6f 74 70 77 20 7b 53 53 48 41 7d 66 73 41 45 79 78 6c 46 4f 74 76 5a 42 77 50 4c 41 46 36 38 7a 70 55 68 74 68 38 6c 45 52 6f 52 }

	condition:
		filename == "slapd.conf" and 
		any of ($c*)
}

rule VULN_Unencrypted_SSH_Private_Key : T1552_004 {
    meta:
        description = "Detects unencrypted SSH private keys with DSA, RSA, ECDSA and ED25519 of openssh or Putty"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp"
        date = "2023-01-06"
        reference = "https://attack.mitre.org/techniques/T1552/004/"
        score = 50
        id = "84b279fc-99c8-5101-b2d8-5c7adbaf753f"
    strings:
        /*
            -----BEGIN RSA PRIVATE KEY-----
            MII
        */
        $openssh_rsa = { 2d 2d 2d 2d 2d 42 45 47 49 4e 20 52 53 41 20 50 52 49 56 41 54 45 20 4b 45 59 2d 2d 2d 2d 2d 0a 4d 49 49 }

        /*
            -----BEGIN DSA PRIVATE KEY-----
            MIIBvAIBAAKBgQ
        */
        $openssh_dsa = { 2d 2d 2d 2d 2d 42 45 47 49 4e 20 44 53 41 20 50 52 49 56 41 54 45 20 4b 45 59 2d 2d 2d 2d 2d 0a 4d 49 49 42 76 41 49 42 41 41 4b 42 67 51 }

        /*
            -----BEGIN EC PRIVATE KEY-----
            M
        */
        $openssh_ecdsa = { 2d 2d 2d 2d 2d 42 45 47 49 4e 20 45 43 20 50 52 49 56 41 54 45 20 4b 45 59 2d 2d 2d 2d 2d 0a 4d }

        /*
            -----BEGIN OPENSSH PRIVATE KEY-----
            b3BlbnNzaC1rZXktdjEAAAAABG5vbmU

            base64 contains: openssh-key-v1.....none
        */
        $openssh_ed25519 = { 2d 2d 2d 2d 2d 42 45 47 49 4e 20 4f 50 45 4e 53 53 48 20 50 52 49 56 41 54 45 20 4b 45 59 2d 2d 2d 2d 2d 0a 62 33 42 6c 62 6e 4e 7a 61 43 31 72 5a 58 6b 74 64 6a 45 41 41 41 41 41 42 47 35 76 62 6d 55 }

        $putty_start = "PuTTY-User-Key-File" ascii
        $putty_noenc = "Encryption: none" ascii

    condition:
        /*
            limit to folders and filenames which are known to contain ssh keys to avoid triggering on all those
            private keys for SSL, signing, ... which might be important but aren't usually used for lateral
            movement => bad signal noise ratio
        */
        (
            filepath contains "ssh" or
            filepath contains "SSH" or
            filepath contains "utty" or
            filename contains "ssh" or
            filename contains "SSH" or
            filename contains "id_" or
            filename contains "id2_" or
            filename contains ".ppk" or
            filename contains ".PPK" or
            filename contains "utty"
        )
        and
        (
            $openssh_dsa     at 0 or
            $openssh_rsa     at 0 or
            $openssh_ecdsa   at 0 or
            $openssh_ed25519 at 0 or
            (
                $putty_start at 0 and
                $putty_noenc
            )
        )
        and not filepath contains "/root/"
        and not filename contains "ssh_host_"
}


rule VULN_Unencrypted_SSH_Private_Key_Root_Folder : T1552_004 {
    meta:
        description = "Detects unencrypted SSH private keys with DSA, RSA, ECDSA and ED25519 of openssh or Putty"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp"
        date = "2023-01-06"
        reference = "https://attack.mitre.org/techniques/T1552/004/"
        score = 65
        id = "9e6a03a1-d95f-5de7-a6c0-a2e77486007c"
    strings:
        /*
            -----BEGIN RSA PRIVATE KEY-----
            MII
        */
        $openssh_rsa = { 2d 2d 2d 2d 2d 42 45 47 49 4e 20 52 53 41 20 50 52 49 56 41 54 45 20 4b 45 59 2d 2d 2d 2d 2d 0a 4d 49 49 }

        /*
            -----BEGIN DSA PRIVATE KEY-----
            MIIBvAIBAAKBgQ
        */
        $openssh_dsa = { 2d 2d 2d 2d 2d 42 45 47 49 4e 20 44 53 41 20 50 52 49 56 41 54 45 20 4b 45 59 2d 2d 2d 2d 2d 0a 4d 49 49 42 76 41 49 42 41 41 4b 42 67 51 }

        /*
            -----BEGIN EC PRIVATE KEY-----
            M
        */
        $openssh_ecdsa = { 2d 2d 2d 2d 2d 42 45 47 49 4e 20 45 43 20 50 52 49 56 41 54 45 20 4b 45 59 2d 2d 2d 2d 2d 0a 4d }

        /*
            -----BEGIN OPENSSH PRIVATE KEY-----
            b3BlbnNzaC1rZXktdjEAAAAABG5vbmU

            base64 contains: openssh-key-v1.....none
        */
        $openssh_ed25519 = { 2d 2d 2d 2d 2d 42 45 47 49 4e 20 4f 50 45 4e 53 53 48 20 50 52 49 56 41 54 45 20 4b 45 59 2d 2d 2d 2d 2d 0a 62 33 42 6c 62 6e 4e 7a 61 43 31 72 5a 58 6b 74 64 6a 45 41 41 41 41 41 42 47 35 76 62 6d 55 }

        $putty_start = "PuTTY-User-Key-File" ascii
        $putty_noenc = "Encryption: none" ascii

    condition:
        /*
            limit to folders and filenames which are known to contain ssh keys to avoid triggering on all those
            private keys for SSL, signing, ... which might be important but aren't usually used for lateral
            movement => bad signal noise ratio
        */
        (
            filepath contains "ssh" or
            filepath contains "SSH" or
            filepath contains "utty" or
            filename contains "ssh" or
            filename contains "SSH" or
            filename contains "id_" or
            filename contains "id2_" or
            filename contains ".ppk" or
            filename contains ".PPK" or
            filename contains "utty"
        )
        and
        (
            $openssh_dsa     at 0 or
            $openssh_rsa     at 0 or
            $openssh_ecdsa   at 0 or
            $openssh_ed25519 at 0 or
            (
                $putty_start at 0 and
                $putty_noenc
            )
        )
        and filepath contains "/root/"
        and not filename contains "ssh_host_"
}
