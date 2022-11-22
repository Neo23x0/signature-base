
/* 
	Rules which detect vulnerabilities in configuration files.
	External variables are used so they only work with YARA scanners, that pass them on (e.g. Thor, Loki and Spyre)
*/


rule VULN_Linux_Sudoers_Commands {
	meta:
		description = "Detects sudoers config with commands which might allow privilege escalation to root"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp"
		reference = "https://wiki.archlinux.org/title/sudo"
		date = "2022-11-22"
		score = 50
	strings:
		$command1 = "/sh " ascii
		$command2 = "/bash " ascii
		$command3 = "/ksh " ascii
		$command4 = "/csh " ascii
		$command5 = "/tcpdump " ascii
		$command6 = "/cat " ascii
		$command7 = "/head " ascii
		$command8 = "/nano " ascii
		$command9 = "/pico " ascii
		$command10 = "/rview " ascii
		$command11 = "/vi " ascii
		$command12 = "/vim " ascii
		$command13 = "/rvi " ascii
		$command14 = "/rvim " ascii
		$command15 = "/more " ascii
		$command16 = "/less " ascii

	condition:
		filename == "sudoers" or filepath contains "/etc/sudoers.d" and 
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
	strings:
		/* \nrootpw \{SSHA\}fsAEyxlFOtvZBwPLAF68zpUhth8lERoR */
		$c1 = { 0A 72 6f 6f 74 70 77 20 7b 53 53 48 41 7d 66 73 41 45 79 78 6c 46 4f 74 76 5a 42 77 50 4c 41 46 36 38 7a 70 55 68 74 68 38 6c 45 52 6f 52 }

	condition:
		filename == "slapd.conf" and 
		any of ($c*)
}

