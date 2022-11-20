
/* 
    Rules which detect vulnerabilities in configuration files.
    External variables are used so they only work with YARA scanners, that pass them on (e.g. Thor, Loki and Spyre)
*/


rule vuln_linux_sudoers {
	meta:
		description = "Detects sudoers config with commands which might allow privilege escalation to root"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp"
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
		filename == "sudoers" or filepath contains "/etc/sudoers.d" 
		and any of ($command*)
}

rule vuln_linux_nfs_exports {
	meta:
		description = "Detects insecure /etc/exports NFS config which might allow privilege escalation to root or other users. The parameter insecure allows any non-root user to mount NFS shares via e.g. an SSH-tunnel. With no_root_squash SUID root binaries are allowed."
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		reference = "https://www.errno.fr/nfs_privesc.html"
		author = "Arnim Rupp"
		score = 50
	strings:
        // line has to start with / to avoid triggering on #-comment lines
		$conf1 = /\n\/.{2,200}?\binsecure\b/ ascii
		$conf2 = /\n\/.{2,200}?\bno_root_squash\b/ ascii

	condition:
		filename == "exports" and filepath == "/etc" 
		and any of ($conf*)
}

rule aes_key_in_mysql_history {
	meta:
		description = "Detects AES key outside of key management in .mysql_history"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp"
		score = 50
	strings:
		$c1 = /\bAES_(DE|EN)CRYPT(.{1,128}?,.??'.{1,128}?')/ ascii
		$c2 = /\baes_(de|en)crypt(.{1,128}?,.??'.{1,128}?')/ ascii

	condition:
		filename == ".mysql_history"
		and any of ($c*)
}

rule slapd_conf_with_default_password {
	meta:
		description = "Detects an openldap slapd.conf with the default password test123"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp"
		score = 100
	strings:
		$c1 = /\nrootpw \{SSHA\}fsAEyxlFOtvZBwPLAF68zpUhth8lERoR/ ascii

	condition:
		filename == "slapd.conf"
		and any of ($c*)
}

