
rule ChinaChopper_Generic {
	meta:
		description = "China Chopper Webshells - PHP and ASPX"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth"
		reference = "https://www.fireeye.com/content/dam/legacy/resources/pdfs/fireeye-china-chopper-report.pdf"
		date = "2015/03/10"
		modified = "2021-10-29"
	strings:
		$x_aspx = /%@\sPage\sLanguage=.Jscript.%><%eval\(RequestItem\[.{,100}unsafe/
		$x_php = /<?php.\@eval\(\$_POST./

		$fp1 = "GET /"
		$fp2 = "POST /"
	condition:
		1 of ($x*) and not 1 of ($fp*)
	}
