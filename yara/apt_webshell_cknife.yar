
rule cknife_webshells {
	meta:
		description = "Cknife JSP, ASP, PHP webshells"
		author = "Levi (levi@recordedfuture.com) (modified by Florian Roth)"
		reference = "https://www.recordedfuture.com/web-shell-analysis-part-2/"
		hash = "a182cb2d696a99caa3052475b916110ca10fdccb35a11724c59bac4e05eb4740"
		hash = "5110dcd8b18b59ed8d1a88fcf5affe489586a9928b3c0ac5c977e134595ab398"
		hash = "2bc0ed9f40b81c8641cedae93cc33bc40a6d52b38542b8bc310cb30fb843af47"
		hash = "35128ca92e2c8ed800b4913f73b6bc1de2f4b3ee2dd19ef6c93d173b64c92221"
	strings:
		$author_string = "choraheiheihei"
		$pwd = "Cknife"
		$http_response_write = "->|"
		$http_response_echo = "|<-"
	condition:
		($author_string or $pwd) or ($http_response_write and $http_response_echo)
		and filesize < 300
}
