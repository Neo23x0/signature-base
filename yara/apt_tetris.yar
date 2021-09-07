
rule apt_CN_Tetris_JS_advanced_1
{
	meta:
		author      = "@imp0rtp3"
		description = "Unique code from Jetriz, Swid & Jeniva of the Tetris framework"
		reference   = "https://imp0rtp3.wordpress.com/2021/08/12/tetris"
		date = "2020-09-06"


	strings:
		$a1 = "var a0_0x"
		$b1 = /a0_0x[a-f0-9]{4}\('0x[0-9a-f]{1,3}'\)/
		$c1 = "))),function(){try{var _0x"
		$c2 = "=window)||void 0x0===_0x"
		$c3 = "){}});}();};window['$']&&window['$']()[a0_0x"
		$c4 = "&&!(Number(window['$']()[a0_0x"
		$c5 = "=function(){return!window['$']||!window['$']()[a0_0x" // second
		$c6 = "')]||Number(window['$']()[a0_0x"
		$c7 = "')]>0x3&&void 0x0!==arguments[0x3]?arguments[0x3]:document;"
		$d1 = "){if(opener&&void 0x0!==opener[" //not dep on a0
		$d2 = "&&!/loaded|complete/"
		$d3 = "')]=window['io']["
		$d4 = "==typeof console["
		$d5 = /=setInterval\(this\[[a-fx0-9_]{2,10}\([0-9a-fx']{1,8}\)\]\[[a-fx0-9_]{2,10}\([0-9a-fx']{1,8}\)\]\(this\),(0x1388|5000)\);}/
		$d6 = "['shift']());}};"
		$d7 = "=Function('return\\x20(function()\\x20'+'{}.constructor(\\x22return\\x20this\\x22)(\\x20)'+');');"
		$d8 = "['atob']=function("
		$d9 = ")['replace'](/=+$/,'');var"
		$d10 = /\+=String\['fromCharCode'\]\(0xff&_?[0-9a-fx_]{1,10}>>\(\-(0x)?2\*/
		$e1 = "')](__p__)"
	condition:
	$a1 at 0 
	or (
		filesize<1000000
		and (
			#b1 > 2000
			or #e1 > 1 
			or 3 of ($c*)
			or 6 of ($d*) 
			or ( 	
				any of ($c*) 
				and 4 of ($d*)
			)
		)
	)
}

rule apt_CN_Tetris_JS_advanced_2
{
	meta:
		author      = "@imp0rtp3"
		description = "Strings used by Jetriz, Swid & Jeniva of the Tetris framework"
		reference   = "https://imp0rtp3.wordpress.com/2021/08/12/tetris"
		date = "2020-09-06"

	strings:
		$a1 = "SFRNTEFsbENvbGxlY3Rpb24=" // '#Socket receive,'
		$a2 = "Y2FuY2VsYWJsZQ==" // '#socket receive,'
		$a3 = "U29nb3U=" // '#task'
		$a4 = "U291cmNlQnVmZmVyTGlzdA==" // '/public/_images/'
		$a5 = "RE9NVG9rZW5MaXN0" // '/public/dependence/jquery/1.12.4/jquery.min.js'
		$a6 = "c2V0U3Ryb25n" // '/public/jquery.min.js?ver='
		$a7 = "ZWxlbQ==" // '/public/socket.io/socket.io.js'
		$a8 = "SW50MzI=" // '/sSocket'
		$a9 = "cmVzdWx0" // '/zSocket'
		$a10 = "dHJpbVJpZ2h0" // '<script>document.F=Object</script>'
		$a11 = "TUFYX1NBRkVfSU5URUdFUg==" // 'AliApp(TB'
		$a12 = "ZW50cmllcw==" // 'BIDUBrowser'
		$a13 = "X19wcm90b19f" // 'Body not allowed for GET or HEAD requests'
		$a14 = "Z2V0T3duUHJvcGVydHlTeW1ib2xz" // 'Chromium'
		$a15 = "Xi4qS29ucXVlcm9yXC8oW1xkLl0rKS4qJA==" // 'ClientRectList'
		$a16 = "emgtbW8=" // 'DOMStringList'
		$a17 = "cG93" // 'DataView'
		$a18 = "RmlsZUxpc3Q=" // 'EPSILON'
		$a19 = "YWNvc2g=" // 'FileReader'
		$a20 = "U3VibWl0" // 'Firebug'
		$a21 = "NS4x" // 'Firefox Focus'
		$a22 = "ZmluZEluZGV4" // 'FreeBSD'
		$a23 = "SW52YWxpZCBEYXRl" // 'FxiOS'
		$a24 = "ZGlzcGxheQ==" // 'HTMLSelectElement'
		$a25 = "YmFzZTY0RW5jb2Rl" // 'HeadlessChrome'
		$a26 = "RmxvYXQzMg==" // 'HuaweiBrowser'
		$a27 = "Y2xvbmU=" // 'Iceweasel'
		$a28 = "aGVhcnRCZWF0cw==" // 'Int8Array,Uint8Array,Uint8ClampedArray,Int16Array,Uint16Array,Int32Array,Uint32Array,Float32Array,Float64Array'
		$a29 = "bGFuZw==" // 'IqiyiApp'
		$a30 = "Z2V0TGFuZw==" // 'LBBROWSER'
		$a31 = "c3BsaWNl" // 'Mb2345Browser'
		$a32 = "YXRhbmg=" // 'NEW GET JOB, [GET] URL='
		$a33 = "b25yZWFkeXN0YXRlY2hhbmdl" // 'NEW LocalStorage JOB, [LocalStorage] URL='
		$a34 = "QmFpZHU=" // 'NEW POST JOB, [POST] URL='
		$a35 = "PG1ldGEgaHR0cC1lcXVpdj0iWC1VQS1Db21wYXRpYmxlIiBjb250ZW50PSJJRT0=" // 'Number#toPrecision: incorrect invocation!'
		$a36 = "Xi4qUWlob29Ccm93c2VyXC8oW1xkLl0rKS4qJA==" // 'OnlineTimer'
		$a37 = "dXNlclNvY2tldElk" // 'PaintRequestList'
		$a38 = "UGFk" // 'PluginArray'
		$a39 = "MTEuMA==" // 'Promise-chain cycle'
		$a40 = "YWJvcnQ=" // 'QHBrowser'
		$a41 = "Ni41" // 'QQBrowser'
		$a42 = "Y29tbW9uMjM0NQ==" // 'QihooBrowser'
		$a43 = "TnVtYmVyLnRvRml4ZWQ6IGluY29ycmVjdCBpbnZvY2F0aW9uIQ==" // 'SNEBUY-APP'
		$a44 = "Y29uc3RydWN0b3IsaGFzT3duUHJvcGVydHksaXNQcm90b3R5cGVPZixwcm9wZXJ0eUlzRW51bWVyYWJsZSx0b0xvY2FsZVN0cmluZyx0b1N0cmluZyx2YWx1ZU9m" // 'SourceBufferList'
		$a45 = "aG9yaXpvbnRhbA==" // 'Symbian'
		$a46 = "Z2V0VVRDTWlsbGlzZWNvbmRz" // 'URLSearchParams'
		$a47 = "cmVzcG9uc2VUZXh0" // 'WebKitMutationObserver'
		$a48 = "P3Y9" // 'Wechat'
		$a49 = "Ni4y" // 'Weibo'
		$a50 = "NjA4NzgyMjBjMjVmYmYwMDM1Zjk4NzZj" // 'X-Request-URL'
		$a51 = "aXNDb25jYXRTcHJlYWRhYmxl" // 'XiaoMi'
		$a52 = "dG9JU09TdHJpbmc=" // 'YaBrowser'
		$a53 = "ZGVm" // '[object Int16Array]'
		$a54 = "Y29uY2F0" // '^.*2345Explorer\\/([\\d.]+).*$'
		$a55 = "YnJvd3Nlckxhbmd1YWdl" // '^.*BIDUBrowser[\\s\\/]([\\d.]+).*$'
		$a56 = "ZGVidWc=" // '^.*IqiyiVersion\\/([\\d.]+).*$'
		$a57 = "W29iamVjdCBVaW50OENsYW1wZWRBcnJheV0=" // '^.*SogouMobileBrowser\\/([\\d.]+).*$'
		$a58 = "Z2V0" // '^Mozilla\\/\\d.0 \\(Windows NT ([\\d.]+);.*$'
		$a59 = "c3RvcA==" // '__FILE__'
		$a60 = "TUFYX1ZBTFVF" // '__core-js_shared__'
		$a61 = "Y3Jvc3NPcmlnaW4=" // '__devtools__'
		$a62 = "SWNlYXBl" // '__p__'
		$a63 = "Ym9sZA==" // '__pdr__'
		$a64 = "dHJpbQ==" // '__proto__'
		$a65 = "TnVtYmVyI3RvUHJlY2lzaW9uOiBpbmNvcnJlY3QgaW52b2NhdGlvbiE=" // '_initBody'
		$a66 = "cmVtb3ZlQ2hpbGQ=" // 'addEventListener'
		$a67 = "OS4w" // 'addIEMeta'
		$a68 = "ZGV2dG9vbHNjaGFuZ2U=" // 'addNoRefererMeta'
		$a69 = "bmV4dExvYw==" // 'appendChild'
		$a70 = "OTg2" // 'application/360softmgrplugin'
		$a71 = "aXNHZW5lcmF0b3JGdW5jdGlvbg==" // 'application/hwepass2001.installepass2001'
		$a72 = "ZW4t" // 'application/vnd.chromium.remoting-viewer'
		$a73 = "UHJlc3Rv" // 'baiduboxapp'
		$a74 = "c29tZQ==" // 'browserLanguage'
		$a75 = "Q3JPUw==" // 'callback'
		$a76 = "U05FQlVZLUFQUA==" // 'charCodeAt'
		$a77 = "Vml2bw==" // 'clearImmediate'
		$a78 = "RGlzcGF0Y2g=" // 'codePointAt'
		$a79 = "ZXhwb3J0cw==" // 'copyWithin'
		$a80 = "QlJFQUs=" // 'credentials'
		$a81 = "a2V5cw==" // 'crossOrigin'
		$a82 = "TWVzc2FnZUNoYW5uZWw=" // 'crossOriginJsonp'
		$a83 = "YWRkRXZlbnRMaXN0ZW5lcg==" // 'devtoolschange'
		$a84 = "c2F2ZQ==" // 'executing'
		$a85 = "dG9KU09O" // 'fakeScreen'
		$a86 = "d2ViZHJpdmVy" // 'fastKey'
		$a87 = "IHJlcXVpcmVkIQ==" // 'finallyLoc'
		$a88 = "Xi4qT1MgKFtcZF9dKykgbGlrZS4qJA==" // 'g__Browser'
		$a89 = "c2NyaXB0VmlhV2luZG93" // 'getAllResponseHeaders'
		$a90 = "Q2xpZW50UmVjdExpc3Q=" // 'getHighestZindex'
		$a91 = "dG9QcmltaXRpdmU=" // 'getOwnPropertyDescriptors'
		$a92 = "bGlua3M=" // 'handleLS'
		$a93 = "MTEuMQ==" // 'handleMessage'
		$a94 = "RGF0YVRyYW5zZmVySXRlbUxpc3Q=" // 'hasInstance,isConcatSpreadable,iterator,match,replace,search,species,split,toPrimitive,toStringTag,unscopables'
		$a95 = "Zm9udA==" // 'heartBeats'
		$a96 = "Q1NTU3R5bGVEZWNsYXJhdGlvbg==" // 'heartBeatsForLS'
		$a97 = "ZW5jdHlwZQ==" // 'heartbeat'
		$a98 = "W29iamVjdCBXaW5kb3dd" // 'hiddenIframe'
		$a99 = "c3Vic3Ry" // 'hiddenImg'
		$a100 = "aW5uZXJXaWR0aA==" // 'iQiYi'
		$a101 = "SW5maW5pdHk=" // 'imgUrl2Base64'
		$a102 = "ZnJvbQ==" // 'importScripts'
		$a103 = "c29ja2V0" // 'initSocket'
		$a104 = "bWVzc2FnZQ==" // 'inspectSource'
		$a105 = "TWl1aUJyb3dzZXI=" // 'ipec'
		$a106 = "b3NWZXJzaW9u" // 'isConcatSpreadable'
		$a107 = "YXBwbGljYXRpb24veC13d3ctZm9ybS11cmxlbmNvZGVkO2NoYXJzZXQ9VVRGLTg=" // 'isExtensible'
		$a108 = "dW5kZWZpbmVk" // 'isRender'
		$a109 = "Xi4qTWIyMzQ1QnJvd3NlclwvKFtcZC5dKykuKiQ=" // 'isView'
		$a110 = "UmVnRXhwIGV4ZWMgbWV0aG9kIHJldHVybmVkIHNvbWV0aGluZyBvdGhlciB0aGFuIGFuIE9iamVjdCBvciBudWxs" // 'like Mac OS X'
		$a111 = "aXNJbnRlZ2Vy" // 'link[href="'
		$a112 = "Q3VzdG9tRXZlbnQ=" // 'link[rel=stylesheet]'
		$a113 = "Zm9udHNpemU=" // 'localStorage'
		$a114 = "NC4w" // 'meta[name="referrer"][content="always"]'
		$a115 = "c2lnbmFs" // 'noRefererJsonp'
		$a116 = "aGFzSW5zdGFuY2U=" // 'onFreeze'
		$a117 = "UUhCcm93c2Vy" // 'onabort'
		$a118 = "Y3JlYXRlSGlkZGVuRWxlbWVudA==" // 'onerror'
		$a119 = "aW1hZ2UvcG5n" // 'onload'
		$a120 = "cGx1Z2luVHlwZQ==" // 'onloadend'
		$a121 = "Q2Fubm90IGNhbGwgYSBjbGFzcyBhcyBhIGZ1bmN0aW9u" // 'onmessage'
		$a122 = "dHJhaWxpbmc=" // 'onreadystatechange'
		$a123 = "cHJvamVjdElk" // 'onrejectionhandled'
		$a124 = "cmV0dXJuIChmdW5jdGlvbigpIA==" // 'pluginId'
		$a125 = "b25tZXNzYWdl" // 'pluginType'
		$a126 = "TnVtYmVy" // 'processGET'
		$a127 = "dGV4dGFyZWE=" // 'processLS'
		$a128 = "aXRlcmF0b3I=" // 'processPOST'
		$a129 = "Ni42" // 'projectId'
		$a130 = "TW9iaQ==" // 'pushxhr'
		$a131 = "MzYw" // 'readAsDataURL'
		$a132 = "T3BlcmE=" // 'reduceRight'
		$a133 = "bWFyaw==" // 'regeneratorRuntime = r'
		$a134 = "ZGV2aWNl" // 'return (function() '
		$a135 = "ZmV0Y2g=" // 'return new F('
		$a136 = "Xi4qVmVyc2lvblwvKFtcZC5dKykuKiQ=" // 'rewriteLinks'
		$a137 = "ZG9uZQ==" // 'sSocket'
		$a138 = "TE4y" // 'scriptViaIframe'
		$a139 = "YWxs" // 'scriptViaWindow'
		$a140 = "MjAwMA==" // 'setLS'
		$a141 = "ZmFpbA==" // 'setSL'
		$a142 = "dHJhY2U=" // 'stringify'
		$a143 = "Y29tcGxldGlvbg==" // 'suspendedStart'
		$a144 = "bmV4dA==" // 'toISOString'
		$a145 = "Z19fQnJvd3Nlcg==" // 'userSocketId'
		$a146 = "b25yZWplY3Rpb25oYW5kbGVk" // 'withCredentials'
		$a147 = "VW5kZWZpbmVk" // 'xsrf'
		$a148 = "Q2hyb21lLzY2" // 'zIndex'
		$a149 = "Y2FuY2Vs" // 'zh-mo'
		$a150 = "cmVzdWx0TmFtZQ==" // 'zh-tw'
		$a151 = "YXBwbGljYXRpb24vbW96aWxsYS1ucHFpaG9vcXVpY2tsb2dpbg==" // '{}.constructor("return this")( )'
		$a152 = "YXJn" // '© 2020 Denis Pushkarev (zloirock.ru)'
		$a153 = "U3ltYm9sIGlzIG5vdCBhIGNvbnN0cnVjdG9yIQ==" // '不支持FileReader'
		$b1 = "#Socket receive,"
		$b2 = "#socket receive,"
		$b3 = "'#task'"
		$b4 = "/public/_images/"
		$b5 = "/public/dependence/jquery/1.12.4/jquery.min.js"
		$b6 = "/public/jquery.min.js?ver="
		$b7 = "/public/socket.io/socket.io.js"
		$b8 = "/sSocket"
		$b9 = "/zSocket"
		$b10 = "<script>document.F=Object</script>"
		$b11 = "AliApp(TB"
		$b12 = "BIDUBrowser"
		$b13 = "Body not allowed for GET or HEAD requests"
		$b14 = "Chromium"
		$b15 = "ClientRectList"
		$b17 = "DataView"
		$b18 = "EPSILON"
		$b20 = "Firebug"
		$b21 = "Firefox Focus"
		$b22 = "FreeBSD"
		$b23 = "FxiOS"
		$b24 = "HTMLSelectElement"
		$b25 = "HeadlessChrome"
		$b26 = "HuaweiBrowser"
		$b27 = "Iceweasel"
		$b28 = "Int8Array,Uint8Array,Uint8ClampedArray,Int16Array,Uint16Array,Int32Array,Uint32Array,Float32Array,Float64Array"
		$b29 = "IqiyiApp"
		$b30 = "LBBROWSER"
		$b31 = "Mb2345Browser"
		$b32 = "NEW GET JOB, [GET] URL="
		$b33 = "NEW LocalStorage JOB, [LocalStorage] URL="
		$b34 = "NEW POST JOB, [POST] URL="
		$b35 = "Number#toPrecision: incorrect invocation!"
		$b36 = "OnlineTimer"
		$b37 = "PaintRequestList"
		$b38 = "PluginArray"
		$b39 = "Promise-chain cycle"
		$b40 = "QHBrowser"
		$b41 = "QQBrowser"
		$b42 = "QihooBrowser"
		$b43 = "SNEBUY-APP"
		$b44 = "SourceBufferList"
		$b45 = "Symbian"
		$b46 = "URLSearchParams"
		$b47 = "WebKitMutationObserver"
		$b48 = "Wechat"
		$b49 = "Weibo"
		$b50 = "X-Request-URL"
		$b51 = "XiaoMi"
		$b52 = "YaBrowser"
		$b53 = "[object Int16Array]"
		$b54 = "^.*2345Explorer\\/([\\d.]+).*$"
		$b55 = "^.*BIDUBrowser[\\s\\/]([\\d.]+).*$"
		$b56 = "^.*IqiyiVersion\\/([\\d.]+).*$"
		$b57 = "^.*SogouMobileBrowser\\/([\\d.]+).*$"
		$b58 = "^Mozilla\\/\\d.0 \\(Windows NT ([\\d.]+);.*$"
		$b59 = "__FILE__"
		$b60 = "__core-js_shared__"
		$b61 = "__devtools__"
		$b62 = "__p__"
		$b63 = "__pdr__"
		$b64 = "__proto__"
		$b65 = "_initBody"
		$b66 = "addEventListener"
		$b67 = "addIEMeta"
		$b68 = "addNoRefererMeta"
		$b69 = "appendChild"
		$b70 = "application/360softmgrplugin"
		$b71 = "application/hwepass2001.installepass2001"
		$b72 = "application/vnd.chromium.remoting-viewer"
		$b73 = "baiduboxapp"
		$b74 = "browserLanguage"
		$b75 = "callback"
		$b76 = "charCodeAt"
		$b77 = "clearImmediate"
		$b78 = "codePointAt"
		$b79 = "copyWithin"
		$b80 = "credentials"
		$b81 = "crossOrigin"
		$b82 = "crossOriginJsonp"
		$b83 = "devtoolschange"
		$b84 = "executing"
		$b85 = "fakeScreen"
		$b86 = "fastKey"
		$b87 = "finallyLoc"
		$b88 = "g__Browser"
		$b89 = "getAllResponseHeaders"
		$b90 = "getHighestZindex"
		$b91 = "getOwnPropertyDescriptors"
		$b92 = "handleLS"
		$b93 = "handleMessage"
		$b94 = "hasInstance,isConcatSpreadable,iterator,match,replace,search,species,split,toPrimitive,toStringTag,unscopables"
		$b95 = "heartBeats"
		$b96 = "heartBeatsForLS"
		$b97 = "heartbeat"
		$b98 = "hiddenIframe"
		$b99 = "hiddenImg"
		$b100 = "iQiYi"
		$b101 = "imgUrl2Base64"
		$b102 = "importScripts"
		$b103 = "initSocket"
		$b104 = "inspectSource"
		$b106 = "isConcatSpreadable"
		$b107 = "isExtensible"
		$b108 = "isRender"
		$b109 = "isView"
		$b110 = "like Mac OS X"
		$b111 = "link[href=\""
		$b112 = "link[rel=stylesheet]"
		$b113 = "localStorage"
		$b114 = "meta[name=\"referrer\"][content=\"always\"]"
		$b115 = "noRefererJsonp"
		$b116 = "onFreeze"
		$b117 = "onabort"
		$b118 = "onerror"
		$b120 = "onloadend"
		$b122 = "onreadystatechange"
		$b123 = "onrejectionhandled"
		$b125 = "pluginType"
		$b126 = "processGET"
		$b127 = "processLS"
		$b128 = "processPOST"
		$b129 = "projectId"
		$b130 = "pushxhr"
		$b131 = "readAsDataURL"
		$b132 = "reduceRight"
		$b133 = "regeneratorRuntime = r"
		$b134 = "return (function() "
		$b135 = "return new F("
		$b136 = "rewriteLinks"
		$b138 = "scriptViaIframe"
		$b139 = "scriptViaWindow"
		$b140 = "setLS"
		$b141 = "setSL"
		$b142 = "stringify"
		$b143 = "suspendedStart"
		$b144 = "toISOString"
		$b145 = "userSocketId"
		$b146 = "withCredentials"
		$b151 = "{}.constructor(\"return this\")( )"
		$b152 = "© 2020 Denis Pushkarev (zloirock.ru)"
		$b153 = "不支持FileReader"

	condition:
		filesize < 1000000 and (
			25 of ($a*) or
			72 of ($b*)
		)

}

rule apt_CN_Tetrisplugins_JS    
{
	meta:
		author      = "@imp0rtp3"
		description = "Code and strings of plugins from the Tetris framework loaded by Swid"
		reference   = "https://imp0rtp3.wordpress.com/2021/08/12/tetris"
		date = "2020-09-06"

	strings:


		// Really unique strings
		$a1 = "this.plugin = plugin; // 自动运行"
		$a2 = "[Success]用户正在使用\\x20Tor\\x20网络"
		$a3 = "(0xbb8);this['socketWatcher'](0xbb9);this["
		$a4 = "a2869674571f77b5a0867c3d71db5856"
		$a5 = "\\x0a\\x20\\x20var\\x20data\\x20=\\x20{}\\x0a\\x20\\x20window.c\\x20=\\x200\\x0a\\x20\\x20script2\\x20=\\x20document.createElement(\\x22script\\x22)\\x0a\\x20\\x20script2.async\\x20=\\x20true\\x0a\\x20\\x20script2.src\\x20=\\x20\\x22"
		$a6 = "{isPluginCallback:\\x20true,\\x20data,\\x20plugin:\\x20'"
		$a7 = "\\x20\\x22*\\x22)\\x0a\\x20\\x20}\\x0a\\x20\\x20document.documentElement.appendChild("
		
		// Still quite unique, but FP possible
		$b1 = "String(str).match(/red\">(.*?)<\\/font>/)"
		$b2 = "['data']);}};}},{'key':'run','value':function _0x"
		$b3 = "},{'plugin':this['plugin'],'save':!![],'type':_typeof("
		$b4 = "Cannot\\x20call\\x20a\\x20class\\x20as\\x20a\\x20function"
		$b5 = "The\\x20command\\x20is\\x20sent\\x20successfully,\\x20wait\\x20for\\x20the\\x20result\\x20to\\x20return"
		$b6 = "getUserMedia\\x20is\\x20not\\x20implemented\\x20in\\x20this\\x20browser"
		$b7 = "{'autoplay':'true'},!![]);setTimeout(function(){return $('#'+"
		$b8 = "keyLogger($('input'));\n        keyLogger($('textarea'));"
		$b9 = "api.loadJS(\"\".concat(api.base.baseUrl"
		$b10 = "\"\".concat(imgUrls[i], \"?t=\""
		$b11 = "key: \"report\",\n      value: function report(data) {\n        return this.api.callback"
		$b12 = "that.api.base.debounce("
		$b13 = "'className','restOfNavigator','push'"
		$b14 = ";};'use strict';function _typeof("
		
		// Rare strings, but not unique
		$c1 = "/public/dependence/jquery"
		$c2 = "'http://bn6kma5cpxill4pe.onion/static/images/tor-logo1x.png'"
		$c3 = "'163.com not login';"
		$c4 = "'ws://localhost:'"
		$c5 = "function _typeof(obj) { \"@babel/helpers - typeof\"; "
		$c6 = "'socketWatcher'"
		$c7 = "['configurable']=!![];"
		$c8 = "')]({'status':!![],'data':_0x"
		$c9 = "')]={'localStorage':'localStorage'in window?window[_0x"
		$c10 = "Browser not supported geolocation.');"
		$c11 = "')]({'status':!![],'msg':'','data':_0x"
		$c12 = "var Plugin = /*#__PURE__*/function () {"
		
		// The TA uses the use strict in all his plugins
		$use_strict1 = "\"use strict\";"
		$use_strict2 = "'use strict';"

		// Some of the same strings in base64, in case the attacker change their obfuscation there
		$e1 = "Cannot\x20call\x20a\x20class\x20as\x20a\x20function" base64
		$e2 = "The\x20command\x20is\x20sent\x20successfully,\x20wait\x20for\x20the\x20result\x20to\x20return" base64
		$e3 = "getUserMedia\x20is\x20not\x20implemented\x20in\x20this\x20browser" base64
		$e4 = "http://bn6kma5cpxill4pe.onion/static/images/tor-logo1x.png" base64
		$e5 = "/public/dependence/jquery" base64
		$e6 = "\x20\x22*\x22)\x0a\x20\x20}\x0a\x20\x20document.documentElement.appendChild(" base64
		$e7 = "[Success]用户正在使用\x20Tor\x20网络" base64
		$e8 = "\x0a\x20\x20var\x20data\x20=\x20{}\x0a\x20\x20window.c\x20=\x200\x0a\x20\x20script2\x20=\x20document.createElement(\x22script\x22)\x0a\x20\x20script2.async\x20=\x20true\x0a\x20\x20script2.src\x20=\x20\x22"  base64
		$e9 = "{isPluginCallback:\x20true,\x20data,\x20plugin:\x20" base64
		
	condition:
		filesize < 1000000 
		and (
			any of ($a*) 
			or 2 of ($b*)
			or 4 of ($c*)
			or 2 of ($e*)
			or(
				any of ($use_strict*)
				and(
					(
						any of ($b*) 
						and 2 of ($c*)
					)
					or any of ($e*)
				)
			)
		)
}
