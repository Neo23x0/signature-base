rule APT_MAL_Fujinama {
    meta:
        description = "Fujinama RAT used by Leonardo SpA Insider Threat"
        author = "ReaQta Threat Intelligence Team"
        reference = "https://reaqta.com/2021/01/fujinama-analysis-leonardo-spa"
        date = "2021-01-07"
        version = "1"   
        id = "b10b1e45-aa6c-53fa-8e02-7a325c3e12fb"
    strings:
        $kaylog_1 = "SELECT" wide ascii nocase
        $kaylog_2 = "RIGHT" wide ascii nocase
        $kaylog_3 = "HELP" wide ascii nocase
        $kaylog_4 = "WINDOWS" wide ascii nocase
        $computername = "computername" wide ascii nocase
        $useragent = "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; SV1; .NET CLR 2.0.50727)" wide ascii nocase
        $pattern = "'()*+,G-./0123456789:" wide ascii nocase
        $function_1 = "t_save" wide ascii nocase
        $cftmon = "cftmon" wide ascii nocase
        $font = "Tahoma" wide ascii nocase
    condition:
        uint16(0) == 0x5a4d and all of them
}