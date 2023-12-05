rule crime_h2miner_kinsing
{
    meta:
        description = "Rule to find Kinsing malware"
        author = "Tony Lambert, Red Canary"
        date = "2020-06-09"
        id = "1cabca0d-7134-517e-b82e-f2b20b4d1c34"
    strings:
        $s1 = "-iL $INPUT --rate $RATE -p$PORT -oL $OUTPUT"
        $s2 = "libpcap"
        $s3 = "main.backconnect"
        $s4 = "main.masscan"
        $s5 = "main.checkHealth"
        $s6 = "main.redisBrute"
        $s7 = "ActiveC2CUrl"
        $s8 = "main.RC4"
        $s9 = "main.runTask"
    condition:
        (uint32(0) == 0x464C457F) and filesize > 1MB and all of them 
}
