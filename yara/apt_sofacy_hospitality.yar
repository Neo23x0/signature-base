import "pe"

rule APT28_HospitalityMalware_document {
   meta:
      description = "Yara Rule for APT28_Hospitality_Malware document identification"
      author = "CSE CybSec Enterprise - Z-Lab"
      reference = "http://csecybsec.com/download/zlab/APT28_Hospitality_Malware_report.pdf"
      last_updated = "2017-10-02"
      tlp = "white"
   strings:
      /* this string identifies the malicious payload */
      $a = {75 52 B9 ED 1B D6 83 0F DB 24 CA 87 4F 5F 25 36 BF 66 BA}
      /* this string identifies the document */
      $b = {EC 3B 6D 74 5B C5 95 F3 9E 24 5B FE 4A 64 C7 09 CE 07 C9 58 4E 62 3B}
   condition:
      all of them and filesize > 75KB and filesize < 82KB
}

rule APT28_HospitalityMalware_mvtband_file {
   meta:
      description = "Yara Rule for mvtband.dll malware"
      author = "CSE CybSec Enterprise - Z-Lab"
      reference = "http://csecybsec.com/download/zlab/APT28_Hospitality_Malware_report.pdf"
      last_updated = "2017-10-02"
      tlp = "white"
   strings:
      $a = "DGMNOEP"
      $b = {C7 45 94 0A 25 73 30 8D 45 94}  // two significant instructions
   condition:
      all of them and pe.sections[2].raw_data_size == 0
}