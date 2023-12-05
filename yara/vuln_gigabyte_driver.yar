
rule VULN_PUA_GIGABYTE_Driver_Jul22_1 {
   meta:
      description = "Detects a vulnerable GIGABYTE driver sometimes used by malicious actors to escalate privileges"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://twitter.com/malmoeb/status/1551449425842786306"
      date = "2022-07-25"
      score = 65
      hash1 = "31f4cfb4c71da44120752721103a16512444c13c2ac2d857a7e6f13cb679b427"
      id = "c66b858f-a034-53e1-b0fd-e48693fc6913"
   strings:
      $xc1 = { 00 46 00 69 00 6C 00 65 00 56 00 65 00 72 00 73
               00 69 00 6F 00 6E 00 00 00 00 00 35 00 2E 00 32
               00 2E 00 33 00 37 00 39 00 30 00 2E 00 31 00 38
               00 33 00 30 00 20 00 62 00 75 00 69 00 6C 00 74
               00 20 00 62 00 79 00 3A 00 20 00 57 00 69 00 6E
               00 44 00 44 00 4B 00 00 00 00 00 32 00 09 00 01
               00 49 00 6E 00 74 00 65 00 72 00 6E 00 61 00 6C
               00 4E 00 61 00 6D 00 65 00 00 00 67 00 64 00 72
               00 76 00 2E 00 73 00 79 00 73 }
      
      /* base64 encoded form */
      $x1 = "AEYAaQBsAGUAVgBlAHIAcwBpAG8AbgAAAAAANQAuADIALgAzADcAOQAwAC4AMQA4ADMAMAAgAGIAdQBpAGwAdAAgAGIAeQA6ACAAVwBpAG4ARABEAEsAAAAAADIACQABAEkAbgB0AGUAcgBuAGEAbABOAGEAbQBlAAAAZwBkAHIAdgAuAHMAeQBz"
      $x2 = "BGAGkAbABlAFYAZQByAHMAaQBvAG4AAAAAADUALgAyAC4AMwA3ADkAMAAuADEAOAAzADAAIABiAHUAaQBsAHQAIABiAHkAOgAgAFcAaQBuAEQARABLAAAAAAAyAAkAAQBJAG4AdABlAHIAbgBhAGwATgBhAG0AZQAAAGcAZAByAHYALgBzAHkAc"
      $x3 = "ARgBpAGwAZQBWAGUAcgBzAGkAbwBuAAAAAAA1AC4AMgAuADMANwA5ADAALgAxADgAMwAwACAAYgB1AGkAbAB0ACAAYgB5ADoAIABXAGkAbgBEAEQASwAAAAAAMgAJAAEASQBuAHQAZQByAG4AYQBsAE4AYQBtAGUAAABnAGQAcgB2AC4AcwB5AH"
   condition:
      filesize < 4000KB and 1 of them
}
