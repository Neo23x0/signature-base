/*
   YARA rules for detection of Spring Boot Actuator data egress, motivated by
   CVE-2026-40976 (Spring Boot 4.0.0-4.0.5 default-security misconfigured when
   spring-boot-actuator-autoconfigure is on the classpath without
   spring-boot-health). Both rules are CVE-AGNOSTIC: they fire on any Spring
   Boot deployment where actuator data is reaching an unintended client,
   regardless of whether the underlying cause is CVE-2026-40976, an
   exposure-misconfiguration in management.endpoints.web.exposure.include, a
   reverse-proxy mis-routing, or a future regression of similar shape.

   Both rules are body-content rules — match on captured HTTP response
   payloads (WAF body capture, tcpdump/PCAP, mirrored egress traffic).

   References:
     - https://spring.io/security/cve-2026-40976/
     - https://github.com/spring-projects/spring-boot/commit/874f6294b91da18367b8b5ab7b2fad3fa23cfba6
     - https://docs.spring.io/spring-boot/reference/actuator/endpoints.html#actuator.endpoints.heapdump
     - https://binautopsy.com/research/cve-2026-40976/

   Author: Binautopsy Labs (defensive analysis brief)
   Created: 2026-04-28
*/

rule EXPL_Spring_Boot_HPROF_Egress_Apr26_1 {
   meta:
      description = "Detects a Java HPROF heap dump in an HTTP response body — typically an unauthenticated /actuator/heapdump exfiltration. CVE-AGNOSTIC: any Spring deployment streaming HPROF to an off-host client is in trouble regardless of the specific advisory."
      author = "Binautopsy Labs"
      reference = "https://binautopsy.com/research/cve-2026-40976/"
      date = "2026-04-28"
      score = 75
      id = "ad285a2e-4e3f-4347-be4f-4f8a06402a77"
      hash1 = "JAVA PROFILE 1.0.2"
   strings:
      $magic_102 = "JAVA PROFILE 1.0.2"
      $magic_101 = "JAVA PROFILE 1.0.1"
      $magic_103 = "JAVA PROFILE 1.0.3"
   condition:
      filesize > 1024 and any of them at 0
}

rule EXPL_Spring_Security_Noop_Password_Egress_Apr26_1 {
   meta:
      description = "Detects Spring Security's {noop} PasswordEncoder marker followed by a printable-ASCII password in an HTTP response body. The {noop} prefix indicates plaintext password storage and SHOULD NEVER appear in any normal response — its presence in egress traffic is a high-fidelity credential-leak indicator. Most commonly observed in heap-dump exfiltration (CVE-2026-40976 follow-on) but generalises to any heap, log, or config-dump leak."
      author = "Binautopsy Labs"
      reference = "https://docs.spring.io/spring-security/reference/features/authentication/password-storage.html#authentication-password-storage-dpe-format"
      date = "2026-04-28"
      score = 70
      id = "70d594d5-33b9-4a8f-8183-7726f679dbf1"
   strings:
      $marker = /\{noop\}[\x21-\x7e]{4,200}/
   condition:
      $marker
}
