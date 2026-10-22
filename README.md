# CertificateCheck
A simple app to check if an Android device is secure against CVE-2026-111943

It simply mimics https://emudhra.we-have-a-problem.com/ and initiates OkHttp connections to insecure hosts.

It doesn't have Certificate Transparency enabled, which means the app checks only local certificate revocation.
