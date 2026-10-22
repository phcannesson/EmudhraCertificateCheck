# EmudhraCertificateCheck
A simple app to check if an Android device is secure against 2026 eMudhra Intermediate CA certificates compromission.

It simply mimics https://emudhra.we-have-a-problem.com/ and initiates OkHttp connections to insecure hosts.

It doesn't have Certificate Transparency enabled, which means the app checks only local certificate revocation.

# Installation

An APK is available directly with the [1.1 release](https://github.com/phcannesson/EmudhraCertificateCheck/releases/tag/1.1).

Or you can simply build the project yourself.
