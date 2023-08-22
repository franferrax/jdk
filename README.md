# `java` launcher with _SSB_ mitigation for the _Red Hat_ Build of OpenJDK

This launcher enables the [_Linux_ kernel mitigation] for the _Speculative Store
Bypass (SSB) variant 4_ vulnerability ([CVE-2018-3639]), and then replaces the
process with `java` by calling [`execv("/…/java", argv)`]. The `java` executable
must be in the same directory as the launcher's realpath (which the launcher
finds by resolving its `/proc/self/exe` _symlink_).


[_Linux_ kernel mitigation]: https://www.kernel.org/doc/html/latest/userspace-api/spec_ctrl.html "The Linux kernel user-space API guide - Speculation Control"
[CVE-2018-3639]: https://www.cve.org/CVERecord?id=CVE-2018-3639 "CVE-2018-3639 record at www.cve.org"
[`execv("/…/java", argv)`]: https://www.kernel.org/doc/man-pages/online/pages/man3/exec.3.html "exec(3) — Linux manual page"
