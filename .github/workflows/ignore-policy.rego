package trivy

import data.lib.trivy

default ignore = false

ignore_cves := {
    "CVE-2022-1471",
    "CVE-2022-25857",
    "CVE-2022-38749",
    "CVE-2022-38750",
    "CVE-2022-38751",
    "CVE-2022-38752",
    "CVE-2022-41854"
}

ignore {
  input.VulnerabilityID == ignore_cves[_]
}
