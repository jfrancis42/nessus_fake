# Nessus Fake
A bit of code to generate fake Nessus reports for use when
demonstrating the Illumio Vulnerability Maps feature. This script was
written for (and tested with) python3.

The user provides login credentials to a PCE, long with one or more
sample Nessus vulnerability scans in the sample directory (more info
below). This script pulls all IPv4 address info from the PCE, parses
the sample Nessus reports in the sample directory, and constructs a
new, fake, Nessus report using random vulnerabilities from the sample
report(s) customized with the actual IP addresses of real
workloads. While no effort is made to match the vulnerabilities with
the actual Workload OS, the code does insure that all vulnerabilities
for a given Workload are all from the same OS (ie, it doesn't mix
Windows and Linux vulnerabilities on the same Workload).

The APIKEY.json file contains the full configuration for the script to
run:

```
{
    "pce":"pce.example.com",
    "port":"8443",
    "org":"69",
    "auth_username":"api_14b2acc4538725efc",
    "secret":"c592f6927998d7b0caac733a2a46b1743b1688398c86d704fb1170aa0bdc66a4",
    "self_signed":true,
    "max_vulns":10,
    "samples":"samples/",
    "report_name":"Example Nessus Report",
    "output_file":"Example_Report.nessus"
}
```

These values are as follows:

* pce - The FQDN of the PCE. Do not include the port or "http://"
* port - An integer representing the API port. Typically 8443 or 443
  for on-prem, 443 for SaaS.
* org - An integer representing your OrgID. Typically 1 for on-prem.
* auth_username - Your API key username.
* secret - Your API key secret.
* self_signed - 'true' if using a self-signed cert, otherwise 'false'.
* max_vulns - An integer representing the maximum numbers of
  vulnerabilities reported per Workload.
* samples - A string representing the directory where sample Nessus
  reports are stored. Can be relative or absolute.
* report_name - A string representing the internal name of the report.
* output_file - A string representing the file name of the generated
  report. Can be absolute or relative.

Once the sample reports are in place and the APIKEY.json file is
populated, simply run the script, and it should generate your output
file. Very little (ie, none) error checking is in the script, so if
you feed it bad input, it'll die. Note that it only makes a sync API
call to the PCE, so it's limited to returning 500 Workloads. If you
want more, you'll have to write an async API call. I didn't need it
for what I was doing, so I didn't bother. This is left as an exercise
for the reader.
