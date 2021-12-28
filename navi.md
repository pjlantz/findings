# CVE-2020-13111: Out-of-bounds write in NaviServer

NaviServer 4.99.4 to 4.99.19 mishandles parsing and validation of chunk lengths in the function `ChunkedDecode` in `driver.c`  This will result in a negative value being passed to memmove via the `size` parameter, causing a huge copy to hit an unmapped page, so called wild copy and termination of the `nsd` process.

Patch is available in [3].

## References 

[1] NaviServer - https://sourceforge.net/projects/naviserver/

[2] Wild copy - https://googleprojectzero.blogspot.com/2015/03/taming-wild-copy-parallel-thread.html

[3] Patch - https://bitbucket.org/naviserver/naviserver/commits/a5c3079f1d8996d5f34c9384a440acf3519ca3bb
