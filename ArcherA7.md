# Command injection in TP-Link Archer A7

CVE-2020-10882 [1] was used to exploit the TP-Link Archer C7 in Pwn2Own 2019. This write-up provides details about the patch that was issued by TP-Link for this vulnerability and why it is insufficient as a remediation for the command injection.


## Details
During the parsing of a Slave Key Offer message to the device, a MAC address can be supplied in the `slave_mac` parameter as shown below

```
{"method":"slave_key_offer","data":{"group_id":"-1","ip":"192.168.0.5","slave_mac":"'00:00:00:00:00:00","slave_private_account":"0e8c507fbc4b1ad0fef7b8706b0006f4340542f3a45c6012efa0f4a73356037a02f5351a0a08c76bf984cb7b9302f55689c5ec4219392aa4fed50676f891469b80c3e06332182da121528dc9d54560b94df65923b904d9ebb6c4db1fbf0b0b21c9b03df88453160be9c941115c8b0e16e22b0d7614941bb822e4d4220f7b621e","slave_private_password":"0e8c507fbc4b1ad0fef7b8706b0006f4340542f3a45c6012efa0f4a73356037a02f5351a0a08c76bf984cb7b9302f55689c5ec4219392aa4fed50676f891469b80c3e06332182da121528dc9d54560b94df65923b904d9ebb6c4db1fbf0b0b21c9b03df88453160be9c941115c8b0e16e22b0d7614941bb822e4d4220f7b621e","want_to_join":false,"model":"RE300","product_type":"RangeExtender","operation_mode":"RE","signal_strength_24g":-41,"signal_strength_5g":0,"link_speed_24g":144000,"link_speed_5g":0,"level":1,"connection_type":"2.4GHz"}}
```

Previously, the vulnerable code that handled this message was located in the `tdpServer` binary and was equivalent to the following lines of code
which enabled the command injection via the `slave_mac` variable:

```
snprintf(command, 0x1ff, "lua -e 'require(\"luci.controller.admin.onemesh\").sync_wifi_specified({mac=\"%s\"})'", slave_mac);
system(command);
```

This vulnerable code was removed in the firmware version 1.0.15 Build 20200721 rel.40773. Instead of the above code, there is now
a call to the function `fcn.004171ac` which takes `param_1` as input, that is the `slave_mac` value:

```
undefined4 fcn.004171ac(int32_t param_1)
{
    int32_t iVar1;
    int32_t iVar2;
    undefined4 uVar3;
    undefined *puVar4;
    undefined4 in_stack_00000014;
    int32_t in_stack_00000018;
    int32_t in_stack_ffffffec;
   
    puVar4 = &stack0xffffffd0;
    if (param_1 != 0) {
        iVar1 = fcn.0040a180(0x41fd04);
        puVar4 = &stack0xffffffd4;
    // esilref: 'luci.controller.admin.onemesh'
        if (iVar1 != 0) {
    // esilref: 'dispatch'
            iVar2 = fcn.0040a790(iVar1, 0x41b984, param_1, 0x41aac0);
            uVar3 = 0;
            if (iVar2 < 0) {
    // esilref: 'tdpOneMeshStruct.c:688'
    // esilref: '_lua_do'
                uVar3 = 0xffffffff;
                fcn.00403764(in_stack_00000014, in_stack_00000018, in_stack_ffffffec);
            }
            fcn.0040a264(iVar1);
            return uVar3;
        }
    }
    fcn.00403764(*(undefined4 *)(puVar4 + 0x3c), *(int32_t *)(puVar4 + 0x40), *(int32_t *)(puVar4 + 0x14));
    return 0xffffffff;
}
```

`fcn.004171ac` calls `fcn.0040a180` with the string `"luci.controller.admin.onemesh"` as input argument.
`fcn.0040a180` will then programmatically setup which script to invoke using lualib APIs and the `lua_pcall` function.
Furthermore, `fcn.0040a790` which takes `param_1` (`slave_mac`) as input will complete the invoking of the script.

The `luci.controller.admin.onemesh` module is implemented in the `onemesh.lua` script which is located in `/usr/lib/lua/luci/controller/admin/onemesh.lua` on the device.
This Lua script was disassembled with the Luadec tool [2] and the following disassembly snippet of the script shows that it executes the following code which is vulnerable to injection

```
.
.
.
  193 [-]: GETTABLE  R11 R11 K55  ; R11 := R11["fork_call"]
  194 [-]: LOADK     R12 K53      ; R12 := "ubus call sync sync_wifi \'"
  195 [-]: MOVE      R13 R10      ; R13 := R10
  196 [-]: LOADK     R14 K54      ; R14 := "\' &"
  197 [-]: CONCAT    R12 R12 R14  ; R12 := concat(R12 to R14)
  198 [-]: CALL      R11 2 1      ;  := R11(R12)
  199 [-]: LOADBOOL  R11 1 0      ; R11 := true
  200 [-]: RETURN    R11 2        ; return R11
  201 [-]: RETURN    R0 1         ; return
.
.
.
```

This snippet corresponds to the following shell command with the help of the `fork_call` function.

```
ubus call sync sync_wifi '%s'
````

This allows an attacker to still break out of the current command with `';` and inject more commands.

To summarize, the root cause of the command injection is now the Lua script as opposed to the previous case where the command injection was possible via the `system` function in the tdpServer binary.

## References
[1] https://nvd.nist.gov/vuln/detail/CVE-2020-10882

[2] https://github.com/viruscamp/luadec
