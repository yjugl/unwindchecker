unwindchecker - Check Windows x64 stack unwinding information
=============================================================

Purpose
-------

On Windows x64, any code that uses the `call` instruction should have
associated [stack unwinding information](
    https://learn.microsoft.com/en-us/cpp/build/exception-handling-x64
).
Otherwise, unwinding the stack from callees will fail once it reaches the
return address that points to this code.

Failures in stack unwinding lead to incomplete stacks when debugging.
They also prevent structured exception handlers (SEH) from being called, in
particular the [unhandled exception filter](
    https://learn.microsoft.com/en-us/windows/win32/api/errhandlingapi/nf-errhandlingapi-setunhandledexceptionfilter
).

For static code, the stack unwinding information is stored in the executable
file.
Use this tool to identify call instructions that do not have associated stack
unwinding information in your Windows binaries so that you can add this
information to avoid stack unwinding failures.

Setup
-----

```
pip install bitmap capstone pefile
```

Usage
-----

```
python show_missing_unwind_info.py <EXE or DLL file> [<EXE or DLL file> ...]
```

Example
-------

```
> python show_missing_unwind_info.py "C:\Program Files\Mozilla Firefox\xul.dll"

Loading 'C:\Program Files\Mozilla Firefox\xul.dll', please wait...

Section .text: unwind information covers 94.55% of 86739456 bytes.

Looking for call instructions in the parts not covered by unwind information...

0x1803ec3a9:    e8f2fbffff      call    0x1803ebfa0
0x1803ec3ae:    58      pop     rax
0x1803ec3af:    59      pop     rcx
0x1803ec3b0:    5f      pop     rdi

...

0x1852b999c:    e80f7fd7fc      call    0x1820318b0
0x1852b99a1:    660f6f0424      movdqa  xmm0, xmmword ptr [rsp]
0x1852b99a6:    660f6f4c2410    movdqa  xmm1, xmmword ptr [rsp + 0x10]
0x1852b99ac:    660f6f542420    movdqa  xmm2, xmmword ptr [rsp + 0x20]

Found 72 call instructions without unwind information in section .text.
Note that some of those may be false positives.

Section .orpc: unwind information covers 0.00% of 512 bytes.

Looking for call instructions in the parts not covered by unwind information...

Found no call instructions without unwind information in section .orpc.

Section .rodata: unwind information covers 0.00% of 2560 bytes.

Looking for call instructions in the parts not covered by unwind information...

Found no call instructions without unwind information in section .rodata.
```
