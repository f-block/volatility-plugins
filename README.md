# volatility-plugins

To use these plugins, simply place them in the `volatility3/framework/plugins/windows` subfolder.

## Ptenum

For a detailed description see [here](https://insinuator.net/2021/12/release-of-pte-analysis-plugins-for-volatility-3/) and [here](https://insinuator.net/2022/09/some-experiments-with-process-hollowing/)

The corresponding memory dump can be downloaded from: https://fx.ernw.de/portal-seefx/~public/YzMxMzkxZDAtY2I0My00M2Q5LWIzZjMtNGIwYTcyNjIwMTgz?download


## imgmalfind

The `imgmalfind` plugin identifies modifications to memory mapped image files in user space (DLLs, executables), such as hooks and patches. It comes with an allow-listing mechanism and some pre-defined rules, which, however, might not yet include your particular legitimate modifications (e.g., caused by an AV or EDR system). We will see later, how we can add these.

The execution of the plugin is straight forward, we can either scan all processes or focus on a particular process by providing the PID:

```shell
vol3 -f mem.dump windows.imgmalfind --pid 1912

PID   Process  Section name(s)  First modified byte  Function(s)          Modified Module                Modified bytes Count
1912  abc.exe  .text            0x7781eb90           EtwEventWrite + 0x0  \Windows\SysWOW64\ntdll.dll    4

Orig Data
	
8b ff 55 8b ec 83 e4 f8	..U.....	
0x7781eb90:	mov	edi, edi
0x7781eb92:	push	ebp
0x7781eb93:	mov	ebp, esp
0x7781eb95:	and	esp, 0xfffffff8	

New Data
	
c2 14 00 00 ec 83 e4 f8	........	
0x7781eb90:	ret	0x14
0x7781eb93:	add	ah, ch
0x7781eb95:	and	esp, 0xfffffff8	
```

The output is structured as follows. The first line (after the header) contains:

- The Process `PID`
- The Process name (`Process`).
- The PE section(s) for the corresponding modification offset (`Section name(s)`).
- The virtual address of the first modified byte (`First modified byte`).
- A function name for the modified byte (`Function(s)`), if it can be resolved, including an offset from the start of the function (in this case `+ 0x0`, so the modification is rigth at the beginning).
- The affected image file (`Modified Module`).
- The total number of modified bytes (`Modified bytes Count`).

Some notes on the first line:

- There might be multiple results for the same modified image file, if multiple locations are modified, but not the data in between. This is especially the case with hooks.
- The PE Section field can also contains the specific PE header, if applicable.
- As modified bytes can spread across multiple PE sections, and in some cases one modified byte can belong to a PE header and a Section, we print each hit, which means this field can contain multiple entries. 
- Some modifications might be near certain functions, but not related to them. In the current implementation we simply look for the nearest function (below a given threshold) and print that function with the offset. This might, however, be a false positive and could be unrelated to the function resp. belonging to another, anonymous function. At least with offsets near the beginning of a known function, chances are good that the modification affects this particular function.
- The `Modified bytes Count` is not equivalent to the range of bytes. So, if only the first and last byte of a 8 byte chunk is modified, this field contains the value `2`.


After the first line, the rest is split into two parts: `Orig Data` and `New Data`. As the names suggest, the first part contains the original data, before any modifications, and the second part contains the identified modifications. Both are printed with a hexdump and disassembly output.

In the current example we see the effect of an ETW bypass. The first 4 bytes of the `EtwEventWrite` function were patched with a `ret 14`, preventing the function from writing any ETW event.

A similar bypass can be seen in the following output:

```shell
PID   Process         Section name(s)  First modified byte  Function(s)           Modified Module              Modified bytes Count
4936  powershell_ise  .text            0x7ff837f123e0       AmsiScanBuffer + 0x0  \Windows\System32\amsi.dll   3  

Orig Data
	
4c 8b dc 49 89 5b 08 49	L..I.[.I	
0x7ff837f123e0:	mov	r11, rsp
0x7ff837f123e3:	mov	qword ptr [r11 + 8], rbx	

New Data
	
31 c0 c3 49 89 5b 08 49	1..I.[.I	
0x7ff837f123e0:	xor	eax, eax
0x7ff837f123e2:	ret	
0x7ff837f123e3:	mov	qword ptr [r11 + 8], rbx	

```

The first three bytes of the `AmsiScanBuffer` function have been patched with `return 0`, which means even malicious data that normally would have been scanned and identified as malicious would now stay unscanned and undetected.

The next example shows a hook placed by the [NetRipper](https://github.com/NytroRST/NetRipper/) project:

```shell
PID   Process     Section name(s)  First modified byte  Function(s)           Modified Module               Modified bytes Count
7716  msedge.exe  .text            0x7fff27fa2320       send + 0x0            \Windows\System32\ws2_32.dll  5  

Orig Data
	
48 89 5c 24 08 48 89 6c	H.\$.H.l	
0x7fff27fa2320:	mov	qword ptr [rsp + 8], rbx	

New Data
	
e9 6e ec fe ff 48 89 6c	.n...H.l	
0x7fff27fa2320:	jmp	0x7fff27f90f93	

Target:
	The final target page is anonymous memory (either private or shared). Target VAD at 0x13cefb20000: 	private/shared	
44 89 4c 24 20 44 89 44	D.L$.D.D
24 18 48 89 54 24 10 89	$.H.T$..	
0x13cefb271c0:	mov	dword ptr [rsp + 0x20], r9d
0x13cefb271c5:	mov	dword ptr [rsp + 0x18], r8d
0x13cefb271ca:	mov	qword ptr [rsp + 0x10], rdx
```

The first 5 bytes of the `send` function have been overwritten with a jump to an anonymous memory region, containing a handler function of the NetRipper project.


In some cases, there might be output like this:

```shell
PID   Process         Section name(s)  First modified byte  Function(s)           Modified Module                                        Modified bytes Count
7728  powershell.exe  .text            0x7ffeeb3c4000       N/A                   \Windows\Microsoft.NET\Framework64\v4.0.30319\clr.dll  -1

Orig Data


New Data

48 c1 e9 0b 80 3c 08 ff	H....<..
75 02 f3 c3 c6 04 08 ff	u.......
c3 66 66 66 66 66 66 66	.fffffff
0f 1f 84 00 00 00 00 00	........
f3 c3 66 66 66 66 66 66	..ffffff
0f 1f 84 00 00 00 00 00	........
90 90 66 66 66 66 66 66	..ffffff
0f 1f 84 00 00 00 00 00	........	
0x7ffeeb3c4000:	shr	rcx, 0xb
0x7ffeeb3c4004:	cmp	byte ptr [rax + rcx], 0xff
0x7ffeeb3c4008:	jne	0x7ffeeb3c400c
0x7ffeeb3c400a:	ret	
0x7ffeeb3c400c:	mov	byte ptr [rax + rcx], 0xff
0x7ffeeb3c4010:	ret	
0x7ffeeb3c4011:	nop	word ptr [rax + rax]
0x7ffeeb3c4020:	ret	
0x7ffeeb3c4022:	nop	word ptr [rax + rax]
0x7ffeeb3c4030:	nop	
0x7ffeeb3c4031:	nop	
0x7ffeeb3c4032:	nop	word ptr [rax + rax]
```

Here, we have a `Modified bytes Count` of `-1` and no `Orig Data`. This means, the original data is not available from the memory dump and we have nothing to compare the modified data against. In this case, the plugin simply prints the first 64 bytes and disassembly output for the corresponding page, but it might not contain the contain the actual modifications.


At last, let's examine the plugin options:

- `--start` and `--end` allow to focus on a given memory range instead of the whole process address space. Note that the plugin uses Ptenum, so we work on page boundaries and the `--start` option requires a value that is a multiple of 0x1000 (e.g. `0x7ffeeb3c4000`).
- `--precontext` and `--postcontext` enable the inclusion of additional bytes before/after the modified bytes. Both accept an integer as argument, specifying the number of bytes to additionally include in the modification-analysis.
- `--disable-filtering` disables the allow-listing algorithm.
- `--filters` expects a json file, containing additional filters for the allow-listing algorithm. The format is described below.

Before reporting a modification, the allow-listing logic is applied in order to discard benign modifications. One example for such a benign modification is shown below. It affects the Google Chrome browser and is a functionality for blocking unwanted/malicious third party DLLs. For more details and further benign hooks, see the paper.

```shell
6580    chrome.exe  .text   0x7ff876f4d5b0  ZwMapViewOfSection + 0x0    \Windows\System32\ntdll.dll 16

Orig Data
    
4c 8b d1 b8 28 00 00 00 L...(...
f6 04 25 08 03 fe 7f 01 ..%.....
0x7ff876f4d5b0: mov r10, rcx
0x7ff876f4d5b3: mov eax, 0x28
0x7ff876f4d5b8: test    byte ptr [0x7ffe0308], 1

New Data
    
48 b8 10 be aa 61 f8 7f H....a..
00 00 ff e0 aa aa aa aa ........
0x7ff876f4d5b0: movabs  rax, 0x7ff861aabe10
0x7ff876f4d5ba: jmp rax
0x7ff876f4d5bc: stosb   byte ptr [rdi], al
0x7ff876f4d5bd: stosb   byte ptr [rdi], al
0x7ff876f4d5be: stosb   byte ptr [rdi], al
0x7ff876f4d5bf: stosb   byte ptr [rdi], al

Target:
    The target page is an unmodified page. Target VAD: \Program Files\Google\Chrome\Application\109.0.5414.75\chrome_elf.dll at 0x7ff861a90000
55 56 57 48 83 ec 60 48 UVWH..`H
8d 6c 24 60 4c 89 c0 49 .l$`L..I
0x7ff861aabe10: push    rbp
0x7ff861aabe11: push    rsi
0x7ff861aabe12: push    rdi
0x7ff861aabe13: sub rsp, 0x60
0x7ff861aabe17: lea rbp, [rsp + 0x60]
0x7ff861aabe1c: mov rax, r8
```

In contrast to the previous example, this time the hook points back to a mapped image file (and also unmodified page) and not anonymous memory, which might (but does not necessarily!) indicate a benign hook.


The plugin comes with pre-defined filters, but can be extended with the `--filters` option. It should be noted that currently we only support custom filters for hooks. The `--filters` option expects a json file containing a list of json objects with three fields:

- The affected process(es)
- The modified VAD/Memory-Mapped Image File(s)
- The target VAD/Memory-Mapped Image File(s)

Following a simple example of some custom filters. Note that the plugin interprets each field's value as a Perl-compatible regular expressions (PCRE).


```json
[
  {
    "process": "^abc\\.exe$",
    "modified_vad": "^\\\\windows\\\\system32\\\\ntdll\\.dll$",
    "target_vad": "^\\\\path\\\\to\\\\dll\\\\abc\\.dll$"
  },
  {
    "process": ".",
    "modified_vad": "^\\\\windows\\\\system32\\\\ntdll\\.dll$",
    "target_vad": "^\\\\path\\\\to\\\\dll\\\\abc\\.dll$"
  },
  {
    "process": ".",
    "modified_vad": ".",
    "target_vad": "\\\\super_legit\\.dll$"
  }
]
```

The first filter marks a hook as benign, if the process name is exactly `abc.exe`, the modified image has exactly the path `\windows\system32\ntdll.dll` and the hook-target is a DLL with the path `\path\to\dll\abc.dll`.
The second filter is intended for AV and EDR systems and is similar to the first one, except the fact that it matches every process, as AVs and EDRs typically affect most/all processes.
The last filter is extremely permissive and not recommended for "production use": It matches every process and every modified image file, as long as the target is a DLL named `super_legit.dll`, no matter at which file location.

Note:
- Even if the path should be ignored, the leading backslashes are important, as otherwise the filter would in our example also match `not_really_super_legit.dll`.
- Upper and lowercase does not have to be considered, all filters and the data from processes are all converted to lowercase before comparison.


As writing `json` involves more backslashes and is not for everybody, we can also use `yaml` and the tool `yq`:

```shell
cat filters.yml

- process: ^abc\.exe$
  modified_vad: ^\\windows\\system32\\ntdll\.dll$
  target_vad: ^\\path\\to\\dll\\abc\.dll$
- process: .
  modified_vad: ^\\windows\\system32\\ntdll\.dll$
  target_vad: ^\\path\\to\\dll\\abc\.dll$
- process: .
  modified_vad: .
  target_vad: \\super_legit\.dll$



cat filters.yml | yq > filters.json

vol3 -f mem.dump windows.imgmalfind --filters filters.json
...
```

For detailed information on the theory behind the plugin, see the [paper](https://dfrws.org/wp-content/uploads/2023/07/block-windowsmemoryforensics.pdf) resp. the [conference repository](https://github.com/f-block/DFRWS-USA-2023) for evaluation details.

