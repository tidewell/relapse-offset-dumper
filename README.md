# relapse-offset-dumper

Kernel offset dumper for the [Relapse](https://github.com/soniciso1/relapse) PS5 jailbreak. Extracts all firmware-specific kernel values needed to build an `offsets/XX.XX.js` file for a new firmware port.

Runs as an ELF payload on a jailbroken console (loaded via elfldr on port 9021). Results are written to `/data/relapse_dump/` and can be transferred to a PC via FTP.

## What it extracts

| Offset | Method |
|---|---|
| `kernelData` (data-text delta) | SDK kernel base addresses |
| `allproc`, `rootvnode`, `security_flags` | SDK addresses + verification reads |
| `retStatic` / `retLow16` (KASLR leak) | Active RTM_GET on PF_ROUTE socket (mirrors `exploit.js`) |
| `rodataProbe.rva` | Brute-force scan for `"_aio_submit_cmd"` in kernel `.rodata` |
| `oid.a`, `oid.b`, `oid.c` (sysctl OIDs) | Scan for `kind == 0x80048002` structs |
| `nodeMutex` | Scan for `"sysctl lock"` / `"sysctl"` mutex name |
| Raw kernel memory regions | Binary dumps for offline analysis |

## Firmware compatibility

The dumper works across PS5 firmware versions. The core techniques (RTM_GET leak, rodata string scan, OID kind matching, mutex name scan) are all firmware-independent. The scan ranges use reference points from firmware 11.20 and 11.60 with margins, covering roughly the 7.x to 13.x range. For firmware outside that range the reference RVAs in `main.c` (`REF_1120` / `REF_1160`) may need updating.

## Building

Requires the [ps5-payload-dev SDK](https://github.com/ps5-payload-dev/sdk).

```sh
export PS5_PAYLOAD_SDK=/path/to/ps5-payload-dev-sdk
make
```

Produces `relapse-dumper.elf`.

## Running

Send the ELF to a jailbroken PS5 running an ELF loader:

```sh
# Using the SDK deployer
make deploy PS5_HOST=<console-ip>

# Or manually with netcat
nc <console-ip> 9021 < relapse-dumper.elf
```

Progress is shown via PS5 toast notifications (`[0/7]` through `[7/7]`).

## Output

Written to `/data/relapse_dump/`:

| File | Contents |
|---|---|
| `offsets.txt` | All extracted offsets in human-readable format |
| `dumper.log` | Detailed execution log with timestamps |
| `kdata_*.bin` | Raw kernel memory dumps (4 regions) for offline analysis |

Transfer the output directory to your PC via FTP (port 1337 after loading `ftpsrv`).

## Using the output

1. Copy `offsets/TEMPLATE.js` from the [Relapse repo](https://github.com/soniciso1/relapse) to `offsets/<version>.js`
2. Fill in the kernel values from `offsets.txt`
3. Determine the OID struct layout: kind at `+0x14` (11.20 style) or `+0x1C` (11.60 style)
4. Add the version to `SUPPORTED` in `firmware.js`
5. Test on real hardware before contributing

The userland offsets (WebKit, libkernel, libc, gadgets, syscalls) are not extracted by this dumper. Those come from separate analysis of the userland binaries.

## License

MIT
