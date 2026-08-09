# Ghidra Direct3D Xref Notes

Generated from `Omsi.exe` with Ghidra headless on 2026-08-08.

Source outputs:

- `ghidra-omsi-string-xrefs.tsv`
- `ghidra-omsi-rva-context.tsv`

## Confirmed String Xrefs

| Error string | String RVA | Xref/instruction RVA | Notes |
| --- | ---: | ---: | --- |
| `Error while creating Direct3D-Device` | `0x00279D90` | `0x0027988F` | Inside `FUN_006793a8`, function entry `0x002793A8`. |
| `Direct3D-Device lost!` | `0x0042B8D8` | `0x00429FDA` operand | Instruction starts at `0x00429FD8`. |
| `Direct3D-Device resetted!` | `0x0042BB3C` | `0x0042A392` operand | Instruction starts at `0x0042A391`; branch begins at `0x0042A38F`. |
| `Direct3D-Device-Reset schlug fehl, Fehler:` | `0x0042BB7C` | `0x0042A3BD` operand | Instruction starts at `0x0042A3BC`. |

Ghidra's xref address may point into the immediate operand bytes rather than to
the beginning of the x86 instruction. The adjusted instruction starts above are
what should be used for code context.

## Device Creation Path

Range added to the probe known-RVA table:

```text
Omsi.exe+0x002793A8..0x0027992B
```

High-signal instructions:

```text
0x0027987C  CALL dword ptr [EAX + 0x40]
0x0027987F  MOV EBX,EAX
0x00279883  MOV EAX,0x679d38
0x00279888  CALL 0x008022c0
0x0027988F  MOV EDX,0x679d90 ; "Error while creating Direct3D-Device"
0x00279896  CALL 0x008029ac
```

Interpretation: this path calls a Direct3D interface method and builds/raises the
creation failure string when the result is bad.

## Device Lost / Reset Path

Range added to the probe known-RVA table:

```text
Omsi.exe+0x00429FD8..0x0042A412
```

High-signal instructions:

```text
0x00429FD8  MOV DL,0x2
0x00429FDA  MOV EAX,0x82b8d8 ; "Direct3D-Device lost!"
0x00429FDF  CALL 0x008022c0

0x0042A386  CALL dword ptr [EAX + 0x40]
0x0042A389  MOV EBX,EAX
0x0042A38B  TEST EBX,EBX
0x0042A38D  JNZ 0x0082a39d
0x0042A38F  MOV DL,0x1
0x0042A391  MOV EAX,0x82bb3c ; "Direct3D-Device resetted!"
0x0042A396  CALL 0x008022c0

0x0042A39D  PUSH EBX
0x0042A39E  CALL 0x00562a84
0x0042A3BC  MOV EDX,0x82bb7c ; "Direct3D-Device-Reset schlug fehl, Fehler:"
0x0042A3C1  CALL 0x00409788
0x0042A3CE  CALL 0x008022c0
```

Interpretation: `EBX` holds the reset result/HRESULT-style value. On success it
logs `Direct3D-Device resetted!`; on failure it converts the error value and
formats the reset-failed message.

## Probe Impact

`OmsiCrashProbe.cpp` now labels these two ranges. Future stack candidates inside
these RVAs will be reported as Direct3D creation/reset context instead of plain
unknown `Omsi.exe` offsets.
