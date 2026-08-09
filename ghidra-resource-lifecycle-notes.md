# Ghidra Resource Lifecycle Notes

## Scope

This pass inspected `Omsi.exe`, its imported symbols, and generated Ghidra
output only. No excluded content or SDK/Addons directory was scanned.

## PhysObj collision meshes

The warning literal is owned by `0x003AE8E0..0x003AEC00`. The loader checks
fields `+0x16C` and `+0x170` and loads only when both buffers are null. A
non-null field takes the warning branch without replacing or freeing them.

The successful path allocates vertex and index buffers, creates ODE trimesh
data, builds it, and marks collision state as loaded. Its caller is
`0x003B432C`, a large object/parser owner.

The paired unload routine is `0x003AE554`. It destroys ODE trimesh data, frees
both buffers, and clears `+0x16C/+0x170`. The warning therefore demonstrates
load-before-unload ordering or duplicate load state; it does not by itself
prove that the unload routine leaks.

A second collision owner uses build `0x003AB190` and unload `0x003AB110`.
That pair creates/destroys ODE trimesh data and owner buffers symmetrically.

## Texture lifecycle

Texture creation has three established owners:

- `0x0024307C..0x00244AB3`: wide-path D3DX texture loader.
- `0x003F891C..0x003F933B`: ANSI D3DX texture/image loader.
- `0x003BB224..0x003BBDE1`: script-texture validation/creation path.

The central release routine is `0x003F9C48..0x003F9DB5`. It calls the texture
COM object's `Release`, logs `Textur-Release-Counter` when references remain,
clears the managed interface field, and resets the 0x68-byte record state.

Observed release owners include `0x003F7258`, `0x003F9E30`, and `0x001FDB48`.
Runtime VAS exhaustion may still result from delayed cleanup, retained
references, allocation size, or fragmentation; static symmetry cannot
distinguish those cases.

## Allocator map

OMSI's Delphi runtime uses VirtualAlloc wrappers for the paths found here:

- `0x00003034`: grows or relocates allocator blocks using reserve/commit.
- `0x00003508`: coalesces blocks and releases complete regions with VirtualFree.
- Additional callers exist at `0x00002E6C`, `0x00002F2C`, `0x00003CA8`, and
  `0x00058940`.

No `HeapAlloc` or `HeapFree` symbol was present in the analyzed symbol table.
Delphi internals may still reach heap services through other wrappers.

## AI cleanup checkpoints

The diagnostic pointer sites remain `0x0042AD90..0x0042ADB0` for buses and
`0x0042AE20..0x0042AE40` for cars. The clean Ghidra database does not define a
complete containing function for this Delphi checkpoint region. The narrow
labels are reliable for runtime attribution, but broader ownership would be
speculative.
