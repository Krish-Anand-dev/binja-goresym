# binja-goresym

A Binary Ninja plugin that applies [GoReSym](https://github.com/mandiant/GoReSym) 
JSON output directly inside the Binary Ninja disassembler.

When analysing a stripped Go binary, Binary Ninja shows you this:
```
sub_401000
sub_4010c8
data_804ab20
```

After running this plugin with a GoReSym JSON file, you see this:
```
main.main
main.connectC2
// Source: c2.go:42
```

---

## What it does

This plugin brings GoReSym's recovered metadata into Binary Ninja across 
four areas — mirroring what the existing IDA and Ghidra scripts do in 
the GoReSym repo:

**1. Function renaming**
Applies `FullName` from `UserFunctions` to each address in the binary.
If BN did not detect a function at a recovered address, the plugin creates
one before renaming — critical for stripped binaries.

**2. Go primitive type registration**
Registers `GoString`, `GoSlice`, and `GoIface` as proper Binary Ninja
struct types under a `Go` namespace in the type system. Without these,
any recovered struct referencing a string or slice field has nothing to
resolve against — you see raw bytes instead of named fields.

**3. Struct type application**
Parses the `CReconstructed` C-like struct definitions from GoReSym's
JSON, builds a `StructureType` per type, and applies it at the type's
virtual address. Analysts see named fields in the decompiler view
instead of raw bytes.

**4. Interface layout application**
Applies the `GoIface` struct layout at each interface VA so `tab` and
`data` pointer fields are visible in the listing — rather than just
a label with no type information.

**5. Source file comments**
Writes `// Source: file.go:42` as a comment on each user function's
entry point using the `FileName` and `LineNumber` fields GoReSym
recovers when run with the `-p` flag.

---

## Requirements

- Binary Ninja 3.5 or newer (personal or commercial edition)
- GoReSym — download from [GoReSym releases](https://github.com/mandiant/GoReSym/releases)
- No pip dependencies — the plugin uses BN's embedded Python runtime

---

## Installation

**Step 1** — Clone this repo into your Binary Ninja plugins folder:

Windows:
```
cd %APPDATA%\Binary Ninja\plugins
git clone https://github.com/YOUR_USERNAME/binja-goresym
```

Mac:
```
cd ~/Library/Application\ Support/Binary Ninja/plugins
git clone https://github.com/YOUR_USERNAME/binja-goresym
```

Linux:
```
cd ~/.binaryninja/plugins
git clone https://github.com/YOUR_USERNAME/binja-goresym
```

**Step 2** — Restart Binary Ninja. The plugin will appear under:
```
Plugins → GoReSym → Apply GoReSym JSON
```

---

## Usage

**Step 1** — Run GoReSym against your Go binary to produce JSON output:
```
GoReSym -t -d -p /path/to/binary > output.json
```

The `-t` flag recovers types, `-p` recovers file paths and line numbers.
Both are needed for the full plugin experience.

**Step 2** — Open the binary in Binary Ninja.

**Step 3** — Click `Plugins → GoReSym → Apply GoReSym JSON`

**Step 4** — Select your `output.json` file when prompted.

**Step 5** — Optionally enter a load offset if the binary was loaded
at a different base address than GoReSym recorded. Leave blank for most
binaries.

Results appear immediately in the listing and decompiler views.
Check the Binary Ninja log panel for a summary of what was applied.

---

## Testing without Binary Ninja

The plugin's JSON parsing and type reconstruction logic can be tested
with plain Python — no BN license required:
```
python goresym_rename.py sample_output.json
```

This runs Layer 1 (pure Python) only and prints a summary of what
would be applied inside BN.

---

## Relation to GoReSym

This plugin is designed as a first-class companion to
[GoReSym](https://github.com/mandiant/GoReSym) by Mandiant,
bringing it to parity with the existing IDE integrations:

| Script | Location in GoReSym repo |
|---|---|
| IDA Pro | `IDAPython/goresym_rename.py` |
| Ghidra | `GhidraPython/goresym_rename.py` |
| Binary Ninja | this plugin |

The existing `BinjaPython` submodule in the GoReSym repo points to an
unmaintained external repository. This plugin is a clean, maintained
replacement with full type application, interface layout, and source
comment support.
