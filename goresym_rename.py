# goresym_rename.py
# Binary Ninja plugin — companion to GoReSym (https://github.com/mandiant/GoReSym)
#
# Applies GoReSym JSON output directly inside Binary Ninja:
#   1. Renames functions using recovered symbol names
#   2. Registers Go primitive types (GoString, GoSlice, GoIface) in the type system
#   3. Applies reconstructed struct layouts at their virtual addresses
#   4. Applies GoIface layout at interface addresses
#   5. Writes source file + line number as a comment on each function entry point
#
# Mirrors the behaviour of:
#   - IDAPython/goresym_rename.py  (IDA Pro)
#   - GhidraPython/goresym_rename.py (Ghidra)
#
# Usage:
#   Plugins menu → GoReSym → Apply GoReSym JSON
#   Or run via Binary Ninja's script runner pointing at a GoReSym JSON file.
#
# Tested against: Binary Ninja >= 3.5, GoReSym >= 2.0 JSON output format

import json
import os
import re

# Binary Ninja API — only available inside the BN runtime.
# All imports are wrapped so the pure-Python logic remains testable outside BN.
try:
    import binaryninja as bn
    from binaryninja import (
        BinaryView,
        StructureBuilder,
        Type,
        log_info,
        log_warn,
        log_error,
    )
    BN_AVAILABLE = True
except ImportError:
    BN_AVAILABLE = False

# ── Layer 1: Pure Python — testable without Binary Ninja ──────────────────────

def load_goresym(json_path: str) -> dict:
    """
    Load and validate a GoReSym JSON output file.
    Returns the parsed dict or raises with a clear message.
    """
    if not os.path.exists(json_path):
        raise FileNotFoundError(f"GoReSym JSON not found: {json_path}")

    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    # Basic sanity check — a valid GoReSym file always has at least one of these
    if not any(k in data for k in ("UserFunctions", "StdFunctions", "Types")):
        raise ValueError("File does not appear to be valid GoReSym output.")

    return data


def extract_user_functions(data: dict) -> list[dict]:
    """
    Pull UserFunctions from the GoReSym JSON.
    Each entry looks like:
      { "FullName": "main.connectC2", "Start": 4198600, "End": 4198700,
        "FileName": "c2.go", "LineNumber": 42 }
    """
    return data.get("UserFunctions", [])


def extract_types(data: dict) -> list[dict]:
    """
    Pull reconstructed Go types from the GoReSym JSON.
    Each entry includes a CReconstructed field with a C-like struct definition
    and a VA field with the virtual address to apply it at.
    """
    return [t for t in data.get("Types", []) if t.get("CReconstructed") and t.get("VA")]


def extract_interfaces(data: dict) -> list[dict]:
    """
    Pull interface entries. Each has a VA where the GoIface layout should be applied.
    """
    return data.get("Interfaces", [])


def parse_struct_fields(c_reconstructed: str) -> list[tuple[str, str]]:
    """
    Parse a C-like struct definition from GoReSym's CReconstructed field.
    Returns a list of (field_name, field_type) tuples.

    Example input:
        struct MyStruct {
            GoString name;
            uint64_t size;
            GoSlice items;
        }

    Example output:
        [("name", "GoString"), ("size", "uint64_t"), ("items", "GoSlice")]
    """
    fields = []
    # Match lines like:  uint64_t fieldName;
    pattern = re.compile(r'^\s*([\w\s\*]+?)\s+(\w+)\s*;', re.MULTILINE)

    for match in pattern.finditer(c_reconstructed):
        field_type = match.group(1).strip()
        field_name = match.group(2).strip()

        # Skip the outer struct declaration line itself
        if field_type.startswith("struct"):
            continue

        fields.append((field_name, field_type))

    return fields


def build_function_map(user_functions: list[dict]) -> dict[int, dict]:
    """
    Build a lookup dict keyed by start address for fast access.
    { 4198600: { "FullName": "main.connectC2", "FileName": "c2.go", "LineNumber": 42 } }
    """
    func_map = {}
    for fn in user_functions:
        start = fn.get("Start")
        if start is not None:
            func_map[start] = fn
    return func_map


def get_go_version(data: dict) -> str:
    """Extract Go version string from GoReSym output."""
    return data.get("Version", "unknown")

# ── Layer 2: Binary Ninja API ─────────────────────────────────────────────────
# All functions below require BN_AVAILABLE = True to do anything useful.
# They are written against the Binary Ninja 3.5+ Python API.

def register_go_primitives(bv: "BinaryView") -> dict[str, "bn.Type"]:
    """
    Register GoString, GoSlice, and GoIface as proper struct types
    in Binary Ninja's type system under a 'Go' namespace.

    These are the three fundamental Go runtime types that appear as fields
    in nearly every reconstructed struct GoReSym produces. Without registering
    them first, any struct referencing a GoString or GoSlice field has nothing
    to resolve against — you just see raw bytes.

    Mirrors what IDAPython does via idc_parse_types() and what the Ghidra
    script does via register_go_primitives(dtm).

    Returns a dict of { type_name: bn.Type } for use in apply_types().
    """
    if not BN_AVAILABLE:
        return {}

    ptr_size = bv.arch.address_size
    registered = {}

    # ── GoString ──────────────────────────────────────────────────────────────
    # type GoString struct { ptr *uint8; len int }
    with StructureBuilder.builder(bv, bn.QualifiedName(["Go", "GoString"])) as sb:
        sb.packed = True
        sb.append(Type.pointer(bv.arch, Type.int(1, False)), "ptr")
        sb.append(Type.int(ptr_size, False),                 "len")

    registered["GoString"] = bv.get_type_by_name(
        bn.QualifiedName(["Go", "GoString"])
    )

    # ── GoSlice ───────────────────────────────────────────────────────────────
    # type GoSlice struct { ptr *uint8; len int; cap int }
    with StructureBuilder.builder(bv, bn.QualifiedName(["Go", "GoSlice"])) as sb:
        sb.packed = True
        sb.append(Type.pointer(bv.arch, Type.int(1, False)), "ptr")
        sb.append(Type.int(ptr_size, False),                 "len")
        sb.append(Type.int(ptr_size, False),                 "cap")

    registered["GoSlice"] = bv.get_type_by_name(
        bn.QualifiedName(["Go", "GoSlice"])
    )

    # ── GoIface ───────────────────────────────────────────────────────────────
    # type GoIface struct { tab *uint8; data *uint8 }
    # tab points to the interface type descriptor (itab)
    # data points to the concrete value
    with StructureBuilder.builder(bv, bn.QualifiedName(["Go", "GoIface"])) as sb:
        sb.packed = True
        sb.append(Type.pointer(bv.arch, Type.int(1, False)), "tab")
        sb.append(Type.pointer(bv.arch, Type.int(1, False)), "data")

    registered["GoIface"] = bv.get_type_by_name(
        bn.QualifiedName(["Go", "GoIface"])
    )

    log_info(
        f"[GoReSym] Registered Go primitives: "
        f"GoString ({ptr_size*2}B), GoSlice ({ptr_size*3}B), GoIface ({ptr_size*2}B)"
    )

    return registered


def resolve_field_type(
    type_name: str,
    ptr_size: int,
    registered: dict,
) -> "bn.Type | None":
    """
    Convert a C-like type string from CReconstructed into a Binary Ninja Type.
    Handles Go primitives, standard C integer types, and pointer types.
    Falls back to a byte array for anything unrecognised.
    """
    if not BN_AVAILABLE:
        return None

    # Go primitives registered in the type system
    if type_name in registered and registered[type_name]:
        return Type.named_type_from_registered_type(registered[type_name])

    # Standard C integer types GoReSym uses in CReconstructed
    c_int_map = {
        "uint8_t":  Type.int(1, False),
        "uint16_t": Type.int(2, False),
        "uint32_t": Type.int(4, False),
        "uint64_t": Type.int(8, False),
        "int8_t":   Type.int(1, True),
        "int16_t":  Type.int(2, True),
        "int32_t":  Type.int(4, True),
        "int64_t":  Type.int(8, True),
        "uintptr":  Type.int(ptr_size, False),
        "bool":     Type.int(1, False),
        "float32":  Type.float(4),
        "float64":  Type.float(8),
    }
    if type_name in c_int_map:
        return c_int_map[type_name]

    # Pointer types — e.g. "*uint8", "*GoString"
    if type_name.startswith("*"):
        inner = resolve_field_type(type_name[1:], ptr_size, registered)
        if inner:
            return Type.pointer(bn.Architecture["x86_64"], inner)

    # Fallback — represent unknown types as a void pointer
    log_warn(f"[GoReSym] Unrecognised field type '{type_name}', using void*")
    return Type.pointer(bn.Architecture["x86_64"], Type.void())

def rename_functions(bv: "BinaryView", user_functions: list[dict], offset: int = 0) -> dict:
    """
    Rename functions in Binary Ninja using recovered symbol names from GoReSym.

    For each entry in UserFunctions:
      - Looks up the function at Start address (adjusted by offset)
      - Sets its name to FullName (e.g. "main.connectC2")
      - If FileName and LineNumber are present, writes a source comment

    The offset parameter handles binaries where the loaded base address
    differs from what GoReSym recorded — common with ASLR or manual loads.

    Returns a simple stats dict for logging.
    """
    if not BN_AVAILABLE:
        return {}

    stats = {
        "renamed":   0,
        "commented": 0,
        "not_found": 0,
    }

    func_map = build_function_map(user_functions)

    for va, fn in func_map.items():
        adjusted_va = va + offset
        full_name   = fn.get("FullName", "").strip()

        if not full_name:
            continue

        # Look up the function at this address in BN
        func = bv.get_function_at(adjusted_va)

        if func is None:
            # BN didn't find a function here — create one and try again
            bv.create_user_function(adjusted_va)
            func = bv.get_function_at(adjusted_va)

        if func is None:
            log_warn(f"[GoReSym] Could not find or create function at 0x{adjusted_va:x} ({full_name})")
            stats["not_found"] += 1
            continue

        # Rename the function
        func.name = full_name
        stats["renamed"] += 1

        # Write source file + line number as a comment on the entry point
        annotate_func_source(bv, func, fn)
        if fn.get("FileName"):
            stats["commented"] += 1

    log_info(
        f"[GoReSym] Renamed {stats['renamed']} functions, "
        f"added {stats['commented']} source comments, "
        f"{stats['not_found']} addresses not found."
    )

    return stats


def annotate_func_source(
    bv: "BinaryView",
    func: "bn.Function",
    fn_entry: dict,
) -> None:
    """
    Write a source file and line number comment at a function's entry point.

    Produces comments like:
        // Source: c2.go:42

    This mirrors the PRE_COMMENT behaviour added to the Ghidra script.
    Analysts can see the original source location directly in the
    disassembly listing without cross-referencing the JSON separately.

    Only writes the comment if FileName is present in the GoReSym entry.
    LineNumber is included when available but not required.
    """
    if not BN_AVAILABLE:
        return

    file_name   = fn_entry.get("FileName", "").strip()
    line_number = fn_entry.get("LineNumber")

    if not file_name:
        return

    # Build the comment string
    if line_number:
        comment = f"// Source: {file_name}:{line_number}"
    else:
        comment = f"// Source: {file_name}"

    # Set as a regular comment at the function entry address
    # This appears in the disassembly listing view
    bv.set_comment_at(func.start, comment)


def annotate_entry_points(bv: "BinaryView", data: dict) -> None:
    """
    Convenience wrapper — annotates all user functions with metadata comments.
    Writes the Go version as a comment at the binary's entry point address
    so analysts immediately know what compiler version produced this binary.
    """
    if not BN_AVAILABLE:
        return

    go_version = get_go_version(data)
    arch       = data.get("Arch", "unknown")
    build_id   = data.get("BuildId", "")

    # Write a header comment at the binary entry point
    entry = bv.entry_point
    if entry:
        lines = [
            f"// GoReSym analysis applied",
            f"// Go version : {go_version}",
            f"// Architecture: {arch}",
        ]
        if build_id:
            lines.append(f"// Build ID   : {build_id[:48]}")

        bv.set_comment_at(entry, "\n".join(lines))
        log_info(f"[GoReSym] Annotated entry point 0x{entry:x} with binary metadata")

def apply_types(
    bv: "BinaryView",
    types: list[dict],
    registered: dict,
) -> dict:
    """
    Parse CReconstructed struct definitions from GoReSym and apply them
    at their virtual addresses in Binary Ninja.

    For each type entry:
      - Parses the C-like CReconstructed field into (name, type) pairs
      - Builds a BN StructureType from those fields
      - Registers it in BN's type system
      - Applies it at the type's VA so analysts see named fields
        instead of raw bytes in the listing and decompiler views

    This is the single largest gap between the original BinjaPython submodule
    and the IDA/Ghidra scripts. IDA did this via idc_parse_types() +
    apply_tinfo(). Ghidra via listing.createData(). This mirrors both.

    Returns stats dict for logging.
    """
    if not BN_AVAILABLE:
        return {}

    stats = {
        "applied":   0,
        "skipped":   0,
        "failed":    0,
    }

    ptr_size = bv.arch.address_size

    for type_entry in types:
        type_name      = type_entry.get("Str", "").strip()
        c_reconstructed = type_entry.get("CReconstructed", "").strip()
        va             = type_entry.get("VA")

        if not type_name or not c_reconstructed or not va:
            stats["skipped"] += 1
            continue

        # Parse the C-like struct definition into field pairs
        fields = parse_struct_fields(c_reconstructed)
        if not fields:
            log_warn(f"[GoReSym] No fields parsed for type '{type_name}' — skipping")
            stats["skipped"] += 1
            continue

        try:
            # Build a BN structure from the parsed fields
            builder = bn.StructureBuilder.create()
            builder.packed = True

            for field_name, field_type_str in fields:
                bn_type = resolve_field_type(field_type_str, ptr_size, registered)
                if bn_type is None:
                    # Use a pointer-sized integer as a safe fallback
                    bn_type = Type.int(ptr_size, False)
                builder.append(bn_type, field_name)

            structure = builder.immutable_copy()

            # Register the type in BN's type system
            qualified_name = bn.QualifiedName(["Go", type_name])
            bv.define_user_type(qualified_name, Type.structure_type(structure))

            # Apply the type at the virtual address
            # This makes named fields visible in the listing + decompiler
            bv.define_user_data_var(va, Type.named_type_from_registered_type(
                bv.get_type_by_name(qualified_name)
            ))

            stats["applied"] += 1

        except Exception as e:
            log_error(f"[GoReSym] Failed to apply type '{type_name}' at 0x{va:x}: {e}")
            stats["failed"] += 1
            continue

    log_info(
        f"[GoReSym] Types — applied: {stats['applied']}, "
        f"skipped: {stats['skipped']}, failed: {stats['failed']}"
    )

    return stats


def apply_interfaces(
    bv: "BinaryView",
    interfaces: list[dict],
    registered: dict,
) -> dict:
    """
    Apply GoIface struct layout at each interface's virtual address.

    The original BinjaPython submodule passed interfaces to a generic
    annotate() function which only created a label — the same gap that
    existed in the original Ghidra script before the PR fix.

    IDA's script cleared the item and applied abi_Type tinfo at each
    interface VA. This mirrors that behaviour by applying the GoIface
    struct layout so tab/data pointer fields are visible in the listing.

    Returns stats dict for logging.
    """
    if not BN_AVAILABLE:
        return {}

    stats = {
        "applied": 0,
        "skipped": 0,
        "failed":  0,
    }

    # GoIface must have been registered by register_go_primitives first
    go_iface_type = registered.get("GoIface")
    if go_iface_type is None:
        log_error(
            "[GoReSym] GoIface type not registered — "
            "call register_go_primitives() before apply_interfaces()"
        )
        return stats

    for iface in interfaces:
        va        = iface.get("VA")
        name      = iface.get("Name", "").strip()

        if not va:
            stats["skipped"] += 1
            continue

        try:
            # Apply GoIface layout at this address
            bv.define_user_data_var(
                va,
                Type.named_type_from_registered_type(go_iface_type)
            )

            # Also set a label so the interface is named in the listing
            if name:
                bv.define_user_symbol(
                    bn.Symbol(bn.SymbolType.DataSymbol, va, name)
                )

            stats["applied"] += 1

        except Exception as e:
            log_error(f"[GoReSym] Failed to apply interface at 0x{va:x}: {e}")
            stats["failed"] += 1
            continue

    log_info(
        f"[GoReSym] Interfaces — applied: {stats['applied']}, "
        f"skipped: {stats['skipped']}, failed: {stats['failed']}"
    )

    return stats


def apply_strings(bv: "BinaryView", data: dict) -> int:
    """
    Label GoString locations in the listing view.
    For each entry in Strings that has a VA, applies the GoString
    struct type so the ptr/len fields are visible instead of raw bytes.
    """
    if not BN_AVAILABLE:
        return 0

    go_string_type = bv.get_type_by_name(bn.QualifiedName(["Go", "GoString"]))
    if go_string_type is None:
        log_warn("[GoReSym] GoString type not registered — skipping string annotation")
        return 0

    count = 0
    for entry in data.get("Strings", []):
        va = entry.get("VA") if isinstance(entry, dict) else None
        if not va:
            continue
        try:
            bv.define_user_data_var(
                va,
                Type.named_type_from_registered_type(go_string_type)
            )
            count += 1
        except Exception as e:
            log_warn(f"[GoReSym] Could not annotate string at 0x{va:x}: {e}")

    log_info(f"[GoReSym] Annotated {count} GoString locations")
    return count

# ── Entry point ───────────────────────────────────────────────────────────────

def apply_goresym(bv: "BinaryView", json_path: str, offset: int = 0) -> None:
    """
    Main orchestrator — called by the Binary Ninja plugin menu entry.

    Runs all analysis steps in the correct order:
      1. Load and validate the GoReSym JSON
      2. Register Go primitive types (GoString, GoSlice, GoIface)
      3. Rename functions + write source comments
      4. Apply reconstructed struct types at their VAs
      5. Apply GoIface layout at interface addresses
      6. Annotate GoString locations
      7. Write binary metadata comment at entry point

    All steps are wrapped individually so a failure in one does not
    stop the rest from running — partial results are better than none.
    """
    if not BN_AVAILABLE:
        print("[GoReSym] Binary Ninja is not available — cannot apply results.")
        return

    log_info(f"[GoReSym] Starting analysis — loading {json_path}")

    # ── Step 1: Load JSON ──────────────────────────────────────────────────────
    try:
        data = load_goresym(json_path)
    except (FileNotFoundError, ValueError, json.JSONDecodeError) as e:
        log_error(f"[GoReSym] Failed to load JSON: {e}")
        return

    go_version = get_go_version(data)
    log_info(f"[GoReSym] Detected Go version: {go_version}")

    # ── Step 2: Register Go primitives ────────────────────────────────────────
    try:
        registered = register_go_primitives(bv)
        log_info(f"[GoReSym] Go primitives registered: {list(registered.keys())}")
    except Exception as e:
        log_error(f"[GoReSym] Failed to register Go primitives: {e}")
        registered = {}

    # ── Step 3: Rename functions + source comments ─────────────────────────────
    try:
        user_functions = extract_user_functions(data)
        rename_functions(bv, user_functions, offset=offset)
    except Exception as e:
        log_error(f"[GoReSym] Failed during function renaming: {e}")

    # ── Step 4: Apply reconstructed types ─────────────────────────────────────
    try:
        types = extract_types(data)
        if types:
            apply_types(bv, types, registered)
        else:
            log_info("[GoReSym] No types found in JSON — run GoReSym with -t flag")
    except Exception as e:
        log_error(f"[GoReSym] Failed during type application: {e}")

    # ── Step 5: Apply interface layouts ───────────────────────────────────────
    try:
        interfaces = extract_interfaces(data)
        if interfaces:
            apply_interfaces(bv, interfaces, registered)
        else:
            log_info("[GoReSym] No interfaces found in JSON")
    except Exception as e:
        log_error(f"[GoReSym] Failed during interface application: {e}")

    # ── Step 6: Annotate GoString locations ───────────────────────────────────
    try:
        apply_strings(bv, data)
    except Exception as e:
        log_error(f"[GoReSym] Failed during string annotation: {e}")

    # ── Step 7: Entry point metadata comment ──────────────────────────────────
    try:
        annotate_entry_points(bv, data)
    except Exception as e:
        log_error(f"[GoReSym] Failed during entry point annotation: {e}")

    log_info("[GoReSym] Analysis complete.")


def run_from_file(bv: "BinaryView") -> None:
    """
    Plugin menu handler — prompts the analyst for a JSON file path
    and calls apply_goresym with it.

    Registered under Plugins → GoReSym → Apply GoReSym JSON
    """
    if not BN_AVAILABLE:
        return

    json_path = bn.interaction.get_open_filename_input(
        "Select GoReSym JSON output file",
        "*.json"
    )

    if not json_path:
        log_info("[GoReSym] No file selected — cancelled.")
        return

    # Ask for an optional load offset
    # Default 0 works for most binaries — only needed if ASLR shifted addresses
    offset_str = bn.interaction.get_text_line_input(
        "Enter load offset (hex, e.g. 0x400000) or leave blank for 0",
        "Load Offset"
    )

    offset = 0
    if offset_str and offset_str.strip():
        try:
            offset = int(offset_str.strip(), 16)
        except ValueError:
            log_warn(f"[GoReSym] Invalid offset '{offset_str}' — using 0")

    apply_goresym(bv, json_path, offset=offset)


# ── Register the plugin with Binary Ninja ─────────────────────────────────────

if BN_AVAILABLE:
    bn.PluginCommand.register(
        "GoReSym\\Apply GoReSym JSON",
        "Apply GoReSym symbol recovery output to the current binary view. "
        "Renames functions, applies Go types, annotates interfaces, "
        "and writes source file comments.",
        run_from_file,
    )
    log_info("[GoReSym] Plugin loaded — use Plugins → GoReSym → Apply GoReSym JSON")


# ── Standalone test entry (outside Binary Ninja) ──────────────────────────────

if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Standalone test mode (no Binary Ninja)")
        print("Usage: python goresym_rename.py sample_output.json")
        sys.exit(0)

    path = sys.argv[1]
    print(f"[GoReSym] Loading {path} ...")

    try:
        data = load_goresym(path)
        print(f"[GoReSym] Go version  : {get_go_version(data)}")
        print(f"[GoReSym] Functions   : {len(extract_user_functions(data))}")
        print(f"[GoReSym] Types       : {len(extract_types(data))}")
        print(f"[GoReSym] Interfaces  : {len(extract_interfaces(data))}")

        print("\n[GoReSym] Sample function map (first 5):")
        func_map = build_function_map(extract_user_functions(data))
        for va, fn in list(func_map.items())[:5]:
            fname = fn.get("FullName", "?")
            ffile = fn.get("FileName", "")
            fline = fn.get("LineNumber", "")
            src   = f" — {ffile}:{fline}" if ffile else ""
            print(f"  0x{va:x}  →  {fname}{src}")

        print("\n[GoReSym] Sample struct parse (first type):")
        types = extract_types(data)
        if types:
            t = types[0]
            print(f"  Type : {t.get('Str')}")
            print(f"  VA   : 0x{t.get('VA', 0):x}")
            fields = parse_struct_fields(t.get("CReconstructed", ""))
            for fname, ftype in fields:
                print(f"  Field: {ftype:20s} {fname}")
        else:
            print("  No types in this JSON (run GoReSym with -t flag)")

        print("\n[GoReSym] Layer 1 test complete — all pure Python logic works.")

    except Exception as e:
        print(f"[GoReSym] Error: {e}")
        sys.exit(1)
