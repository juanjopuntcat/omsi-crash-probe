// Find Delphi TResStringRec-like records for selected resource string IDs.
//
// Delphi localized exception strings are often referenced through 8-byte
// records:
//
//   DWORD module/resource-handle slot
//   DWORD resource-id
//
// This script scans initialized memory for records whose low 16 bits match a
// selected string resource ID, then exports references and nearby context.
//@category OMSI

import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;

public class ExportOmsiResourceRecordRefs extends GhidraScript {
    private Address imageBase;

    @Override
    public void run() throws Exception {
        imageBase = currentProgram.getImageBase();

        String[] args = getScriptArgs();
        if (args.length < 2) {
            throw new IllegalArgumentException("Usage: <output.tsv> <name=id> [<name=id> ...]");
        }

        File outFile = new File(args[0]);
        File parent = outFile.getParentFile();
        if (parent != null) {
            parent.mkdirs();
        }

        Map<Integer, String> targetNamesById = new LinkedHashMap<>();
        for (int i = 1; i < args.length; ++i) {
            Target target = parseTarget(args, i);
            if (args[i].indexOf('=') < 0) {
                i += 1;
            }
            targetNamesById.put(target.id, target.name);
        }

        try (PrintWriter writer = new PrintWriter(
                new OutputStreamWriter(new FileOutputStream(outFile), StandardCharsets.UTF_8))) {
            writer.println("target\tresourceId\trecordAddress\trecordRva\tmoduleSlot\tidDword\txrefKind\txrefAddress\txrefRva\tfunctionRva\tinstruction\tcontext");

            for (MemoryBlock block : currentProgram.getMemory().getBlocks()) {
                if (!block.isInitialized() || !block.isLoaded() || block.getSize() < 8) {
                    continue;
                }

                Address cursor = block.getStart();
                Address end = block.getEnd().subtract(7);
                while (cursor.compareTo(end) <= 0 && !monitor.isCancelled()) {
                    int moduleSlot = currentProgram.getMemory().getInt(cursor);
                    int idDword = currentProgram.getMemory().getInt(cursor.add(4));
                    int resourceId = idDword & 0xffff;

                    String targetName = targetNamesById.get(resourceId);
                    if (targetName != null && isLikelyResourceModuleSlot(moduleSlot)) {
                        exportRecord(writer, targetName, resourceId, cursor, moduleSlot, idDword);
                    }

                    cursor = cursor.add(1);
                }
            }
        }

        println("Output: " + outFile.getAbsolutePath());
    }

    private void exportRecord(
            PrintWriter writer,
            String targetName,
            int resourceId,
            Address record,
            int moduleSlot,
            int idDword) {
        int xrefCount = 0;
        ReferenceIterator refs = currentProgram.getReferenceManager().getReferencesTo(record);
        while (refs.hasNext() && !monitor.isCancelled()) {
            Reference ref = refs.next();
            Address from = normalizeInstructionAddress(ref.getFromAddress());
            Function function = currentProgram.getFunctionManager().getFunctionContaining(from);
            CodeUnit unit = currentProgram.getListing().getCodeUnitContaining(from);
            writeRow(
                writer,
                targetName,
                resourceId,
                record,
                moduleSlot,
                idDword,
                ref.getReferenceType().toString(),
                from,
                function,
                unit);
            xrefCount += 1;
        }

        if (xrefCount == 0) {
            writeRow(writer, targetName, resourceId, record, moduleSlot, idDword, "none", null, null, null);
        }
    }

    private void writeRow(
            PrintWriter writer,
            String targetName,
            int resourceId,
            Address record,
            int moduleSlot,
            int idDword,
            String xrefKind,
            Address xref,
            Function function,
            CodeUnit unit) {
        writer.println(
            escape(targetName) + "\t" +
            String.format("0x%04X", resourceId) + "\t" +
            escape(record.toString()) + "\t" +
            formatRva(record) + "\t" +
            String.format("0x%08X", moduleSlot) + "\t" +
            String.format("0x%08X", idDword) + "\t" +
            escape(xrefKind) + "\t" +
            escape(xref == null ? "" : xref.toString()) + "\t" +
            (xref == null ? "" : formatRva(xref)) + "\t" +
            (function == null ? "" : formatRva(function.getEntryPoint())) + "\t" +
            escape(unit == null ? "" : unit.toString()) + "\t" +
            escape(xref == null ? "" : formatContext(xref)));
    }

    private boolean isLikelyResourceModuleSlot(int raw) {
        long value = raw & 0xffffffffL;
        if (value == 0) {
            return false;
        }

        Address address = imageBase.getAddressSpace().getAddress(value);
        if (address == null || !address.getAddressSpace().equals(imageBase.getAddressSpace())) {
            return false;
        }

        long rva = address.subtract(imageBase);
        return rva >= 0x00400000L && rva <= 0x004FFFFFL;
    }

    private Address normalizeInstructionAddress(Address address) {
        Instruction instruction = currentProgram.getListing().getInstructionContaining(address);
        return instruction == null ? address : instruction.getMinAddress();
    }

    private String formatContext(Address address) {
        StringBuilder builder = new StringBuilder();
        Instruction instruction = currentProgram.getListing().getInstructionContaining(address);
        if (instruction == null) {
            return "";
        }

        Instruction cursor = instruction;
        for (int i = 0; i < 4 && cursor != null; ++i) {
            cursor = cursor.getPrevious();
        }

        for (int i = 0; i < 9 && cursor != null; ++i) {
            if (builder.length() > 0) {
                builder.append(" | ");
            }
            builder.append(formatRva(cursor.getMinAddress())).append(": ").append(cursor.toString());
            cursor = cursor.getNext();
        }
        return builder.toString();
    }

    private Target parseTarget(String[] args, int index) {
        String raw = args[index];
        int separator = raw.indexOf('=');
        if (separator < 0) {
            if (index + 1 >= args.length) {
                throw new IllegalArgumentException("Bad target argument, expected name id pair: " + raw);
            }
            return parseTargetParts(raw, args[index + 1]);
        }

        if (separator == 0 || separator == raw.length() - 1) {
            throw new IllegalArgumentException("Bad target argument, expected name=id: " + raw);
        }

        String name = raw.substring(0, separator);
        String idText = raw.substring(separator + 1);
        return parseTargetParts(name, idText);
    }

    private Target parseTargetParts(String name, String rawId) {
        String idText = rawId.trim().toLowerCase();
        int id = idText.startsWith("0x")
            ? Integer.parseInt(idText.substring(2), 16)
            : Integer.parseInt(idText, 16);
        return new Target(name, id & 0xffff);
    }

    private String formatRva(Address address) {
        if (address == null || !address.getAddressSpace().equals(imageBase.getAddressSpace())) {
            return "";
        }
        return String.format("0x%08X", address.subtract(imageBase));
    }

    private String escape(String value) {
        if (value == null) {
            return "";
        }
        return value
            .replace("\t", " ")
            .replace("\r", " ")
            .replace("\n", " ");
    }

    private static class Target {
        final String name;
        final int id;

        Target(String name, int id) {
            this.name = name;
            this.id = id;
        }
    }
}
