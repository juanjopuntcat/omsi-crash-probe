// Export instruction/data context around selected OMSI RVAs.
//
// Usage from headless:
//   -postScript ExportOmsiRvaContext.java <output.tsv> <rva> [<rva> ...]
//@category OMSI

import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.CodeUnitIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.mem.MemoryAccessException;

public class ExportOmsiRvaContext extends GhidraScript {
    private Address imageBase;

    @Override
    public void run() throws Exception {
        imageBase = currentProgram.getImageBase();

        String[] args = getScriptArgs();
        if (args.length < 2) {
            throw new IllegalArgumentException("Usage: <output.tsv> <rva> [<rva> ...]");
        }

        File outFile = new File(args[0]);
        File parent = outFile.getParentFile();
        if (parent != null) {
            parent.mkdirs();
        }

        try (PrintWriter writer = new PrintWriter(
                new OutputStreamWriter(new FileOutputStream(outFile), StandardCharsets.UTF_8))) {
            writer.println("requestedRva\taddress\trva\tkind\tfunction\tfunctionEntryRva\tbytes\ttext\treferencesFrom");

            for (int i = 1; i < args.length && !monitor.isCancelled(); ++i) {
                long rva = parseRva(args[i]);
                Address center = imageBase.add(rva);
                exportWindow(writer, args[i], center, 96, 160);
            }
        }

        println("Output: " + outFile.getAbsolutePath());
    }

    private void exportWindow(
            PrintWriter writer,
            String requestedRva,
            Address center,
            int bytesBefore,
            int bytesAfter) {
        Address start = center.subtract(bytesBefore);
        Address end = center.add(bytesAfter);
        AddressSet set = new AddressSet(start, end);
        CodeUnitIterator iterator = currentProgram.getListing().getCodeUnits(set, true);

        while (iterator.hasNext() && !monitor.isCancelled()) {
            CodeUnit unit = iterator.next();
            Address address = unit.getMinAddress();
            Function function = currentProgram.getFunctionManager().getFunctionContaining(address);
            String kind = unit instanceof Instruction ? "instruction" : "data";

            writer.println(
                escape(requestedRva) + "\t" +
                escape(address.toString()) + "\t" +
                formatRva(address) + "\t" +
                kind + "\t" +
                escape(function == null ? "" : function.getName()) + "\t" +
                (function == null ? "" : formatRva(function.getEntryPoint())) + "\t" +
                escape(formatBytes(unit)) + "\t" +
                escape(unit.toString()) + "\t" +
                escape(formatReferences(unit.getReferencesFrom())));
        }
    }

    private String formatBytes(CodeUnit unit) {
        try {
            byte[] bytes = unit.getBytes();
            StringBuilder builder = new StringBuilder();
            for (int i = 0; i < bytes.length; ++i) {
                if (i > 0) {
                    builder.append(' ');
                }
                builder.append(String.format("%02X", bytes[i] & 0xff));
            }
            return builder.toString();
        }
        catch (MemoryAccessException e) {
            return "";
        }
    }

    private String formatReferences(Reference[] references) {
        if (references == null || references.length == 0) {
            return "";
        }

        StringBuilder builder = new StringBuilder();
        for (Reference reference : references) {
            if (builder.length() > 0) {
                builder.append("; ");
            }
            builder
                .append(reference.getReferenceType().toString())
                .append("->")
                .append(reference.getToAddress().toString())
                .append("/")
                .append(formatRvaOrBlank(reference.getToAddress()));
        }
        return builder.toString();
    }

    private long parseRva(String raw) {
        String value = raw.trim().toLowerCase();
        if (value.startsWith("0x")) {
            return Long.parseLong(value.substring(2), 16);
        }
        return Long.parseLong(value, 16);
    }

    private String formatRva(Address address) {
        long rva = address.subtract(imageBase);
        return String.format("0x%08X", rva);
    }

    private String formatRvaOrBlank(Address address) {
        if (address == null || !address.getAddressSpace().equals(imageBase.getAddressSpace())) {
            return "";
        }
        return formatRva(address);
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
}
