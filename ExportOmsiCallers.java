// Export callers for selected OMSI runtime/helper RVAs.
//
// Usage from headless:
//   -postScript ExportOmsiCallers.java <output.tsv> <name=rva> [<name=rva> ...]
//@category OMSI

import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;

public class ExportOmsiCallers extends GhidraScript {
    private Address imageBase;

    @Override
    public void run() throws Exception {
        imageBase = currentProgram.getImageBase();

        String[] args = getScriptArgs();
        if (args.length < 2) {
            throw new IllegalArgumentException("Usage: <output.tsv> <name=rva> [<name=rva> ...]");
        }

        File outFile = new File(args[0]);
        File parent = outFile.getParentFile();
        if (parent != null) {
            parent.mkdirs();
        }

        try (PrintWriter writer = new PrintWriter(
                new OutputStreamWriter(new FileOutputStream(outFile), StandardCharsets.UTF_8))) {
            writer.println("target\ttargetRva\tcallerAddress\tcallerRva\tcallerFunction\tcallerFunctionRva\treferenceType\tinstruction\tcontext");

            for (int i = 1; i < args.length && !monitor.isCancelled(); ++i) {
                Target target = parseTarget(args, i);
                if (args[i].indexOf('=') < 0) {
                    i += 1;
                }
                Address targetAddress = imageBase.add(target.rva);
                exportCallers(writer, target, targetAddress);
            }
        }

        println("Output: " + outFile.getAbsolutePath());
    }

    private void exportCallers(PrintWriter writer, Target target, Address targetAddress) {
        ReferenceIterator refs = currentProgram.getReferenceManager().getReferencesTo(targetAddress);
        int count = 0;
        while (refs.hasNext() && !monitor.isCancelled()) {
            Reference ref = refs.next();
            Address from = normalizeInstructionAddress(ref.getFromAddress());
            Function function = currentProgram.getFunctionManager().getFunctionContaining(from);
            CodeUnit unit = currentProgram.getListing().getCodeUnitContaining(from);

            writer.println(
                escape(target.name) + "\t" +
                formatRva(targetAddress) + "\t" +
                escape(from.toString()) + "\t" +
                formatRva(from) + "\t" +
                escape(function == null ? "" : function.getName()) + "\t" +
                (function == null ? "" : formatRva(function.getEntryPoint())) + "\t" +
                escape(ref.getReferenceType().toString()) + "\t" +
                escape(unit == null ? "" : unit.toString()) + "\t" +
                escape(formatContext(from)));
            count += 1;
        }

        if (count == 0) {
            writer.println(
                escape(target.name) + "\t" +
                formatRva(targetAddress) + "\t\t\t\t\t\t\t");
        }
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
            builder
                .append(formatRva(cursor.getMinAddress()))
                .append(": ")
                .append(cursor.toString());
            cursor = cursor.getNext();
        }
        return builder.toString();
    }

    private Target parseTarget(String[] args, int index) {
        String raw = args[index];
        int separator = raw.indexOf('=');
        if (separator < 0) {
            if (index + 1 >= args.length) {
                throw new IllegalArgumentException("Bad target argument, expected name rva pair: " + raw);
            }
            return parseTargetParts(raw, args[index + 1]);
        }

        if (separator == 0 || separator == raw.length() - 1) {
            throw new IllegalArgumentException("Bad target argument, expected name=rva: " + raw);
        }

        String name = raw.substring(0, separator);
        String rvaText = raw.substring(separator + 1);
        return parseTargetParts(name, rvaText);
    }

    private Target parseTargetParts(String name, String rawRva) {
        String rvaText = rawRva.trim().toLowerCase();
        long rva = rvaText.startsWith("0x")
            ? Long.parseLong(rvaText.substring(2), 16)
            : Long.parseLong(rvaText, 16);
        return new Target(name, rva);
    }

    private String formatRva(Address address) {
        if (address == null || !address.getAddressSpace().equals(imageBase.getAddressSpace())) {
            return "";
        }
        long rva = address.subtract(imageBase);
        return String.format("0x%08X", rva);
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
        final long rva;

        Target(String name, long rva) {
            this.name = name;
            this.rva = rva;
        }
    }
}
