// Export function ranges for selected OMSI function RVAs.
//@category OMSI

import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;

public class ExportOmsiFunctionRanges extends GhidraScript {
    private Address imageBase;

    @Override
    public void run() throws Exception {
        imageBase = currentProgram.getImageBase();

        String[] args = getScriptArgs();
        if (args.length < 3) {
            throw new IllegalArgumentException("Usage: <output.tsv> <name rva>...");
        }

        File outFile = new File(args[0]);
        File parent = outFile.getParentFile();
        if (parent != null) {
            parent.mkdirs();
        }

        try (PrintWriter writer = new PrintWriter(
                new OutputStreamWriter(new FileOutputStream(outFile), StandardCharsets.UTF_8))) {
            writer.println("name\trequestedRva\tfunction\tentryRva\tbodyMinRva\tbodyMaxRva");

            for (int i = 1; i + 1 < args.length && !monitor.isCancelled(); i += 2) {
                String name = args[i];
                long rva = parseRva(args[i + 1]);
                Address address = imageBase.add(rva);
                Function function = currentProgram.getFunctionManager().getFunctionAt(address);
                if (function == null) {
                    function = currentProgram.getFunctionManager().getFunctionContaining(address);
                }

                if (function == null) {
                    writer.println(escape(name) + "\t" + escape(args[i + 1]) + "\t\t\t\t");
                    continue;
                }

                writer.println(
                    escape(name) + "\t" +
                    escape(args[i + 1]) + "\t" +
                    escape(function.getName()) + "\t" +
                    formatRva(function.getEntryPoint()) + "\t" +
                    formatRva(function.getBody().getMinAddress()) + "\t" +
                    formatRva(function.getBody().getMaxAddress()));
            }
        }

        println("Output: " + outFile.getAbsolutePath());
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

    private String escape(String value) {
        if (value == null) {
            return "";
        }
        return value.replace("\t", " ").replace("\r", " ").replace("\n", " ");
    }
}
