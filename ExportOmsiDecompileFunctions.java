// Decompile selected OMSI functions by RVA and write the output to files.
//
// Usage from headless:
//   -postScript ExportOmsiDecompileFunctions.java <out-dir> <summary.tsv> <name rva>...
//@category OMSI

import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;

public class ExportOmsiDecompileFunctions extends GhidraScript {
    private Address imageBase;

    @Override
    public void run() throws Exception {
        imageBase = currentProgram.getImageBase();

        String[] args = getScriptArgs();
        if (args.length < 4) {
            throw new IllegalArgumentException("Usage: <out-dir> <summary.tsv> <name rva>...");
        }

        File outDir = new File(args[0]);
        outDir.mkdirs();
        File summaryFile = new File(args[1]);

        DecompInterface decompiler = new DecompInterface();
        DecompileOptions options = new DecompileOptions();
        options.grabFromProgram(currentProgram);
        decompiler.setOptions(options);
        decompiler.openProgram(currentProgram);

        try (PrintWriter summary = new PrintWriter(
                new OutputStreamWriter(new FileOutputStream(summaryFile), StandardCharsets.UTF_8))) {
            summary.println("name\trequestedRva\tfunction\tfunctionEntryRva\tstatus\toutputFile\tmessage");

            for (int i = 2; i + 1 < args.length && !monitor.isCancelled(); i += 2) {
                String name = args[i];
                long rva = parseRva(args[i + 1]);
                Address address = imageBase.add(rva);
                Function function = currentProgram.getFunctionManager().getFunctionAt(address);
                if (function == null) {
                    function = currentProgram.getFunctionManager().getFunctionContaining(address);
                }

                if (function == null) {
                    summary.println(row(name, args[i + 1], "", "", "missing-function", "", "No function at or containing RVA"));
                    continue;
                }

                String fileName = sanitize(name) + "_" + formatRva(function.getEntryPoint()) + ".c";
                File outFile = new File(outDir, fileName);
                DecompileResults results = decompiler.decompileFunction(function, 90, monitor);
                if (!results.decompileCompleted()) {
                    summary.println(row(
                        name,
                        args[i + 1],
                        function.getName(),
                        formatRva(function.getEntryPoint()),
                        "decompile-failed",
                        outFile.getAbsolutePath(),
                        results.getErrorMessage()));
                    continue;
                }

                try (PrintWriter writer = new PrintWriter(
                        new OutputStreamWriter(new FileOutputStream(outFile), StandardCharsets.UTF_8))) {
                    writer.println("/*");
                    writer.println(" * name: " + name);
                    writer.println(" * function: " + function.getName());
                    writer.println(" * entryRva: " + formatRva(function.getEntryPoint()));
                    writer.println(" */");
                    writer.println();
                    writer.println(results.getDecompiledFunction().getC());
                }

                summary.println(row(
                    name,
                    args[i + 1],
                    function.getName(),
                    formatRva(function.getEntryPoint()),
                    "ok",
                    outFile.getAbsolutePath(),
                    ""));
            }
        }
        finally {
            decompiler.dispose();
        }

        println("Summary: " + summaryFile.getAbsolutePath());
        println("Output dir: " + outDir.getAbsolutePath());
    }

    private String row(
            String name,
            String requestedRva,
            String function,
            String functionEntryRva,
            String status,
            String outputFile,
            String message) {
        return escape(name) + "\t" +
            escape(requestedRva) + "\t" +
            escape(function) + "\t" +
            escape(functionEntryRva) + "\t" +
            escape(status) + "\t" +
            escape(outputFile) + "\t" +
            escape(message);
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

    private String sanitize(String value) {
        return value.replaceAll("[^A-Za-z0-9_.-]", "_");
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
