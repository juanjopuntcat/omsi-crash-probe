// Export call-target frequency stats for low-level OMSI/Delphi helper functions.
//
// The Delphi runtime often raises common errors such as range checks through
// tiny helper functions that are not directly referenced by the localized
// message strings. Counting direct call targets gives us a compact map of
// heavily reused helpers worth inspecting in Ghidra.
//
// Usage from headless:
//   -postScript ExportOmsiCallTargetStats.java <output.tsv> <minRva> <maxRva>
//@category OMSI

import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.TreeMap;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.symbol.FlowType;

public class ExportOmsiCallTargetStats extends GhidraScript {
    private Address imageBase;

    @Override
    public void run() throws Exception {
        imageBase = currentProgram.getImageBase();

        String[] args = getScriptArgs();
        if (args.length < 3) {
            throw new IllegalArgumentException("Usage: <output.tsv> <minRva> <maxRva>");
        }

        File outFile = new File(args[0]);
        File parent = outFile.getParentFile();
        if (parent != null) {
            parent.mkdirs();
        }

        long minRva = parseRva(args[1]);
        long maxRva = parseRva(args[2]);
        Map<Address, TargetStats> statsByTarget = new TreeMap<>();

        InstructionIterator instructions = currentProgram.getListing().getInstructions(true);
        while (instructions.hasNext() && !monitor.isCancelled()) {
            Instruction instruction = instructions.next();
            FlowType flowType = instruction.getFlowType();
            if (!flowType.isCall()) {
                continue;
            }

            Address[] flows = instruction.getFlows();
            if (flows.length == 0) {
                continue;
            }

            Address target = flows[0];
            if (!isImageAddress(target)) {
                continue;
            }

            long targetRva = target.subtract(imageBase);
            if (targetRva < minRva || targetRva > maxRva) {
                continue;
            }

            TargetStats stats = statsByTarget.get(target);
            if (stats == null) {
                stats = new TargetStats(target);
                statsByTarget.put(target, stats);
            }
            stats.callCount += 1;

            Function caller = currentProgram.getFunctionManager().getFunctionContaining(instruction.getMinAddress());
            if (caller != null) {
                stats.callerFunctions.put(caller.getEntryPoint(), true);
            }
        }

        try (PrintWriter writer = new PrintWriter(
                new OutputStreamWriter(new FileOutputStream(outFile), StandardCharsets.UTF_8))) {
            writer.println("targetRva\tcallCount\tcallerFunctionCount\tfunctionName\tfunctionEntryRva\tfunctionBodyMinRva\tfunctionBodyMaxRva");

            for (TargetStats stats : statsByTarget.values()) {
                Function targetFunction = currentProgram.getFunctionManager().getFunctionContaining(stats.target);
                writer.println(
                    formatRva(stats.target) + "\t" +
                    stats.callCount + "\t" +
                    stats.callerFunctions.size() + "\t" +
                    escape(targetFunction == null ? "" : targetFunction.getName()) + "\t" +
                    (targetFunction == null ? "" : formatRva(targetFunction.getEntryPoint())) + "\t" +
                    (targetFunction == null ? "" : formatRva(targetFunction.getBody().getMinAddress())) + "\t" +
                    (targetFunction == null ? "" : formatRva(targetFunction.getBody().getMaxAddress())));
            }
        }

        println("Output: " + outFile.getAbsolutePath());
    }

    private boolean isImageAddress(Address address) {
        return address != null && address.getAddressSpace().equals(imageBase.getAddressSpace());
    }

    private long parseRva(String raw) {
        String value = raw.trim().toLowerCase();
        if (value.startsWith("0x")) {
            return Long.parseLong(value.substring(2), 16);
        }
        return Long.parseLong(value, 16);
    }

    private String formatRva(Address address) {
        if (!isImageAddress(address)) {
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

    private static class TargetStats {
        final Address target;
        int callCount;
        final Map<Address, Boolean> callerFunctions = new TreeMap<>();

        TargetStats(Address target) {
            this.target = target;
        }
    }
}
