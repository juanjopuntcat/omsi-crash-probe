// Export references to named imported or internal symbols.
//
// Usage: -postScript ExportOmsiSymbolRefs.java <output.tsv> <symbol>...
//@category OMSI

import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;

public class ExportOmsiSymbolRefs extends GhidraScript {
    private Address imageBase;

    @Override
    public void run() throws Exception {
        imageBase = currentProgram.getImageBase();
        String[] args = getScriptArgs();
        if (args.length < 2) {
            throw new IllegalArgumentException("Usage: <output.tsv> <symbol>...");
        }

        File outFile = new File(args[0]);
        File parent = outFile.getParentFile();
        if (parent != null) {
            parent.mkdirs();
        }

        try (PrintWriter writer = new PrintWriter(
                new OutputStreamWriter(new FileOutputStream(outFile), StandardCharsets.UTF_8))) {
            writer.println("requestedSymbol\tsymbol\tsymbolAddress\tsymbolRva\tcallerRva\tcallerFunction\tcallerFunctionRva\treferenceType\tinstruction");
            for (int i = 1; i < args.length && !monitor.isCancelled(); ++i) {
                exportSymbol(writer, args[i]);
            }
        }

        println("Output: " + outFile.getAbsolutePath());
    }

    private void exportSymbol(PrintWriter writer, String requested) {
        SymbolIterator symbols = currentProgram.getSymbolTable().getAllSymbols(true);
        boolean found = false;
        while (symbols.hasNext() && !monitor.isCancelled()) {
            Symbol symbol = symbols.next();
            if (!symbol.getName().equalsIgnoreCase(requested)) {
                continue;
            }
            found = true;
            ReferenceIterator refs = currentProgram.getReferenceManager().getReferencesTo(symbol.getAddress());
            if (!refs.hasNext()) {
                writeRow(writer, requested, symbol, null, null);
                continue;
            }
            while (refs.hasNext()) {
                Reference ref = refs.next();
                Instruction instruction = currentProgram.getListing().getInstructionContaining(ref.getFromAddress());
                Address caller = instruction == null ? ref.getFromAddress() : instruction.getMinAddress();
                writeRow(writer, requested, symbol, caller, ref);
            }
        }
        if (!found) {
            writer.println(escape(requested) + "\t<not-found>\t\t\t\t\t\t\t");
        }
    }

    private void writeRow(PrintWriter writer, String requested, Symbol symbol, Address caller, Reference ref) {
        Function function = caller == null ? null : currentProgram.getFunctionManager().getFunctionContaining(caller);
        Instruction instruction = caller == null ? null : currentProgram.getListing().getInstructionContaining(caller);
        writer.println(
            escape(requested) + "\t" +
            escape(symbol.getName(true)) + "\t" +
            escape(symbol.getAddress().toString()) + "\t" +
            formatRvaOrBlank(symbol.getAddress()) + "\t" +
            formatRvaOrBlank(caller) + "\t" +
            escape(function == null ? "" : function.getName()) + "\t" +
            (function == null ? "" : formatRvaOrBlank(function.getEntryPoint())) + "\t" +
            escape(ref == null ? "" : ref.getReferenceType().toString()) + "\t" +
            escape(instruction == null ? "" : instruction.toString()));
    }

    private String formatRvaOrBlank(Address address) {
        if (address == null || !address.getAddressSpace().equals(imageBase.getAddressSpace())) {
            return "";
        }
        return String.format("0x%08X", address.subtract(imageBase));
    }

    private String escape(String value) {
        return value == null ? "" : value.replace("\t", " ").replace("\r", " ").replace("\n", " ");
    }
}
