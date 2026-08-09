// Export xrefs for high-signal OMSI error strings.
//
// Run from Ghidra headless through Run-GhidraOmsiStringXrefs.ps1. The script
// writes TSV so we can diff and post-process results without opening Ghidra UI.
//@category OMSI

import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;

import ghidra.app.plugin.core.analysis.ReferenceAddressPair;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.util.ProgramMemoryUtil;
import ghidra.util.exception.CancelledException;

public class ExportOmsiStringXrefs extends GhidraScript {
    private static final String[][] DEFAULT_TARGETS = {
        { "range_check", "Fehler bei Bereich" },
        { "access_violation_module", "Zugriffsverletzung bei Adresse" },
        { "invalid_float", "Gleitkommawert" },
        { "float_divide_zero", "Gleitkommadivision durch Null" },
        { "divide_zero", "Division durch Null" },
        { "invalid_bitmap", "Bitmap ist" },
        { "argument_out_of_range", "Argument au" },
        { "list_index_max", "Listenindex" },
        { "out_of_memory", "Zu wenig Arbeitsspeicher" },
        { "system_error_code", "Systemfehler. Code" },
        { "d3d_device_lost", "Direct3D-Device lost" },
        { "d3d_device_reset", "Direct3D-Device-Reset" },
        { "d3d_device_resetted", "Direct3D-Device resetted" },
        { "d3d_create_device", "Error while creating Direct3D-Device" }
    };

    private Listing listing;
    private Address imageBase;
    private List<Target> targets;

    @Override
    public void run() throws Exception {
        listing = currentProgram.getListing();
        imageBase = currentProgram.getImageBase();

        String[] args = getScriptArgs();
        if (args.length < 1) {
            throw new IllegalArgumentException("Output TSV path argument is required");
        }

        targets = buildTargets(args);

        File outFile = new File(args[0]);
        File parent = outFile.getParentFile();
        if (parent != null) {
            parent.mkdirs();
        }

        int stringsMatched = 0;
        int rowsWritten = 0;

        try (PrintWriter writer = new PrintWriter(
                new OutputStreamWriter(new FileOutputStream(outFile), StandardCharsets.UTF_8))) {
            writer.println(
                "target\tstringAddress\tstringRva\tstringType\tstringText\txrefKind\txrefAddress\txrefRva\tfunction\tfunctionEntryRva\treferenceType");

            DataIterator dataIterator = listing.getDefinedData(true);
            while (dataIterator.hasNext() && !monitor.isCancelled()) {
                Data data = dataIterator.next();
                String type = data.getDataType().getName().toLowerCase();
                if (!type.contains("unicode") && !type.contains("string")) {
                    continue;
                }

                String text = getStringText(data);
                if (text.length() == 0) {
                    continue;
                }

                List<String> targetNames = matchingTargets(text);
                if (targetNames.isEmpty()) {
                    continue;
                }

                stringsMatched += 1;
                Address stringAddress = data.getMinAddress();
                List<XrefRow> xrefs = collectXrefs(stringAddress);
                if (xrefs.isEmpty()) {
                    for (String targetName : targetNames) {
                        writeRow(writer, targetName, data, text, "none", null, null);
                        rowsWritten += 1;
                    }
                    continue;
                }

                for (String targetName : targetNames) {
                    for (XrefRow xref : xrefs) {
                        writeRow(writer, targetName, data, text, xref.kind, xref.address, xref.referenceType);
                        rowsWritten += 1;
                    }
                }
            }
        }

        println("Matched strings: " + stringsMatched);
        println("Rows written: " + rowsWritten);
        println("Output: " + outFile.getAbsolutePath());
    }

    private String getStringText(Data data) {
        Object value = data.getValue();
        if (value instanceof String) {
            return (String)value;
        }
        return data.getDefaultValueRepresentation();
    }

    private List<Target> buildTargets(String[] args) {
        List<Target> parsedTargets = new ArrayList<>();

        // Optional arguments allow focused runs, for example:
        //   texture_load=Texturladen texture_manager=Speicherbedarf Texturmanager
        for (int i = 1; i < args.length; ++i) {
            String raw = args[i];
            int separator = raw.indexOf('=');
            if (separator < 0) {
                if (i + 1 >= args.length) {
                    throw new IllegalArgumentException("Bad target argument, expected name=needle or name needle pair: " + raw);
                }
                parsedTargets.add(new Target(raw, args[i + 1]));
                i += 1;
                continue;
            }
            if (separator == 0 || separator == raw.length() - 1) {
                throw new IllegalArgumentException("Bad target argument, expected name=needle: " + raw);
            }
            parsedTargets.add(new Target(raw.substring(0, separator), raw.substring(separator + 1)));
        }

        if (!parsedTargets.isEmpty()) {
            return parsedTargets;
        }

        for (String[] target : DEFAULT_TARGETS) {
            parsedTargets.add(new Target(target[0], target[1]));
        }
        return parsedTargets;
    }

    private List<String> matchingTargets(String text) {
        String lowerText = text.toLowerCase();
        List<String> matches = new ArrayList<>();
        for (Target target : targets) {
            if (lowerText.contains(target.needle.toLowerCase())) {
                matches.add(target.name);
            }
        }
        return matches;
    }

    private List<XrefRow> collectXrefs(Address stringAddress) {
        LinkedHashSet<String> seen = new LinkedHashSet<>();
        List<XrefRow> rows = new ArrayList<>();

        ReferenceIterator directRefs = currentProgram.getReferenceManager().getReferencesTo(stringAddress);
        while (directRefs.hasNext() && !monitor.isCancelled()) {
            Reference ref = directRefs.next();
            addRow(rows, seen, "direct", ref.getFromAddress(), ref.getReferenceType().toString());
        }

        for (Address pointerAddress : findPointerReferences(stringAddress)) {
            addRow(rows, seen, "pointer", pointerAddress, "pointer-to-string");

            ReferenceIterator pointerRefs = currentProgram.getReferenceManager().getReferencesTo(pointerAddress);
            while (pointerRefs.hasNext() && !monitor.isCancelled()) {
                Reference ref = pointerRefs.next();
                addRow(rows, seen, "indirect", ref.getFromAddress(), ref.getReferenceType().toString());
            }
        }

        return rows;
    }

    private List<Address> findPointerReferences(Address stringAddress) {
        List<ReferenceAddressPair> directReferenceList = new ArrayList<>();
        List<Address> results = new ArrayList<>();
        try {
            ProgramMemoryUtil.loadDirectReferenceList(
                currentProgram,
                1,
                stringAddress,
                null,
                directReferenceList,
                monitor);
        }
        catch (CancelledException e) {
            return results;
        }

        for (ReferenceAddressPair pair : directReferenceList) {
            Address source = pair.getSource();
            if (source != null && !results.contains(source)) {
                results.add(source);
            }
        }
        return results;
    }

    private void addRow(
            List<XrefRow> rows,
            LinkedHashSet<String> seen,
            String kind,
            Address address,
            String referenceType) {
        if (address == null) {
            return;
        }

        Instruction instruction = listing.getInstructionContaining(address);
        Address normalized = instruction != null ? instruction.getMinAddress() : address;
        String key = kind + "|" + normalized.toString() + "|" + referenceType;
        if (seen.add(key)) {
            rows.add(new XrefRow(kind, normalized, referenceType));
        }
    }

    private void writeRow(
            PrintWriter writer,
            String targetName,
            Data data,
            String text,
            String xrefKind,
            Address xrefAddress,
            String referenceType) {
        Function function = xrefAddress == null
            ? null
            : currentProgram.getFunctionManager().getFunctionContaining(xrefAddress);

        writer.println(
            escape(targetName) + "\t" +
            escape(data.getMinAddress().toString()) + "\t" +
            formatRva(data.getMinAddress()) + "\t" +
            escape(data.getDataType().getName()) + "\t" +
            escape(text) + "\t" +
            escape(xrefKind) + "\t" +
            escape(xrefAddress == null ? "" : xrefAddress.toString()) + "\t" +
            (xrefAddress == null ? "" : formatRva(xrefAddress)) + "\t" +
            escape(function == null ? "" : function.getName()) + "\t" +
            (function == null ? "" : formatRva(function.getEntryPoint())) + "\t" +
            escape(referenceType == null ? "" : referenceType));
    }

    private String formatRva(Address address) {
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

    private static class XrefRow {
        final String kind;
        final Address address;
        final String referenceType;

        XrefRow(String kind, Address address, String referenceType) {
            this.kind = kind;
            this.address = address;
            this.referenceType = referenceType;
        }
    }

    private static class Target {
        final String name;
        final String needle;

        Target(String name, String needle) {
            this.name = name;
            this.needle = needle;
        }
    }
}
