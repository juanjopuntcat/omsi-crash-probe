// Export Delphi raise sites with best-effort exception class decoding.
//
// OMSI's localized exception messages are often reached indirectly through
// Delphi resource/string tables, so plain string xrefs miss important errors
// such as range checks. This script follows the common pattern:
//
//   MOV ECX,<message-or-resource>
//   MOV DL,1
//   MOV EAX,[<class-slot>]
//   CALL <constructor>
//   CALL 0x00407E8C
//
// For each raise call it records the nearby context and tries to decode the
// Delphi class name from the VMT pointer stored in the class slot.
//@category OMSI

import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;

public class ExportOmsiRaiseSites extends GhidraScript {
    private static final long DEFAULT_RAISE_RVA = 0x00007E8CL;
    private static final Pattern EAX_CLASS_SLOT =
        Pattern.compile("MOV EAX,\\[(0x[0-9a-fA-F]+)\\]");
    private static final Pattern ECX_MESSAGE_SLOT =
        Pattern.compile("MOV ECX,(?:dword ptr )?\\[(0x[0-9a-fA-F]+)\\]");

    private Address imageBase;

    @Override
    public void run() throws Exception {
        imageBase = currentProgram.getImageBase();

        String[] args = getScriptArgs();
        if (args.length < 1) {
            throw new IllegalArgumentException("Usage: <output.tsv> [raiseRva]");
        }

        File outFile = new File(args[0]);
        File parent = outFile.getParentFile();
        if (parent != null) {
            parent.mkdirs();
        }

        long raiseRva = args.length >= 2 ? parseRva(args[1]) : DEFAULT_RAISE_RVA;
        Address raiseAddress = imageBase.add(raiseRva);

        try (PrintWriter writer = new PrintWriter(
                new OutputStreamWriter(new FileOutputStream(outFile), StandardCharsets.UTF_8))) {
            writer.println("raiseRva\tcallerRva\tcallerFunctionRva\tclassSlot\tclassVmt\tclassName\tmessageSlot\tmessagePtr\tmessageResourceModule\tmessageResourceId\tmessageText\tconstructorRva\tcontext");

            ReferenceIterator refs = currentProgram.getReferenceManager().getReferencesTo(raiseAddress);
            while (refs.hasNext() && !monitor.isCancelled()) {
                Reference ref = refs.next();
                Instruction callInstruction = currentProgram.getListing().getInstructionContaining(ref.getFromAddress());
                if (callInstruction == null) {
                    continue;
                }

                RaiseSite site = analyzeRaiseSite(callInstruction);
                Function function = currentProgram.getFunctionManager().getFunctionContaining(callInstruction.getMinAddress());

                writer.println(
                    formatRva(raiseAddress) + "\t" +
                    formatRva(callInstruction.getMinAddress()) + "\t" +
                    (function == null ? "" : formatRva(function.getEntryPoint())) + "\t" +
                    escape(site.classSlot) + "\t" +
                    escape(site.classVmt) + "\t" +
                    escape(site.className) + "\t" +
                    escape(site.messageSlot) + "\t" +
                    escape(site.messagePtr) + "\t" +
                    escape(site.messageResourceModule) + "\t" +
                    escape(site.messageResourceId) + "\t" +
                    escape(site.messageText) + "\t" +
                    escape(site.constructorRva) + "\t" +
                    escape(site.context));
            }
        }

        println("Output: " + outFile.getAbsolutePath());
    }

    private RaiseSite analyzeRaiseSite(Instruction callInstruction) {
        RaiseSite site = new RaiseSite();
        StringBuilder context = new StringBuilder();

        Instruction cursor = callInstruction;
        for (int i = 0; i < 7 && cursor != null; ++i) {
            cursor = cursor.getPrevious();
        }

        for (int i = 0; i < 12 && cursor != null; ++i) {
            if (context.length() > 0) {
                context.append(" | ");
            }

            String text = cursor.toString();
            context.append(formatRva(cursor.getMinAddress())).append(": ").append(text);

            Matcher eax = EAX_CLASS_SLOT.matcher(text);
            if (eax.find()) {
                site.classSlot = eax.group(1);
                site.classVmt = readPointerText(site.classSlot);
                site.className = readDelphiClassName(site.classVmt);
            }

            Matcher ecx = ECX_MESSAGE_SLOT.matcher(text);
            if (ecx.find()) {
                site.messageSlot = ecx.group(1);
                site.messagePtr = readPointerText(site.messageSlot);
                ResStringRecord record = readResStringRecord(site.messagePtr);
                site.messageResourceModule = record.moduleAddress;
                site.messageResourceId = record.resourceId;
                site.messageText = readDelphiString(site.messagePtr);
            }

            if (cursor != callInstruction && cursor.getFlowType().isCall()) {
                Address[] flows = cursor.getFlows();
                if (flows.length > 0 && isImageAddress(flows[0])) {
                    site.constructorRva = formatRva(flows[0]);
                }
            }

            cursor = cursor.getNext();
        }

        site.context = context.toString();
        return site;
    }

    private String readPointerText(String absoluteAddressText) {
        Address address = parseAbsoluteAddress(absoluteAddressText);
        if (!isImageAddress(address)) {
            return "";
        }

        try {
            int value = currentProgram.getMemory().getInt(address);
            long unsigned = value & 0xffffffffL;
            Address pointed = imageBase.getAddressSpace().getAddress(unsigned);
            return isImageAddress(pointed) ? pointed.toString() : String.format("0x%08X", unsigned);
        }
        catch (MemoryAccessException e) {
            return "";
        }
    }

    private String readDelphiClassName(String absoluteAddressText) {
        Address vmt = parseAbsoluteAddress(absoluteAddressText);
        if (!isImageAddress(vmt)) {
            return "";
        }

        for (int delta = 0; delta <= 0x40; ++delta) {
            try {
                Address candidate = vmt.add(delta);
                int length = currentProgram.getMemory().getByte(candidate) & 0xff;
                if (length < 2 || length > 80) {
                    continue;
                }

                byte[] bytes = new byte[length];
                currentProgram.getMemory().getBytes(candidate.add(1), bytes);
                String value = new String(bytes, StandardCharsets.ISO_8859_1);
                if (value.startsWith("E") && value.matches("[A-Za-z0-9_.]+")) {
                    return value;
                }
            }
            catch (Exception e) {
                return "";
            }
        }

        return "";
    }

    private String readDelphiString(String absoluteAddressText) {
        Address textAddress = parseAbsoluteAddress(absoluteAddressText);
        if (!isImageAddress(textAddress)) {
            return "";
        }

        String defined = readDefinedString(textAddress);
        if (defined.length() > 0) {
            return defined;
        }

        String unicode = readUnicodeStringData(textAddress);
        if (unicode.length() > 0) {
            return unicode;
        }

        return readAnsiStringData(textAddress);
    }

    private ResStringRecord readResStringRecord(String absoluteAddressText) {
        ResStringRecord record = new ResStringRecord();
        Address address = parseAbsoluteAddress(absoluteAddressText);
        if (!isImageAddress(address)) {
            return record;
        }

        try {
            int moduleRaw = currentProgram.getMemory().getInt(address);
            int idRaw = currentProgram.getMemory().getInt(address.add(4));
            long moduleUnsigned = moduleRaw & 0xffffffffL;
            int resourceId = idRaw & 0xffff;

            if (moduleUnsigned != 0) {
                record.moduleAddress = String.format("0x%08X", moduleUnsigned);
            }
            if (resourceId != 0) {
                record.resourceId = String.format("0x%04X", resourceId);
            }
        }
        catch (Exception e) {
            return record;
        }

        return record;
    }

    private String readDefinedString(Address textAddress) {
        try {
            Object value = currentProgram.getListing().getDataContaining(textAddress).getValue();
            if (value instanceof String) {
                return (String)value;
            }
        }
        catch (Exception e) {
            return "";
        }
        return "";
    }

    private String readUnicodeStringData(Address textAddress) {
        try {
            int charCount = currentProgram.getMemory().getInt(textAddress.subtract(4));
            if (charCount <= 0 || charCount > 1024) {
                return "";
            }

            byte[] bytes = new byte[charCount * 2];
            currentProgram.getMemory().getBytes(textAddress, bytes);
            String value = new String(bytes, StandardCharsets.UTF_16LE);
            return looksReadable(value) ? value : "";
        }
        catch (Exception e) {
            return "";
        }
    }

    private String readAnsiStringData(Address textAddress) {
        try {
            int byteCount = currentProgram.getMemory().getInt(textAddress.subtract(4));
            if (byteCount <= 0 || byteCount > 2048) {
                return "";
            }

            byte[] bytes = new byte[byteCount];
            currentProgram.getMemory().getBytes(textAddress, bytes);
            String value = new String(bytes, StandardCharsets.ISO_8859_1);
            return looksReadable(value) ? value : "";
        }
        catch (Exception e) {
            return "";
        }
    }

    private boolean looksReadable(String value) {
        if (value == null || value.length() == 0) {
            return false;
        }

        int readable = 0;
        for (int i = 0; i < value.length(); ++i) {
            char ch = value.charAt(i);
            if (ch == '\t' || ch == '\n' || ch == '\r' || ch >= 0x20) {
                readable += 1;
            }
        }
        return readable >= value.length() * 9 / 10;
    }

    private Address parseAbsoluteAddress(String raw) {
        if (raw == null || raw.length() == 0) {
            return null;
        }

        String value = raw.trim().toLowerCase();
        long numeric = value.startsWith("0x")
            ? Long.parseLong(value.substring(2), 16)
            : Long.parseLong(value, 16);
        return imageBase.getAddressSpace().getAddress(numeric);
    }

    private long parseRva(String raw) {
        String value = raw.trim().toLowerCase();
        if (value.startsWith("0x")) {
            return Long.parseLong(value.substring(2), 16);
        }
        return Long.parseLong(value, 16);
    }

    private boolean isImageAddress(Address address) {
        return address != null && address.getAddressSpace().equals(imageBase.getAddressSpace());
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

    private static class RaiseSite {
        String classSlot = "";
        String classVmt = "";
        String className = "";
        String messageSlot = "";
        String messagePtr = "";
        String messageResourceModule = "";
        String messageResourceId = "";
        String messageText = "";
        String constructorRva = "";
        String context = "";
    }

    private static class ResStringRecord {
        String moduleAddress = "";
        String resourceId = "";
    }
}
