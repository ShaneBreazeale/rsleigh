// Ghidra headless script: export raw P-code + CFG + function metadata
// as JSON for rsleigh oracle parity tests.
//
// Run via:
//   analyzeHeadless <proj-dir> <proj-name> \
//     -import <fixture.bin> \
//     -processor <ghidra-proc-spec> \
//     -scriptPath scripts \
//     -postScript ExportRsleighOracle.java <out.json>
//
// Output schema is documented in test-harness/fixtures/oracle/README.md.
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.block.CodeBlockIterator;
import ghidra.program.model.block.CodeBlockReference;
import ghidra.program.model.block.CodeBlockReferenceIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;

import java.io.FileWriter;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.List;

public class ExportRsleighOracle extends GhidraScript {

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        String outPath = (args.length > 0) ? args[0] : "oracle.json";

        // For raw-blob imports there is no entry point + no defined functions.
        // Force disassembly across the entire memory image and create a function
        // at the start of every executable block so HighFunction-free pcode
        // export still has something to walk.
        Address minAddr = currentProgram.getMinAddress();
        Address maxAddr = currentProgram.getMaxAddress();
        AddressSet body = new AddressSet(minAddr, maxAddr);
        DisassembleCommand dis = new DisassembleCommand(minAddr, body, true);
        dis.applyTo(currentProgram, monitor);

        if (currentProgram.getFunctionManager().getFunctionAt(minAddr) == null) {
            CreateFunctionCmd mk = new CreateFunctionCmd(minAddr);
            mk.applyTo(currentProgram, monitor);
        }

        StringBuilder json = new StringBuilder();
        json.append("{\n");
        json.append("  \"schema_version\": 1,\n");
        json.append("  \"arch\": ").append(quote(processorString())).append(",\n");
        json.append("  \"binary_sha256\": ").append(quote(programSha256())).append(",\n");
        json.append("  \"functions\": [\n");

        Listing listing = currentProgram.getListing();
        BasicBlockModel bbm = new BasicBlockModel(currentProgram);
        FunctionIterator funcs = listing.getFunctions(true);

        boolean firstFunc = true;
        while (funcs.hasNext() && !monitor.isCancelled()) {
            Function f = funcs.next();
            if (f.isExternal() || f.isThunk()) continue;
            if (!firstFunc) json.append(",\n");
            firstFunc = false;
            emitFunction(json, f, listing, bbm);
        }
        json.append("\n  ]\n}\n");

        try (PrintWriter w = new PrintWriter(new FileWriter(outPath))) {
            w.print(json);
        }
        println("Wrote oracle JSON: " + outPath);
    }

    private void emitFunction(StringBuilder json, Function f, Listing listing, BasicBlockModel bbm) throws Exception {
        long entry = f.getEntryPoint().getOffset();
        json.append("    {\n");
        json.append("      \"entry\": ").append(entry).append(",\n");
        json.append("      \"name\": ").append(quote(f.getName())).append(",\n");

        // Blocks
        json.append("      \"blocks\": [");
        CodeBlockIterator blocks = bbm.getCodeBlocksContaining(f.getBody(), monitor);
        boolean firstBlk = true;
        while (blocks.hasNext()) {
            CodeBlock b = blocks.next();
            if (!firstBlk) json.append(", ");
            firstBlk = false;
            json.append("\n        {");
            json.append("\"start\": ").append(b.getFirstStartAddress().getOffset());
            json.append(", \"end\": ").append(b.getMaxAddress().getOffset() + 1);
            json.append(", \"succs\": [");
            CodeBlockReferenceIterator succs = b.getDestinations(monitor);
            boolean firstSucc = true;
            while (succs.hasNext()) {
                CodeBlockReference r = succs.next();
                if (!firstSucc) json.append(", ");
                firstSucc = false;
                json.append(r.getDestinationAddress().getOffset());
            }
            json.append("]}");
        }
        json.append("\n      ],\n");

        // Instructions
        json.append("      \"instructions\": [");
        InstructionIterator iter = listing.getInstructions(f.getBody(), true);
        boolean firstIns = true;
        while (iter.hasNext()) {
            Instruction insn = iter.next();
            if (!firstIns) json.append(",");
            firstIns = false;
            emitInstruction(json, insn);
        }
        json.append("\n      ]\n");
        json.append("    }");
    }

    private void emitInstruction(StringBuilder json, Instruction insn) throws Exception {
        json.append("\n        {");
        json.append("\"addr\": ").append(insn.getAddress().getOffset());
        json.append(", \"len\": ").append(insn.getLength());
        json.append(", \"bytes\": ").append(quote(hex(insn.getBytes())));
        json.append(", \"disasm\": ").append(quote(insn.toString()));
        json.append(", \"pcode\": [");
        PcodeOp[] ops = insn.getPcode();
        for (int i = 0; i < ops.length; i++) {
            if (i > 0) json.append(", ");
            emitPcode(json, ops[i]);
        }
        json.append("]}");
    }

    private void emitPcode(StringBuilder json, PcodeOp op) {
        json.append("{\"op\": ").append(quote(op.getMnemonic()));
        Varnode out = op.getOutput();
        if (out != null) {
            json.append(", \"out\": ").append(varnodeJson(out));
        }
        json.append(", \"inputs\": [");
        for (int i = 0; i < op.getNumInputs(); i++) {
            if (i > 0) json.append(", ");
            json.append(varnodeJson(op.getInput(i)));
        }
        json.append("]}");
    }

    private String varnodeJson(Varnode v) {
        StringBuilder s = new StringBuilder();
        s.append("{\"space\": ").append(quote(v.getAddress().getAddressSpace().getName()));
        s.append(", \"offset\": ").append(v.getOffset());
        s.append(", \"size\": ").append(v.getSize());
        s.append("}");
        return s.toString();
    }

    private String processorString() {
        return currentProgram.getLanguage().getLanguageID().getIdAsString();
    }

    private String programSha256() throws Exception {
        String imported = currentProgram.getExecutableSHA256();
        return imported == null ? "" : imported.toLowerCase();
    }

    private static String hex(byte[] b) {
        StringBuilder s = new StringBuilder(b.length * 2);
        for (byte x : b) s.append(String.format("%02x", x & 0xff));
        return s.toString();
    }

    private static String quote(String raw) {
        StringBuilder s = new StringBuilder("\"");
        for (int i = 0; i < raw.length(); i++) {
            char c = raw.charAt(i);
            switch (c) {
                case '\\': s.append("\\\\"); break;
                case '"':  s.append("\\\""); break;
                case '\n': s.append("\\n"); break;
                case '\r': s.append("\\r"); break;
                case '\t': s.append("\\t"); break;
                default:
                    if (c < 0x20) s.append(String.format("\\u%04x", (int) c));
                    else s.append(c);
            }
        }
        s.append("\"");
        return s.toString();
    }
}
