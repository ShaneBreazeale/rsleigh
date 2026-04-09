// Ghidra headless script to dump P-code for test instructions
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.address.*;
import ghidra.app.cmd.disassemble.DisassembleCommand;

public class DumpPcode extends GhidraScript {
    @Override
    public void run() throws Exception {
        // Force disassembly at address 0
        Address start = currentProgram.getMinAddress();
        Address end = currentProgram.getMaxAddress();

        println("Disassembling from " + start + " to " + end);

        DisassembleCommand cmd = new DisassembleCommand(start, null, true);
        cmd.applyTo(currentProgram, monitor);

        Listing listing = currentProgram.getListing();
        InstructionIterator iter = listing.getInstructions(start, true);

        int count = 0;
        while (iter.hasNext()) {
            Instruction insn = iter.next();
            count++;

            StringBuilder bytes = new StringBuilder();
            for (byte b : insn.getBytes()) {
                bytes.append(String.format("%02x ", b & 0xff));
            }

            println("=== " + insn.getAddress() + ": " + insn.toString() + " ===");
            println("  bytes: " + bytes.toString().trim());
            println("  length: " + insn.getLength());

            PcodeOp[] pcode = insn.getPcode();
            println("  pcode_ops: " + pcode.length);

            for (PcodeOp op : pcode) {
                StringBuilder line = new StringBuilder("    " + op.getMnemonic());
                if (op.getOutput() != null) {
                    Varnode out = op.getOutput();
                    line.append(" out=(")
                        .append(out.getAddress().getAddressSpace().getName())
                        .append(",0x").append(Long.toHexString(out.getOffset()))
                        .append(",").append(out.getSize()).append(")");
                }
                for (int i = 0; i < op.getNumInputs(); i++) {
                    Varnode inp = op.getInput(i);
                    line.append(" in").append(i).append("=(")
                        .append(inp.getAddress().getAddressSpace().getName())
                        .append(",0x").append(Long.toHexString(inp.getOffset()))
                        .append(",").append(inp.getSize()).append(")");
                }
                println(line.toString());
            }
        }
        println("Total: " + count + " instructions");
    }
}
