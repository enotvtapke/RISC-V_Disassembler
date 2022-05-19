package Disassembler;

import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.HashMap;

public class Main {
    private static byte[][] SegregateCode(byte[] code) {
        byte[][] processed = new byte[code.length / 4][4];
        for (int i = 0; i < code.length / 4; i++) {
            System.arraycopy(code, i * 4, processed[i], 0, 4);
        }
        return processed;
    }

    public static void main(String[] args) {
        if (args.length == 0) {
            System.out.println("Input file name expected");
            System.exit(0);
        }
        InstructionSet instructionSet = new InstructionSet();
        ElfParser elf = null;
        try {
            elf = new ElfParser(args[0]);
        } catch (ParseException e) {
            System.out.println(e.getMessage());
            System.exit(0);
        } catch (IOException e) {
            System.err.println("I/O error: " + e.getMessage());
            System.exit(0);
        }
        byte[] code = elf.getCode();
        byte[][] processedCode = SegregateCode(code);
        HashMap<Integer, String> labels = elf.getLabels();

        int sectionTextVirtualAddress = elf.getSectionTextVirtualAddress();

        //Getting labels from code
        int offset;
        for (int i = 0; i < processedCode.length; i++) {
            AbstractInstruction inst = instructionSet.get(processedCode[i]);
            switch (inst.getMnemonic()) {
                case ("JAL") -> {
                    offset = i * 4 + ((JTypeInstruction) inst).getImmediate();
                    labels.put(offset, String.format("LOC_%08x",
                            offset + sectionTextVirtualAddress));
                }
                case ("BEQ"), ("BLT"), ("BGE"), ("BLTU"), ("BGEU") -> {
                    offset = i * 4 + ((BTypeInstruction) inst).getImmediate();
                    labels.put(offset, String.format("LOC_%08x",
                            offset + sectionTextVirtualAddress));
                }
            }
        }

        try {
            BufferedWriter out;
            if (args.length > 1) {
                out = new BufferedWriter(new FileWriter(args[1]));
            } else {
                out = new BufferedWriter(new PrintWriter(System.out));
            }
            try {
                for (int i = 0; i < processedCode.length; i++) {
                    AbstractInstruction inst =
                            instructionSet.get(processedCode[i]);
                    int address = sectionTextVirtualAddress + i * 4;
                    if (labels.containsKey(i * 4)) {
                        String label = labels.get(i * 4);
                        if (label.equals("")) {
                            label = String.format("LOC_%08x", address);
                        }
                        out.write(String.format("%08x: %-9s %s%n",
                                address, '<' + label + '>', inst.toString()));
                    } else {
                        out.write(String.format("%08x:           %s%n",
                                address, inst.toString()));
                    }
                }
                if (args.length > 2 && args[2].equals("e")) {
                    out.write("\nSymbol Table (.symtab)\n");
                    elf.dumpSymbolTable(out);
                }
            } finally {
                out.close();
            }
        } catch (ParseException e) {
            System.out.println(e.getMessage());
        } catch (IOException e) {
            System.err.println("I/O error: " + e.getMessage());
        }
    }
}