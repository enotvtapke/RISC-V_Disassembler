package Disassembler;

import java.io.IOException;
import java.io.Reader;
import java.io.StringReader;
import java.util.HashMap;
import java.util.Scanner;

public class InstructionSet {
    Scanner sc;
    char[] typeTable = new char[128];
    HashMap<Integer, HashMap<Integer, String>> mnemonicTable = new HashMap<>();
    String source =
            """
                    0110111 U LUI
                    0010111 U AUIPC
                    1101111 J JAL
                    1100111 I JALR 000
                    1100011 B BEQ 000
                    1100011 B BNE 001
                    1100011 B BLT 100
                    1100011 B BGE 101
                    1100011 B BLTU 110
                    1100011 B BGEU 111
                    0000011 I LB 000
                    0000011 I LH 001
                    0000011 I LW 010
                    0000011 I LBU 100
                    0000011 I LHU 101
                    0100011 S SB 000
                    0100011 S SH 001
                    0100011 S SW 010
                    0010011 I ADDI 000
                    0010011 I SLTI 010
                    0010011 I SLTIU 011
                    0010011 I XORI 100
                    0010011 I ORI 110
                    0010011 I ANDI 111
                    0010011 I SLLI 001
                    0010011 I SRLI 101
                    0010011 I SRAI 101
                    0110011 R ADD 000 0000000
                    0110011 R SUB 000 0100000
                    0110011 R SLL 001 0000000
                    0110011 R SLT 010 0000000
                    0110011 R SLTU 011 0000000
                    0110011 R XOR 100 0000000
                    0110011 R SRL 101 0000000
                    0110011 R SRA 101 0100000
                    0110011 R OR 110 0000000
                    0110011 R AND 111 0000000
                    0110011 R MUL 000 0000001
                    0110011 R MULH 001 0000001
                    0110011 R MULHSU 010 0000001
                    0110011 R MULHU 011 0000001
                    0110011 R DIV 100 0000001
                    0110011 R DIVU 101 0000001
                    0110011 R REM 110 0000001
                    0110011 R REMU 111 0000001""";

    public InstructionSet() {
        try {
            try (Reader rd = new StringReader(source)) {
                sc = new Scanner(rd);
                parse();
            }
        } catch (IOException e) {
            System.out.println(e.getMessage());
        }
    }

    private void parse() {
        while (sc.hasNext()) {
            int opcode = Integer.parseInt(sc.next(), 2);
            char type = sc.next().charAt(0);
            typeTable[opcode] = type;
            String mnemonic = sc.next();

            int func3;
            int func7;

            switch (type) {
                case ('R') -> {
                    func3 = Integer.parseInt(sc.next(), 2);
                    func7 = Integer.parseInt(sc.next(), 2);
                    int key = func7 * 8 + func3;
                    update(opcode, key, mnemonic);
                }
                case ('I'), ('S'), ('B') -> {
                    func3 = Integer.parseInt(sc.next(), 2);
                    update(opcode, func3, mnemonic);
                }
                case ('U'), ('J') -> update(opcode, 0, mnemonic);
                default -> throw new ParseException("Invalid instruction set (Unknown instruction type)");
            }
        }
    }

    private void update(int opcode, int key, String mnemonic) {
        HashMap<Integer, String> tmp = mnemonicTable.getOrDefault(opcode, new HashMap<>());
        tmp.put(key, mnemonic);
        mnemonicTable.put(opcode, tmp);
    }

    public static int parseBytes(byte[] bytes) {
        int parsed = bytes[3];
        for (int i = 2; i >= 0; i--) {
            parsed <<= 8;
            parsed = parsed | (bytes[i] & 0b011111111);

        }
        return parsed;
    }

    public AbstractInstruction get(byte[] bytes) {
        return get(parseBytes(bytes));
    }

    private boolean ifSpecialInstruction(int opcode) {
        return opcode == 0b1110011 || opcode == 0b0001111;
    }

    public int getBits(int hex, int first, int last) {
        return (hex << (31 - last)) >>> (31 - last + first);
    }

    private AbstractInstruction specialInstruction(int opcode, int hex) {
        if (opcode == 0b0001111) {
            return new SpecialTypeInstruction("FENCE", hex);
        } else if (opcode == 0b1110011) {
            if (getBits(hex, 20, 20) == 0) {
                return new SpecialTypeInstruction("ECALL", hex);
            } else if (getBits(hex, 20, 20) == 1) {
                return new SpecialTypeInstruction("EBREAK", hex);
            }
        }
        throw new ParseException("Unknown special case: " + hex);
    }

    public AbstractInstruction get(int hex) {
        int opcode = getOpcode(hex);

        if (ifSpecialInstruction(opcode)) {
            return specialInstruction(opcode, hex);
        }

        char type = getType(opcode, hex);
        int key;
        String mnemonic;
        switch (type) {
            case ('R'):
                key = getFunc3(hex) + getFunc7(hex) * 8;
                mnemonic = mnemonicTable.get(opcode).get(key);
                return new RTypeInstruction(mnemonic, type, hex);
            case ('I'):
                if (opcode == 0b0010011) { //Specialized shift instruction handle
                    int func3 = getFunc3(hex);
                    if (func3 == 0b101) {
                        int func7 = getFunc7(hex);
                        if (func7 == 0b0000000) {
                            return new SpecializedITypeShiftInstruction("SRLI", type, hex);
                        } else if (func7 == 0b0100000) {
                            return new SpecializedITypeShiftInstruction("SRAI", type, hex);
                        }
                    } else if (func3 == 0b001) {
                        return new SpecializedITypeShiftInstruction("SLLI", type, hex);
                    }
                }
                key = getFunc3(hex);
                mnemonic = mnemonicTable.get(opcode).get(key);
                return new ITypeInstruction(mnemonic, type, hex);
            case ('S'):
                key = getFunc3(hex);
                mnemonic = mnemonicTable.get(opcode).get(key);
                return new STypeInstruction(mnemonic, type, hex);
            case ('B'):
                key = getFunc3(hex);
                mnemonic = mnemonicTable.get(opcode).get(key);
                return new BTypeInstruction(mnemonic, type, hex);
            case ('U'):
                mnemonic = mnemonicTable.get(opcode).get(0);
                return new UTypeInstruction(mnemonic, type, hex);
            case ('J'):
                mnemonic = mnemonicTable.get(opcode).get(0);
                return new JTypeInstruction(mnemonic, type, hex);
            default:
                return new SpecialTypeInstruction("unknown command", 0x00000000);
        }
    }

    private char getType(int opcode, int hex) {
        return typeTable[opcode];
    }

    public int getOpcode(int hex) {
        return hex & 0x0000007F;
    }

    public int getFunc3(int hex) {
        return (hex & 0x00007000) >>> 12;
    }

    public int getFunc7(int hex) {
        return (hex & 0xFE000000) >>> 25;
    }

    private void dumpTable() {
        for (int opcode : mnemonicTable.keySet())
        {
            System.out.println(opcode + ": ");
            for (int func : mnemonicTable.get(opcode).keySet()) {
                System.out.println("    " + func + ": " + mnemonicTable.get(opcode).get(func));
            }
        }
    }
}
