package Disassembler;

public abstract class AbstractInstruction {
    String mnemonic;
    char type;
    int hex;

    public AbstractInstruction(String mnemonic, char type, int hex) {
        this.mnemonic = mnemonic;
        this.type = type;
        this.hex = hex;
    }

    protected int getBits(int first, int last) {
        return (hex << (31 - last)) >>> (31 - last + first);
    }

    protected boolean isNegative() {
        return getBits(31, 31) == 1;
    }

    protected String getRegName(int R) {
        if (R == 0) {
            return "zero";
        } else {
            return "x" + R;
        }
    }

    protected int getRd() {
        return getBits(7, 11);
    }

    protected int getRs1() {
        return getBits(15, 19);
    }

    protected int getRs2() {
        return getBits(20, 24);
    }

    public String getMnemonic() {
        return mnemonic;
    }

    public int getHex() {
        return hex;
    }

    @Override
    public String toString() {
        return String.format("%-5s ", getMnemonic().toLowerCase());
    }
}