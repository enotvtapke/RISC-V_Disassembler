package Disassembler;

public class SpecializedITypeShiftInstruction extends AbstractInstruction {
    public SpecializedITypeShiftInstruction(String mnemonic, char type, int hex) {
        super(mnemonic, type, hex);
    }

    protected int getImmediate() {
        int initial = 0;
        if (isNegative()) {
            initial = 0xFFFFFFFF;
        }
        initial <<= 11;
        initial |= getBits(20, 30);
        return initial;
    }

    private int getShamt() {
        return getImmediate() & 0x0000_001F;
    }

    @Override
    public String toString() {
        return super.toString() + String.format("%s, %s, %d", getRegName(getRd()), getRegName(getRs1()), getShamt());
    }
}
