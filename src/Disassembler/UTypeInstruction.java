package Disassembler;

public class UTypeInstruction extends AbstractInstruction {
    public UTypeInstruction(String mnemonic, char type, int hex) {
        super(mnemonic, type, hex);
    }

    private int getImmediate() {
        int initial = 0;
        if (isNegative()) {
            initial = 0xFFFFFFFF; //Immediates are sign-extended
        }
        initial <<= 31;
        initial |= (getBits(12, 30) << 12);
        return initial;
    }

    @Override
    public String toString() {
        return super.toString() + String.format("%s, %d", getRegName(getRd()), getImmediate());
    }
}
