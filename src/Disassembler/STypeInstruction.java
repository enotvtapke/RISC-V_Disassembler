package Disassembler;

public class STypeInstruction extends AbstractInstruction {
    public STypeInstruction(String mnemonic, char type, int hex) {
        super(mnemonic, type, hex);
    }

    private int getImmediate() {
        int initial = 0;
        if (isNegative()) {
            initial = 0xFFFFFFFF; //Immediates are sign-extended
        }
        initial <<= 11;
        initial |= (getBits(25, 30) << 5);
        initial |= (getBits(8, 11) << 1);
        initial |= getBits(7, 7);
        return initial;
    }

    @Override
    public String toString() {
        return super.toString() + String.format("%s, %s, %d", getRegName(getRs1()), getRegName(getRs2()), getImmediate());
    }
}
