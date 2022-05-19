package Disassembler;

public class BTypeInstruction extends AbstractInstruction {
    public BTypeInstruction(String mnemonic, char type, int hex) {
        super(mnemonic, type, hex);
    }

    public int getImmediate() {
        int initial = 0;
        if (isNegative()) {
            initial = 0xFFFFFFFF; //Immediates are sign-extended
        }
        initial <<= 12;
        initial |= (getBits(7, 7) << 11);
        initial |= (getBits(25, 30) << 5);
        initial |= (getBits(8, 11) << 1);
        return initial;
    }

    @Override
    public String toString() {
        return super.toString() + String.format("%s, %s, %d", getRegName(getRs1()), getRegName(getRs2()), getImmediate());
    }
}
