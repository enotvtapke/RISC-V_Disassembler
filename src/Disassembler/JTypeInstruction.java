package Disassembler;

public class JTypeInstruction extends AbstractInstruction {
    public JTypeInstruction(String mnemonic, char type, int hex) {
        super(mnemonic, type, hex);
    }

    public int getImmediate() {
        int initial = 0;
        if (isNegative()) {
            initial = 0xFFFFFFFF; //Immediates are sign-extended
        }
        initial <<= 20;
        initial |= (getBits(12, 19) << 12);
        initial |= (getBits(20, 20) << 11);
        initial |= (getBits(21, 30) << 1);
        return initial;
    }

    @Override
    public String toString() {
        return super.toString() + String.format("%s, %d", getRegName(getRd()), getImmediate());
    }
}
