package Disassembler;

public class ITypeInstruction extends AbstractInstruction {
    public ITypeInstruction(String mnemonic, char type, int hex) {
        super(mnemonic, type, hex);
    }

    protected int getImmediate() {
        int initial = 0;
        if (isNegative()) {
            initial = 0xFFFFFFFF; //Immediates are sign-extended
        }
        initial <<= 11;
        initial |= getBits(20, 30);
        return initial;
    }

    @Override
    public String toString() {
        return super.toString() + String.format("%s, %s, %d", getRegName(getRd()), getRegName(getRs1()), getImmediate());
    }
}
