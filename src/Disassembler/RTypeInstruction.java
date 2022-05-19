package Disassembler;

public class RTypeInstruction extends AbstractInstruction {
    public RTypeInstruction(String mnemonic, char type, int hex) {
        super(mnemonic, type, hex);
    }

    @Override
    public String toString() {
        return super.toString() + String.format("%s, %s, %s", getRegName(getRd()), getRegName(getRs1()), getRegName(getRs2()));
    }
}
