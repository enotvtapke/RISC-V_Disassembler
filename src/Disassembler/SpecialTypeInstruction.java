package Disassembler;

public class SpecialTypeInstruction extends AbstractInstruction {
    public SpecialTypeInstruction(String mnemonic, int hex) {
        super(mnemonic, 'X', hex);
    }

    @Override
    public String toString() {
        return super.toString();
    }
}
