package de.rub.nds.asn1.translator.defaultcontextcomponentoptions;

import de.rub.nds.asn1.TagClass;
import de.rub.nds.asn1.TagConstructed;
import de.rub.nds.asn1.TagNumber;
import de.rub.nds.asn1.model.Asn1PrimitivePrintableString;
import de.rub.nds.asn1.translator.ContextComponentOption;
import de.rub.nds.asn1.translator.fieldtranslators.Asn1PrimitivePrintableStringFT;

public class Asn1PrimitivePrintableStringCCO extends ContextComponentOption<Asn1PrimitivePrintableString> {

    public Asn1PrimitivePrintableStringCCO() {
        super(
                TagClass.UNIVERSAL.getIntValue(),
                TagConstructed.PRIMITIVE.getBooleanValue(),
                TagNumber.PRINTABLESTRING.getIntValue(),
                false,
                Asn1PrimitivePrintableStringFT.class,
                null
        );
    }
}