package de.rub.nds.asn1.translator.defaultcontextcomponentoptions;

import de.rub.nds.asn1.TagClass;
import de.rub.nds.asn1.TagConstructed;
import de.rub.nds.asn1.TagNumber;
import de.rub.nds.asn1.model.Asn1ConstructedPrintableString;
import de.rub.nds.asn1.translator.ContextComponentOption;
import de.rub.nds.asn1.translator.fieldtranslators.Asn1ConstructedPrintableStringFT;

public class Asn1ConstructedPrintableStringCCO extends ContextComponentOption<Asn1ConstructedPrintableString> {

    public Asn1ConstructedPrintableStringCCO(final String subContextName) {
        super(
                TagClass.UNIVERSAL.getIntValue(),
                TagConstructed.CONSTRUCTED.getBooleanValue(),
                TagNumber.PRINTABLESTRING.getIntValue(),
                true,
                Asn1ConstructedPrintableStringFT.class,
                subContextName
        );
    }
}