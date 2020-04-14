package de.rub.nds.asn1.translator.defaultcontextcomponentoptions;

import de.rub.nds.asn1.TagClass;
import de.rub.nds.asn1.TagConstructed;
import de.rub.nds.asn1.TagNumber;
import de.rub.nds.asn1.model.Asn1ConstructedT61String;
import de.rub.nds.asn1.translator.ContextComponentOption;
import de.rub.nds.asn1.translator.fieldtranslators.Asn1ConstructedT61StringFT;

public class Asn1ConstructedT61StringCCO extends ContextComponentOption<Asn1ConstructedT61String> {

    public Asn1ConstructedT61StringCCO(final String subContextName) {
        super(
                TagClass.UNIVERSAL.getIntValue(),
                TagConstructed.CONSTRUCTED.getBooleanValue(),
                TagNumber.T61STRING.getIntValue(),
                true,
                Asn1ConstructedT61StringFT.class,
                subContextName
        );
    }
}