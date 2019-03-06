package de.rub.nds.x509attacker.x509.meta;

import de.rub.nds.x509attacker.asn1.model.Asn1RawField;

import java.util.List;

public interface X509Asn1ValueHolder {
    List<Asn1RawField> getValues();

    void addValue(Asn1RawField value);
}
