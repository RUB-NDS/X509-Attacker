package de.rub.nds.x509attacker.x509.model.types.inhibitpolicy;

import de.rub.nds.x509attacker.x509.model.types.policyconstraints.SkipCerts;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlRootElement;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class InhibitAnyPolicy extends SkipCerts {

    public InhibitAnyPolicy() {
        super();
    }
}