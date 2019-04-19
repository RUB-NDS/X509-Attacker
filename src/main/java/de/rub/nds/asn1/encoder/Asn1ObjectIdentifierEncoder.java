package de.rub.nds.asn1.encoder;

import de.rub.nds.asn1.model.Asn1ObjectIdentifier;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class Asn1ObjectIdentifierEncoder extends Asn1FieldEncoder {

    private static final Logger LOGGER = LogManager.getLogger();

    private final Asn1ObjectIdentifier asn1ObjectIdentifier;

    public Asn1ObjectIdentifierEncoder(Asn1ObjectIdentifier asn1ObjectIdentifier) {
        super(asn1ObjectIdentifier);
        this.asn1ObjectIdentifier = asn1ObjectIdentifier;
    }

    @Override
    public byte[] encode() {
        this.updateModifiableVariables();
        this.encodeObjectIdentifier();
        return super.encode();
    }

    private void updateModifiableVariables() {
        String objectIdentifierValue = this.asn1ObjectIdentifier.getObjectIdentifierValue();
        this.asn1ObjectIdentifier.setObjectIdentifierValueModificationValue(objectIdentifierValue);
    }

    private void encodeObjectIdentifier() {
        byte[] content = null;
        String fullIdentifierString = this.asn1ObjectIdentifier.getFinalObjectIdentifierValue().trim();
        String[] identifierStrings = fullIdentifierString.split("\\.");
        if (identifierStrings.length >= 2) {
            byte[][] encodedIdentifiers = this.encodeIdentifierStrings(identifierStrings);
            int totalLength = 0;
            int contentPos = 0;
            for (int i = 0; i < encodedIdentifiers.length; i++) {
                totalLength += encodedIdentifiers[i].length;
            }
            content = new byte[totalLength];
            for (int i = 0; i < encodedIdentifiers.length; i++) {
                for (int j = 0; j < encodedIdentifiers[i].length; j++) {
                    content[contentPos] = encodedIdentifiers[i][j];
                    contentPos++;
                }
            }
        } else {
            content = new byte[0];
        }
        this.asn1ObjectIdentifier.setContent(content);
    }

    private byte[][] encodeIdentifierStrings(String[] identifierStrings) {
        byte[][] encodedIdentifiers = new byte[identifierStrings.length - 1][];
        encodedIdentifiers[0] = this.encodeFirstTwoIdentifierStrings(identifierStrings);
        for (int i = 1; i < encodedIdentifiers.length; i++) {
            int identifierValue = Integer.parseInt(identifierStrings[i + 1]);
            encodedIdentifiers[i] = this.encodeSingleIdentifier(identifierValue);
        }
        return encodedIdentifiers;
    }

    private byte[] encodeFirstTwoIdentifierStrings(String[] identifierStrings) {
        int identifier1 = Integer.parseInt(identifierStrings[0]);
        int identifier2 = Integer.parseInt(identifierStrings[1]);
        return new byte[]{(byte) (identifier1 * 40 + identifier2)};
    }

    private byte[] encodeSingleIdentifier(int identifierValue) {
        int numberOfIdentifierValueBytes = this.computeNumberOfIdentifierValueBytes(identifierValue);
        byte[] encodedIdentifier = new byte[numberOfIdentifierValueBytes];
        byte moreFlag = 0x00;
        for (int i = numberOfIdentifierValueBytes - 1; i >= 0; i--) {
            encodedIdentifier[i] = (byte) (moreFlag | (identifierValue & 0x7F));
            identifierValue = identifierValue >> 7;
            moreFlag = (byte) 0x80;
        }
        return encodedIdentifier;
    }

    private int computeNumberOfIdentifierValueBytes(int identifierValue) {
        int numberOfIdentifierValueBytes = 1;
        identifierValue = identifierValue >> 7;
        while (identifierValue > 0) {
            numberOfIdentifierValueBytes++;
            identifierValue = identifierValue >> 7;
        }
        return numberOfIdentifierValueBytes;
    }
}
