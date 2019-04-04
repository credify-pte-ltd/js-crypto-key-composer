import { RsaPrivateKey } from './asn1-entities';
import { decodeAsn1, encodeAsn1 } from '../../util/asn1';
import { uint8ArrayToInteger } from '../../util/binary';

export const decomposeRsaPrivateKey = (rsaPrivateKeyAsn1) => {
    const { version, ...keyData } = decodeAsn1(rsaPrivateKeyAsn1, RsaPrivateKey);

    return {
        keyAlgorithm: {
            id: 'rsa-encryption',
        },
        keyData: {
            ...keyData,
            // The publicExponent is small, so just transform it to a number
            publicExponent: uint8ArrayToInteger(keyData.publicExponent),
        },
    };
};

export const composeRsaPrivateKey = (rsaKeyData) => {
    const otherPrimeInfos = rsaKeyData.otherPrimeInfos;
    const hasMultiplePrimes = otherPrimeInfos && otherPrimeInfos.length > 0;

    const rsaPrivateKey = {
        ...rsaKeyData,
        version: hasMultiplePrimes ? 1 : 0,
        otherPrimeInfos: hasMultiplePrimes ? otherPrimeInfos : undefined,
    };

    return encodeAsn1(rsaPrivateKey, RsaPrivateKey);
};
