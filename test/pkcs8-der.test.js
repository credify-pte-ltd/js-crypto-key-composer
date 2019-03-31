import fs from 'fs';
import { decomposePrivateKey, composePrivateKey } from '../src';
import { typedArrayToUint8Array } from '../src/util/binary';

const KEYS = {
    'rsa-1': fs.readFileSync('test/fixtures/pkcs8-der/rsa-1'),
    'rsa-2': fs.readFileSync('test/fixtures/pkcs8-der/rsa-2'),
    'rsa-3': fs.readFileSync('test/fixtures/pkcs8-der/rsa-3'),
    'rsa-4': fs.readFileSync('test/fixtures/pkcs8-der/rsa-4'),
    'rsa-5': fs.readFileSync('test/fixtures/pkcs8-der/rsa-5'),
    'rsa-6': fs.readFileSync('test/fixtures/pkcs8-der/rsa-6'),
    'rsa-7': fs.readFileSync('test/fixtures/pkcs8-der/rsa-7'),
    'rsa-8': fs.readFileSync('test/fixtures/pkcs8-der/rsa-8'),
    'rsa-9': fs.readFileSync('test/fixtures/pkcs8-der/rsa-9'),
    'rsa-10': fs.readFileSync('test/fixtures/pkcs8-der/rsa-10'),
    'rsa-11': fs.readFileSync('test/fixtures/pkcs8-der/rsa-11'),
    'rsa-12': fs.readFileSync('test/fixtures/pkcs8-der/rsa-12'),
    'rsa-13': fs.readFileSync('test/fixtures/pkcs8-der/rsa-13'),
    'rsa-14': fs.readFileSync('test/fixtures/pkcs8-der/rsa-14'),
    'rsa-15': fs.readFileSync('test/fixtures/pkcs8-der/rsa-15'),
    'ed25519-1': fs.readFileSync('test/fixtures/pkcs8-der/ed25519-1'),
    'invalid-1': fs.readFileSync('test/fixtures/pkcs8-der/invalid-1'),
    'invalid-2': fs.readFileSync('test/fixtures/pkcs8-der/invalid-2'),
    'invalid-3': fs.readFileSync('test/fixtures/pkcs8-der/invalid-3'),
    'invalid-4': fs.readFileSync('test/fixtures/pkcs8-der/invalid-4'),
    'invalid-5': fs.readFileSync('test/fixtures/pkcs8-der/invalid-5'),
    'invalid-6': fs.readFileSync('test/fixtures/pkcs8-der/invalid-6'),
    'invalid-7': fs.readFileSync('test/fixtures/pkcs8-der/invalid-7'),
};

const password = 'password';

describe('decomposePrivateKey', () => {
    it('should decompose a standard RSA key', () => {
        expect(decomposePrivateKey(KEYS['rsa-1'], { format: 'pkcs8-der' })).toMatchSnapshot();
    });

    it('should decompose a RSA key with 3 primes', () => {
        expect(decomposePrivateKey(KEYS['rsa-2'], { format: 'pkcs8-der' })).toMatchSnapshot();
    });

    it('should decompose a RSA key with 4 primes', () => {
        expect(decomposePrivateKey(KEYS['rsa-3'], { format: 'pkcs8-der' })).toMatchSnapshot();
    });

    it('should decompose a ed25519 key', () => {
        expect(decomposePrivateKey(KEYS['ed25519-1'], { format: 'pkcs8-der' })).toMatchSnapshot();
    });

    it('should also support Uint8Array, ArrayBuffer and string besides Node\'s Buffer', () => {
        const nodeBuffer = fs.readFileSync('test/fixtures/pkcs8-der/rsa-1');

        expect(decomposePrivateKey(typedArrayToUint8Array(nodeBuffer), { format: 'pkcs8-der' })).toMatchSnapshot();
        expect(decomposePrivateKey(typedArrayToUint8Array(nodeBuffer).buffer, { format: 'pkcs8-der' })).toMatchSnapshot();
        expect(decomposePrivateKey(nodeBuffer.toString('binary'), { format: 'pkcs8-der' })).toMatchSnapshot();
    });

    it('should fail if the key algorithm is not supported', () => {
        expect.assertions(2);

        try {
            decomposePrivateKey(KEYS['invalid-1'], { format: 'pkcs8-der' });
        } catch (err) {
            expect(err.message).toBe('Unsupported key algorithm OID \'0.20.999\'');
            expect(err.code).toBe('UNSUPPORTED_ALGORITHM');
        }
    });

    it('should fail if the input key is invalid', () => {
        expect.assertions(2);

        try {
            decomposePrivateKey('', { format: 'pkcs8-der' });
        } catch (err) {
            expect(err.message).toBe('Failed to decode PrivateKeyInfo');
            expect(err.code).toBe('INVALID_INPUT_KEY');
        }
    });

    describe('decryption', () => {
        it('should decompose a RSA key encrypted with pbes2+pbkdf2+aes128-cbc', () => {
            expect(decomposePrivateKey(KEYS['rsa-4'], { format: 'pkcs8-der', password })).toMatchSnapshot();
        });

        it('should decompose a RSA key encrypted with pbes2+pbkdf2+aes192-cbc', () => {
            expect(decomposePrivateKey(KEYS['rsa-5'], { format: 'pkcs8-der', password })).toMatchSnapshot();
        });

        it('should decompose a RSA key encrypted with pbes2+pbkdf2+aes256-cbc', () => {
            expect(decomposePrivateKey(KEYS['rsa-6'], { format: 'pkcs8-der', password })).toMatchSnapshot();
        });

        it('should decompose a RSA key encrypted with pbes2+pbkdf2+rc2 40 bits', () => {
            expect(decomposePrivateKey(KEYS['rsa-7'], { format: 'pkcs8-der', password })).toMatchSnapshot();
        });

        it('should decompose a RSA key encrypted with pbes2+pbkdf2+rc2 64 bits', () => {
            expect(decomposePrivateKey(KEYS['rsa-8'], { format: 'pkcs8-der', password })).toMatchSnapshot();
        });

        it('should decompose a RSA key encrypted with pbes2+pbkdf2+rc2 128 bits', () => {
            expect(decomposePrivateKey(KEYS['rsa-9'], { format: 'pkcs8-der', password })).toMatchSnapshot();
        });

        it('should fail if the rc2 parameter version in pbes2+pbkdf2+rc2 is not supported', () => {
            expect.assertions(2);

            try {
                decomposePrivateKey(KEYS['invalid-5'], { format: 'pkcs8-der', password });
            } catch (err) {
                expect(err.message).toBe('Unsupported RC2 version parameter with value \'1\'');
                expect(err.code).toBe('UNSUPPORTED_ALGORITHM');
            }
        });

        it('should decompose a RSA key encrypted with pbes2+pbkdf2+des-ede3-cbc', () => {
            expect(decomposePrivateKey(KEYS['rsa-11'], { format: 'pkcs8-der', password })).toMatchSnapshot();
        });

        it('should decompose a RSA key encrypted with all other PBKDF2 prf variants', () => {
            expect(decomposePrivateKey(KEYS['rsa-12'], { format: 'pkcs8-der', password })).toMatchSnapshot('sha1');
            // expect(decomposePrivateKey(KEYS['rsa-13'], { format: 'pkcs8-der', password })).toMatchSnapshot();
            expect(decomposePrivateKey(KEYS['rsa-14'], { format: 'pkcs8-der', password })).toMatchSnapshot('sha384');
            expect(decomposePrivateKey(KEYS['rsa-15'], { format: 'pkcs8-der', password })).toMatchSnapshot('sha512');
        });

        it('should fail if the key derivation func prf in the PBES2 encryption algorithm is not supported', () => {
            expect.assertions(2);

            try {
                decomposePrivateKey(KEYS['invalid-7'], { format: 'pkcs8-der', password });
            } catch (err) {
                expect(err.message).toBe('Unsupported prf algorithm OID \'0.20.999\'');
                expect(err.code).toBe('UNSUPPORTED_ALGORITHM');
            }
        });

        it('should fail if the key derivation func in the PBES2 encryption algorithm is not supported', () => {
            expect.assertions(2);

            try {
                decomposePrivateKey(KEYS['invalid-2'], { format: 'pkcs8-der', password });
            } catch (err) {
                expect(err.message).toBe('Unsupported key derivation function algorithm OID \'0.20.999\'');
                expect(err.code).toBe('UNSUPPORTED_ALGORITHM');
            }
        });

        it('should fail if the encryption scheme in the PBES2 encryption algorithm is not supported', () => {
            expect.assertions(2);

            try {
                decomposePrivateKey(KEYS['invalid-3'], { format: 'pkcs8-der', password });
            } catch (err) {
                expect(err.message).toBe('Unsupported encryption scheme algorithm OID \'0.20.999\'');
                expect(err.code).toBe('UNSUPPORTED_ALGORITHM');
            }
        });

        it('should fail if the encryption algorithm is not supported', () => {
            expect.assertions(2);

            try {
                decomposePrivateKey(KEYS['invalid-4'], { format: 'pkcs8-der', password });
            } catch (err) {
                expect(err.message).toBe('Unsupported encryption algorithm OID \'0.20.999\'');
                expect(err.code).toBe('UNSUPPORTED_ALGORITHM');
            }
        });

        it('should fail to decompose an encrypted RSA key without suplying a password', () => {
            expect.assertions(2);

            try {
                decomposePrivateKey(KEYS['rsa-4'], { format: 'pkcs8-der' });
            } catch (err) {
                expect(err.message).toBe('Please specify the password to decrypt the key');
                expect(err.code).toBe('MISSING_PASSWORD');
            }
        });

        it('should fail if the decrypted data is not a valid PrivateKeyInfo', () => {
            expect.assertions(2);

            try {
                decomposePrivateKey(KEYS['invalid-6'], { format: 'pkcs8-der', password });
            } catch (err) {
                expect(err.message).toBe('Failed to decode PrivateKeyInfo');
                expect(err.code).toBe('DECODE_ASN1_FAILED');
            }
        });

        it('should fail to decompose an encrypted RSA key with the wrong password', () => {
            expect.assertions(2);

            try {
                decomposePrivateKey(KEYS['rsa-4'], {
                    format: 'pkcs8-der',
                    password: 'foo',
                });
            } catch (err) {
                expect(err.message).toBe('Decryption failed, mostly likely the password is wrong');
                expect(err.code).toBe('DECRYPTION_FAILED');
            }
        });
    });
});

describe('composePrivateKey', () => {
    it('should compose a standard RSA key (mirroring)', () => {
        const decomposedKey = decomposePrivateKey(KEYS['rsa-1'], { format: 'pkcs8-der' });
        const composedKey = composePrivateKey(decomposedKey);

        expect(composedKey).toEqual(typedArrayToUint8Array(KEYS['rsa-1']));
    });

    it('should compose a RSA key with 3 primes (mirroring)', () => {
        const decomposedKey = decomposePrivateKey(KEYS['rsa-2'], { format: 'pkcs8-der' });
        const composedKey = composePrivateKey(decomposedKey);

        expect(composedKey).toEqual(typedArrayToUint8Array(KEYS['rsa-2']));
    });

    it('should compose a RSA key with 4 primes (mirroring)', () => {
        const decomposedKey = decomposePrivateKey(KEYS['rsa-3'], { format: 'pkcs8-der' });
        const composedKey = composePrivateKey(decomposedKey);

        expect(composedKey).toEqual(typedArrayToUint8Array(KEYS['rsa-3']));
    });

    it('should compose a standard ed25519 key', () => {
        const decomposedKey = decomposePrivateKey(KEYS['ed25519-1'], { format: 'pkcs8-der' });
        const composedKey = composePrivateKey(decomposedKey);

        expect(composedKey).toEqual(typedArrayToUint8Array(KEYS['ed25519-1']));
    });

    it('should fail if the key algorithm is not supported', () => {
        expect.assertions(2);

        try {
            composePrivateKey({
                format: 'pkcs8-der',
                keyAlgorithm: { id: 'foo' },
                keyData: {},
            });
        } catch (err) {
            expect(err.message).toBe('Unsupported key algorithm id \'foo\'');
            expect(err.code).toBe('UNSUPPORTED_ALGORITHM');
        }
    });

    it('should support a string in the key algorithm', () => {
        const decomposedKey = decomposePrivateKey(KEYS['rsa-1'], { format: 'pkcs8-der' });

        expect(composePrivateKey({ ...decomposedKey, keyAlgorithm: 'rsa-encryption' })).toMatchSnapshot();
    });

    it('should support the \'rsa\' alias as the key algorithm', () => {
        const decomposedKey = decomposePrivateKey(KEYS['rsa-1'], { format: 'pkcs8-der' });

        expect(composePrivateKey({ ...decomposedKey, keyAlgorithm: 'rsa' })).toMatchSnapshot();
    });

    describe('encryption', () => {
        it('should compose a RSA key encrypted with pbes2+pbkdf2+aes128-cbc (mirroring)', () => {
            const decomposedKey = decomposePrivateKey(KEYS['rsa-4'], { format: 'pkcs8-der', password });
            const composedKey = composePrivateKey(decomposedKey, { password });

            expect(composedKey).toEqual(typedArrayToUint8Array(KEYS['rsa-4']));
        });

        it('should compose a RSA key encrypted with pbes2+pbkdf2+aes192-cbc (mirroring)', () => {
            const decomposedKey = decomposePrivateKey(KEYS['rsa-5'], { format: 'pkcs8-der', password });
            const composedKey = composePrivateKey(decomposedKey, { password });

            expect(composedKey).toEqual(typedArrayToUint8Array(KEYS['rsa-5']));
        });

        it('should compose a RSA key encrypted with pbes2+pbkdf2+aes256-cbc (mirroring)', () => {
            const decomposedKey = decomposePrivateKey(KEYS['rsa-6'], { format: 'pkcs8-der', password });
            const composedKey = composePrivateKey(decomposedKey, { password });

            expect(composedKey).toEqual(typedArrayToUint8Array(KEYS['rsa-6']));
        });

        it('should compose a RSA key encrypted with pbes2+pbkdf2+rc2 40 bits (mirroring)', () => {
            const decomposedKey = decomposePrivateKey(KEYS['rsa-7'], { format: 'pkcs8-der', password });
            const composedKey = composePrivateKey(decomposedKey, { password });

            expect(composedKey).toEqual(typedArrayToUint8Array(KEYS['rsa-7']));
        });

        it('should compose a RSA key encrypted with pbes2+pbkdf2+rc2 64 bits (mirroring)', () => {
            const decomposedKey = decomposePrivateKey(KEYS['rsa-8'], { format: 'pkcs8-der', password });
            const composedKey = composePrivateKey(decomposedKey, { password });

            expect(composedKey).toEqual(typedArrayToUint8Array(KEYS['rsa-8']));
        });

        it('should compose a RSA key encrypted with pbes2+pbkdf2+rc2 128 bits (mirroring)', () => {
            const decomposedKey = decomposePrivateKey(KEYS['rsa-9'], { format: 'pkcs8-der', password });
            const composedKey = composePrivateKey(decomposedKey, { password });

            expect(composedKey).toEqual(typedArrayToUint8Array(KEYS['rsa-9']));
        });

        it('should fail if the bits specified in pbes2+pbkdf2+rc2 is not supported', () => {
            const decomposedKey = decomposePrivateKey(KEYS['rsa-9'], { format: 'pkcs8-der', password });

            expect.assertions(2);

            try {
                composePrivateKey({
                    ...decomposedKey,
                    encryptionAlgorithm: {
                        ...decomposedKey.encryptionAlgorithm,
                        encryptionScheme: { id: 'rc2-cbc', bits: 1024 },
                    },
                }, {
                    password,
                });
            } catch (err) {
                expect(err.message).toBe('Unsupported RC2 bits parameter with value \'1024\'');
                expect(err.code).toBe('UNSUPPORTED_ALGORITHM');
            }
        });

        it('should default to 128 bits for pbes2+pbkdf2+rc2', () => {
            const decomposedKey = decomposePrivateKey(KEYS['rsa-9'], { format: 'pkcs8-der', password });
            const composedKey = composePrivateKey({
                ...decomposedKey,
                encryptionAlgorithm: {
                    ...decomposedKey.encryptionAlgorithm,
                    encryptionScheme: { id: 'rc2-cbc' },
                },
            }, {
                password,
            });
            const recomposedKey = decomposePrivateKey(composedKey, { format: 'pkcs8-der', password });

            expect(recomposedKey.encryptionAlgorithm.encryptionScheme.id).toBe('rc2-cbc');
            expect(recomposedKey.encryptionAlgorithm.encryptionScheme.bits).toBe(128);
        });

        it('should compose a RSA key encrypted with pbes2+pbkdf2+des-cbc (mirroring)', () => {
            const decomposedKey = decomposePrivateKey(KEYS['rsa-10'], { format: 'pkcs8-der', password });
            const composedKey = composePrivateKey(decomposedKey, { password });

            expect(composedKey).toEqual(typedArrayToUint8Array(KEYS['rsa-10']));
        });

        it('should compose a RSA key encrypted with pbes2+pbkdf2+des-ede3-cbc (mirroring)', () => {
            const decomposedKey = decomposePrivateKey(KEYS['rsa-11'], { format: 'pkcs8-der', password });
            const composedKey = composePrivateKey(decomposedKey, { password });

            expect(composedKey).toEqual(typedArrayToUint8Array(KEYS['rsa-11']));
        });

        it('should default to using pbes2+pbkdf2+aes256-cbc if no encryption algorithm was passed', () => {
            const decomposedKey = decomposePrivateKey(KEYS['rsa-1'], { format: 'pkcs8-der' });
            const composedKey = composePrivateKey(decomposedKey, { password });
            const recomposedKey = decomposePrivateKey(composedKey, { format: 'pkcs8-der', password });

            expect(recomposedKey.encryptionAlgorithm.id).toBe('pbes2');
            expect(recomposedKey.encryptionAlgorithm.keyDerivationFunc.id).toBe('pbkdf2');
            expect(recomposedKey.encryptionAlgorithm.encryptionScheme.id).toBe('aes256-cbc');
        });

        it('should decompose a RSA key encrypted with all other PBKDF2 prf variants', () => {
            ['rsa-12', /* 'rsa-13' , */'rsa-14', 'rsa-15'].forEach((keyProp) => {
                const decomposedKey = decomposePrivateKey(KEYS[keyProp], { format: 'pkcs8-der', password });
                const composedKey = composePrivateKey(decomposedKey, { password });

                expect(composedKey).toEqual(typedArrayToUint8Array(KEYS[keyProp]));
            });
        });

        it('should fail if the key derivation func prf in the PBES2 encryption algorithm is not supported', () => {
            const decomposedKey = decomposePrivateKey(KEYS['rsa-4'], { format: 'pkcs8-der', password });

            expect.assertions(2);

            try {
                composePrivateKey({
                    ...decomposedKey,
                    encryptionAlgorithm: {
                        ...decomposedKey.encryptionAlgorithm,
                        keyDerivationFunc: {
                            ...decomposedKey.encryptionAlgorithm.keyDerivationFunc,
                            prf: 'foo',
                        },
                    },
                }, {
                    password,
                });
            } catch (err) {
                expect(err.message).toBe('Unsupported prf algorithm id \'foo\'');
                expect(err.code).toBe('UNSUPPORTED_ALGORITHM');
            }
        });

        it('should fail if the encryption scheme for PBES2 is not supported', () => {
            const decomposedKey = decomposePrivateKey(KEYS['rsa-4'], { format: 'pkcs8-der', password });

            expect.assertions(2);

            try {
                composePrivateKey({
                    ...decomposedKey,
                    encryptionAlgorithm: {
                        ...decomposedKey.encryptionAlgorithm,
                        encryptionScheme: { id: 'foo' },
                    },
                }, {
                    password,
                });
            } catch (err) {
                expect(err.message).toBe('Unsupported encryption scheme id \'foo\'');
                expect(err.code).toBe('UNSUPPORTED_ALGORITHM');
            }
        });

        it('should fail if the key derivation func for PBES2 is not supported', () => {
            const decomposedKey = decomposePrivateKey(KEYS['rsa-4'], { format: 'pkcs8-der', password });

            expect.assertions(2);

            try {
                composePrivateKey({
                    ...decomposedKey,
                    encryptionAlgorithm: {
                        ...decomposedKey.encryptionAlgorithm,
                        keyDerivationFunc: { id: 'foo' },
                    },
                }, {
                    password,
                });
            } catch (err) {
                expect(err.message).toBe('Unsupported key derivation function id \'foo\'');
                expect(err.code).toBe('UNSUPPORTED_ALGORITHM');
            }
        });

        it('should fail if encryption algorithm was specified without a password', () => {
            const decomposedKey = decomposePrivateKey(KEYS['rsa-4'], { format: 'pkcs8-der', password });

            expect.assertions(2);

            try {
                composePrivateKey(decomposedKey);
            } catch (err) {
                expect(err.message).toBe('An encryption algorithm was specified but no password was set');
                expect(err.code).toBe('MISSING_PASSWORD');
            }
        });

        it('should fail if the encryption algorithm is not supported', () => {
            const decomposedKey = decomposePrivateKey(KEYS['rsa-1'], { format: 'pkcs8-der' });

            expect.assertions(2);

            try {
                composePrivateKey({
                    ...decomposedKey,
                    encryptionAlgorithm: { id: 'foo' },
                }, {
                    password,
                });
            } catch (err) {
                expect(err.message).toBe('Unsupported encryption algorithm id \'foo\'');
                expect(err.code).toBe('UNSUPPORTED_ALGORITHM');
            }
        });
    });
});
