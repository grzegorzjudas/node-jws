import fs from 'fs';
import { JWS, JWK } from 'jose';
import { KeyProvider, JWTClaims, JWTHeader } from 'node-jws';

export default function FileJwtProvider (privateKeyPath: string, publicKeyPath: string): KeyProvider {
    const privateKey = privateKeyPath ? JWK.asKey(fs.readFileSync(privateKeyPath)) : null;
    const publicKey = publicKeyPath ? JWK.asKey(fs.readFileSync(publicKeyPath)) : null;

    return {
        sign: async (claims: JWTClaims, header: JWTHeader) => {
            if (!privateKey) throw new Error('Cannot sign JWS - private key not provided.');

            return JWS.sign(claims, privateKey, header);
        },
        valid: async (raw: string) => {
            if (!publicKey) throw new Error('Cannot verify JWS - public key not provided.');

            try {
                JWS.verify(raw, publicKey);

                return true;
            } catch (error) {
                return false;
            }
        }
    };
}
