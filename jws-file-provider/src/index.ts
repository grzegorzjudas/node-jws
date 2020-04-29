import fs from 'fs';
import { JWS, JWK } from 'jose';
import { KeyProvider, JWTClaims, JWTHeader } from 'node-jws';

export default function FileJwtProvider (privateKeyPath: string, publicKeyPath: string): KeyProvider {
    const privateKey = JWK.asKey(fs.readFileSync(privateKeyPath));
    const publicKey = JWK.asKey(fs.readFileSync(publicKeyPath));

    return {
        sign: async (claims: JWTClaims, header: JWTHeader) => {
            return JWS.sign(claims, privateKey, header);
        },
        valid: async (raw: string) => {
            try {
                JWS.verify(raw, publicKey);

                return true;
            } catch (error) {
                return false;
            }
        }
    };
}
