import crypto from 'crypto';
import { KeyManagementServiceClient } from '@google-cloud/kms';
import { sanitizeBase64, desanitizeBase64, KeyProvider, JWTClaims, JWTHeader, JWTAlghoritm } from 'node-jws';

const client = new KeyManagementServiceClient();
const publicKeys = {};

function getKeyPath (project: string, location: string, keyring: string, keyname: string, version: string): string {
    return client.cryptoKeyVersionPath(project, location, keyring, keyname, version);
}

function mapAlghoritmToHash (alg: JWTAlghoritm): string {
    switch (alg) {
        case JWTAlghoritm.RS256: return 'sha256';
        case JWTAlghoritm.RS384: return 'sha384';
        case JWTAlghoritm.RS512: return 'sha512';
        case JWTAlghoritm.PS256: return 'sha256';
        case JWTAlghoritm.PS384: return 'sha384';
        case JWTAlghoritm.PS512: return 'sha512';
        case JWTAlghoritm.HS256: return 'sha256';
        case JWTAlghoritm.HS384: return 'sha384';
        case JWTAlghoritm.HS512: return 'sha512';
        case JWTAlghoritm.ES256: return 'sha256';
        case JWTAlghoritm.ES384: return 'sha384';
        case JWTAlghoritm.ES512: return 'sha512';
        case JWTAlghoritm.none: throw new Error('No alghorithm, hash not available.');
        default: throw new Error('Not (fully) supported alghoritm: did not find hash matching it.');
    }
}

async function sign (name: string, alg: JWTAlghoritm, message: string): Promise<string> {
    const hash = mapAlghoritmToHash(alg);
    const digest = crypto.createHash(hash).update(message).digest();

    try {
        const [ result ] = await client.asymmetricSign({
            name,
            digest: {
                [hash]: digest
            }
        });

        return Buffer.from(result.signature).toString('base64');
    } catch (error) {
        throw new Error(`GCP request error: ${error.details}`);
    }
}

async function getPublicKey (name: string): Promise<string> {
    if (publicKeys[name]) return publicKeys[name];

    try {
        const [ publicKey ] = await client.getPublicKey({ name });
        publicKeys[name] = publicKey.pem;

        return publicKey.pem;
    } catch (error) {
        throw new Error(`GCP request error: ${error.details}`);
    }
}

async function verify (keyPath: string, alg: JWTAlghoritm, message: string, signature: string): Promise<boolean> {
    const publicKey = await getPublicKey(keyPath);
    const hash = mapAlghoritmToHash(alg);
    const verifier = crypto.createVerify(hash);

    verifier.write(message);
    verifier.end();

    return verifier.verify({
        key: publicKey,
        padding: crypto.constants.RSA_PKCS1_PSS_PADDING
    }, Buffer.from(signature, 'base64'));
}

export default function GoogleKmsKeyProvider (project: string, location: string, keyring: string, keyname: string, version: string): KeyProvider {
    const keyPath = getKeyPath(project, location, keyring, keyname, version);

    return {
        sign: async (claims: JWTClaims, header: JWTHeader) => {
            const rawHeader = sanitizeBase64(Buffer.from(JSON.stringify(header), 'utf8').toString('base64'));
            const rawClaims = sanitizeBase64(Buffer.from(JSON.stringify(claims), 'utf8').toString('base64'));
            const signature = sanitizeBase64(await sign(keyPath, header.alg, `${rawHeader}.${rawClaims}`));

            return `${rawHeader}.${rawClaims}.${signature}`;
        },
        valid: async (raw: string) => {
            const message = raw.split('.').slice(0, 2).join('.');
            const signature = desanitizeBase64(raw.split('.')[2]);
            const header = JSON.parse(Buffer.from(raw.split('.')[0], 'base64').toString());

            return verify(keyPath, header.alg, message, signature);
        }
    };
}
