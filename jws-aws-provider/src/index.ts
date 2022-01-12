import { KMS } from '@aws-sdk/client-kms';
import { sanitizeBase64, desanitizeBase64, KeyProvider, JWTClaims, JWTHeader, JWTAlghoritm } from 'node-jws';

const kms = new KMS({});

async function sign (keyId: string, alg: JWTAlghoritm, message: string): Promise<string> {
    const response = await kms.sign({
        KeyId: keyId,
        Message: Buffer.from(message),
        MessageType: 'RAW',
        SigningAlgorithm: mapAlghoritmToAwsCounterpart(alg)
    });

    return desanitizeBase64(Buffer.from(response.Signature).toString('base64'));
}

async function verify (keyId: string, alg: JWTAlghoritm, message: string, signature: string): Promise<boolean> {
    const response = await kms.verify({
        KeyId: keyId,
        Message: Buffer.from(message),
        MessageType: 'RAW',
        Signature: Buffer.from(signature, 'base64'),
        SigningAlgorithm: mapAlghoritmToAwsCounterpart(alg)
    });

    return response.SignatureValid;
}

function mapAlghoritmToAwsCounterpart (alg: JWTAlghoritm): string {
    switch (alg) {
        case JWTAlghoritm.RS256: return 'RSASSA_PKCS1_V1_5_SHA_256';
        case JWTAlghoritm.RS384: return 'RSASSA_PKCS1_V1_5_SHA_384';
        case JWTAlghoritm.RS512: return 'RSASSA_PKCS1_V1_5_SHA_512';
        case JWTAlghoritm.PS256: return 'RSASSA_PSS_SHA_256';
        case JWTAlghoritm.PS384: return 'RSASSA_PSS_SHA_384';
        case JWTAlghoritm.PS512: return 'RSASSA_PSS_SHA_512';
        case JWTAlghoritm.HS256: throw new Error('HMAC algorithm with SHA-256 is not supported by AWS KMS.');
        case JWTAlghoritm.HS384: throw new Error('HMAC algorithm with SHA-384 is not supported by AWS KMS.');
        case JWTAlghoritm.HS512: throw new Error('HMAC algorithm with SHA-512 is not supported by AWS KMS.');
        case JWTAlghoritm.ES256: return 'ECDSA_SHA_256';
        case JWTAlghoritm.ES384: return 'ECDSA_SHA_384';
        case JWTAlghoritm.ES512: return 'ECDSA_SHA_512';
        case JWTAlghoritm.none: throw new Error('No alghorithm, hash not available.');
        default: throw new Error('Not (fully) supported alghoritm: did not find hash matching it.');
    }
}

export default function AwsKmsKeyProvider (accessKey: string, secretAccessKey: string, region: string, keyId: string): KeyProvider {
    process.env.AWS_ACCESS_KEY_ID = accessKey;
    process.env.AWS_SECRET_ACCESS_KEY = secretAccessKey;
    process.env.AWS_REGION = region;

    return {
        sign: async (claims: JWTClaims, header: JWTHeader) => {
            const rawHeader = sanitizeBase64(Buffer.from(JSON.stringify(header), 'utf8').toString('base64'));
            const rawClaims = sanitizeBase64(Buffer.from(JSON.stringify(claims), 'utf8').toString('base64'));
            const signature = sanitizeBase64(await sign(keyId, header.alg, `${rawHeader}.${rawClaims}`));

            return `${rawHeader}.${rawClaims}.${signature}`;
        },
        valid: async (raw: string) => {
            const message = raw.split('.').slice(0, 2).join('.');
            const signature = desanitizeBase64(raw.split('.')[2]);
            const header = JSON.parse(Buffer.from(raw.split('.')[0], 'base64').toString()) as JWTHeader;

            return verify(keyId, header.alg, message, signature);
        }
    };
}
