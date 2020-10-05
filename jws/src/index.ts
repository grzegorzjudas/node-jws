export enum JWTAlghoritm {
    RS256 = 'RS256',
    RS384 = 'RS384',
    RS512 = 'RS512',
    PS256 = 'PS256',
    PS384 = 'PS384',
    PS512 = 'PS512',
    ES256 = 'ES256',
    ES384 = 'ES384',
    ES512 = 'ES512',
    HS256 = 'HS256',
    HS384 = 'HS384',
    HS512 = 'HS512',
    none = 'none'
}

export type JWTHeader = {
    alg: JWTAlghoritm;
    jku?: string;
    jwk?: string;
    kid?: string;
    x5u?: string;
    x5c?: string[];
    x5t?: string;
    'x5t#S256'?: string;
    typ?: string;
    [k: string]: any;
}

export type JWTClaims = {
    iss?: string;
    sub?: string;
    aud?: string[];
    exp?: number;
    nbf?: number;
    iat?: number;
    jti?: string;
    [k: string]: any;
}

export interface KeyProvider {
    sign(claims: JWTClaims, header: JWTHeader): Promise<string>;
    valid(raw: string): Promise<boolean>;
}

export function sanitizeBase64 (base64: string): string {
    return base64.replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
}

export function desanitizeBase64 (base64: string): string {
    return base64.replace(/=/g, '').replace(/-/g, '+').replace(/_/g, '/');
}

export default class JWS {
    private provider: KeyProvider;

    private header: JWTHeader = { alg: JWTAlghoritm.none };
    private claims: JWTClaims = {};

    private raw: string;

    constructor (provider: KeyProvider) {
        this.provider = provider;
    }

    expiresIn (sec: number): JWS {
        this.claims.exp = Math.floor(Date.now() / 1000) + sec;

        return this;
    }

    expiresAt (date: Date): JWS {
        this.claims.exp = Math.floor(date.getTime() / 1000);

        return this;
    }

    notValidBefore (date: Date): JWS {
        this.claims.nbf = Math.floor(date.getTime() / 1000);

        return this;
    }

    issuedBy (issuer: string): JWS {
        this.claims.iss = issuer;

        return this;
    }

    intendedFor (audience: string | string[]): JWS {
        this.claims.aud = [].concat(audience);

        return this;
    }

    useAlghoritm (alg: JWTAlghoritm): JWS {
        this.header.alg = alg;

        return this;
    }

    isBeforeIssueTime (): boolean {
        if (!this.claims.iat || typeof this.claims.iat !== 'number') return false;

        return this.claims.iat > Math.floor(Date.now() / 1000);
    }

    isExpired (): boolean {
        if (!this.claims.exp || typeof this.claims.exp !== 'number') return false;

        return this.claims.exp <= Math.floor(Date.now() / 1000);
    }

    isIntendedFor (aud: string): boolean {
        if (!this.claims.aud || !Array.isArray(this.claims.aud)) return true;

        return this.claims.aud.includes(aud);
    }

    setHeader (header: JWTHeader): JWS {
        this.header = {
            ...this.header,
            ...header
        };

        return this;
    }

    setClaims (claims: JWTClaims): JWS {
        this.claims = {
            ...this.claims,
            ...claims
        };

        return this;
    }

    setProvider (provider: KeyProvider): void {
        this.provider = provider;
    }

    getHeader (): JWTHeader {
        return this.header;
    }

    getClaims (): JWTClaims {
        return this.claims;
    }

    setRaw (raw: string): void {
        const header = JSON.parse(Buffer.from(raw.split('.')[0], 'base64').toString());
        const claims = JSON.parse(Buffer.from(raw.split('.')[1], 'base64').toString());

        this.claims = claims as JWTClaims;
        this.header = header as JWTHeader;
        this.raw = raw;
    }

    async sign (): Promise<void> {
        if (!this.provider || !this.provider.sign) {
            throw new Error('Invalid provider. Make sure it has a sign() method.');
        }

        const issuedAt = this.claims.iat;

        try {
            this.claims.iat = Math.floor(Date.now() / 1000);
            this.raw = await this.provider.sign(this.claims, this.header);
        } catch (error) {
            this.claims.iat = issuedAt;

            throw error;
        }
    }

    async valid (): Promise<boolean> {
        if (!this.provider || !this.provider.valid) {
            throw new Error('Invalid provider. Make sure it has a valid() method.');
        }

        if (!this.raw) {
            if (this.header.alg !== JWTAlghoritm.none) {
                throw new Error('Cannot verify an unsigned token.');
            }

            return true;
        }

        return this.provider.valid(this.raw);
    }

    toString (): string {
        if (!this.raw) {
            throw new Error('JWS needs to be signed first.');
        }

        return this.raw;
    }

    static fromString (raw: string, provider: KeyProvider): JWS {
        const token = new JWS(provider);

        token.setRaw(raw);

        return token;
    }
}
