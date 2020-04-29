# node-jws-file-provider
GCP Provider for node-jws handling signatures/verification using Google Cloud KMS service.

## Introduction
This is a Provider indended for use with `node-jws` library - allowing for signing and verification of JWS tokens using Google Cloud's KMS service.

## Usage
Use by calling the provider with the key location variables:

```typescript
import JWS from 'node-jws';
import GcpProvider from 'node-jws-gcp-provider';

const provider = new GcpProvider('my-gcp-project', 'global', 'my-keyring', 'my-key', '1');
const jws = new JWS(provider);
```

Where the variables are, in order:

> **project** - Google Cloud project ID

> **location** - Region name for the KMS service

> **keyring** - Name you've given to the keyring created beforehand

> **keyname** - Name of the key itself in KMS

> **version** - Key version, a string with a number
