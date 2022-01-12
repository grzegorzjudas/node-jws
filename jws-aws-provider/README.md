# node-jws-file-provider
AWS Provider for node-jws handling of signatures/verification using Amazon Web Services KMS service.

## Introduction
This is a Provider indended for use with `node-jws` library - allowing for signing and verification of JWS tokens using AWS's KMS service.

## Installation
First, install the base library with:

```bash
npm install node-jws-aws-provider
```

## Usage
Use by calling the provider with the key location variables:

```typescript
import JWS from 'node-jws';
import AwsProvider from 'node-jws-gcp-provider';

const provider = new AwsProvider('my-aws-project', 'global', 'my-keyring', 'my-key', '1');
const jws = new JWS(provider);
```

Where the variables are, in order:

> **project** - AWS project ID

> **location** - Region name for the KMS service

> **keyring** - Name you've given to the keyring created beforehand

> **keyname** - Name of the key itself in KMS

> **version** - Key version, a string with a number
