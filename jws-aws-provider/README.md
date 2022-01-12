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
import AwsProvider from 'node-jws-aws-provider';

const provider = new AwsProvider('access-key', 'secret-access-key', 'region', 'key-id');
const jws = new JWS(provider);
```

Where the variables are, in order:

> **access-key** - AWS Access Key ID

> **secret-access-key** - AWS Secret Access Key

> **region** - AWS region (i.e. us-east-1)

> **key-id** - KMS Key ID
