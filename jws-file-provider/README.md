# node-jws-file-provider
File Provider for node-jws handling signatures/verification using file-based keys.

## Introduction
This is a Provider indended for use with `node-jws` library - allowing for signing and verification of JWS tokens using keys stored in file system.

## Installation
First, install the base library with:

```bash
npm install node-jws-file-provider
```

## Usage
Use by calling the provider with two arguments: paths to a private and public keys (in PEM format):

```typescript
import JWS from 'node-jws';
import FileProvider from 'node-jws-file-provider';

const provider = new FileProvider('./private.pem', './public.pem');
const jws = new JWS(provider);
```
