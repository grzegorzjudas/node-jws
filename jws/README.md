# node-jws
Json Web Signature library for signing/verifying signatures working natively with cloud

## Introduction
This library provides an easy-to-use interface for creating, signing and validating Json Web Tokens (or rather, Json Web Signatures - JWSes), based on externally provided providers (plug-ins) giving the base library ability to provide the expected functionality using different services (for example, a cloud key management service).

We've prepared a few providers you can use of the box, but nothing stops you from creating your own - it's a simple object with key methods, really. Those providers are separate dependencies, since you're probably only going to use one at a time - so your project won't grow unnecessarily big with not needed dependencies.

## Installation
First, install the base library with:

```bash
npm install node-jws
```

Next, you need at least one provider (here, File Provider as an example):

```bash
npm install node-jws-file-provider
```

## Usage

### Creating new tokens
Take a look at a basic example:
```typescript
import JWS from 'node-jws';
import FileProvider from 'node-jws-file-provider';

const provider = FileProvider('./private.pem', './public.pem');
const token = new JWS(provider);
```

The `FileProvider` is actually a function, which makes it easy to inject configuration to it. It requires two argments, paths to private and public keys (in PEM format). Next, an actual token is being created by injecting the provider to a constructor.

### Modifying the contents
Empty tokens are useless, really, so the first thing we need to do, is to specify what alghoritm is going to be used for signing it.
```typescript
import JWS, { JWTAlghoritm } from 'node-jws';

// ...
token.useAlghoritm(JWTAlghoritm.RS256);
```
in this case, it's an 2048-bit RSA with SHA256 as hashing function. Note that by default, the alghoritm is set to `none`, which is not really a JWS, so it's not supported by this library.

You can now proceed and pass any data to the contents (claims) of the token:
```typescript
token.setClaims({
    email: 'foo@bar.com',
    admin: false
});
```

### Setting metadata
JWS has an ability to keep metadata used to validate it later - such as an expiry time or intended audience. You can read more about them in [RFC7519 section 4.1](https://tools.ietf.org/html/rfc7519#section-4.1). You can set them manually using `setClaims()`, but for ease of use, there are a couple of handy methods as well:

```typescript
jws.issuedBy('bar')
   .intendedFor([ 'foo' ])
   .notValidBefore(new Date())
   .expiresIn(3600);
```
Note that you can also chain the methods, but don't have to, if that's not your thing.

### Signing
When everything's ready, it's time for actual signing. It's as simple as:

```typescript
await jws.sign();
```

If you then want to return the final token:

```typescript
console.log(jws.toString());
```

Keep in mind you won't be able to use `toString()` before signing the token.

### Validating
The token created above is already complete, so if you want to make sure it's valid:

```typescript
const valid = await jws.valid();
```

Will result in true/false, depending on the outcome. But usually, we want to validate a token we got in a string version from some other service. In this case, we can't create a new token manually, but parse it instead:

```typescript
const jws = JWS.fromString(mytokenstring, provider);
const valid = await jws.valid();
```

You can also check for the metadata to make sure it's correct (even if the signature is fine, it could have expired for example).

```typescript
const expired = jws.isExpired();
const correctAudience = jws.isIntendedFor('foo');
```

For all other use cases, you still have access to raw headers and claims:

```typescript
const header = jws.getHeader();
const claims = jws.getClaims();
```

## FAQ

**There is no provider for my cloud**

No worries - you can create it by yourself if you feel like it - see `Contributing` section below for how to do that. Or you can let us know by creating a Feature Request on Github. If it's a popular enough of a service, we may (or some other developer) find time to prepare it.

**If have a custom provider, that I think should be a part of default set of providers**

Great! There are many cloud services, and we didn't have time (yet?) for handling all of them. Fork the repo and create a PR to ours - we'll love to review and approve it!

**I tried using it, but I'm getting errors during signing/validation**

We're still alpha, so there's bound to be issues with some providers and/or alghoritms/hashes. Make sure to create an issue in Github providing all necessary information - what provider, what alghoritm, and so on.

## Contributing Guide

We'd love to see people contribute by extending the functionality and/or adding new providers. This library is written entirely in TypeScript, so it should be easy enough to both extend the `node-jws` and create new providers based on the exisiting ones. Make sure the provider is a function returning object of `KeyProvider` type.

If you're not into TypeScript, make sure that your provider object has two methods:

> **sign(claims, header)** should return a Promise resolved with a base64-encoded signature string

> **valid(token)** should return a Promise resolved with a boolean

Feel free to fork this repository and add new provider to the list (best if you use same file structure and ESLint rules) and open a Pull Request.

## Changelog

All changes are listed on Github under Releases; each release has a changelog in the description.
