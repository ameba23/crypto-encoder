# crypto-encoder

A simple hypercore-compatible crypto encoder.

## Example

```js
const hypercore = require('hypercore')
const Encoder = require('.')

const encryptionKey = Encoder.encryptionKey()
const nonce = Encoder.generateNonce()
const valueEncoding = Encoder(encrytionKey, { nonce, valueEncoding: 'utf-8' })

const feed = hypercore(storage, { valueEncoding })
```

## API

```js
const Encoder = require('.')
```

```js
const encryptionKey = Encoder.encryptionKey()
```
Generate a random 32 byte key to be used to encrypt.

```js
const nonce = Encoder.generateNonce()
```
Generate a random nonce used to encrypt.

```js
const valueEncoding = Encoder(encryptionKey, opts)
```
Returns a message encoder used for encrypting messages in hypercore. 
- `encryptionKey` must be a buffer of length `Encoder.KEYBYTES`.
- `opts` is an optional object which may contain:
  - `ops.nonce` a buffer containing a 24 byte nonce
  - `opts.valueEncoder`, an additional encoder to be used before encryption. May be one of:
    - The string 'utf-8' - utf-8 encoded strings will be assumed.
    - The string 'JSON' - JSON encoding will be assumed.
    - A custom encoder of the form `{ encode: [function] decode: [function] }`
