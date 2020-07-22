const { describe } = require('tape-plus')
const hypercore = require('hypercore')
const path = require('path')
const fs = require('fs')

const Encoder = require('../')

const { cleanup, tmp } = require('./util')

describe('message encoding', (context) => {
  context('encrypt and decrypt a message', (assert, next) => {
    const key = Encoder.encryptionKey()
    const nonce = Encoder.generateNonce()
    const encoder = Encoder(key, { nonce, valueEncoding: 'utf-8' })

    const encrypted = encoder.encode('Hello World')
    assert.ok(encrypted, 'Encrypts the message')
    assert.ok(encrypted instanceof Buffer, 'Returns a buffer')
    assert.equals(encrypted.length, 'Hello World'.length, 'Ciphertext and plaintext are same length')

    const message = encoder.decode(encrypted)
    assert.same(message, 'Hello World', 'Decrypts the message')
    next()
  })
})

describe('hypercore', (context) => {
  let storage

  context.beforeEach((c) => {
    storage = tmp()
  })

  context('encrypted the log', (assert, next) => {
    const key = Encoder.encryptionKey()
    const nonce = Encoder.generateNonce()
    const encoder = Encoder(key, { nonce, valueEncoding: 'utf-8' })
    const feed = hypercore(storage, { valueEncoding: encoder })

    feed.append('boop', (err) => {
      assert.error(err, 'no error')

      const data = fs.readFileSync(path.join(storage, 'data'))
      assert.notSame(data, 'boop', 'log entry is encrypted')
      assert.same(encoder.decode(data), 'boop', 'log entry is encrypted')

      feed.get(0, (err, entry) => {
        assert.error(err, 'no error')
        assert.same(entry, 'boop', 'hypercore decrypts the message')

        cleanup(storage, next)
      })
    })
  })

  context('encrypted the log, with a json object', (assert, next) => {
    const key = Encoder.encryptionKey()
    const nonce = Encoder.generateNonce()
    const encoder = Encoder(key, { nonce, valueEncoding: 'json' })
    const feed = hypercore(storage, { valueEncoding: encoder })

    const message = { boop: 'beep' }

    feed.append(message, (err) => {
      assert.error(err, 'no error')

      const data = fs.readFileSync(path.join(storage, 'data'))
      assert.notSame(JSON.stringify(data), JSON.stringify(message), 'log entry is encrypted')
      assert.same(JSON.stringify(encoder.decode(data)), JSON.stringify(message), 'log entry is encrypted')

      feed.get(0, (err, entry) => {
        assert.error(err, 'no error')
        assert.same(message, entry, 'hypercore decrypts the message')

        cleanup(storage, next)
      })
    })
  })
})
