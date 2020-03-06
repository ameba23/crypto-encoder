const { describe } = require('tape-plus')
const hypercore = require('hypercore')
const path = require('path')
const fs = require('fs')
const sodium = require('sodium-native')

const secretBoxEncoder = require('../')
const chacha20Encoder = require('../cha20stream')

const { cleanup, tmp } = require('./util')
describe('secretbox', (context) => {
  let storage

  context.beforeEach((c) => {
    storage = tmp()
  })

  context('encrypt and decrypt a message', (assert, next) => {
    const key = secretBoxEncoder.encryptionKey()
    const encoder = secretBoxEncoder(key, { valueEncoding: 'utf-8' })

    const encrypted = encoder.encode('Hello World')
    assert.ok(encrypted, 'Encrypts the message')
    assert.ok(encrypted instanceof Buffer, 'Returns a buffer')

    const message = encoder.decode(encrypted)
    assert.same(message, 'Hello World', 'Decrypts the message')
    next()
  })

  context('hypercore - encrypts the log', (assert, next) => {
    const key = secretBoxEncoder.encryptionKey()
    const encoder = secretBoxEncoder(key, { valueEncoding: 'utf-8' })
    const feed = hypercore(storage, { valueEncoding: encoder })

    feed.append('boop', (err) => {
      assert.error(err, 'no error')

      var data = fs.readFileSync(path.join(storage, 'data'))
      assert.notSame(data, 'boop', 'log entry is encrypted')
      assert.same(encoder.decode(data), 'boop', 'log entry is encrypted')

      feed.get(0, (err, entry) => {
        assert.error(err, 'no error')
        assert.same('boop', entry, 'hypercore decrypts the message')

        cleanup(storage, next)
      })
    })
  })

  context('hypercore - encrypts the log, using JSON encoding', (assert, next) => {
    const key = secretBoxEncoder.encryptionKey()
    const encoder = secretBoxEncoder(key, { valueEncoding: 'json' })
    const feed = hypercore(storage, { valueEncoding: encoder })

    const message = { boop: 'beep' }

    feed.append(message, (err) => {
      assert.error(err, 'no error')

      feed.get(0, (err, entry) => {
        assert.error(err, 'no error')
        assert.same(message.boop, entry.boop, 'hypercore decrypts the message')

        cleanup(storage, next)
      })
    })
  })

  context('hypercore - encrypt 100 megabytes of data, in 64kb blocks', (assert, next) => {
    const key = secretBoxEncoder.encryptionKey()
    const encoder = secretBoxEncoder(key)
    const feed = hypercore(storage, { valueEncoding: encoder })
    feed.on('ready', () => {
      const block = Buffer.alloc(65536)

      let i = 0
      const start = Date.now()
      addBlock()

      function addBlock () {
        sodium.randombytes_buf(block)
        feed.append(block, (err) => {
          if (err) throw err
          i++
          if (i < 1600) {
            addBlock()
          } else {
            done()
          }
        })
      }
      function done () {
        const end = Date.now()

        console.log(feed.length, feed.byteLength / (1024 * 1024))
        console.log(`Time taken to encrypt ${end - start} ms`)

        const startRead = Date.now()
        const readStream = feed.createReadStream()
        readStream.on('data', (chunk) => {
        })
        readStream.on('end', () => {
          const endRead = Date.now()
          console.log(`Time taken to decrypt ${endRead - startRead} ms`)
          cleanup(storage, next)
        })
      }
    })
  })
})

describe('crypto_stream_chacha20_XOR_instance', (context) => {
  let storage

  context.beforeEach((c) => {
    storage = tmp()
  })

  context('encrypt and decrypt a message', (assert, next) => {
    const key = chacha20Encoder.encryptionKey()
    const encoder1 = chacha20Encoder(key, { valueEncoding: 'utf-8' })
    const encoder2 = chacha20Encoder(key, { valueEncoding: 'utf-8', nonce: encoder1.nonce })

    const encrypted = encoder1.encode('Hello World')
    assert.ok(encrypted, 'Encrypts the message')
    assert.ok(encrypted instanceof Buffer, 'Returns a buffer')

    const message = encoder2.decode(encrypted)
    assert.same(message, 'Hello World', 'Decrypts the message')
    next()
  })

  context('hypercore - encrypt the log - binary encoding', (assert, next) => {
    const key = chacha20Encoder.encryptionKey()
    const encoder = chacha20Encoder(key)
    const testEncoder = chacha20Encoder(key, { nonce: encoder.nonce })
    const feed = hypercore(storage, { valueEncoding: encoder })

    const message = Buffer.from('boop beep beep boop')

    feed.append(message, (err) => {
      assert.error(err, 'no error')

      var data = fs.readFileSync(path.join(storage, 'data'))
      assert.notSame(data.toString(), message.toString(), 'log entry is encrypted')
      assert.same(testEncoder.decode(data).toString(), message.toString(), 'log entry is encrypted')

      feed.get(0, (err, entry) => {
        assert.error(err, 'no error')
        assert.same(entry.toString(), message.toString(), 'hypercore decrypts the message')

        cleanup(storage, next)
      })
    })
  })
  context('hypercore - encrypt the log - utf-8 encoding', (assert, next) => {
    const key = chacha20Encoder.encryptionKey()
    const encoder = chacha20Encoder(key, { valueEncoding: 'utf-8' })
    const testEncoder = chacha20Encoder(key, { valueEncoding: 'utf-8', nonce: encoder.nonce })
    const feed = hypercore(storage, { valueEncoding: encoder })

    feed.append('boop', (err) => {
      assert.error(err, 'no error')

      var data = fs.readFileSync(path.join(storage, 'data'))
      assert.notSame(data, 'boop', 'log entry is encrypted')
      assert.same(testEncoder.decode(data), 'boop', 'log entry is encrypted')

      feed.get(0, (err, entry) => {
        assert.error(err, 'no error')
        assert.same('boop', entry, 'hypercore decrypts the message')

        cleanup(storage, next)
      })
    })
  })

  context('hypercore - encrypt the log - json encoding', (assert, next) => {
    const key = chacha20Encoder.encryptionKey()
    const encoder = chacha20Encoder(key, { valueEncoding: 'json' })
    const testEncoder = chacha20Encoder(key, { valueEncoding: 'json', nonce: encoder.nonce })
    const feed = hypercore(storage, { valueEncoding: encoder })

    const message = { boop: 'beep' }

    feed.append(message, (err) => {
      assert.error(err, 'no error')

      const data = fs.readFileSync(path.join(storage, 'data'))
      assert.notSame(data.toString(), JSON.stringify(message), 'log entry is unreadable')
      const plain = testEncoder.decode(data)
      assert.same(JSON.stringify(plain), JSON.stringify(message), 'log entry is encrypted')

      feed.get(0, (err, entry) => {
        assert.error(err, 'no error on read entry')
        assert.same(message.boop, entry.boop, 'hypercore decrypts the message')

        cleanup(storage, next)
      })
    })
  })

  context('hypercore - encrypt 100 megabytes of data, in 64kb blocks', (assert, next) => {
    const key = chacha20Encoder.encryptionKey()
    const encoder = chacha20Encoder(key)
    const feed = hypercore(storage, { valueEncoding: encoder })
    feed.on('ready', () => {
      const block = Buffer.alloc(65536)

      let i = 0
      const start = Date.now()
      addBlock()

      function addBlock () {
        sodium.randombytes_buf(block)
        feed.append(block, (err) => {
          if (err) throw err
          i++
          if (i < 1600) {
            addBlock()
          } else {
            done()
          }
        })
      }
      function done () {
        const end = Date.now()

        console.log(feed.length, feed.byteLength / (1024 * 1024))
        console.log(`Time taken to encrypt ${end - start} ms`)

        const startRead = Date.now()
        const readStream = feed.createReadStream()
        readStream.on('data', (chunk) => {
        })
        readStream.on('end', () => {
          const endRead = Date.now()
          console.log(`Time taken to decrypt ${endRead - startRead} ms`)
          cleanup(storage, next)
        })
      }
    })
  })
})
