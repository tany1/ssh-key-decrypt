const assert = require('assert');
const fs = require('fs');
const path = require('path');
const t = require('tap');

const decrypt = require('./index.js');

// All the fixtures should decrypt to this key
let unenc = path.resolve(__dirname, 'fixtures', 'id_rsa_unencrypted');
unenc = new Buffer.from(fs.readFileSync(unenc, 'ascii')
  .trim()
  .split('\n')
  .slice(1, -1)
  .join(''), 'base64');

let tests =
  [
    'aes128',
    'aes192',
    'aes256',
    'des3',
    'des'
  ];

tests = tests.map(function (t) {
  return 'enc_' + t + '_asdf';
});

tests.push('unencrypted');

tests.forEach(test);

function test(f) {
  let file;
  let fileData;

  tryThis(function () {
    file = path.resolve(__dirname, 'fixtures', 'id_rsa_' + f);
    fileData = fs.readFileSync(file, 'ascii');
  }, f, 'failed reading test key');

  let data;
  tryThis(function () {
    assert(data = decrypt(fileData, 'asdf'));
    assert(Buffer.isBuffer(data), 'should be buffer');
  }, f, 'failed decryption');

  let hex;
  tryThis(function () {
    assert(hex = decrypt(fileData, 'asdf', 'hex'));
    assert.strictEqual(typeof hex, 'string');
    assert.strictEqual(hex, data.toString('hex'));
  }, f, 'failed hex decryption');

  let base64;
  tryThis(function () {
    assert(base64 = decrypt(fileData, 'asdf', 'base64'));
    assert.strictEqual(typeof base64, 'string');
    assert.strictEqual(base64, data.toString('base64'));
  }, f, 'failed base64 decryption');

  tryThis(function () {
    assert.strictEqual(data.length, unenc.length);
  }, f, 'length differs');

  tryThis(function () {
    for (let i = 0; i < data.length; i++) {
      assert.strictEqual(data[i], unenc[i], 'differs at position ' + i);
    }
  }, f, 'byte check');
}

function tryThis(fn, f, msg) {
  t.test(f, function (t) {
    t.plan(1);
    t.doesNotThrow(fn, msg);
  })
}
