/*
 * Wire
 * Copyright (C) 2016 Wire Swiss GmbH
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see http://www.gnu.org/licenses/.
 *
 */

'use strict';

const TestStore = require('./TestStore');

const assert_decrypt = (expected, plaintext) => {
  return assert.strictEqual(expected, sodium.to_string(plaintext));
};

describe('Basic functionality', () => {
  const new_store_closure = () => new TestStore();

  const two_boxes = () => {
    return Promise.all([0, 1].map(() => new cryptobox.Cryptobox(new_store_closure())));
  };

  it('can initiate a Cryptobox session', (done) => {
    let alice_cryptobox = null;
    let bob_cryptobox = null;
    let alice_session = null;
    let bob_session = null;
    let plaintext = null;

    return two_boxes().then((boxes) => {
      alice_cryptobox = boxes[0];
      bob_cryptobox = boxes[1];
      return bob_cryptobox.new_prekey(1);
    }).then((bob_serialized_pre_key_bundle) => {
      return alice_cryptobox.session_from_prekey('bob_client_id', bob_serialized_pre_key_bundle);
    }).then((session) => {
      alice_session = session;
      return alice_cryptobox.session_save(alice_session);
    }).then(() => {
      return alice_session.encrypt('Hello Bob!');
    }).then((hello_bob) => {
      return bob_cryptobox.session_from_message('alice', hello_bob);
    }).then((session) => {
      bob_session = session[0];
      plaintext = session[1];
      assert_decrypt('Hello Bob!', plaintext);
      return bob_cryptobox.session_save(bob_session);
    }).then(() => {
      assert(bob_session.fingerprint_local() === alice_session.fingerprint_remote());
      assert(bob_session.fingerprint_remote() === alice_session.fingerprint_local());
      return alice_cryptobox.session_load('bob_client_id');
    }).then((session) => {
      alice_session = session;
      return bob_cryptobox.session_load('alice');
    }).then((session) => {
      bob_session = session;
      assert.isOk(alice_session);
      assert.isOk(bob_session);
      return alice_cryptobox.session_load('unknown');
    }).catch((session) => {
      console.log(session);
      return assert.isNotOk(session);
    }).then(() => done(), (err) => done(err));
  });

  it('preserves pre-keys in case of emergency', (done) => {
    let alice_cryptobox = null;
    let bob_cryptobox = null;
    let alice_session = null;
    let bob_session = null;
    let plaintext = null;
    let hello_bob = null;

    return two_boxes().then((boxes) => {
      alice_cryptobox = boxes[0];
      bob_cryptobox = boxes[1];
      return bob_cryptobox.new_prekey(1);
    }).then((bob_serialized_pre_key_bundle) => {
      return alice_cryptobox.session_from_prekey('bob_client_id', bob_serialized_pre_key_bundle);
    }).then((session) => {
      alice_session = session;
      return alice_cryptobox.session_save(alice_session);
    }).then(() => {
      return alice_session.encrypt('Hello Bob!');
    }).then((msg) => {
      hello_bob = msg;
      return bob_cryptobox.session_from_message('alice', hello_bob);
    }).then((session) => {
      bob_session = session[0];
      plaintext = session[1];

      assert_decrypt('Hello Bob!', plaintext);

      // Pretend something happened before Bob could save his session and he retries.
      // The prekey should not be removed (yet).
      return bob_cryptobox.session_from_message('alice', hello_bob);
    }).then((session) => {
      bob_session = session[0];
      return bob_cryptobox.session_save(bob_session);
    }).then(() => {
      // Now the prekey should be gone
      return bob_cryptobox.session_from_message('alice', hello_bob);
    }).then((e) => {
      return assert.fail('', '', 'session_from_message should have rejected promise');
    }).catch((e) => {
      return assert.instanceOf(e, Proteus.errors.DecryptError.PrekeyNotFound);
    }).then(() => done(), (err) => done(err));
  });

  it('makes use of the last pre-key', (done) => {
    let alice_cryptobox = null;
    let bob_cryptobox = null;
    let alice_session = null;
    let bob_session = null;
    let plaintext = null;
    let hello_bob = null;

    return two_boxes().then((boxes) => {
      alice_cryptobox = boxes[0];
      bob_cryptobox = boxes[1];
      return bob_cryptobox.new_prekey(Proteus.keys.PreKey.MAX_PREKEY_ID);
    }).then((bob_serialized_pre_key_bundle) => {
      return alice_cryptobox.session_from_prekey('bob_client_id', bob_serialized_pre_key_bundle);
    }).then((session) => {
      alice_session = session;
      return alice_cryptobox.session_save(alice_session);
    }).then(() => {
      return alice_session.encrypt('Hello Bob!');
    }).then((msg) => {
      hello_bob = msg;
      return bob_cryptobox.session_from_message('alice', hello_bob);
    }).then((session) => {
      bob_session = session[0];
      plaintext = session[1];
      assert_decrypt('Hello Bob!', plaintext);
      return bob_cryptobox.session_save(bob_session);
    }).then(() => {
      return bob_cryptobox.session_from_message('alice', hello_bob);
    }).then((session) => {
      bob_session = session[0];
      plaintext = session[1];
      return assert_decrypt('Hello Bob!', plaintext);
    }).then(() => done(), (err) => done(err));
  });

  it('handles duplicated messages', (done) => {
    let alice_cryptobox = null;
    let bob_cryptobox = null;
    let alice_session = null;
    let bob_session = null;
    let plaintext = null;
    let hello_bob = null;

    return two_boxes().then((boxes) => {
      alice_cryptobox = boxes[0];
      bob_cryptobox = boxes[1];
      return bob_cryptobox.new_prekey(0);
    }).then((bob_serialized_pre_key_bundle) => {
      return alice_cryptobox.session_from_prekey('bob_client_id', bob_serialized_pre_key_bundle);
    }).then((session) => {
      alice_session = session;
      return alice_cryptobox.session_save(alice_session);
    }).then(() => {
      return alice_session.encrypt('Hello Bob!');
    }).then((msg) => {
      hello_bob = msg;
      return bob_cryptobox.session_from_message('alice', hello_bob);
    }).then((session) => {
      bob_session = session[0];
      plaintext = session[1];
      assert_decrypt('Hello Bob!', plaintext);
      return bob_session.decrypt(hello_bob);
    }).then((msg) => {
      return assert.fail('', '', 'Session.decrypt should throw Proteus.errors.DecryptError.DuplicateMessage');
    }).catch((e) => {
      return assert.instanceOf(e, Proteus.errors.DecryptError.DuplicateMessage);
    }).then(() => done(), (err) => done(err));
  });

  return it('can delete a session', (done) => {
    let alice_cryptobox = null;
    let bob_cryptobox = null;
    let alice_session = null;
    let bob_session = null;
    let plaintext = null;
    let hello_bob = null;

    return two_boxes().then((boxes) => {
      alice_cryptobox = boxes[0];
      bob_cryptobox = boxes[1];
      return bob_cryptobox.new_prekey(0);
    }).then((bob_serialized_pre_key_bundle) => {
      return alice_cryptobox.session_from_prekey('bob_client_id', bob_serialized_pre_key_bundle);
    }).then((session) => {
      alice_session = session;
      return alice_cryptobox.session_save(alice_session);
    }).then(() => {
      return alice_session.encrypt('Hello Bob!');
    }).then((msg) => {
      hello_bob = msg;
      return bob_cryptobox.session_from_message('alice', hello_bob);
    }).then((session) => {
      bob_session = session[0];
      plaintext = session[1];
      assert_decrypt('Hello Bob!', plaintext);
      return alice_cryptobox.session_save(alice_session);
    }).then(() => {
      return alice_cryptobox.session_delete('bob_client_id');
    }).then(() => {
      return alice_cryptobox.session_load('bob_client_id');
    }).then((session) => {
      return assert.isNotOk(session);
    }).then(() => done(), (err) => done(err));
  });
});
