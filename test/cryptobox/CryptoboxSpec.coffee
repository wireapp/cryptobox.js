TestStore = require './TestStore'

assert_decrypt = (expected, plaintext) ->
  assert(expected is sodium.to_string(plaintext))

describe 'Basic functionality', ->
  new_store_closure = -> new TestStore

  two_boxes = ->
    return Promise.all [0..1].map(-> return new cryptobox.Cryptobox new_store_closure())

  it 'can initiate a Cryptobox session', (done) ->
    alice_cryptobox = null
    bob_cryptobox = null
    alice_session = null
    bob_session = null
    plaintext = null

    two_boxes()
    .then (boxes) ->
      [alice_cryptobox, bob_cryptobox] = boxes
      bob_cryptobox.new_prekey 1

    .then (bob_serialized_pre_key_bundle) ->
      alice_cryptobox.session_from_prekey 'bob_client_id', bob_serialized_pre_key_bundle

    .then (session) ->
      alice_session = session
      alice_cryptobox.session_save alice_session

    .then ->
      alice_session.encrypt 'Hello Bob!'

    .then (hello_bob) ->
      bob_cryptobox.session_from_message 'alice', hello_bob

    .then (session) ->
      [bob_session, plaintext] = session

      assert_decrypt 'Hello Bob!', plaintext
      bob_cryptobox.session_save bob_session

    .then ->
      assert(bob_session.fingerprint_local() is alice_session.fingerprint_remote())
      assert(bob_session.fingerprint_remote() is alice_session.fingerprint_local())

      alice_cryptobox.session_load 'bob_client_id'

    .then (session) ->
      alice_session = session
      bob_cryptobox.session_load 'alice'

    .then (session) ->
      bob_session = session

      assert.isOk(alice_session)
      assert.isOk(bob_session)

      alice_cryptobox.session_load 'unknown'

    .catch (session) ->
      assert.isNotOk(session)

    .then((() -> done()), (err) -> done(err))

  it 'preserves pre-keys in case of emergency', (done) ->
    alice_cryptobox = null
    bob_cryptobox = null
    alice_session = null
    bob_session = null
    plaintext = null
    hello_bob = null

    two_boxes()
    .then (boxes) ->
      [alice_cryptobox, bob_cryptobox] = boxes
      bob_cryptobox.new_prekey 1

    .then (bob_serialized_pre_key_bundle) ->
      alice_cryptobox.session_from_prekey 'bob_client_id', bob_serialized_pre_key_bundle

    .then (session) ->
      alice_session = session
      alice_cryptobox.session_save alice_session

    .then ->
      alice_session.encrypt 'Hello Bob!'

    .then (msg) ->
      hello_bob = msg
      bob_cryptobox.session_from_message 'alice', hello_bob

    .then (session) ->
      [bob_session, plaintext] = session

      assert_decrypt 'Hello Bob!', plaintext

      # Pretend something happened before Bob could save his session and he retries.
      # The prekey should not be removed (yet).
      bob_cryptobox.session_from_message 'alice', hello_bob

    .then (session) ->
      bob_session = session[0]

      bob_cryptobox.session_save bob_session

      # Now the prekey should be gone
      bob_cryptobox.session_from_message 'alice', hello_bob

    .then (e) ->
      assert.fail '', '', 'session_from_message should have rejected promise'

    .catch (e) ->
      assert.instanceOf e, Proteus.errors.DecryptError.PrekeyNotFound

    .then((() -> done()), (err) -> done(err))

  it 'makes use of the last pre-key', (done) ->
    alice_cryptobox = null
    bob_cryptobox = null
    alice_session = null
    bob_session = null
    plaintext = null
    hello_bob = null

    two_boxes()
    .then (boxes) ->
      [alice_cryptobox, bob_cryptobox] = boxes
      bob_cryptobox.new_prekey Proteus.keys.PreKey.MAX_PREKEY_ID

    .then (bob_serialized_pre_key_bundle) ->
      alice_cryptobox.session_from_prekey 'bob_client_id', bob_serialized_pre_key_bundle

    .then (session) ->
      alice_session = session
      alice_cryptobox.session_save alice_session

    .then ->
      alice_session.encrypt 'Hello Bob!'

    .then (msg) ->
      hello_bob = msg
      bob_cryptobox.session_from_message 'alice', hello_bob

    .then (session) ->
      [bob_session, plaintext] = session

      assert_decrypt 'Hello Bob!', plaintext
      bob_cryptobox.session_save bob_session

      # Bob's last prekey is not removed
      bob_cryptobox.session_from_message 'alice', hello_bob

    .then (session) ->
      [bob_session, plaintext] = session
      assert_decrypt 'Hello Bob!', plaintext

    .then((() -> done()), (err) -> done(err))

  it 'handles duplicated messages', (done) ->
    alice_cryptobox = null
    bob_cryptobox = null
    alice_session = null
    bob_session = null
    plaintext = null
    hello_bob = null

    two_boxes()
    .then (boxes) ->
      [alice_cryptobox, bob_cryptobox] = boxes
      bob_cryptobox.new_prekey 0

    .then (bob_serialized_pre_key_bundle) ->
      alice_cryptobox.session_from_prekey 'bob_client_id', bob_serialized_pre_key_bundle

    .then (session) ->
      alice_session = session
      alice_cryptobox.session_save alice_session

    .then ->
      alice_session.encrypt 'Hello Bob!'

    .then (msg) ->
      hello_bob = msg
      bob_cryptobox.session_from_message 'alice', hello_bob

    .then (session) ->
      [bob_session, plaintext] = session

      assert_decrypt 'Hello Bob!', plaintext

      bob_session.decrypt hello_bob

    .then (msg) ->
      assert.fail '', '', 'Session.decrypt should throw Proteus.errors.DecryptError.DuplicateMessage'

    .catch (e) ->
      assert.instanceOf e, Proteus.errors.DecryptError.DuplicateMessage

    .then((() -> done()), (err) -> done(err))

  it 'can delete a session', (done) ->
    alice_cryptobox = null
    bob_cryptobox = null
    alice_session = null
    bob_session = null
    plaintext = null
    hello_bob = null

    two_boxes()
    .then (boxes) ->
      [alice_cryptobox, bob_cryptobox] = boxes
      bob_cryptobox.new_prekey 0

    .then (bob_serialized_pre_key_bundle) ->
      alice_cryptobox.session_from_prekey 'bob_client_id', bob_serialized_pre_key_bundle

    .then (session) ->
      alice_session = session
      alice_cryptobox.session_save alice_session

    .then ->
      alice_session.encrypt 'Hello Bob!'

    .then (msg) ->
      hello_bob = msg
      bob_cryptobox.session_from_message 'alice', hello_bob

    .then (session) ->
      [bob_session, plaintext] = session

      assert_decrypt 'Hello Bob!', plaintext
      alice_cryptobox.session_save alice_session

    .then ->
      alice_cryptobox.session_delete 'bob_client_id'

    .then ->
      alice_cryptobox.session_load 'bob_client_id'

    .then (session) ->
      assert.isNotOk session

    .then((() -> done()), (err) -> done(err))
