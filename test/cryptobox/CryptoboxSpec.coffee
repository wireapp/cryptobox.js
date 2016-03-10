TestStore = require './TestStore'

assert_decrypt = (expected, plaintext) ->
  assert(expected is sodium.to_string(plaintext))

describe 'Basic functionality', ->
  new_store_closure = -> new TestStore

  two_boxes = ->
    return [0..1].map(-> return new cryptobox.Cryptobox new_store_closure())

  it 'can initiate a Cryptobox session', (done) ->
    [alices_cryptobox, bobs_cryptobox] = two_boxes()

    bobs_cryptobox.new_prekey 1
    .then (bobs_serialized_pre_key_bundle) ->
      alices_session_with_bob = alices_cryptobox.session_from_prekey 'bobs_client_id', bobs_serialized_pre_key_bundle
      alices_cryptobox.session_save alices_session_with_bob

      hello_bob = alices_session_with_bob.encrypt 'Hello Bob!'

      [bob_session, plaintext] = bobs_cryptobox.session_from_message 'alice', hello_bob
      assert_decrypt 'Hello Bob!', plaintext
      bobs_cryptobox.session_save bob_session

      assert(bob_session.fingerprint_local() is alices_session_with_bob.fingerprint_remote())
      assert(bob_session.fingerprint_remote() is alices_session_with_bob.fingerprint_local())

      alices_session_with_bob = alices_cryptobox.session_load 'bobs_client_id'
      bob_session = bobs_cryptobox.session_load 'alice'

      assert.isOk(alices_session_with_bob)
      assert.isOk(bob_session)

      assert.isNotOk(alices_cryptobox.session_load 'unknown')
    .then((() -> done()), (err) -> done(err))

  it 'preserves pre-keys in case of emergency', (done) ->
    [alices_cryptobox, bobs_cryptobox] = two_boxes()

    bobs_cryptobox.new_prekey 1
    .then (pk) ->
      alices_session_with_bob = alices_cryptobox.session_from_prekey 'bobs_client_id', pk
      alices_cryptobox.session_save alices_session_with_bob

      hello_bob = alices_session_with_bob.encrypt 'Hello Bob!'

      [bob_session, plaintext] = bobs_cryptobox.session_from_message 'alice', hello_bob
      assert_decrypt 'Hello Bob!', plaintext

      # Pretend something happened before Bob could save his session and he retries.
      # The prekey should not be removed (yet).
      [bob_session, _] = bobs_cryptobox.session_from_message 'alice', hello_bob

      bobs_cryptobox.session_save bob_session
      # Now the prekey should be gone

      assert.throws((-> bobs_cryptobox.session_from_message 'alice', hello_bob),
        Proteus.errors.DecryptError, Proteus.errors.DecryptError::PREKEY_NOT_FOUND)
    .then((() -> done()), (err) -> done(err))

  it 'makes use of the last pre-key', (done) ->
    [alices_cryptobox, bobs_cryptobox] = two_boxes()

    bobs_cryptobox.new_prekey Proteus.keys.PreKey.MAX_PREKEY_ID
    .then (pk) ->
      alices_session_with_bob = alices_cryptobox.session_from_prekey 'bobs_client_id', pk
      alices_cryptobox.session_save alices_session_with_bob

      hello_bob = alices_session_with_bob.encrypt 'Hello Bob!'

      [bob_session, plaintext] = bobs_cryptobox.session_from_message 'alice', hello_bob
      assert_decrypt 'Hello Bob!', plaintext

      bobs_cryptobox.session_save bob_session
      # Bob's last prekey is not removed

      [bob_session, plaintext] = bobs_cryptobox.session_from_message 'alice', hello_bob
      assert_decrypt 'Hello Bob!', plaintext
    .then((() -> done()), (err) -> done(err))

  it 'handles duplicated messages', (done) ->
    [alices_cryptobox, bobs_cryptobox] = two_boxes()

    bobs_cryptobox.new_prekey 0
    .then (pk) ->
      alices_session_with_bob = alices_cryptobox.session_from_prekey 'bobs_client_id', pk

      hello_bob = alices_session_with_bob.encrypt 'Hello Bob!'

      [bob_session, plaintext] = bobs_cryptobox.session_from_message 'alice', hello_bob
      assert_decrypt 'Hello Bob!', plaintext

      assert.throws((-> bob_session.decrypt hello_bob),
        Proteus.errors.DecryptError, Proteus.errors.DecryptError::DUPLICATE_MESSAGE)
    .then((() -> done()), (err) -> done(err))

  it 'can delete a session', (done) ->
    [alices_cryptobox, bobs_cryptobox] = two_boxes()

    bobs_cryptobox.new_prekey 0
    .then (pk) ->
      alices_session_with_bob = alices_cryptobox.session_from_prekey 'bobs_client_id', pk

      hello_bob = alices_session_with_bob.encrypt 'Hello Bob!'

      [bob_session, plaintext] = bobs_cryptobox.session_from_message 'alice', hello_bob
      assert_decrypt 'Hello Bob!', plaintext

      alices_cryptobox.session_save alices_session_with_bob
      alices_cryptobox.session_delete 'bobs_client_id'

      assert.isNotOk(alices_cryptobox.session_load 'bobs_client_id')
    .then((() -> done()), (err) -> done(err))
