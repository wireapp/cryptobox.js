module.exports = class TestStore extends cryptobox.CryptoboxStore
  constructor: ->
    @identity = Proteus.keys.IdentityKeyPair.new()
    @sessions = {}
    @prekeys = {}

  load_identity: ->
    return @identity

  save_identity: (identity) ->
    @identity = identity

  load_session: (identity, session_id) ->
    serialised = @sessions[session_id]
    if not serialised
      return undefined

    return Proteus.session.Session.deserialise identity, serialised

  save_session: (session_id, session) ->
    @sessions[session_id] = session.serialise()

  delete_session: (session_id) ->
    delete @sessions[session_id]

  add_prekey: (prekey) ->
    # Proteus.util.TypeUtil.assert_is_instance Proteus.keys.PreKey, prekey

    @prekeys[prekey.key_id] = prekey.serialise()
    return new Promise (resolve, reject) => resolve true

  load_prekey: (prekey_id) ->
    serialised = @prekeys[prekey_id]
    if not serialised
      return undefined

    return Proteus.keys.PreKey.deserialise serialised

  delete_prekey: (prekey_id) ->
    delete @prekeys[prekey_id]
