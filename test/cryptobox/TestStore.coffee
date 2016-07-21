#
# Wire
# Copyright (C) 2016 Wire Swiss GmbH
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see http://www.gnu.org/licenses/.
#

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
