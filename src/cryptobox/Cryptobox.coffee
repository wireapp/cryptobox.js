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

Proteus = require 'proteus'

CryptoboxStore = require './CryptoboxStore'
CryptoboxSession = require './CryptoboxSession'

class ReadOnlyStore extends Proteus.session.PreKeyStore
  constructor: (@store) ->
    @removed_prekeys = []

  get_prekey: (prekey_id) ->
      if @removed_prekeys.indexOf(prekey_id) isnt -1
        return new Promise (resolve, reject) ->
          resolve null
      return @store.load_prekey prekey_id

  remove: (prekey_id) ->
    return new Promise (resolve, reject) =>
      @removed_prekeys.push prekey_id
      resolve()

module.exports = class Cryptobox
  constructor: (@store) ->
    # XXX: no access to proteus internal funcs, replace with typescript annotation
    # Proteus.util.TypeUtil.assert_is_instance cryptobox.CryptoboxStore, @store

    @identity = @store.load_identity()

    if not @identity
      @identity = Proteus.keys.IdentityKeyPair.new()
      @store.save_identity @identity

    Object.freeze @

  ###
  @param client_id [String] Client ID
  @param pre_key_bundle [ArrayBuffer] Serialized Pre-Key Bundle
  ###
  session_from_prekey: (client_id, pre_key_bundle) ->
    bundle = Proteus.keys.PreKeyBundle.deserialise pre_key_bundle
    pk_store = new ReadOnlyStore @store
    session = Proteus.session.Session.init_from_prekey @identity, bundle
    return new CryptoboxSession client_id, pk_store, session

  session_from_message: (session_id, envelope) ->
    env = Proteus.message.Envelope.deserialise envelope
    pk_store = new ReadOnlyStore @store
    [session, plaintext] = Proteus.session.Session.init_from_message @identity, pk_store, env
    return [new CryptoboxSession(session_id, pk_store, session), plaintext]

  session_load: (session_id) ->
    session = @store.load_session @identity, session_id
    if not session
      return null

    pk_store = new ReadOnlyStore @store
    return new cryptobox.CryptoboxSession session_id, pk_store, session

  session_save: (session) ->
    @store.save_session session.id, session.session

    for pk in session.pk_store.removed_prekeys
      @store.delete_prekey pk

  session_delete: (session_id) ->
    @store.delete_session session_id

  new_prekey: (prekey_id) ->
    return new Promise (resolve, reject) =>
      pk = Proteus.keys.PreKey.new prekey_id
      @store.add_prekey pk
      .then =>
        resolve Proteus.keys.PreKeyBundle.new(@identity.public_key, pk).serialise()
      .catch (error) ->
        reject error
