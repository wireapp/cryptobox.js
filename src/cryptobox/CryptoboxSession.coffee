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

module.exports = class CryptoboxSession
  ###
  @param id [String] Unique session identifier
  @param pk_store [Proteus.session.PreKeyStore] Pre-key store
  @param session [Proteus.session.Session] Proteus session
  ###
  constructor: (@id, @pk_store, @session) ->
    Object.freeze @

  ###
  @param plaintext [String] Text to be encrypted
  @return [ArrayBuffer] CBOR representation of a message envelope which holds the encrypted text
  ###
  encrypt: (plaintext) ->
    return new Promise (resolve, reject) =>
      @session.encrypt(plaintext)
      .then (ciphertext) ->
        resolve ciphertext.serialise()
      .catch (e) ->
        reject e

  decrypt: (ciphertext) ->
    return new Promise (resolve, reject) =>
      envelope = Proteus.message.Envelope.deserialise ciphertext
      @session.decrypt @pk_store, envelope
      .then (plaintext) ->
        resolve plaintext
      .catch (e) ->
        reject e

  fingerprint_local: ->
    return @session.local_identity.public_key.fingerprint()

  fingerprint_remote: ->
    return @session.remote_identity.fingerprint()
