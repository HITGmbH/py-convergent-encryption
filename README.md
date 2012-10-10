# Convergent Encryption Overview [![Build Status](https://secure.travis-ci.org/HITGmbH/py-convergent-encryption.png)](http://travis-ci.org/HITGmbH/py-convergent-encryption)

This module implements convergent encryption and generation of an id derived
from the plaintext.


# Requirements

This module depends on the availability of either [pycryptopp][] or
[pycrypto][] as provider of the AES-256 block cipher. This dependency must be
resolved manually. By default it uses pycryptopp (as that seemed to be a bit
faster in our tests) and falls back to pycrypto if the first one is not
available.


# Usage and API

## convergent.SHA256d

SHA-256 extension against length-extension-attacks as defined by Schneier and Fergusson. Basically just `sha256(sha256(data))`

    >>> from convergent import SHA256d
    >>> s = SHA256d()
    >>> s.update("Lorem ipsum dolor sit amet")
    >>> s.digest()
    "\xa1\xdbyA\x04\xf5\xa6S'1\xe7\xa0\xf3\xfd9\x07y2\xa3\xb9x\xcc\x9e%\x0f %\x9d\xa9\x00\xda\xd4"
    >>> s.hexdigest()
    'a1db794104f5a6532731e7a0f3fd39077932a3b978cc9e250f20259da900dad4'


## convergent.ConvergentEncryption

Convergent encryption using SHA256d and AES-256 CTR with added security and
block id generation for deduplicated content addressable storage.

Example encrypting the lorem ipsum[^1]:

    >>> from convergent import ConvergentEncryption
    >>> c1 = ConvergentEncryption("hard to guess secret")
    >>> key, blockid, ciphertext = c1.encrypt(lorem)
    >>> len(lorem) == len(ciphertext)
    True
    >>> c2 = ConvergentEncryption()
    >>> plain_text = c2.decrypt(key, ciphertext)
    >>> plain_text == lorem
    True

### convergent.ConvergentEncryption(secret, warn)

`secret`: an optional secret string that guards against confirmation-of-a-file
attack and learn-partial-information attack. The secret is **not needed** for
successfull decryption but only to verify if the decryption process was
successfull.

`warn`: True by default, sends a warning message to the logging system if no
secret was given. Only one log message per process is logged.

### convergent.ConvergentEncryption.set_convergence_secret(secret)

`secret`: See `secret` above. Used to set the secret if the class is used as a
mix-in. The secret can only be set once.

Returns nothing

Raises convergent.CryptError if the secret was already set.


### convergent.ConvergentEncryption.encrypt(data)

Encrypts the string `data`.

Returns a tuple of three: the encryption key (needed for decryption), a block
id and the encrypted data.

### convergent.ConvergentEncryption.decrypt(key, ciphertext, verify=False)

Decrypts the ciphertext using `key`. If verify is true and the convergence
secret was set the decrypted plain text is verified and convergent.CryptError
raised if the decryption process was not successfull.


### convergent.encrypt_key(key, nonce, data)

Convenience function. En- or decrypts data using a one time key calculated
from `key` and `nonce`.

`Nonce` may become publicly known but must only be used once or else the
system becomes insecure.

Example:

    >>> import os, convergent
    >>> nonce = os.urandom(32).encode("hex")
    >>> ciphertext = convergent.encrypt_key("password", nonce,
                                            "this is totally secret data")
    >>> ciphertext == "this is totally secret data"
    False
    >>> plain_text = convergent.encrypt_key("password", nonce, ciphertext)
    >>> plain_text == "this is totally secret data"
    True

[^1]: without line breaks: "Lorem ipsum dolor sit amet, consectetur
adipisicing elit, sed do eiusmod tempor incididunt ut labore et dolore magna
aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris
nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in
reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur.
Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia
deserunt mollit anim id est laborum."


# Cryptographic Details

## SHA256d

The output of SHA256(data) (32 Bytes) are again fed into SHA256. The resulting
32 Bytes are used as a cryptographic hash.

## Convergent Encryption and deduplicated storage

Convergent encryptions uses the cryptographic hash of the plaintext as the
encryption key so that identical plaintexts always encrypt to identical
ciphertext values as it always uses identical encryption keys.

This implementation uses SHA256d as a cryptographic hash function and AES-256 in Counter (CTR) mode as a block cipher.

By applying a cryptographic hash function to the encryption key a storage id
may be constructed that when used in an addressing schema allows the
construction of efficiently used encrypted storage as identical blocks resolve
to the same id.

As of now (02/2011) at least two weaknesses of this encryption schema are
known: [confirmation-of-a-file attack and learn-partial-information
attack][attacks1]. Both can be adverted by mixing a secret value into the
encryption key.

This module works as follows, the additional secret and the merge step are
optional:

![Convergent Encryption Schema](py-convergent-encryption/raw/master/Documentation/CE-Schema.png)

Where `secret` is a random string of at least 32 Bytes and `append` is
technically implemented by first updating an initialized SHA256d object with
the plain text and second with the secret.


# Changelog

* 0.2 2011-02-28 Public release
* 0.1 Initial version

# LICENSE

    Copyright (c) 2011, HIT Information-Control GmbH
    All rights reserved.

    Redistribution and use in source and binary forms, with or without
    modification, are permitted provided that the following conditions are
    met:

    * Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.

    * Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in the
      documentation and/or other materials provided with the distribution.

    * Neither the name of the HIT Information-Control GmbH nor the names of
      its contributors may be used to endorse or promote products derived from
      this software without specific prior written permission.

    THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
    IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
    THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
    PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL HIT Information-Control GmbH BE
    LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
    CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
    SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
    INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
    CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
    ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
    POSSIBILITY OF SUCH DAMAGE.

[attacks1]: http://www.mail-archive.com/cryptography@metzdowd.com/msg08949.html
[pycrypto]: http://pypi.python.org/pypi/pycrypto
[pycryptopp]: http://pypi.python.org/pypi/pycryptopp
