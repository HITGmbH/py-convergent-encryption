#  Copyright (c) 2011, HIT Information-Control GmbH
#  All rights reserved.
#
#  Redistribution and use in source and binary forms, with or
#  without modification, are permitted provided that the following
#  conditions are met:
#
#      * Redistributions of source code must retain the above
#        copyright notice, this list of conditions and the following
#        disclaimer.
#
#      * Redistributions in binary form must reproduce the above
#        copyright notice, this list of conditions and the following
#        disclaimer in the documentation and/or other materials
#        provided with the distribution.
#
#      * Neither the name of the HIT Information-Control GmbH nor the names of its
#        contributors may be used to endorse or promote products
#        derived from this software without specific prior written
#        permission.
#
#  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND
#  CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
#  INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
#  MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
#  DISCLAIMED. IN NO EVENT SHALL HIT Information-Control GmbH BE
#  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
#  OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
#  PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA,
#  OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
#  THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR
#  TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
#  OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY
#  OF SUCH DAMAGE.


"""
creates and updates crypto- and weak hashes. Operates on blocks of data.
"""

from hashlib import sha256
from tools import clean_string
import struct
import logging


class HashError(Exception):
    pass

class CryptError(HashError):
    pass

log = logging.getLogger("convergent")


KByte = 1024
MByte = KByte * 1024

try:
    # use either pycryptopp
    from pycryptopp.cipher.aes import AES
except ImportError:
    # or use PyCrypto 
    from Crypto.Cipher import AES


class Counter(object):
    """ 16 Byte binary counter
    
    Example:
        c = Counter()
        c() => \00 * 16
        c() => \00...01
    """
    
    def __init__(self, a=0, b=0, c=0, d=0):
        self.a = a
        self.b = b
        self.c = c
        self.d = d
        
    first = True
    def __call__(self):
        if self.first:
            self.first = False
        else:
            if self.d < 0xFFFFFFFF:
                self.d += 1                     # increment byte 0
            elif self.c < 0xFFFFFFFF:
                self.c += 1                     # increment byte 1
                self.d = 0                      # reset byte 0
            elif self.b < 0xFFFFFFFF:
                self.b += 1                     # increment byte 2
                self.c = self.d = 0             # reset bytes 0 and 1
            elif self.a < 0xFFFFFFFF:
                self.a += 1                     # increment byte 3 
                self.b = self.c = self.d = 0    # reset bytes 0, 1, 2
        return struct.pack(">4L", self.a, self.b, self.c, self.d)


def aes(key, data, counter=False):
    """ encrypt data with aes, using either pycryptopp or PyCrypto.
        Args
            key: The encryption key
            data: plain text data
            counter: a callable, usually not needed
    """
    # using either pycryptopp...
    if hasattr(AES, "process"):
        a = AES(key)
        return a.process(data)
    # ... or PyCrypto
    counter = counter or Counter()
    a = AES.new(key, AES.MODE_CTR, counter=counter)
    rest = len(data) % 16
    if not rest:
        return a.encrypt(data)
    # Data length must be a multiple of 16
    # Pad with bytes all of the same value as the number of padding bytes
    pad = (16 - rest)
    data += chr(pad) * pad
    return a.encrypt(data)[:-pad]


class SHA256d(object):
    """ implements SHA-265d against length-extensions-attacks
        as defined by Schneier and Fergusson
    """
    
    def __init__(self, data=None, truncate_to=None):
        """ SHA-265d against length-extensions-attacks
            with optional truncation of the hash

        Args:
            data: Initial string, optional
            truncate_to: length to truncate the hash to, optional
        """
        self.h = sha256()
        self.truncate_to = truncate_to
        if data:
            self.h.update(data)
    
    def update(self, data):
        assert(isinstance(data, str))
        self.h.update(data)

    def digest(self):
        if not hasattr(self,"_digest"):
            self._digest = sha256(self.h.digest()).digest()[:self.truncate_to]
            del self.h
        return self._digest
    
    def hexdigest(self):
        return self.digest().encode('hex')
    

class ConvergentEncryption(object):
    """ provides convergent encryption and decryption

        This class provides convergent en-/decryption and provides
        a block id that can calculated from the encryption key.
        This class can be either used stand alone or as a mix-in.

        Attributes
            info: describes the cryptographic hash and the block
                  cipher algorithms used
    """

    info = "Digest: SHA-256d, Enc-Algo: AES 256 CTR"
    __convergence_secret = None

    def __init__(self, secret=None, warn=True):
        """ initializes a ConvergentEncryption object

            Args
                secret: string, optional, to defeat confirmation-of-a-file attack
                warn: bool, default: True, log a warning if no secret was given

        """
        if secret:
            self.set_convergence_secret(secret)
        if not warn:
            self.__warn_convergence(warn=False)

    def set_convergence_secret(self, secret):
        """ sets the secret used to defeat confirmation-of-a-file attack
        """
        secret = clean_string(secret)
        if self.__convergence_secret and self.__convergence_secret != secret:
            msg = "Do not change the convergence secret during encryption!"
            raise CryptError(msg)
        self.__convergence_secret = secret
    
    @classmethod
    def __warn_convergence(cls, warn=True):
        """ Utter this warning only once per system run"""
        if not hasattr(cls, "warned") and warn:
            msg = "No convergence secret, some information may leak."
            log.warning(msg)
        cls.warned = True

    def __sec_key(self, data):
        """ returns secret key and block id

            Args
                data: string
        """
        h = SHA256d(data)
        if not self.__convergence_secret:
            self.__warn_convergence()
        else:
            h.update(self.__convergence_secret)
        key = h.digest()
        del h
        id = SHA256d(key).digest()
        return key, id
    
    def encrypt(self, data):
        """ encrypt data with convergence encryption.

            Args
                data: str, the plain text to be encrypted
        
            Returns
                key: hash(block), encryption key
                id: hash(hash(block), block ID
                ciphertext: enc(key, block)
        """
        assert(isinstance(data, str))
        key, id = self.__sec_key(data)
        return key, id, aes(key, data)
    
    def decrypt(self, key, ciphertext, verify=False):
        """ decrypt data with convergence encryption.
        
            Args
                key: str, encryption key
                cipher: str, ciphertext
                verify: bool, verify decrypted data, default: False
        
            Returns
                the plain text
        """
        plain = aes(key, ciphertext)
        if verify:
            h = SHA256d(plain)
            if self.__convergence_secret:
                h.update(self.__convergence_secret)
            digest = h.digest()
            # can verify only if convergence secret is known!
            if self.__convergence_secret and not key == digest:
                msg = "Block verification error on %s." % SHA256d(key).hexdigest()
                log.error(msg)
                raise CryptError(msg)
        return plain


def encrypt_key(key, nonce, data):
    """ use "key" and "nonce" to generate a one time key and en-/decrypt
        "data" with the one time key.

        Args
            key: encryption key
            nounce: exactly once used string (try a time-based UUID)
            data: the encrypted data
        Returns
            ciphertext: AES256 encrypted data
    """

    key = clean_string(key)
    key = SHA256d(key).digest()
    nonce_hash = SHA256d(nonce).digest()# assert 32 bytes key
    enc_key = aes(key, nonce_hash)      # generate encryption key
    return aes(enc_key, data)           # encrypt data using the new key
