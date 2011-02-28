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


import tempfile
import shutil
import os
import hashlib
import logging
import unittest
from convergent import crypto

log = logging.getLogger("convergent.test_hashes")

# some generic strings
STRINGS = ("\x00", "\x01", "\xFF", "\x00"*15, 
           "\x00\xFF"*20, "test"*1024, "\xFF"*23)



class SHA256dHashTestCase(unittest.TestCase):
    
    def setUp(self):
        self.hex = "f5a1f608f4cd6abaf52e716739a68bc83b0e91872c1f70916e59756ea122f047"

    def test_sha256d_wo_initial_data(self):
        h = crypto.SHA256d()
        h.update("test test 123")
        h.update("test test 345")
        self.assertEqual(h.hexdigest(), self.hex)
    
    def test_sha256d_with_initial_data(self):
        h = crypto.SHA256d("test test 123")
        h.update("test test 345")
        self.assertEqual(h.hexdigest(), self.hex)
        
    def test_sha256d_cache(self):
        h = crypto.SHA256d("test test 123test test 345")
        void = h.digest() #@UnusedVariable
        self.assertEqual(h.hexdigest(), self.hex)


class CounterTestCase(unittest.TestCase):

    def test_Counter(self):
        c = crypto.Counter()
        for x in range(300):
            c()
        self.assertEqual(c(), "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01,")



class AESTestCase(unittest.TestCase):
    
    #
    # NIST TESTVEKTOREN AES256CTR (SP800-38A)
    #
    key = "\x60\x3d\xeb\x10\x15\xca\x71\xbe\x2b\x73\xae\xf0\x85\x7d\x77\x81\x1f\x35\x2c\x07\x3b\x61\x08\xd7\x2d\x98\x10\xa3\x09\x14\xdf\xf4"
    c = (0xf0f1f2f3, 0xf4f5f6f7, 0xf8f9fafb, 0xfcfdfeff)
    plain = ("\x6b\xc1\xbe\xe2\x2e\x40\x9f\x96\xe9\x3d\x7e\x11\x73\x93\x17\x2a"
             "\xae\x2d\x8a\x57\x1e\x03\xac\x9c\x9e\xb7\x6f\xac\x45\xaf\x8e\x51"
             "\x30\xc8\x1c\x46\xa3\x5c\xe4\x11\xe5\xfb\xc1\x19\x1a\x0a\x52\xef"
             "\xf6\x9f\x24\x45\xdf\x4f\x9b\x17\xad\x2b\x41\x7b\xe6\x6c\x37\x10")
    cipher = ("`\x1e\xc3\x13wW\x89\xa5\xb7\xa7\xf5\x04\xbb\xf3\xd2(\xf4C\xe3"
              "\xcaMb\xb5\x9a\xca\x84\xe9\x90\xca\xca\xf5\xc5+\t0\xda\xa2="
              "\xe9L\xe8p\x17\xba-\x84\x98\x8d\xdf\xc9\xc5\x8d\xb6z\xad\xa6"
              "\x13\xc2\xdd\x08EyA\xa6")
    def test_1_nist_crypto(self):
        """ 1.: testing PyCrypto, using the NIST test vectors."""
        # test using Crypto.Cipher.AES
        counter = crypto.Counter(*self.c)
        from Crypto.Cipher import AES as aes_cc
        crypto.AES = aes_cc
        self.assertEquals(self.cipher, crypto.aes(self.key, self.plain,
                                                  counter=counter))
        #
        # we can't test using pycryptopp.cipher.aes
        # since the counter of PyCryptoPP can't be set
        #
    
    def test_2_self_cryptopp(self):
        """ 2.: testing CryptoPP using PyCrypto..."""
        # generate a cipher string using nist plaintext BUT counter start at "\x00"*16
        # Crypto.Cipher.AES shoud work okay, since tested with NIST test vectors
        from Crypto.Cipher import AES as aes_cc
        crypto.AES = aes_cc
        counter = crypto.Counter()
        cipher0 = crypto.aes(self.key, self.plain, counter=counter)
        # testing PyCryptoPP, not as well as Crypto.Cipher.AES
        # but well... better that not at all I  guess
        from pycryptopp.cipher.aes import AES as aes_pp #@UnresolvedImport
        crypto.AES = aes_pp
        self.assertEquals(cipher0, crypto.aes(self.key, self.plain))
    
    def test_3_padding_and_compatibility(self):
        """ 3.: en- and decryption using CryptoPP and PyCrypto with """
        strings = STRINGS
        
        from pycryptopp.cipher.aes import AES as aes_pp #@UnresolvedImport
        from Crypto.Cipher import AES as aes_cc
        for s in strings:
            # testing encryption
            #
            crypto.AES = aes_cc     # monkey-patch Crypto.Cipher.AES
            counter = crypto.Counter()
            cipher0 = crypto.aes(self.key, s, counter=counter)
            # using pycryptopp.cipher.aes
            crypto.AES = aes_pp     # monkey-patch pycryptopp.cipher.aes.AES
            cipher1 = crypto.aes(self.key, s)
            self.assertEquals(cipher0, cipher1)
            #
            # testing decryption
            plain1 = crypto.aes(self.key, cipher0) # still using pycryptopp.cipher.aes.AES
            crypto.AES = aes_cc     # monkey-patch Crypto.Cipher.AES
            counter = crypto.Counter()
            plain0 = crypto.aes(self.key, cipher0, counter=counter)
            self.assertEquals(plain0, plain1)
            

class ConvergentEncryptionTestBase(crypto.ConvergentEncryption):

    def test_set_convergence_secret(self):
        c1 = self.encrypt("test123")
        self.set_convergence_secret("B"*5)
        c2 = self.encrypt("test123")
        self.assertNotEqual(c1, c2)

    def test_encrypt_decrypt(self):
        for data in self.strings:
            skey, pkey, crypted = self.encrypt(data)
            self.assertNotEquals(data, crypted)
            plain = self.decrypt(skey, crypted, verify=True)
            self.assertEqual(data, plain)
    
    def test_encrypt_error(self):
        for data in self.strangelings:
            self.assertRaises(AssertionError, self.encrypt, data)

    def test_encrypt_decrypt_with_convergence(self):
        for plaintext in self.strings:
            self.set_convergence_secret("B"*5)
            skey, pkey, crypted = self.encrypt(plaintext)
            self.assertNotEquals(plaintext, crypted)
            decrypted = self.decrypt(skey, crypted, verify=True)
            self.assertEqual(plaintext, decrypted)
    
    def test_convergence(self):
        without_convergence = []    # (key, cyphertext), ...
        for plaintext in self.strings:
            skey, pkey, crypted = self.encrypt(plaintext)
            without_convergence.append((skey, crypted))
        self.set_convergence_secret("B"*5)
        with_convergence = []       # (key, cyphertext), ...
        for plaintext in self.strings:
            skey, pkey, crypted = self.encrypt(plaintext)
            with_convergence.append((skey, crypted))
        for w, wo in zip(with_convergence, without_convergence):
            self.assertTrue(w[0] != wo[0])    # key must not be equal
            self.assertTrue(w[1] != wo[1])  # cyphertext must not be equal
            
    def test_process_key(self):
        cyphertext = crypto.encrypt_key("test123", "nounce", "my_sec.key")
        plaintext = crypto.encrypt_key("test123", "nounce", cyphertext)
        self.assertEqual(plaintext, "my_sec.key")



from pycryptopp.cipher.aes import AES as aes_pp
crypto.AES = aes_pp
class ConvergentEncryptionPyCryptoPPTestCase(unittest.TestCase, ConvergentEncryptionTestBase):
    """ConvergentEncryption TestCase using pycryptopp."""
    def setUp(self):
        self.strings = STRINGS
        self.strangelings = (1, 0x12, False)

from Crypto.Cipher import AES as aes_cc
crypto.AES = aes_cc
class ConvergentEncryptionPyCryptoTestCase(unittest.TestCase, ConvergentEncryptionTestBase):
    """ConvergentEncryption TestCase using PyCrypto"""
    def setUp(self):
        self.strings = STRINGS
        self.strangelings = (1, 0x12, False)


