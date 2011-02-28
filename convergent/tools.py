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


class CleanupError(Exception):
    pass




def clean_string(s):
    """ returns str from unicode, raises if not str or unicode.
    
    >>> clean_string(u"test")
    'test'
    >>> clean_string("test")
    'test'
    >>> b = clean_string(u'\\xc3\\xa4\\xc3\\xb6\\xc3\\xbc')
    >>> assert b == '\xc3\x83\xc2\xa4\xc3\x83\xc2\xb6\xc3\x83\xc2\xbc'
    """
    if isinstance(s, str):
        return s
    try:
        return s.encode("UTF-8")
    except:
        raise CleanupError("Unicode or string works but not %r." % type(s))

