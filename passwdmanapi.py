# -*- coding: utf-8 -*-
copywrong = """
Copyright (c) 2013, 2014, Oskar Skog <oskar.skog.finland@gmail.com>
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1.  Redistributions of source code must retain the above copyright notice,
    this list of conditions and the following disclaimer.

2.  Redistributions in binary form must reproduce the above copyright notice,
    this list of conditions and the following disclaimer in the documentation
    and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE."""

__doc__ = """
passwdmanapi - functions and classes used by passwdman

    Python 2/3 compatibility functions
    ----------------------------------
    is_anystr(x)
    is_bytestr(x)
    is_unicodestr(x)
    u(x)
    b(x)
    is_int(x)
    is_num(x)
    
    Classes
    -------
    passwd(common_data)
    honeypot(common_data)
    common_data()               Internally used.
    
    RNGs
    ----
    get10(length)               Internally used.
    get64(length)               Internally used.
    getint(a, b)                Internally used.
    randomize(method, minlength, maxlength)
    
    Misc.
    -----
    open_rng()                  Internally used.
    unquote(x)
    undo(passwdobj,honeypotobj)
    redo(passwdobj,honeypotobj)
    ckmkdir(d)                  Internally used. Not in man-page.
    ckmkfile(f, content)        Internally used. Not in man-page.
    ope = os.path.expanduser    Internally used. Not in man-page.

    Progress-bar
    ------------
    class progress_bar()
    no_pb()
    no_pb_f()                   Internally used.

    Exceptions
    ----------
    err_norandom(Exception)
    err_nolength(Exception)
    err_loaderr(Exception)
    err_notfound(Exception)
    err_duplicate(Exception)
    err_idiot(Exception)
    err_nometa(Exception)

    NOTES
    -----
    What I call strings is really:
    
        - Python 2:     unicode
        - Python 3:     str
        
    The `pb`-keyword argument, seen in lots of functions, expects a
    `progress_bar`-object.

"""

import xml.etree.ElementTree as XML
import os.path
import time
import logging
import string
import sys
import locale
import fcntl

class err_norandom(Exception):
    """class err_norandom(Exception)
    Cannot open '/dev/random', cannot open '/dev/urandom'.
    """
    pass

class err_nolength(Exception):
    """class err_nolength(Exception) - Invalid length (get10()
    or get64()).
    """
    pass

class err_loaderr(Exception):
    """class err_loaderr(Exception) - Failure to load data file (XML)."""
    pass

class err_notfound(Exception):
    """class err_notfound(Exception)
    The record in object.data cannot be found."""
    pass

class err_duplicate(Exception):
    """class err_duplicate(Exception)
    The value to be added already exist in object.data."""
    pass

class err_idiot(Exception):
    """class err_idiot(Exception) - Incorrect usage."""
    pass

class err_nometa(Exception):
    """class err_nometa(Exception) - Meta-data is required."""
    pass

def is_int(x):
    """is_int(x) = True, False (is x int or long)"""
    if isinstance(x, int):
        return True
    v, f, f, f, f = sys.version_info
    if v == 2:
        return isinstance(x, long)
    return False

def is_num(x):
    """is_num(x) = True, False (is x a number)"""
    return is_int(x) or isinstance(x, float)
    
def is_bytestr(x):
    """is_bytestr(x) = True, False (is x encoded/bytes)"""
    v, f, f, f, f = sys.version_info
    if v == 2:
        return isinstance(x, str)
    else:
        return isinstance(x, bytes)

def is_unicodestr(x):
    """is_unicodestr(x) = True, False (is x decoded/unicode)"""
    v, f, f, f, f = sys.version_info
    if v == 2:
        return isinstance(x, unicode)
    else:
        return isinstance(x, str)

def is_anystr(x):
    """is_anystr(x) = True, False (is x any kind of string)"""
    if isinstance(x, str):
        return True
    v, f, f, f, f = sys.version_info
    if v == 2:
        return isinstance(x, unicode)
    else:
        return isinstance(x, bytes)

def u(x):
    """u(x) return a unicode/decoded string"""
    assert is_anystr(x)
    if not is_unicodestr(x):
        return x.decode(code)
    else:
        return x

def b(x):
    """b(x) return a byte/encoded string"""
    assert is_anystr(x)
    if not is_bytestr(x):
        return x.encode(code)
    else:
        return x

def b2u3(x):
    """b2u3(x)
    b(x) if Python 2.x
    u(x) if Python 3.x
    """
    v, f, f, f, f = sys.version_info
    if v == 2:
        return b(x)
    else:
        return u(x)

ope = os.path.expanduser

def no_pb_f(percent, data):
    """no_pb_f(percent, data)
    The actual function used by a progress bar created by `no_pb`.
    """
    pass

def no_pb():
    """no_pb()
    Return an invisible progress_bar.
    """
    return progress_bar(0.0, 100.0, no_pb_f, None)
    
def open_rng():
    """open_rng() - Open random(4) or urandom(4), returns an open file.
ERRORS
    err_norandom(Exception)           Cannot open random(4) or urandom.
    """
    # Open /dev/urandom if /dev/random cannot be opened.
    try:
        f = open('/dev/random', 'rb')
    except:
        try:
            f = open('/dev/urandom', 'rb')
        except:
            raise err_norandom('Cannot open "/dev/random" or "/dev/urandom".')
    return f

def get64(length, pb=None):
    """get64(length)
    Returns a random string containing A-Z a-z 0-9 underscore and
    exclamation mark, with the length `length`.
ERRORS
    err_nolength(Exception)             Invalid `length`.
    err_norandom                        open_rng()
    """
    # rng        The random number generator '/dev/random'.
    # passwd     The password to be returned.
    # number     Integer used as a buffer/pipe between rng and passwd.
    # bits       The amount of bits left in 'number'.
    if not is_int(length):   # Check type.
        raise err_idiot('get64 called with non-integer length.')
    logging.info("get64: length={0}".format(length))
    if length < 1:
        raise err_nolength('get64 called with length < 1.')
    if pb is None:
        pb = no_pb()
    letters=("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef" +
            "ghijklmnopqrstuvwxyz0123456789!_")
    passwd, bits, number = '', 0, 0
    rng = open_rng()
    while len(passwd) < length: # Main loop.
        if bits < 6:
            logging.info("get64: Need more random bits.")
            number |= ord(rng.read(1)) << bits # Prepend the bits in number
                                               # with a random byte.
            # Progress bar.
            pb.progress(float(len(passwd))/float(length) * 100.0)
            bits += 8
        passwd += letters[number % 64] # Use 6 bits to pick a letter and...
                                       # ...append.
        number >>= 6
        bits -= 6
        
        logging.info("get64: Added char {0}/{1}.".format(len(passwd), length))
    rng.close()
    del letters, bits, number, rng
    return u(passwd)

def get10(length, pb=None):
    """get10(length)
    Returns a random string containing 0-9, with the length `length`.
    Raises the same exceptions as get64().
    """
    # rng        The random number generator '/dev/random'.
    # passwd     The password to be returned.
    # number     Integer used as a buffer/pipe between rng and passwd.
    # bits       The amount of bits left in 'number'.
    if not is_int(length):   # Check type.
        raise err_nolength('get10 called with non-integer length.')
    logging.info("get10: length={0}".format(length))
    if length < 1:
        raise err_nolength('get10 called with length < 1.')
    if pb is None:
        pb = no_pb()
    passwd, bits, number = '', 0, 0
    rng = open_rng()
    while len(passwd) < length:    # Main loop.
        if bits < 4:
            # Prepend the bits in `number` with a random byte.
            logging.info("get10: Need more random bits.")
            number |= ord(rng.read(1)) << bits
            bits += 8
        if (number%16) < 10:
            # I don't want 0...5 to occur more frequently than 6...9.
            passwd += chr(number%16 + 48) # digits ASCII
            # Progress bar.
            pb.progress(float(len(passwd))/float(length) * 100.0)
            logging.info(
                "get10: Added char {0}/{1}.".format(len(passwd), length))
        else:
            logging.info("get10: Bad nibble.")
        number >>= 4 # Next nibble.
        bits -= 4
    rng.close()
    del rng, bits, number
    return u(passwd)

def getint(a, b, pb=None):
    """getint(a, b)
    Return random integer with value a from `a` to `b` - 1.
    """
    assert is_int(a) and is_int(b)
    if b <= a:
        raise err_nolength("b <= a")
    if pb is None:
        pb = no_pb()
    rng = open_rng()
    reqbits = bits = number = smallnum = 0
    while (1 << reqbits) < (b - a):
        reqbits += 1            # How many bits are required?
    number = b-a + 1          # Force loop.
    while number >= (b - a):    # Get a number in range.
        logging.info("getint: Getting number...")
        bits = number = 0
        while bits < reqbits:   # Need more.
            if (reqbits - bits) < 8:    # Prepend a few bits.
                smallnum = ord(rng.read(1))             # Get byte.
                smallnum %= 1<<(reqbits - bits)       # Remove overflow bits.
                number |= smallnum << bits              # Prepend.
            else:                       # Prepend a whole byte.
                number |= ord(rng.read(1)) << bits
            pb.progress(float(bits)/float(reqbits) * 100.0)   # Progress bar.
            bits += 8
    rng.close()
    return number + a

def unquote(x):
    """unquote(x) - Returns `x` without surrounding quotes.
    
    >>> #This is Python 3.x
    >>> import passwdmanapi as api
    >>> api.unquote('\t"Hello, world!"  ')
    'Hello, world!'
    >>> api.unquote('        "Good bye cruel world!')
    '        "Good bye cruel world!'
    >>> api.unquote('foobar')
    'foobar'
    >>> api.unquote("'foobar'")
    'foobar'
    """
    assert is_unicodestr(x)
    the_output, the_input = "", []
    for c in x:
        the_input.append(c)
    
    while True:         # Skip all the whitespace.
        try:
            c = the_input.pop(0)
        except:
            return x
        if not c in string.whitespace:
            if c in "'\"":      # First quote.
                quote = c
                break
            return x            # Not quoted.
    
    while True:         # Quoted string.
        try:
            c = the_input.pop(0)
        except:
            return x    # String with a quote inside.
        if c == quote:
            break       # Possible end of string.
        the_output += c
    
    while True:         # Skip the tail.
        try:
            c = the_input.pop(0)
        except:
            return the_output   # Done.
        if not c in string.whitespace:
            return x            # Bad tail.

def randomize(method, minlength, maxlength, pb=None):
    """randomize(method, minlength, maxlength)
    Return random string with a length >= `minlength` and
        <= `maxlength`.
    `method`:
        - "10" -> use get10()
        - "64" -> use get64()
    """
    assert is_int(minlength) and is_int(maxlength)
    assert is_anystr(method)
    if pb is not None:
        getint_pb = pb.minibar(0.0, 10.0)
        get6410_pb = pb.minibar(10.0, 100.0)
    else:
        getint_pb = get6410_pb = None
    length = getint(minlength, maxlength+1, getint_pb)
    # Even the length should be randomized.
    if method == "10":
        return get10(length, get6410_pb)
    elif method == "64":
        return get64(length, get6410_pb)
    else:
        raise err_nometa("weird 'method'")

class progress_bar():
    """class progress_bar()
    
    pb = progress_bar(start=0.0, stop=100.0, function, data=None)
    pb.progress(percent)
    pb2 = pb.minibar(start, stop)
    brain_dead_object = no_pb()
    brain_dead_object.progress(percent)
    brain_dead_object2 = brain_dead_object.minibar(start, stop)
    
    Methods
    -------
        
        - progress(percent)
        - minibar(start, stop)
    
    start, stop and percent are floating point numbers in the range 0...100.
    """
    def __init__(self, start, stop, function, data=None):
        """__init__(self, start, stop, function, data=None)
        All values are float.
        The values are internally in the range 0...1.
        They are externally in the range 0...100.
        
        `start` and `stop` is where 0% and 100% really is.
        
        `function` is the function used to show progress.
        `function` is ``function(percent, data)``.
        `function`'s `percent` is the total progress in the range
        0...100.
        `function`'s `data` is the `progress_bar`-object's `data`.
        `data` defaults to None and can be whatever you want.
        """
        self.start = start/100.0
        self.stop = stop/100.0
        self.function = function
        self.data = data
        # Full range.
        self.full = self.stop - self.start
    def progress(self, percent):
        """progress(self, percent)
        `percent` is in the range 0...100.
        Show progress inside `self`'s range.
        """
        if percent < 0.0:
            percent = 0.0
        if percent > 100.0:
            percent = 100.0
        real_percent = self.start  +  (percent/100.0 * self.full)
        self.function(real_percent*100.0, self.data)
    def minibar(self, start, stop):
        """progress_bar.minibar(self, start, stop)
        
        A progress-bar that is a part of another (the parent)
        progress-bar.
        
        `start` and `stop` is where local-0% and local-100% is in the
        parent.
        
        >>> import passwdmanapi as api
        >>> def simple_progress(percent, data):
        ...     print(percent)
        ... 
        >>> pb = progress_bar(0.0, 100.0, simple_progress)
        >>> pb.progress(0.0)
        0.0
        >>> pb.progress(50.0)
        50.0
        >>> pb.progress(100.0)
        100.0
        >>> minipb = pb.minibar(50.0, 100.0)
        >>> minipb.progress(0.0)
        50.0
        >>> minipb.progress(50.0)
        75.0
        >>> minipb.progress(100.0)
        100.0
        """
        start /= 100.0
        stop /= 100.0
        return progress_bar(
            (self.start + start*self.full) * 100.0,
            (self.start + stop*self.full) * 100.0,
            self.function,
            self.data)

class common_data():
    """class common_data():
    
    `xmlfile` is a path.
    All classes based on common_data are list-like with legs.
    
    __init__(self, xmlfile, make_backups=True)
    
    Variables
    ---------
    self.index                  integer; __iter__ and __next__
    self.data                   list
    self.xmltree                `xmlfile` is loaded into this.
    self.xmlroot                The <root> tag.
    self.make_backups           bool; will `writexml` generate a backup
                                in '~/.passwdman/undoable/'.
    
    Methods
    -------
    __iter__
    __getitem__
    __next__ = next
    remove(x, xmlfile, element_name, attrib_name, is_numstring)
    writexml(xmlfile, pb=None)
    """
    def __init__(self, xmlfile, make_backups=True):
        """__init__(self, xmlfile)
        This function is called by passwd.__init__ and honeypot.__init__ and
        creates variables they both have. It loads them from the
        path xmlfile -> self.xmltree -> self.xmlroot.
        """
        #    ~/.passwdman/passwords or ~/.passwdman/honeypots
        assert is_anystr(xmlfile)
        self.data = []
        self.index = 0
        self.make_backups = make_backups
        try:
            parser = XML.XMLParser(encoding="UTF-8")
        except:
            parser = XML.XMLParser() # Above will fail with Python 2.6.
        self.xmltree = XML.parse(ope(xmlfile), parser)
        self.xmlroot = self.xmltree.getroot()
        # Sanity checking...
        # Root tag.
        if self.xmlroot.tag != "root":
            raise err_loaderr(
                  "root element is not 'root' in '{0}'".format(xmlfile))
        # Magic.
        if self.xmlroot.attrib["magic"] != "passwdman":
            raise err_loaderr("incorrect magic in '{0}'".format(xmlfile))
        # Version.
        version = self.xmlroot.attrib["version"].split('.', 2)
        if int(version[0]) != 0:
            raise err_loaderr("version too new in '{0}'".format(xmlfile))
        if int(version[1]) > 1:
            logging.warning("High version number '{0}' in '{1}'".format(
                             self.xmlroot.attrib["version"], xmlfile))
        # Passwords/honey pots.
        # The attribute "file" should have the value <basename of xmlfile>.
        if self.xmlroot.attrib["file"] != os.path.basename(xmlfile):
            raise err_loaderr("incorrect file magic in '{0}'".format(xmlfile))
        logging.info("'{0}' is successfully loaded".format(xmlfile))
    def __iter__(self):
        self.index = 0
        return self
    def __next__(self):
        if self.index < len(self.data):
            self.index += 1
            return self.data[self.index - 1]
        else:
            raise StopIteration
    def next(self):
        return self.__next__()
    def __getitem__(self, i):
        return self.data[i]
    def __len__(self):
        return len(self.data)
    def remove(self, x, xmlfile, element_name, attrib_name, is_numstring):
        """remove(self, x, xmlfile, element_name, attrib_name, is_numstring)
        `x` is an integer used as an index xor a string. It can also be
        a stringed integer.
        
        It removes `x` from the file `xmlfile` and `self.data`.
        It looks for a match in self.xmltree in the attribute
        `attrib_name` in the tags `element_name`
        .
        is_numstring == True:
            `x` is a string of digits, not an integer.
        
        Set is_numstring to True if `x` is NOT an index!
        
        Raises err_notfound.
        
        Example (from passwd.remove)
        ----------------------------
        
        common_data.remove(self, x, "~/.passwdman/passwords", "passwd",
                                                        "name", is_numstring)
        
        """
        assert is_anystr(attrib_name) and is_anystr(element_name)
        assert is_anystr(xmlfile)
        
        if not is_numstring:
            try:
                x = int(x)  # Is it a stringed integer?
            except:
                pass
        
        if is_int(x):
            y = 0
            for z in self.xmlroot.findall(element_name):
                # Loop through the XML.
                if x == y: # y is the index.
                    del self.data[y]
                    self.xmlroot.remove(z)
                    common_data.writexml(self, xmlfile)
                    return
                else:
                    y += 1   # Try next.
            raise err_notfound("Not found.")
        elif is_unicodestr(x):
            y = 0
            for z in self.xmlroot.findall(element_name):
                # Loop through the XML
                if z.attrib[attrib_name] == x:  # Check for a match.
                    del self.data[y]
                    self.xmlroot.remove(z)
                    common_data.writexml(self, xmlfile)
                    return
                else:
                    y += 1
            raise err_notfound("not found")
        else:
            raise err_notfound("not integer and not unicode-string")
    def writexml(self, xmlfile, pb=None):
        """writexml(self, xmlfile)
        
        Write the XML tree (self.xmltree) to `xmlfile`.
        It will add a backup to '~/.passwdman/undoable/' if
        `self.make_backups` is True."""
        assert is_anystr(xmlfile)
        self.xmlroot.text = "\n  "      # Make it look better.
        self.xmlroot.tail = "\n"
        if self.make_backups:
            # Make backup.
            os.rename(ope(xmlfile),
                    os.path.join(ope("~/.passwdman/undoable"),
                            os.path.basename(xmlfile) + '-' + time.ctime()))
            if pb is not None:
                pb.progress(50.0)
        try:
            self.xmltree.write(ope(xmlfile), encoding="UTF-8",
                                                    xml_declaration=True)
        except:         # For Python 2.6.
            self.xmltree.write(ope(xmlfile), encoding="UTF-8")
        if pb is not None:
            pb.progress(100.0)
    def __del__(self):
        """Used by undo() and redo(). Make sure the object is 0xdeadbeef."""
        del self.data
        del self.index
        del self.xmlroot
        del self.xmltree
    def __repr__(self):
        return "<passwdmanapi.common_data object with id {0}>".format(
                                                                id(self))

class passwd(common_data):
    """passwd(common_data) - The passwords.
    All classes based on common_data are list-like with legs.
    __init__(self, backups=True)
    With `backups`=True changes can be undone.
    
    Methods (including those from common_data)
    ------------------------------------------
    add(name, value, m_type, m_minlength, m_maxlength, pb=None)
    add_nometa(name, value)
    remove(x, is_numstring=False)
    mkindex(x, is_numstring=False)
    update(index, pb=None)
    update_meta(index, m_type, m_minlength, m_maxlength, pb=None)
    __iter__
    next = __next__
    __len__
    __getitem__
    
    `passwd`'s entries are dicts
    ----------------------------
    
        - 'name'        What is the password for.
        - 'value'       The password.
        - 'meta'        A dict inside a dict.  The keys are needed for
                        (re)`randomize`ing the password.  See `add` and
                        `update`  The password's meta-data.
                        
                - 'minlength'   Minimal required length for the
                                password.  Use int() on this.
                - 'maxlength'   Maximal allowed length for the
                                password.  Use int() on this.
                - 'type'        String; Allowed characters in the
                                password.  For :method:`update`.
                
                        - '10'          Digits only.
                        - '64'          A-Z, a-z, '_', '!'
                        - 'human'       It was human-generated. The
                                        password should have 0 as
                                        minlength and maxlength.
                                        
    Internals
    ---------
    xmltree     A 'xml.etree.ElementTree.ElementTree'.
    xmlroot     A 'xml.etree.ElementTree.Element'. The 'root' tag.
    writexml()  Not so well hidden method inherited from common_data.
    """
    def __init__(self, backups=True):
        common_data.__init__(self, "~/.passwdman/passwords", backups)
        for passwd_element in self.xmlroot.findall("passwd"): # Get the data.
            meta_element = passwd_element.find("meta")
            # Got the tags/elements.
            if meta_element is not None:
                meta_attrib = {
                    "minlength": int(meta_element.attrib["minlength"]),
                    "maxlength": int(meta_element.attrib["maxlength"]),
                    "type": meta_element.attrib["type"]
                }
            else:
                # The meta tag is optional.
                # This is the magic dictionary.
                meta_attrib = {
                    "minlength": 0,
                    "maxlength": 0,
                    "type": "human"
                } 
            # Got the meta attributes.
            self.data.append({
                "name": passwd_element.attrib["name"],
                "value": passwd_element.attrib["value"],
                "meta": meta_attrib
            })
    def add(self, name, value, m_type, m_minlength, m_maxlength, pb=None):
        assert is_unicodestr(name)
        assert is_unicodestr(value) or value is None
        assert is_anystr(m_type)
        """add(self, name, value, m_type, m_minlength, m_maxlength)
        
        Add the password for `name` with the value `value`.  If `value`
        is None then the password will be `randomize`d.
        
        `m_type`
        ------
        
            - "human"   The password is some human generated password.
                        Cannot be `randomize`d.
            - "10"      It only contains digits.
            - "64"      It contains A-Z, a-z, 0-9, underscore and
                        exclamation mark.
        
        `m_minlength` is the minimum length required for the password.
        `m_maxlength` is the maximum length allowed for the password.
        
        Raises err_duplicate if the password for `name` already exist.
        """
        if is_int(m_minlength):
            m_minlength = str(m_minlength)
        if is_int(m_maxlength):
            m_maxlength = str(m_maxlength)
        assert is_anystr(m_minlength) and is_anystr(m_maxlength)
        forget = int(m_minlength)   # Raise an exception if not a number.
        forget = int(m_maxlength)   # Raise an exception if not a number.
        if pb is None:
            pb = no_pb()
        
        for x in self.data: # Check for duplicates.
            if x["name"] == name:
                raise err_duplicate(
                    "passwd.add_nometa(name='{0}') #duplicate".format(value))
        pb.progress(5.0)
        if value is None:
            value = randomize(m_type, int(m_minlength), int(m_maxlength),
                                                    pb.minibar(5.0, 90.0))
        self.data.append({
            "name": name,
            "value": value,
            "meta": {
                "type": m_type,
                "minlength": m_minlength,
                "maxlength": m_maxlength
                }
            })
         
        # Add new tags.
        passwd_element = XML.SubElement(self.xmlroot, "passwd")
        passwd_element.text = "\n    "  # Make them look better.
        passwd_element.tail = "\n  "
        meta_element = XML.SubElement(passwd_element, "meta")
        meta_element.tail = "\n  "
        
        # Attributes.
        passwd_element.set("name", name)
        passwd_element.set("value", value)
        meta_element.set("type", m_type)
        meta_element.set("minlength", m_minlength)
        meta_element.set("maxlength", m_maxlength)
        
        pb.progress(95.0)
        common_data.writexml(self, "~/.passwdman/passwords")
        pb.progress(100.0)
    def add_nometa(self, name, value):
        """add_nometa(self, name, value)
        ``self.add(name, value, "human", 0, 0)``
        Add a password without meta-data.
        """
        assert is_unicodestr(name) and is_unicodestr(value)
        for x in self.data: # Check for duplicates.
            if x["name"] == name:
                raise err_duplicate(
                    "passwd.add_nometa(name='{0}') #duplicate".format(value))
        self.data.append({
            "name": name,
            "value": value,
            "meta": {
                "type": "human",
                "minlength": 0,
                "maxlength": 0
                }
            })
        passwd_element = XML.SubElement(self.xmlroot, "passwd")
        passwd_element.tail = "\n  "
        passwd_element.set("name", name) #Attributes.
        passwd_element.set("value", value)
        common_data.writexml(self, "~/.passwdman/passwords")
    def remove(self, x, is_numstring=False):
        """remove(self, x, is_numstring=False)
        Remove the password `x`.
        `x` is an integer used as an index for `self.data` xor a string
        xor a stringed integer (index).
        `x` is what the password is for, not the value.
        Set is_numstring to True if x is a string containing only
        digits, but is NOT an index!
        """
        common_data.remove(self, x, "~/.passwdman/passwords", "passwd",
                                                    "name", is_numstring)
    def mkindex(self, x, is_numstring=False):
        """mkindex(self, x, is_numstring=False)
        Return the index of the password for `x`.
        `x` is either an integer=index, a string to find xor a stringed
        integer.
        Set is_numstring to True if x is a string containing only
        digits, but is NOT an index!
        """
        index = 0
        try:
            if not is_numstring:
                index = int(x)      # That was very simple.
            else:
                raise
        except:
            assert is_unicodestr(x)
            for y in self:      # Find it.
                if y["name"] == x:
                    return index
                index += 1
            raise err_notfound("")
        return index
    def update(self, index, pb=None):
        """update(self, index)
        Update the password at index, use its meta-data to know how.
        """
        assert is_int(index)
        if index >= len(self) or index < 0:
            raise err_notfound("index out of range")
        try:
            minlength = int(self[index]['meta']['minlength'])
            maxlength = int(self[index]['meta']['maxlength'])
        except:
            raise err_idiot("INTEGERS")
        method = self[index]["meta"]["type"]
        if method == "human":   # It would probably work with get64, but
            raise err_nometa(   # it will need a check for a meta-element and
                                # might need to create one.
                              # Use update_meta() to force specific meta-data.
                  "Don't know how to update a human-generated password.")
        if pb is None:
            pb = no_pb()
        new = self[index]["value"] = randomize(method, minlength, maxlength,
                                                    pb.minibar(0.0, 90.0))
        # Write the new password to the passwd file.
        counter = 0
        for element in self.xmlroot.findall("passwd"):
            if counter == index:    #Incremented enough?
                element.set("value", new)
                break
            counter += 1
            pb.progress(90.0  +  (counter+1.0) / (index+1.0) * 5.0)
        common_data.writexml(self, "~/.passwdman/passwords",
                                                    pb.minibar(95.0, 100.0))
    def update_meta(self, index, m_type, m_minlength, m_maxlength, pb=None):
        """update_meta(self, index, m_type, m_minlength, m_maxlength)
        Update the password at index and its meta data.
        """
        assert is_anystr(m_type)
        assert is_int(index)
        if index >= len(self) or index < 0:
            raise err_notfound("index out of range")
        try:
            minlength = int(m_minlength)
            maxlength = int(m_maxlength)
        except:
            raise err_idiot("INTEGERS")
        if pb is None:
            pb = no_pb()
        new = self[index]["value"] = randomize(m_type, minlength, maxlength,
                                                    pb.minibar(0.0, 90.0))
        self[index]["meta"]["type"] = m_type
        self[index]["meta"]["minlength"] = m_minlength
        self[index]["meta"]["maxlength"] = m_maxlength
        # Write to the passwd file.
        counter = 0
        for element in self.xmlroot.findall("passwd"):
            if counter == index:    # Incremented enough?
                element.set("value", new)
                # Check meta.
                meta = element.find("meta")
                if meta is not None:
                    element.remove(meta)
                # Create meta.
                meta = XML.SubElement(element, "meta")
                meta.set("type", m_type)
                meta.set("minlength", str(m_minlength))
                meta.set("maxlength", str(m_maxlength))
                break
            counter += 1
            pb.progress(90.0  +  (counter+1.0) / (index+1.0) * 5.0)
        common_data.writexml(self, "~/.passwdman/passwords",
                                                    pb.minibar(95.0, 100.0))
    def __repr__(self):
        return "<passwdmanapi.passwd object with id {0}>".format(id(self))

class honeypot(common_data):
    """honeypot(common_data) - The honeypots.
    All classes based on common_data are list-like with legs.
    __init__(self, backups=True)
    With `backups`=True changes can be undone.
    
    Methods (including those from common_data)
    ------------------------------------------
    add(value)
    pick(n=1, sep=",", log_vs_raise=True, pb=None)
    pickl(n, log_vs_raise=True, pb=None)
    __iter__
    next = __next__
    __len__
    __getitem__
    
    A `honeypot`-object is list of strings.
    
    Internals
    ---------
    xmltree     A 'xml.etree.ElementTree.ElementTree'.
    xmlroot     A 'xml.etree.ElementTree.Element'. The 'root' tag.
    writexml()  Not so well hidden method inherited from common_data.
    """
    def __init__(self, backups=True):
        """__init__(self, backups=True)
        Load ~/.passwdman/honeypots -> self.xmltree 
        -> self.xmlroot -> self.data[].
        self.data is a list of strings.
        """
        common_data.__init__(self, "~/.passwdman/honeypots", backups)
        for honeypot_element in self.xmlroot.findall("honeypot"):
            self.data.append(honeypot_element.attrib["value"])
    def add(self, value):
        assert is_unicodestr(value)
        """add(self, value) - Add a new honey pot with the value <value>."""
        for x in self.data: # Check for duplicates.
            if x == value:
                raise err_duplicate(
                        "honeypot.add(value='{0}') #duplicate".format(value))
        self.data.append(value)
        honeypot_element = XML.SubElement(self.xmlroot, "honeypot")
        honeypot_element.tail = "\n  " # Make it look better.
        honeypot_element.set("value", value)
        common_data.writexml(self, "~/.passwdman/honeypots")
    def remove(self, x, is_numstring=False):
        """remove(self, x, is_numstring=False) - Remove an existing honey pot.
        x is an integer used as index for self.data xor a string.
        Set is_numstring to True if x is NOT an index!
        """
        common_data.remove(self, x, "~/.passwdman/honeypots", "honeypot",
                           "value", is_numstring)
    def pick(self, n=1, sep=",", log_vs_raise=True, pb=None):
        """pick(self, n=1, sep=",", log_vs_raise=True)
        Pick `n` randomly selected honey-pots and separate them with
        `sep`.
        
        If `log_vs_raise` is True then `pick` will log an error if `n`
        is too big.  It will pick fewer fake-passwords than it is
        supposed to.
        If `log_vs_raise` is False it will raise `err_idiot`.
        """
        # Its default is not unicode on Python 2.x.
        assert is_unicodestr(sep) or sep == ","
        return sep.join(self.pickl(n, log_vs_raise=log_vs_raise, pb=pb))
    def pickl(self, n, log_vs_raise=True, pb=None):
        """pickl(self, n, log_vs_raise=True)
        Pick `n` randomly selected honey-pots and return a list.
        
        If `log_vs_raise` is True then `pick` will log an error if `n`
        is too big.  It will pick fewer fake-passwords than it is
        supposed to.
        If `log_vs_raise` is False it will raise `err_idiot`.
        """
        assert is_int(n)
        if pb is None:
            pb = no_pb()
        if n > len(self):
            n = len(self)
            if log_vs_raise:
                logging.error("honeypot.pick: <n> is too big.")
            else:
                raise err_idiot("n is too big!")
        balloons, outlist, output = [], [], ""
        for x in self:                  # Create popable list.
            balloons.append(x)
        while len(outlist) < n:         # Pop random balloons.
            s = float(len(outlist))
            N = float(n)
            outlist.append(balloons.pop(getint(0, len(balloons),
                                pb.minibar(s/N* 100.0, (s+1.0)/N * 100.0))))
        return outlist
    def __repr__(self):
        return "<passwdmanapi.honeypot object with id {0}>".format(id(self))

def _unredo(passwdobj, honeypotobj, undo_unodable, undo_redoable):
    """_unredo(passwdobj=None, honeypotobj=None,
                                        undo_unodable, undo_redoable)
    `passwdobj` and `honeypotobj` are the passwd and honeypot OBJECTS.
    
    Moves '~/.passwdman/passwords' or '~/.passwdman/honeypots' to
    `undo_redoable`.
    
    Moves the newest file from `undo_unodable` to
    '~/.passwdman/passwords' or '~/.passwdman/honeypots'.
    
    """
    if not isinstance(passwdobj, passwd):
        raise err_idiot("Read the fucking __doc__ string")
    if not isinstance(honeypotobj, honeypot):
        raise err_idiot("Read the fucking __doc__ string")
    filename, birth = "", 0
    for x in os.listdir(ope(undo_unodable)):
        y = os.stat(os.path.join(ope(undo_unodable), x))
        if y.st_ctime > birth:      # Newer file.
            del filename
            filename = os.path.join(ope(undo_unodable), x)
            # Update filename to the newer file.
            birth = y.st_ctime      # Increase birth.
    del birth
    # Filename is now the name of the file.
    if "passwords" in filename:
        os.rename(ope("~/.passwdman/passwords"),
            os.path.join(ope(undo_redoable),
                "passwords" + '-' + time.ctime())) # Copy to redoable.
        passwdobj.__del__()
        os.rename(filename, ope("~/.passwdman/passwords"))
        passwdobj.__init__() # Reload the data structure.
    elif "honeypots" in filename:
        os.rename(ope("~/.passwdman/honeypots"),
            os.path.join(ope(undo_redoable),
                "honeypots" + '-' + time.ctime())) # Copy to redoable.
        honeypotobj.__del__()
        os.rename(filename, ope("~/.passwdman/honeypots"))
        honeypotobj.__init__() # Reload the data structure.
    else:
        logging.error("function undo in module passwdmanapi:" +
                      "confused by the file '{0}'".format(filename))

def undo(passwdobj=None, honeypotobj=None):
    """undo(passwdobj=None, honeypotobj=None)
    It's arguments are the passwd and honeypot OBJECTS.
    
    Moves '~/.passwdman/passwords' or '~/.passwdman/honeypots' to
    '~/.passwdman/redoable/*'.
    
    Moves the newest file from '~/.passwdman/undoable/*' to
    '~/.passwdman/passwords' or '~/.passwdman/honeypots'.

    """
    _unredo(passwdobj, honeypotobj, "~/.passwdman/undoable",
                                            "~/.passwdman/redoable")

def redo(passwdobj=None, honeypotobj=None):
    """redo(passwdobj=None, honeypotobj=None)
    It's arguments are the passwd and honeypot OBJECTS.
    
    Moves '~/.passwdman/passwords' or '~/.passwdman/honeypots' to
    '~/.passwdman/undoable/*'.
    
    Moves the newest file from '~/.passwdman/redoable/*' to
    '~/.passwdman/passwords' or '~/.passwdman/honeypots'.
    """
    _unredo(passwdobj, honeypotobj, "~/.passwdman/redoable",
                                            "~/.passwdman/undoable")

# Run this when imported.
assert __name__ != "__main__"

def ckmkdir(x):
    """ckmkdir(x) - make sure that the directory `x` exists."""
    try:
        os.stat(ope(x))
    except:
        os.mkdir(ope(x), 0o700)
def ckmkfile(x, y):
    """ckmkfile(x, y) - make sure that the file `x` exists.
    Its default content is `y`.
    """
    try:
        os.stat(ope(x))
    except:
        f = open(ope(x), "w")
        f.write(y)
        f.close()
# Make sure all the needed files exist.
ckmkdir("~/.passwdman")
ckmkdir("~/.passwdman/undoable")
ckmkdir("~/.passwdman/redoable")
ckmkfile("~/.passwdman/passwords", """<?xml version='1.0' encoding='UTF-8'?>
<root file="passwords" magic="passwdman" version="0.1">
</root>
""")
ckmkfile("~/.passwdman/honeypots", """<?xml version='1.0' encoding='UTF-8'?>
<root file="honeypots" magic="passwdman" version="0.1">
</root>
""")
# Simple exclusive lock for all the files.
ckmkfile("~/.passwdman/lock", "")
f = open(ope("~/.passwdman/lock"), 'w')
try:
    fcntl.lockf(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
except IOError:
    raise err_loaderr('Another passwdman* is running!')

try:
    locale.setlocale(locale.LC_ALL, '')
    code = locale.getpreferredencoding()
except:
    logging.error("Cannot figure out encoding.")
    code = 'ascii'