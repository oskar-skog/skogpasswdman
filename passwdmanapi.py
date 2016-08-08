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
__doc__ = """passwdmanapi - functions and classes used by passwdman
    This was a long __doc__ string. Read SYNOPSIS, EXCEPTIONS, NOTES and BUGS
    """
SYNOPSIS = """
    is_anystr(x) is_bytestr(x) is_int(x) is_num(x) is_unicodestr(x) u(x) b(x)
    class passwdmanapi.passwd(common_data)
    class passwdmanapi.honeypot(common_data)
    class passwdmanapi.common_data()
    def get10(length) def get64(length) def getint(a, b)
    def open_rng()
    def unquote(x)
    def randomize(method, minlength, maxlength)
    def undo(passwdobj,honeypotobj) def redo(passwdobj,honeypotobj)
"""
EXCEPTIONS = """
    They have their own __doc__-strings.
    class err_norandom(Exception)
    class err_nolength(Exception)
    class err_loaderr(Exception)
    class err_notfound(Exception)
    class err_duplicate(Exception)
    class err_idiot(Exception)
    class err_nometa(Exception)
"""
NOTES = """
    What I call strings are really 'unicode' in Python 2.x.
    Unless written otherwise, <xmlfile> is a path. In get10() and get64(),
    <length> must be an integer, not a string.
    passwd.xmltree, honeypot.xmltree, common_data.xmltree are class
        'xml.etree.ElementTree.ElementTree'.
    passwd.xmlroot, honeypot.xmlroot, common_data.xmlroot are class
        'xml.etree.ElementTree.Element'.
    The fake-passwords/honeypots are intended to catch crackers.
    Use honeypots such as "password".
    
    The meta-data:
        passwd[*]["meta"] is a dictionary containing:
            "type":     "10", "64" xor "human"
                        Use get10(), get64() xor (it was human-generated)
            "minlength":        Minimal required length for the password.
            "maxlength":        Maximal allowed length for the password.
        
        Human-generated passwords have 0 as minlength and maxlength.
"""
BUGS = """
    get64() wastes a few bits from the random device.
    get10() wastes lots of bits when it emits:
        "Bad nibble"
"""

import xml.etree.ElementTree as XML
import os.path
import time
import logging
import string
import sys
import locale

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
    The record in object.data cannot be found = cannot remove."""
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
        pb = no_pb()    # No-op progress bar.
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
        pb = no_pb()    # No-op progress bar.
    passwd, bits, number = '', 0, 0
    rng = open_rng()
    while len(passwd) < length:    # Main loop.
        if bits < 4:
            logging.info("get10: Need more random bits.")
            number |= ord(rng.read(1)) << bits  # Prepend the bits in number
            bits += 8                           # with a random byte.
        if (number%16) < 10:                    # I don't want 0...5 to be
                                                # more popular than 6...9.
            passwd += chr(number%16 + 48) # digits ASCII
            # Progress bar.
            pb.progress(float(len(passwd))/float(length) * 100.0)
            logging.info("get10: Added char {0}/{1}.".format(len(passwd),
                                                                  length))
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
    if b < a:
        raise err_nolength("b < a")
    if pb is None:
        pb = no_pb()    # No-op progress bar.
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
    """unquote(x) - Returns x without surrounding quotes."""
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
    
    object = progress_bar(start=0.0, stop=100.0, function, data=None)
    object.progress(percent)
    object2 = object.minibar(start, stop)
    brain_dead_object = no_pb()
    brain_dead_object.progress(percent)
    brain_dead_object2 = brain_dead_object.minibar(start, stop)
    
    start, stop and percent are floating point numbers in the range 0...100.
    """
    def __init__(self, start, stop, function, data=None):
        # The values are internally in the range 0...1.
        # They are externally in the range 0...100.
        self.start = start/100.0
        self.stop = stop/100.0
        self.function = function
        self.data = data
        self.full = self.stop - self.start
    def progress(self, percent):
        if percent < 0.0:
            percent = 0.0
        if percent > 100.0:
            percent = 100.0
        real_percent = self.start  +  (percent/100.0 * self.full)
        self.function(real_percent*100.0, self.data)
    def minibar(self, start, stop):
        start /= 100.0
        stop /= 100.0
        return progress_bar(
            (self.start + start*self.full) * 100.0,
            (self.start + stop*self.full) * 100.0,
            self.function,
            self.data)

class common_data():
    """class common_data():
    self.data[]      Password-records or honey pots.
    self.index   Used in for loops.
    self.xmltree
    self.xmlroot
    __init__(self, xmlfile)
        Load the file xmlfile -> self.xmltree -> self.xmlroot.
    __iter__(self)
    __getitem__(self, i)     self.data[i]
    __len__(self)            len(self.data)
    remove(self, x, xmlfile, element_name, attrib_name, is_numstring=False)
        x is an integer used as an index xor a string that it removes from
        self.data and xmlfile. x can also be a stringed integer used as index
        xmlfile is the path to the file from which the data was loaded
        element_name, attrib_name      "passwd","honeypot"  "name","value"
        it needs them to find the data in the XML.
        Set is_numstring to True if x is NOT an index!
        Raises err_notfound.
    writexml(self, xmlfile)     save
    """
    def __init__(self, xmlfile):
        """__init__(self, xmlfile)
        This function is called by passwd.__init__ and honeypot.__init__ and
        creates variables they both have. It loads them from the
        path xmlfile -> self.xmltree -> self.xmlroot.
        """
        #    ~/.passwdman/passwords or ~/.passwdman/honeypots
        assert is_anystr(xmlfile)
        self.data = []
        self.index = 0
        try:
            parser = XML.XMLParser(encoding="UTF-8")     # Unicode stuff here.
        except:
            parser = XML.XMLParser() # Above will fail with Python 2.6.
        self.xmltree = XML.parse(os.path.expanduser(xmlfile), parser)
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
        """Reset index and return self."""
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
        """__getitem__(self,i)
        return self.data[i]"""
        return self.data[i]
    def __len__(self):
        """__len__(self)
        return len(self.data)"""
        return len(self.data)
    def remove(self, x, xmlfile, element_name, attrib_name, is_numstring):
        """remove(self, x, xmlfile, element_name, attrib_name, is_numstring)
        x is an integer used as an index xor a string. It can also be a
        stringed integer.
        It removes x from the file xmlfile and self.data
        It looks for a match in self.xmltree in the attribute <attrib_name>
        in the tags <element_name>.
        is_numstring == True: x is a string of digits, not an integer.
        Set is_numstring to True if x is NOT an index!
        """
        # x is an integer used as an index xor a string used to loop until
        # a match.
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
        """writexml(self, xmlfile) - Write the XML tree to disk."""
        assert is_anystr(xmlfile)
        self.xmlroot.text = "\n  "      # Make it look better.
        self.xmlroot.tail = "\n"
        if self.make_backups:
            # Make backup.
            os.rename(os.path.expanduser(xmlfile),
                    os.path.join(os.path.expanduser("~/.passwdman/undoable"),
                    os.path.basename(xmlfile) + '-' + time.ctime()))
            if pb is not None:
                pb.progress(50.0)
        try:
            self.xmltree.write(os.path.expanduser(xmlfile), encoding="UTF-8",
                                                    xml_declaration=True)
        except:         # For Python 2.6.
            self.xmltree.write(os.path.expanduser(xmlfile), encoding="UTF-8")
        if pb is not None:
            pb.progress(100.0)
        # Unicode-stuff here.
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
    """self.data                        List.
    self.data[*]["value"]               The password.
    self.data[*]["name"]       What is the password for (info for the user).
    self.data[*]["meta"][*]    Information useful when updating the password.
    self.data[*]["meta"]["type"]        human, 10, 64
                                        human-generated, get10(), get64()
    self.data[*]["meta"]["minlength"]   Minimum length for a password.
    self.data[*]["meta"]["maxlength"]   Maximum length for a password.
    add(name, value, m_type, m_minlength, m_maxlength)   Raises err_duplicate.
    add_nometa(name, value)             Add human generated password.
        Raises err_duplicate.
    remove(x, is_numstring=False)
        x can be a string, integer or a stringed integer.
        is_numstring == True: x is a string that contains digits.
                               Without this it would treat x as an index.
        Set is_numstring to True if x is NOT an index!
        Raises err_notfound.
    mkindex(x, is_numstring=False)
        x is a string that is either a stringed integer or a name of a
        password.
        Set is_numstring to True if x is NOT an index!
        Raises err_notfound.
    update(index), update_meta(index, m_type, m_minlength, m_maxlength)
        Update passwords automatically.
        They generate the value themselves.
        update_meta forces (new) meta-data.
        Both raises err_notfound.
        update() raises err_nometa.
        update_meta() raises err_idiot.
    """
    # self.index         Index for self.data[] when    'for x in this_object'.
    # self.xmltree                       ~/.passwdman/passwords
    # self.xmlroot                       Root element of self.xmltree.
    def __init__(self, backups=True):
        """__init__(self, backups=True)
        load ~/.passwdman/passwords -> self.xmltree 
        -> self.xmlroot -> self.data[]
        self.data is a list of {'name': 'string',
                            'value': 'string',
                            'meta': {'minlength':0,
                                    'maxlength':0,
                                    'type': 'string'}}
            <name> What is the password for.
            <value> The password.
            <meta> Less important information.
          <minlength> The minimum length for the password, used when updating.
          <maxlength> The maximum length for the password, used when updating.
            <type> '10'=created by get10(), '64'=created by get64(),
                 'human'=old human generated password.
        """
        common_data.__init__(self, "~/.passwdman/passwords")
        self.make_backups = backups
        for passwd_element in self.xmlroot.findall("passwd"): # Get the data.
            meta_element = passwd_element.find("meta")
            # Got the tags/elements.
            if meta_element is not None:
                meta_attrib = {"minlength": int(
                                           meta_element.attrib["minlength"]),
                               "maxlength": int(
                                           meta_element.attrib["maxlength"]),
                               "type": meta_element.attrib["type"]}
            else:    # The meta tag is optional.
                # This is the magic dictionary.
                meta_attrib = {"minlength": 0, "maxlength": 0,
                               "type": "human"} 
            # Got the meta attributes.
            self.data.append({"name": passwd_element.attrib["name"],
                              "value": passwd_element.attrib["value"],
                              "meta": meta_attrib})
    # Will not add __setitem__.
    def add(self, name, value, m_type, m_minlength, m_maxlength, pb=None):
        assert is_unicodestr(name)
        assert is_unicodestr(value) or value is None
        assert is_anystr(m_type)
        """add(self, name, value, m_type, m_minlength, m_maxlength)
        Add the password for <name> with the value <value>.
        m_type is "human" if the password is some old human generated
        password, "10" if it only contains digits, "64" if it contains A-Z,
        a-z, 0-9, underscore and exclamation mark.
        m_minlength is the minimum length required for the password.
        m_maxlength is the maximum length allowed for the password.
        Raises err_duplicate if the password (<name>) already exist.
        """
        if is_int(m_minlength):
            m_minlength = str(m_minlength)
        if is_int(m_maxlength):
            m_maxlength = str(m_maxlength)
        assert is_anystr(m_minlength) and is_anystr(m_maxlength)
        forget = int(m_minlength)   # Raise an exception if not a number.
        forget = int(m_maxlength)   # Raise an exception if not a number.
        if pb is None:
            pb = no_pb()        # No-op progress bar.
        for x in self.data: # Check for duplicates.
            if x["name"] == name:
                raise err_duplicate(
                    "passwd.add_nometa(name='{0}') #duplicate".format(value))
        pb.progress(5.0)
        if value is None:
            value = randomize(m_type, int(m_minlength), int(m_maxlength),
                                                    pb.minibar(5.0, 90.0))
        self.data.append({"name": name, "value": value,
                      "meta": {"type": m_type, "minlength": m_minlength,
                                               "maxlength": m_maxlength}})
        passwd_element = XML.SubElement(self.xmlroot, "passwd")
        passwd_element.text = "\n    "  # Make them look better.
        passwd_element.tail = "\n  "
        meta_element = XML.SubElement(passwd_element, "meta")   # Add new tags.
        meta_element.tail = "\n  "
        passwd_element.set("name", name) # Attributes.
        passwd_element.set("value", value)
        meta_element.set("type", m_type)
        meta_element.set("minlength", m_minlength)
        meta_element.set("maxlength", m_maxlength) # Attributes.
        pb.progress(95.0)
        common_data.writexml(self, "~/.passwdman/passwords")
        pb.progress(100.0)
    def add_nometa(self, name, value):
        """add_nometa(self, name, value)
        Add password with only name and value.
        Raises err_duplicate if the password (<name>) already exist.
        """
        assert is_unicodestr(name) and is_unicodestr(value)
        for x in self.data: # Check for duplicates.
            if x["name"] == name:
                raise err_duplicate(
                    "passwd.add_nometa(name='{0}') #duplicate".format(value))
        self.data.append({"name": name, "value": value,
                      "meta": {"type": "human", "minlength": 0,
                                               "maxlength": 0}})
        passwd_element = XML.SubElement(self.xmlroot, "passwd")
        passwd_element.tail = "\n  "
        passwd_element.set("name", name) #Attributes.
        passwd_element.set("value", value)
        common_data.writexml(self, "~/.passwdman/passwords")
    def remove(self, x, is_numstring=False):
        """remove(self, x, is_numstring=False)
        Remove the password <x>.
        x is an integer used as an index for self.data xor a string (stringed
        integer).
        x is the purpose/name of a password, not the value.
        Set is_numstring to True if x is NOT an index!
        """
        # Wrapper around common_data.remove.
        common_data.remove(self, x, "~/.passwdman/passwords", "passwd",
                           "name", is_numstring)
    def mkindex(self, x, is_numstring=False):
        """mkindex(self, x, is_numstring=False)
        Make index of x (string). x can be a stringed index
           Set is_numstring to True if x is NOT an index!
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
            raise err_notfound("Index out of range.")
        method = self[index]["meta"]["type"]
        if method == "human":   # It would probably work with get64, but
            raise err_nometa(   # it will need a check for a meta-element and
                                # might need to create one.
                              # Use update_meta() to force specific meta-data.
                  "Don't know how to update a human-generated password.")
        try:
            minlength = int(self[index]["meta"]["minlength"])
            maxlength = int(self[index]["meta"]["maxlength"])
        except:
            raise err_nometa("Weird 'minlength' or 'maxlength'.")
        if pb is None:
            pb = no_pb()        # No-op progress bar.
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
            pb = no_pb()        # No-op progress bar.
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
    """self.data[]      List of honey pots.
    add(value)
    remove(x)
    pick(self, n=1, sep=",", log_vs_raise=True)
        Randomly pick <n> honey pots and separate them with <sep>.
        log_vs_raise
            True
                Log an error if <n> is too high.
            False
                Raise err_idiot if <n> is too high.
    pickl(n, log_vs_raise=True) returns a list of n honeypots
    """
    def __init__(self, backups=True):
        """__init__(self, backups=True)
        Load ~/.passwdman/honeypots -> self.xmltree 
        -> self.xmlroot -> self.data[].
        self.data is a list of strings.
        """
        common_data.__init__(self, "~/.passwdman/honeypots")
        self.make_backups = backups
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
        Pick randomly selected honey-pots.
        """
        assert is_int(n)
        # Its default is not unicode on Python 2.x.
        assert is_unicodestr(sep) or sep == ","
        if pb is None:
            pb = no_pb()        # No-op progress bar.
        if n > len(self):
            n = len(self)
            if log_vs_raise:
                logging.error("honeypot.pick: <n> is too big.")
            else:
                raise err_idiot("")
        balloons, outlist, output = [], [], ""
        for x in self:                  # Create popable list.
            balloons.append(x)
        while len(outlist) < n:         # Pop random balloons.
            s = float(len(outlist))
            N = float(n)
            outlist.append(balloons.pop(getint(0, len(balloons),
                            pb.minibar(s/N* 100.0, (s+1.0)/N * 100.0))))
        for y in outlist:
            output += y
            output += sep
        return output[:-(len(sep))] # Do not return the last separator.
    def pickl(self, n, log_vs_raise=True, pb=None):
        """pickl(self, n, log_vs_raise=True)
        Pick randomly selected honey-pots in a list.
        """
        # Copy-pasted from pick()
        assert is_int(n)
        if pb is None:
            pb = no_pb()        # No-op progress bar.
        if n > len(self):
            n = len(self)
            if log_vs_raise:
                logging.error("honeypot.pick:<n> is too big")
            else:
                raise err_idiot("")
        balloons, outlist, output = [], [], ""
        for x in self:                  # Create popable list.
            balloons.append(x)
        while len(outlist) < n:         # Pop random balloons.
            s = float(len(outlist))
            N = float(n)
            outlist.append(balloons.pop(getint(0, len(balloons),
                            pb.minibar(s/N * 100.0, (s+1.0)/N * 100.0))))
        return outlist
    def __repr__(self):
        return "<passwdmanapi.honeypot object with id {0}>".format(id(self))

def _unredo(passwdobj, honeypotobj, undo_unodable, undo_redoable):
    """_unredo(passwdobj=None, honeypotobj=None,
                            undo_unodable, undo_redoable)
    Moves '~/.passwdman/passwords' or '~/.passwdman/honeypots' to
    `undo_redoable`.
    Moves the newest file from `undo_unodable` to
    '~/.passwdman/passwords' or '~/.passwdman/honeypots'.
    It's arguments are the passwd and honeypot OBJECTS.
    """
    if not isinstance(passwdobj, passwd):
        raise err_idiot("Read the fucking __doc__ string")
    if not isinstance(honeypotobj, honeypot):
        raise err_idiot("Read the fucking __doc__ string")
    filename, birth = "", 0
    for x in os.listdir(os.path.expanduser(undo_unodable)):
        y = os.stat(os.path.join(
            os.path.expanduser(undo_unodable), x))
        if y.st_ctime > birth:      # Newer file.
            del filename
            filename = os.path.join(
                os.path.expanduser(undo_unodable), x)
            # Update filename to the newer file.
            birth = y.st_ctime      # Increase birth.
    del birth
    # Filename is now the name of the file.
    if "passwords" in filename:
        os.rename(os.path.expanduser("~/.passwdman/passwords"),
            os.path.join(os.path.expanduser(undo_redoable),
                "passwords" + '-' + time.ctime())) # Copy to redoable.
        passwdobj.__del__()
        os.rename(filename, os.path.expanduser("~/.passwdman/passwords"))
        passwdobj.__init__() # Reload the data structure.
    elif "honeypots" in filename:
        os.rename(os.path.expanduser("~/.passwdman/honeypots"),
            os.path.join(os.path.expanduser(undo_redoable),
                "honeypots" + '-' + time.ctime())) # Copy to redoable.
        honeypotobj.__del__()
        os.rename(filename, os.path.expanduser("~/.passwdman/honeypots"))
        honeypotobj.__init__() # Reload the data structure.
    else:
        logging.error("function undo in module passwdmanapi:" +
                      "confused by the file '{0}'".format(filename))

def undo(passwdobj=None, honeypotobj=None):
    """undo(passwdobj=None, honeypotobj=None)
    Moves '~/.passwdman/passwords' or '~/.passwdman/honeypots' to
    '~/.passwdman/redoable/*'.
    Moves the newest file from '~/.passwdman/undoable/*' to
    '~/.passwdman/passwords' or '~/.passwdman/honeypots'.
    It's arguments are the passwd and honeypot OBJECTS.
    """
    _unredo(passwdobj, honeypotobj, "~/.passwdman/undoable",
                                            "~/.passwdman/redoable")

def redo(passwdobj=None, honeypotobj=None):
    """redo(passwdobj=None, honeypotobj=None)
    Moves '~/.passwdman/passwords' or '~/.passwdman/honeypots' to
    '~/.passwdman/undoable/*'.
    Moves the newest file from '~/.passwdman/redoable/*' to
    '~/.passwdman/passwords' or '~/.passwdman/honeypots'.
    It's arguments are the passwd and honeypot OBJECTS.
    """
    _unredo(passwdobj, honeypotobj, "~/.passwdman/redoable",
                                            "~/.passwdman/undoable")

# Run this when imported.
def ckmkdir(x):
    """ckmkdir(x) - make sure that the directory `x` exists."""
    try:
        os.stat(os.path.expanduser(x))
    except:
        os.mkdir(os.path.expanduser(x), 0o700)
def ckmkfile(x, y):
    """ckmkfile(x, y) - make sure that the file `x` exists.
    Its default content is `y`.
    """
    try:
        os.stat(os.path.expanduser(x))
    except:
        f = open(os.path.expanduser(x), "w")
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
try:
    locale.setlocale(locale.LC_ALL, '')
    code = locale.getpreferredencoding()
except:
    logging.error("Cannot figure out encoding.")
    code = 'ascii'

if __name__ == "__main__":
    print ("I-D-10-T")
