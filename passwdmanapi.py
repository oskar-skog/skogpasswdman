# -*- coding: utf-8 -*-
copywrong = """Copyright (c) 2013, Oskar Skog <oskar.skog.finland@gmail.com>
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
    import passwdmanapi
    class passwdmanapi.passwd(common_data)      Loads and modifies the XML
                                                '~/.passwdman/passwords'.
    class passwdmanapi.honeypot(common_data)    Loads and modifies the XML
                                                '~/.passwdman/honeypots'.
    class passwdmanapi.common_data()        Class defining lots of stuff...
                                    ...passwd() and honeypot() have in common.
    def get10(length)                           Return base10 string. Digits.
    def get64(length)                       Return base64 string. Big letters,
                                            small letters, exclamation marks
                                            and underscores.
    def getint(a, b)                            a <= random integer < b.
    def open_rng()                              Returns a file-descriptor to
                                                /dev/random or '/dev/urandom'.
    def unquote(x)                          Returns x without optional quotes.
    def undo(passwdobj,honeypotobj)         Undoes the latest change. Requires
                                            objects of both classes.
    def redo(passwdobj,honeypotobj)             Look at undo.
"""
EXCEPTIONS = """
    class err_norandom(Exception)               open_rng()
    class err_nolength(Exception)               get10() get64()
    class err_loaderr(Exception)            passwd() honeypot() common_data()
    class err_notfound(Exception)               passwd().remove()
                                                honeypot().remove()
                                                passwd.mkindex()
    class err_duplicate(Exception)          passwd.add() honeypot.add()
                                                passwd.add_nometa()
    class err_idiot(Exception)                  *
    class err_nometa(Exception)                 passwd.update()
"""
NOTES = """
    What I call strings are really 'unicode'. Unicode is supported. (UTF-8)
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

class err_norandom(Exception):
    """Cannot open '/dev/random', cannot open '/dev/urandom'."""
    pass

class err_nolength(Exception):
    """Invalid length (get10() or get64())."""
    pass

class err_loaderr(Exception):
    """Failure to load data file (XML)."""
    pass

class err_notfound(Exception):
    """The record in object.data cannot be found = cannot remove."""
    pass

class err_duplicate(Exception):
    """The value to be added already exist in object.data."""
    pass

class err_idiot(Exception):
    """Incorrect usage."""
    pass

class err_nometa(Exception):
    """Meta-data is required."""
    pass

def open_rng():
    """Open random(4) or urandom(4), returns an open file.
ERRORS
    err_norandom(Exception)             Cannot open random(4) or urandom."""
    #open /dev/urandom if /dev/random cannot be opened
    try:
        f = open('/dev/random', 'rb')
    except:
        try:
            f = open('/dev/urandom', 'rb')
        except:
            raise err_norandom('Cannot open "/dev/random" or "/dev/urandom".')
    return f

def get64(length):
    """get64(length)
    Returns a random string containing A-Z a-z 0-9 underscore and exclamation
    mark, with the length <length>.
ERRORS
    err_nolength(Exception)             Invalid <length>.
    err_norandom                        open_rng()"""
    #rng        The random number generator '/dev/random'.
    #passwd     The password to be returned.
    #number     Integer used as a buffer/pipe between rng and passwd.
    #bits       The amount of bits left in 'number'.
    if not isinstance(length, int):   #check type
        raise err_idiot('get64 called with non-integer length.')
    logging.info("get64:length={}".format(length))
    if length < 1:
        raise err_nolength('get64 called with length < 1.')
    letters=("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef"
            "ghijklmnopqrstuvwxyz0123456789!_") #Break line.
    passwd, bits, number = '', 0, 0
    try:
        rng = open_rng()
    except:
        raise
    while len(passwd) < length: #Main loop.
        if bits < 6:
            logging.info("get64:Need more random bits.")
            number |= ord(rng.read(1)) << bits #prepend the bits in number
                                                #with a random byte
            bits += 8
        passwd += letters[number % 64]#use 6 bits to pick a letter and append
        number >>= 6
        bits -= 6
        
        logging.info("get64:Added char {}/{}.".format(len(passwd), length))
    rng.close()
    del letters, bits, number, rng
    return passwd

def get10(length):
    """get10(length)
    Returns a random string containing 0-9, with the length <length>.
    Raises the same exceptions as get64()."""
    #rng        The random number generator '/dev/random'.
    #passwd     The password to be returned.
    #number     Integer used as a buffer/pipe between rng and passwd.
    #bits       The amount of bits left in 'number'.
    if not isinstance(length, int):   #check type
        raise err_nolength('get10 called with non-integer length.')
    logging.info("get10:length={}".format(length))
    if length < 1:
        raise err_nolength('get10 called with length < 1.')
    passwd, bits, number = '', 0, 0
    try:
        rng = open_rng()
    except:
        raise
    while len(passwd) < length:    #Main loop.
        if bits < 4:
            logging.info("get10:Need more random bits.")
            number |= ord(rng.read(1)) << bits  #Prepend the bits in number
            bits += 8                           #with a random byte.
        if (number % 16) < 10:                  #I don't want 0...5 to be
                                                #more popular than 6...9.
            passwd += chr(number % 16 + 48) #digits ASCII
            logging.info("get10:Added char {}/{}.".format(len(passwd),length))
        else:
            logging.info("get10:Bad nibble.")
        number >>= 4 #Next nibble.
        bits -= 4
    rng.close()
    del rng, bits, number
    return passwd

def getint(a, b):
    """Return random integer with value a from <a> to <b> - 1."""
    if b < a:
        raise err_nolength("b < a")
    try:
        rng = open_rng()
    except:
        raise
    reqbits = bits = number = smallnum = 0
    while (1 << reqbits) < (b - a):
        reqbits += 1            #How many bits are required?
    number = b - a + 1          #Force loop.
    while number >= (b - a):    #Get a number in range.
        logging.info("getint: getting number")
        bits = number = 0
        while bits < reqbits:   #Need more.
            if (reqbits - bits) < 8:
                smallnum = ord(rng.read(1))             #Get byte.
                smallnum %= 1 << (reqbits - bits)       #Remove overflow bits.
                number |= smallnum << bits              #Prepend.
            else:               #Prepend a whole byte.
                number |= ord(rng.read(1)) << bits
            bits += 8
    rng.close()
    return number + a

def unquote_buggy(x):
    """Remove quotes from string, if any
    BUGGY, called by unquote()"""
    c, quote, output = "", "", ""
    for index in range(len(x)):
        c = x[index]
        if c in string.whitespace and quote == "":
            continue            #Ignore leading whitespace.
        if c == '"' and quote == "":
            quote = '"' #Found start.
        elif c == "'" and quote == "":
            quote = "'" #Found start.
        elif quote == "":
            return x            #Not whitespace or first quote, return.
        elif c == quote:
            return output       #Ending quote.
        else:
            output += c
    return x                    #Not terminated.

def unquote(x):
    """Returns x without surrounding quotes."""
    #Check if quoted and ends with optional whitespace.
    quote = ""
    for c in x:
        if not c in string.whitespace:                  #Whitespace.
            if len(quote) == 0 and c == "'":            #Begin.
                quote = "'"
            else:
                if len(quote) == 0 and c == '"':        #Begin.
                    quote = '"'
                else:
                    if c == quote:                      #End.
                        quote = "DONE"
                    else:
                        if len(quote) != 1:
                            return x                    #Text outside quotes.
    return unquote_buggy(x)
class common_data():
    """self.data[]      Password-records or honey pots.
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
    writexml(self, xmlfile)     save"""
    def __init__(self, xmlfile):
        """__init__(self, xmlfile)
        This function is called by passwd.__init__ and honeypot.__init__ and
        creates variables they both have. It loads them from the
        path xmlfile -> self.xmltree -> self.xmlroot."""
        #    ~/.passwdman/passwords or ~/.passwdman/honeypots
        self.data = []
        self.index = 0
        parser = XML.XMLParser(encoding="utf-8")        #Unicode stuff here.
        self.xmltree = XML.parse(os.path.expanduser(xmlfile), parser)
        self.xmlroot = self.xmltree.getroot()
        #Sanity checking...
        #Root tag.
        if self.xmlroot.tag != "root":
            raise err_loaderr(
                  "root element is not 'root' in '{}'".format(xmlfile))
        #Magic.
        if self.xmlroot.attrib["magic"] != "passwdman":
            raise err_loaderr("incorrect magic in '{}'".format(xmlfile))
        #Version.
        version = self.xmlroot.attrib["version"].split('.', 2)
        if int(version[0]) != 0:
            raise err_loaderr("version too new in '{}'".format(xmlfile))
        if int(version[1]) > 1:
            logging.warning("High version number '{}' in '{}'".format(
                             self.xmlroot.attrib["version"], xmlfile))
        #Passwords/honey pots.
        #The attribute "file" should have the value <basename of xmlfile>.
        if self.xmlroot.attrib["file"] != os.path.basename(xmlfile):
            raise err_loaderr("incorrect file magic in '{}'".format(xmlfile))
        logging.info("'{}' is successfully loaded".format(xmlfile))
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
        """x is an integer used as an index xor a string. It can also be a
        stringed integer.
        It removes x from the file xmlfile and self.data
        It looks for a match in self.xmltree in the attribute <attrib_name>
        in the tags <element_name>.
        is_numstring == True: x is a string of digits, not an integer.
        """
        #x is an integer used as an index xor a string used to loop until
        #a match.
        if not is_numstring:
            try:
                x = int(x)  #Is it a stringed integer?
            except:
                pass
        if isinstance(x, int):
            y = 0
            for z in self.xmlroot.findall(element_name):
                #Loop through the XML.
                if x == y: #y is the index.
                    del self.data[y]
                    self.xmlroot.remove(z)
                    common_data.writexml(self, xmlfile)
                    return
                else:
                    y += 1   #Try next.
            raise err_notfound("Not found.")
        elif isinstance(x, unicode): #Use unicode instead of str.
            y = 0
            for z in self.xmlroot.findall(element_name):
                #Loop through the XML
                if z.attrib[attrib_name] == x:  #Check for a match.
                    del self.data[y]
                    self.xmlroot.remove(z)
                    common_data.writexml(self, xmlfile)
                    return
                else:
                    y += 1
            raise err_notfound("not found")
        else:
            raise err_notfound("not integer and not string")
    def writexml(self, xmlfile):
        """Write the XML tree to disk."""
        os.rename(os.path.expanduser(xmlfile),
                os.path.join(os.path.expanduser("~/.passwdman/undoable"),
                os.path.basename(xmlfile) + '-' + time.ctime())) #Make backup.
        self.xmltree.write(os.path.expanduser(xmlfile), encoding="UTF-8",
                                                xml_declaration=True)
        #Unicode-stuff here.
    def __del__(self):
        del self.data
        del self.index
        del self.xmlroot
        del self.xmltree
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
    #self.index          Index for self.data[] when    'for x in this_object'.
    #self.xmltree                        ~/.passwdman/passwords
    #self.xmlroot                        Root element of self.xmltree.
    def __init__(self):
        """load ~/.passwdman/passwords -> self.xmltree 
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
                 'human'=old human generated password."""
        common_data.__init__(self, "~/.passwdman/passwords")
                          
        for passwd_element in self.xmlroot.findall("passwd"): #Get the data.
            meta_element = passwd_element.find("meta")
            #Got the tags/elements.
            if meta_element is not None:
                meta_attrib = {"minlength": int(
                                           meta_element.attrib["minlength"]),
                               "maxlength": int(
                                           meta_element.attrib["maxlength"]),
                               "type": meta_element.attrib["type"]}
            else:    #The meta tag is optional.
                meta_attrib = {"minlength": 0, "maxlength": 0,
                               "type": "human"} #That is the magic dictionary.
            #got the meta attributes
            self.data.append({"name": passwd_element.attrib["name"],
                              "value": passwd_element.attrib["value"],
                              "meta": meta_attrib})
    #Will not add __setitem__.
    def add(self, name, value, m_type, m_minlength, m_maxlength):
        """Add the password for <name> with the value <value>.
        m_type is "human" if the password is some old human generated
        password, "10" if it only contains digits, "64" if it contains A-Z,
        a-z, 0-9, underscore and exclamation mark.
        m_minlength is the minimum length required for the password.
        m_maxlength is the maximum length allowed for the password.
        Raises err_duplicate if the password (<name>) already exist."""
        if isinstance(m_minlength, int):
            m_minlength = str(m_minlength)
        if isinstance(m_maxlength, int):
            m_maxlength = str(m_maxlength)
        for x in self.data: #check for duplicates
            if x["name"] == name:
                raise err_duplicate(
                    "passwd.add_nometa(name='{}') #duplicate".format(value))
        self.data.append({"name": name, "value": value,
                      "meta": {"type": m_type, "minlength": m_minlength,
                                               "maxlength": m_maxlength}})
        passwd_element = XML.SubElement(self.xmlroot, "passwd")
        meta_element = XML.SubElement(passwd_element, "meta")   #add new tags
        passwd_element.set("name", name) #attributes
        passwd_element.set("value", value)
        meta_element.set("type", m_type)
        meta_element.set("minlength", m_minlength)
        meta_element.set("maxlength", m_maxlength) #attributes
        common_data.writexml(self, "~/.passwdman/passwords")
    def add_nometa(self, name, value):
        """Add password with only name and value.
        Raises err_duplicate if the password (<name>) already exist."""
        self.add(name, value, "human", "0", "0")
                                  #the magic used if there is no meta element
    def remove(self, x, is_numstring=False):
        #wrapper around common_data.remove
        """Remove the password <x>.
        x is an integer used as an index for self.data xor a string (stringed
        integer).
        x is the purpose/name of a password, not the value.
        Set is_numstring to True if x is NOT an index!"""
        try:
            common_data.remove(self, x, "~/.passwdman/passwords", "passwd",
                               "name", is_numstring)
        except:
            raise
    def __repr__(self):
        return "passwdmanapi.passwd()"
    def mkindex(self, x, is_numstring=False):
        """Make index of x (string). x can be a stringed index
           Set is_numstring to True if x is NOT an index!"""
        index = 0
        try:
            if not is_numstring:
                index = int(x)      #That was very simple.
            else:
                raise
        except:
            for y in self:      #Find it.
                if y["name"] == x:
                    return index
                index += 1
            raise err_notfound("")
        return index
    def update(self, index):
        """update the password at index, use its meta-data to know how"""
        if index >= len(self) or index < 0:
            raise err_notfound("index out of range")
        method = self[index]["meta"]["type"]
        if method == "human":   #It would probably work with get64, but
            raise err_nometa(   #it will need a check for a meta-element and
                                #might need to create one.
                              #Use update_meta() to force specific meta-data.
                  "Don't know how to update a human-generated password.")
        try:
            minlength = int(self[index]["meta"]["minlength"])
            maxlength = int(self[index]["meta"]["maxlength"])
        except:
            raise err_nometa("weird 'minlength' or 'maxlength'")
        length = getint(minlength, maxlength + 1) #Even the length should be
                                                    #randomized.
        if method == "10":
            new = get10(length)
        elif method == "64":
            new = get64(length)
        else:
            raise err_nometa("weird 'type'")
        self[index]["value"] = new
        #Write the new password to the passwd file.
        counter = 0
        for element in self.xmlroot.findall("passwd"):
            if counter == index:    #Incremented enough?
                element.set("value", new)
                break
            counter += 1
        common_data.writexml(self, "~/.passwdman/passwords")
        return
    def update_meta(self, index, m_type, m_minlength, m_maxlength):
        """Update the password at index and its meta data."""
        if index >= len(self) or index < 0:
            raise err_notfound("index out of range")
        try:
            minlength = int(m_minlength)
            maxlength = int(m_maxlength)
        except:
            raise err_idiot("INTEGERS")
        length = getint(minlength, maxlength + 1)
        if m_type == "human":
            raise err_idiot("????")
        elif m_type == "10":
            new = get10(length)
        elif m_type == "64":
            new = get64(length)
        else:
            raise err_idiot("")
        self[index]["value"] = new
        self[index]["meta"]["type"] = m_type
        self[index]["meta"]["minlength"] = m_minlength
        self[index]["meta"]["maxlength"] = m_maxlength
        #Write to the passwd file.
        counter = 0
        for element in self.xmlroot.findall("passwd"):
            if counter == index:    #Incremented enough?
                element.set("value", new)
                #Check meta.
                meta = element.find("meta")
                if meta is not None:
                    element.remove(meta)
                #Create meta.
                meta = XML.SubElement(element, "meta")
                meta.set("type", m_type)
                meta.set("minlength", str(m_minlength))
                meta.set("maxlength", str(m_maxlength))
                break
            counter += 1
        common_data.writexml(self, "~/.passwdman/passwords")
        return
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
                Raise err_idiot if <n> is too high."""
    def __init__(self):
        """Load ~/.passwdman/honeypots -> self.xmltree 
        -> self.xmlroot -> self.data[].
        self.data is a list of strings."""
        common_data.__init__(self, "~/.passwdman/honeypots")
        for honeypot_element in self.xmlroot.findall("honeypot"):
            self.data.append(honeypot_element.attrib["value"])
    def add(self, value):
        """Add a new honey pot with the value <value>."""
        for x in self.data: #Check for duplicates.
            if x == value:
                raise err_duplicate(
                        "honeypot.add(value='{}') #duplicate".format(value))
        self.data.append(value)
        honeypot_element = XML.SubElement(self.xmlroot, "honeypot")
        honeypot_element.set("value", value)
        common_data.writexml(self, "~/.passwdman/honeypots")
    def remove(self, x, is_numstring=False):
        """Remove an existing honey pot.
        x is an integer used as index for self.data xor a string.
        Set is_numstring to True if x is NOT an index!"""
        try:
            common_data.remove(self, x, "~/.passwdman/honeypots", "honeypot",
                               "value", is_numstring)
        except:
            raise
    def pick(self, n=1, sep=",", log_vs_raise=True):
        """Pick randomly selected honey-pots."""
        if n > len(self):
            n = len(self)
            if log_vs_raise:
                logging.error("honeypot.pick:<n> is too big")
            else:
                raise err_idiot("")
        balloons, outlist, output = [], [], ""
        for x in self:                  #Create popable list.
            balloons.append(x)
        while len(outlist) < n:         #Pop random balloons.
            outlist.append(balloons.pop(getint(0, len(balloons))))
        for y in outlist:
            output += y
            output += sep
        return output[:-(len(sep))] #Do not return the last separator.
    def __repr__(self):
        return "passwdmanapi.honeypot()"

def undo(passwdobj=None, honeypotobj=None):
    """undo(passwdobj=None, honeypotobj=None)
    Moves '~/.passwdman/passwords' or '~/.passwdman/honeypots' to
    '~/.passwdman/redoable/*'.
    Moves the newest file from '~/.passwdman/undoable/*' to
    '~/.passwdman/passwords' or '~/.passwdman/honeypots'.
    It's arguments are the passwd and honeypot OBJECTS."""
    if isinstance(passwdobj, passwd) and isinstance(honeypotobj, honeypot):
        filename, birth = "", 0
        for x in os.listdir(os.path.expanduser("~/.passwdman/undoable")):
            y = os.stat(os.path.join(
                os.path.expanduser("~/.passwdman/undoable"), x))
            if y.st_ctime > birth:      #Newer file.
                del filename
                filename = os.path.join(
                    os.path.expanduser("~/.passwdman/undoable"), x)
                #Update filename to the newer file.
                birth = y.st_ctime      #Increase birth.
        del birth
        #filename is now the name of the file.
        if "passwords" in filename:
            os.rename(os.path.expanduser("~/.passwdman/passwords"),
                os.path.join(os.path.expanduser("~/.passwdman/redoable"),
                    "passwords" + '-' + time.ctime())) #Copy to redoable.
            passwdobj.__del__()
            os.rename(filename, os.path.expanduser("~/.passwdman/passwords"))
            passwdobj.__init__() #Reload the data structure.
        elif "honeypots" in filename:
            os.rename(os.path.expanduser("~/.passwdman/honeypots"),
                os.path.join(os.path.expanduser("~/.passwdman/redoable"),
                    "honeypots" + '-' + time.ctime())) #Copy to redoable.
            honeypotobj.__del__()
            os.rename(filename, os.path.expanduser("~/.passwdman/honeypots"))
            honeypotobj.__init__() #Reload the data structure.
        else:
            logging.error("function undo in module passwdmanapi:"   #Continue.
                          "confused by the file '{}'".format(filename))
    else:
        raise err_idiot("Read the fucking __doc__ string")

def redo(passwdobj=None, honeypotobj=None):
    #Copy-pasted from undo() and hand-hacked.
    """redo(passwdobj=None, honeypotobj=None)
    Moves '~/.passwdman/passwords' or '~/.passwdman/honeypots' to
    '~/.passwdman/undoable/*'.
    Moves the newest file from '~/.passwdman/redoable/*' to
    '~/.passwdman/passwords' or '~/.passwdman/honeypots'.
    It's arguments are the passwd and honeypot OBJECTS."""
    if isinstance(passwdobj, passwd) and isinstance(honeypotobj, honeypot):
        filename, birth = "", 0
        for x in os.listdir(os.path.expanduser("~/.passwdman/redoable")):
            y = os.stat(os.path.join(
                os.path.expanduser("~/.passwdman/redoable"), x))
            if y.st_ctime > birth:      #Newer file.
                del filename
                filename = os.path.join(
                    os.path.expanduser("~/.passwdman/redoable"), x)
                #Update filename to the newer file.
                birth = y.st_ctime      #Increase birth.
        del birth
        #filename is now the name of the file.
        if "passwords" in filename:
            os.rename(os.path.expanduser("~/.passwdman/passwords"),
                os.path.join(os.path.expanduser("~/.passwdman/undoable"),
                    "passwords" + '-' + time.ctime())) #Copy to undoable.
            passwdobj.__del__()
            os.rename(filename, os.path.expanduser("~/.passwdman/passwords"))
            passwdobj.__init__() #Reload the data structure.
        elif "honeypots" in filename:
            os.rename(os.path.expanduser("~/.passwdman/honeypots"),
                os.path.join(os.path.expanduser("~/.passwdman/undoable"),
                    "honeypots" + '-' + time.ctime())) #Copy to undoable.
            honeypotobj.__del__()
            os.rename(filename, os.path.expanduser("~/.passwdman/honeypots"))
            honeypotobj.__init__() #Reload the data structure.
        else:
            logging.error("function undo in module passwdmanapi:"   #Continue.
                          "confused by the file '{}'".format(filename))
    else:
        raise err_idiot("Read the fucking __doc__ string")
    
#Run this when imported.
def ckmkdir(x):
    try:
        os.stat(os.path.expanduser(x))
    except:
        os.mkdir(os.path.expanduser(x), 0o700)
def ckmkfile(x, y):
    try:
        os.stat(os.path.expanduser(x))
    except:
        f = open(os.path.expanduser(x), "w")
        f.write(y)
        f.close()
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

if __name__ == "__main__":
    print ("I-D-10-T")
