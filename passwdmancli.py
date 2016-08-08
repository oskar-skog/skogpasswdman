#!/usr/bin/python
# -*- coding: utf-8 -*-

copywrong = """Copyright (c) 2013, Oskar Skog
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

import passwdmanapi as api
import sys
import logging
import time
import os
import os.path

def se():       #syntax error
    sow("!syntax error, type 'help'\n")
    sow('!')
    sow(theline)
    sow("\n")

def sow(x):
    sys.stdout.write(x.encode(encoding="utf-8"))         #it is used a lot

def siw():
    return sys.stdin.readline().decode(encoding="utf-8")

def v(x):       #verbose
    if verbose:
        sow("#" + x + "\n")

def show_help():
    """#HELP MESSAGE
#passwdmancli uses  colon separated fields  as input. Everything inside angle
#brackets < >,  is intended to be expanded in your brain.
#It tries to be more grepable by making the first letter in error messages be
#an exclamation  mark and  the first  letter in human-friendly  messages be a
#hash/number sign.  Multi-line  outputs are  terminated by a "#READY"
#message. Unless otherwise noted, quotes  around angle  brackets are optional
#and may be either single quotes or double quotes. If the first letter in its
#input is a '#', it will ignore the line. If the first letter in it input is
# '|', it prints out the rest of the line
#It allows ANY crap to surround the commands in the fields.
#It's outputs are prepended with `<command> | tr : .` + '?'
#The error messages are hopefully obvious enough.
#passwd:help            show help for passwd:*
#honeypot:help          show help for honeypot:*
#verbose:on            verbose output, the command 'hell' does the same thing
#verbose:off            brief output
#undo                   undo last change to passwd or honeypot, there is also
#help                   obvious                                 'redo'
#exit                   obvious
#bugs                   bugs
#whistles               bells and whistles
"""
    sow(show_help.__doc__)
def passwd_help():      #22 lines + ('#READY') + new line for input
    """#HELP MESSAGE
#Do you remember the angle brackets and the quotes? If not: type 'help'
#passwd:add:<type>:<min>:<max>:"<name>"         Add password, for <name> with
#                       a minimal length of <min> and maximal length of <max>
#                       <type> == 10 = use digits only, <type> == 64 = use
#                       big and small letters, digits, '!' and '_'
#passwd:add_human:"<name>"                      Add human generated password
#                       for <name>. The password is entered on a new line
#passwd:remove:<index>                          Remove, by index
#passwd:remove:"<name>"                         Remove, by name
#passwd:get:<index>     passwd:get:"<name>"     get password
#passwd:meta:<index>                            get meta data, which is...
#passwd:meta:"<name>"                           ...useful when updating
#passwd:remove:<index>          passwd:remove:"<name>"       remove password
#passwd:list                              list all passwords (index and name)
#passwd:update:"<name>"         passwd:update:<index>   update password, will
#                       print out the new and the old.
#passwd:update_meta:<type>:<min>:<max>:"<name>"      Update the password,...
#passwd:update_meta:<type>:<min>:<max>:<index>       ...but use new meta-data
#                                       (the <type>, <min> and <max>)
#               passwd:update      reuses the existing meta-data
#
"""
    sow(passwd_help.__doc__)

def honeypot_help():
    """#HELP MESSAGE
#Do you remember the angle brackets and the quotes? If not: type 'help'
#The honey pots are human generated  passwords, whose only purposes are to be
#used as traps.
#honeypot:add:"<value>"                 add a new honey pot
#honeypot:pick                          pick a random honeypot
#honeypot:pick:<n>:"<sep>"              pick <n> random honeypots use <sep>
#                                       a separator between them.
#honeypot:remove:"<value>"              remove
#honeypot:list                          list
#
#
#
#
#
#
#
#
#
#
#
#
"""
    sow(honeypot_help.__doc__)
   
def bells_and_whistles():
    """#BELLS AND WHISTLES
#       *       Comments:       It ignores input-lines that begins with a '#'
#       *       Pipe-through:   If it's input begins with a '|', the rest of
#               the line is written to stdout
#
#
#
#
#
#
#
#
#
#
#
#
#
#
#
#
#
#
"""
    sow(bells_and_whistles.__doc__)

def bugs():
    """#BUGS
#If verbose mode is enabled, it will shout '#READY' to stdout way too much.
#
#
#Lots of places where things should be put inside a try block.
#It is noisy and babbles to much.
#It uses the following methods to parse it's input:
#       int()           python built-in
#       api.unquote()   buggy function in passwdmanapi.py
#       'if "keyword" in some_variable:'
#Some of these big message screens looks ugly
#
#
#
#
#
#
#
#
#
#
#
"""
    sow(bugs.__doc__)
    
def passwd_update(x):   #x ends with a newline
    try:                        #unquote gets rid of optional quotes
        index = p.mkindex(api.unquote(x))  #mkindex greps it's argument
    except:                             #in the list and returns an index
        sow("!not found\n")
        return
    old = p[index]["value"]           #it must show the old password, because
                                  #it is probably required to change password
    v("this may take a while")       #verbose
    try:
        p.update(index)               #do lots of the work in the right place
    except api.err_nometa:
        sow("!no meta\n")               #it requires the meta-data
        return
    new = p[index]["value"]
    sow("#old:new\n")
    sow("passwd.update?'{}':'{}'\n".format(old, new))
    return
    
def passwd_update_meta(x):              #update with new meta-data
    fields = x.split(':', 3)
    if len(fields) < 4: #it takes 4 arguments
        se() #syntax error
        return
    name = api.unquote(fields[3])
    try:
        index = p.mkindex(name)     #where is it
    except:
        sow("!not found\n")
        return
    old = p[index]["value"]             #remember old
    v("this may take a while")
    try:
        p.update_meta(index, fields[0], fields[1], fields[2]) #put the work
                                                    #at the right place
    except api.err_idiot:       #incorrect usage
        sow("!stupid arguments\n")
        return
    except:
        sow("!p.update_meta() failed of unknown reason\n")
    new = p[index]["value"]
    sow("#old:new\n")
    sow("passwd.update?'{}':'{}'\n".format(old, new))
    return
    
def passwd_add(x):
    #passwd:add:<type>:<min>:<max>:<name>
    add_args = x.split(':', 3)
    if len(add_args) < 4:
        se()
        return
    add_type = add_args[0]   #"64" or "10"
    try:
        add_min = int(add_args[1])
        add_max = int(add_args[2])
    except:     #it requires integers
        se()
        return
    add_name = api.unquote(add_args[3])    #ignore newline
    #start testing add_type
    if "human" in add_type:
        se()
        sow("#use 'passwd:add_human'\n")   #add_human is inside passwd_cmds()
        return
    elif "10" in add_type:
        try:            #use digits only
            p.add(add_name, api.get10(api.getint(add_min, add_max + 1)), 
                  "10", str(add_min), str(add_max))
        except api.err_duplicate:
            sow("!duplicate\n")
            return
        except:
            sow("!\n")     #it says what it knows
            return
        v("added base10 password")
        return
    elif "64" in add_type:      #WARNING copy-pasted from 'elif "10"...'
        #                        and hand-hacked '10'->'64'
        try:    #A-Z a-z '_' '!'
            p.add(add_name, api.get64(api.getint(add_min, add_max + 1)), 
                  "64", str(add_min), str(add_max))
        except api.err_duplicate:
            sow("!duplicate\n")
            return
        except:
            sow("!\n")     #it says what it knows
            return
        v("added base64 password")
        return
    else:
        se()
        return

def passwd_cmds(x):  #put all the passwd:* here
    twofields = x.split(':', 1)
    a = twofields[0]
    if len(twofields) < 2:
        if "list" in a:         #list doesn't take any arguments
            index = 0
            sow("#\t\tindex:\tname\n")   #human readable message
            for l in p:
                sow("passwd.list?\t{}:\t'{}'\n".format(index,
                                         l["name"]))
                index += 1
            sow("#READY\n")
            return
        elif "help" in a:       #all big messages are done by calling a
            passwd_help()       #function that prints out it's doc-string
            return
        else:
            se()
            return
    else:
        b = twofields[1]
        if "add_human" in a:            #WARNING must be before "add"
            s = siw()
                                                #it is easier and safer to
            try:                                #take the password on a new
                                                #line
                p.add_nometa(api.unquote(b), s[:-1]) #do the work at the
            except api.err_duplicate:                           #right place
                sow("!duplicate\n")
                return
            except:
                sow("!\n")
                return
            v("added human generated password")
            return
        elif "add" in a:                #WARNING must be after "add_human"
            passwd_add(b)       #go up
            return
        elif "get" in a:       #get the value of a password; get the password
            try:
                sow("passwd.get?'{}'\n".format(p[p.mkindex(b)]
                                                ["value"]))
            except:
                sow("!not found \n")
            return
        elif "update_meta" in a:        #WARNING must be before "update" and
                                        #"meta"
            passwd_update_meta(b)       #go up
            return
        elif "update" in a:             #WARNING must be after "update_meta"
            passwd_update(b)
            return
        elif "meta" in a:               #WARNING must be after "update_meta"
            try:                #get meta-data for a password
                metadata = p[p.mkindex(api.unquote(b))]["meta"]
                sow("#\t\ttype:\tminlength:\tmaxlength\n")
                sow("passwd.meta?\t'{}':\t'{}':\t\t'{}'\n".format(
                                                        metadata["type"],
                                                       metadata["minlength"],
                                                      metadata["maxlength"]))
            except:
                sow("!no meta\n")
            return
        elif "remove" in a:
            try:
                p.remove(api.unquote(b))
            except api.err_notfound:
                sow("!not found\n")
                return
            except:
                sow("!cannot remove, unknown reason\n")
                return
            return
        else:
            se()
            return

def honeypot_cmds(x):           #honeypot:*
    twofields = x.split(':', 1)
    a = twofields[0]
    if len(twofields) < 2:
        if "list" in a:
            index = 0
            sow("#\t\tindex:\tname\n")
            for value in h:
                sow("honeypot.list?\t{}:\t'{}'\n".format(index, value))
                index += 1
            sow("#READY\n")
            return
        elif "help" in a:
            honeypot_help()
            return
        elif "pick" in a:       #pick a random honeypot
            v("this may take a while")
            sow("honeypot.pick?'{}'\n".format(h.pick()))
            return
        else:
            se()
            return
    else:
        b = twofields[1]
        if "add" in a:
            try:
                h.add(api.unquote(b))
            except api.err_duplicate:
                sow("!duplicate\n")
                return
            return
        elif "pick" in a:       #pick takes either 0 or 2 arguments
            args = b.split(':', 1)
            if len(args) < 2:   #It does allow 0, reread this function
                se()
                return
            try:
                n = int(args[0])
            except:
                sow("!n must be an integer\n")
                return
            sep = api.unquote(args[1])
            try:                       #3rd arg, make it raise instead of log
                sow("honeypot.pick?'{}'\n".format(h.pick(n, sep, False)))
            except api.err_idiot:
                sow("!n is too big\n")
                return
            return
        elif "remove" in a:
            try:
                h.remove(api.unquote(b))
            except api.err_notfound:
                sow("!not found\n")
                return
            except:
                sow("!cannot remove, unknown reason\n")
                return
            return
        else:
            se()
            return

def main():             #finally
    global verbose
    global p
    global h
    global theline
    while True:
        v("READY")  #show this message after every command, if verbose
                    #It should be moved to line 666
        theline = siw()[:-1]
        if len(theline) < 1:
            continue
        if theline[0] == "#":           #comment
            continue
        if theline[0] == "|":           #pipe through
            sow(theline[1:])
            continue
        twofields = theline.split(':', 1)
        a = twofields[0]
        if len(twofields) < 2:  #check some really short ones
            if "exit" in a:
                quit()
            elif "help" in a:
                show_help()
            elif "undo" in a:
                try:
                    api.undo(p, h)
                except:
                    sow("!cannot undo\n")
                    continue
                v("undone something")
            elif "redo" in a:
                try:
                    api.redo(p, h)
                except:
                    sow("!cannot redo")
                    continue
                v("redone something")
            elif "bells" in a or "whistles" in a:
                bells_and_whistles()
                continue
            elif "bugs" in a:
                bugs()
                continue
            elif "hell" in a:           #synonym for verbose:on
                verbose = True
                sow("#verbose mode enabled\n")
            else:
                se()    #syntax-error
        else:
            #the string has been split
            b = twofields[1]
            if "passwd" in a:
                passwd_cmds(b)      #passwd:*
            elif "honeypot" in a:
                honeypot_cmds(b)    #honeypot:*
            elif "verbose" in a:
                if "on" in b:           #666
                    verbose = True
                    sow("#verbose mode enabled\n")
                elif "off" in b:
                    verbose = False
                else:
                    se()
                    continue
            else:
                se()
                continue

#initialization
p = api.passwd()
h = api.honeypot()
verbose = False
theline = ""
logging.basicConfig(level=logging.CRITICAL)     #STFU
if __name__ == "__main__":      #I want to do that manually when debugging
    main()