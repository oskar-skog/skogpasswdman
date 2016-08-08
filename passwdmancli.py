#!/usr/bin/python

# -*- coding: utf-8 -*-

import passwdmanapi as api
import sys
import logging
import time
import os
import os.path

#NOTE every line of input ends with a newline, use '[:-1]' on every variable
#       that contains the end of the line.
#BUG Sometimes I forget about the smiley

def se():       #syntax error
    ssw("!syntax error, type 'help'\n")
    ssw('!')
    ssw(theline)

def ssw(x):
    sys.stdout.write(x)         #it is used a lot

def v(x):       #verbose
    if verbose:
        ssw(x)

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
#undo                   undo last change to passwd or honeypot
#help                   obvious
#exit                   obvious
#bugs                   bugs
#whistles               bells and whistles
"""
    ssw(show_help.__doc__)
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
    ssw(passwd_help.__doc__)

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
    ssw(honeypot_help.__doc__)
   
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
    ssw(bells_and_whistles.__doc__)

def bugs():
    """#BUGS
#If verbose mode is enabled, it will shout '#READY' to stdout way too much.
#Lots of places where it will include the trailing newline in it's input.
#[:-1]
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
    ssw(bugs.__doc__)
    
def passwd_update(x):   #x ends with a newline
    try:                        #unquote gets rid of optional quotes
        index = p.mkindex(api.unquote(x[:-1]))  #mkindex greps it's argument
    except:                             #in the list and returns an index
        ssw("!not found\n")
        return
    old = p[index]["value"]           #it must show the old password, because
                                  #it is probably required to change password
    v("#this may take a while\n")       #verbose
    try:
        p.update(index)               #do lots of the work in the right place
    except api.err_nometa:
        ssw("!no meta\n")               #it requires the meta-data
        return
    new = p[index]["value"]
    ssw("#old:new\n")
    ssw("passwd.update?'{}':'{}'\n".format(old, new))
    return
    
def passwd_update_meta(x):              #update with new meta-data
    fields = x.split(':', 3)
    if len(fields) < 4: #it takes 4 arguments
        se() #syntax error
        return
    name = api.unquote(fields[3][:-1])
    try:
        index = p.mkindex(name)     #where is it
    except:
        ssw("!not found\n")
        return
    old = p[index]["value"]             #remember old
    v("#this may take a while\n")
    try:
        p.update_meta(index, fields[0], fields[1], fields[2]) #put the work
                                                    #at the right place
    except api.err_idiot:       #incorrect usage
        ssw("!stupid arguments\n")
        return
    except:
        ssw("!p.update_meta() failed of unknown reason\n")
    new = p[index]["value"]
    ssw("#old:new\n")
    ssw("passwd.update?'{}':'{}'\n".format(old, new))
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
    add_name = api.unquote(add_args[3][:-1])    #ignore newline
    #start testing add_type
    if "human" in add_type:
        se()
        ssw("#use 'passwd:add_human'\n")   #add_human is inside passwd_cmds()
        return
    elif "10" in add_type:
        try:            #use digits only
            p.add(add_name, api.get10(api.getint(add_min, add_max + 1)), 
                  "10", str(add_min), str(add_max))
        except api.err_duplicate:
            ssw("!duplicate\n")
            return
        except:
            ssw("!\n")     #it says what it knows
            return
        v("#added base10 password\n")
        return
    elif "64" in add_type:      #WARNING copy-pasted from 'elif "10"...'
        #                        and hand-hacked '10'->'64'
        try:    #A-Z a-z '_' '!'
            p.add(add_name, api.get64(api.getint(add_min, add_max + 1)), 
                  "64", str(add_min), str(add_max))
        except api.err_duplicate:
            ssw("!duplicate\n")
            return
        except:
            ssw("!\n")     #it says what it knows
            return
        v("#added base64 password\n")
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
            ssw("#\t\tindex:\tname\n")   #human readable message
            for l in p:
                ssw("passwd.list?\t{}:\t'{}'\n".format(index,
                                         l["name"].encode(encoding="utf-8")))
                index += 1
            ssw("#READY\n")
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
            s = sys.stdin.readline()            #it is easier and safer to
            try:                                #take the password on a new
                                                #line
                p.add_nometa(api.unquote(b[:-1]), s[:-1]) #do the work at the
            except api.err_duplicate:                           #right place
                ssw("!duplicate\n")
                return
            except:
                ssw("!\n")
                return
            v("#added human generated password\n")
            return
        elif "add" in a:                #WARNING must be after "add_human"
            passwd_add(b)       #go up
            return
        elif "get" in a:       #get the value of a password; get the password
            try:
                ssw("passwd.get?'{}'\n".format(p[p.mkindex(b[:-1])]
                                                ["value"]))
            except:
                ssw("!not found \n")
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
                metadata = p[p.mkindex(api.unquote(b[:-1]))]["meta"]
                ssw("#\t\ttype:\tminlength:\tmaxlength\n")
                ssw("passwd.meta?\t'{}':\t'{}':\t\t'{}'\n".format(
                                                        metadata["type"],
                                                       metadata["minlength"],
                                                      metadata["maxlength"]))
            except:
                ssw("!no meta\n")
            return
        elif "remove" in a:
            try:
                p.remove(api.unquote(b[:-1]))
            except api.err_notfound:
                ssw("!not found\n")
                return
            except:
                ssw("!cannot remove, unknown reason\n")
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
            ssw("#\t\tindex:\tname\n")
            for value in h:
                ssw("honeypot.list?\t{}:\t'{}'\n".format(index, value))
                index += 1
            ssw("#READY\n")
            return
        elif "help" in a:
            honeypot_help()
            return
        elif "pick" in a:       #pick a random honeypot
            v("#this may take a while\n")
            ssw("honeypot.pick?'{}'\n".format(h.pick()))
            return
        else:
            se()
            return
    else:
        b = twofields[1]
        if "add" in a:
            try:
                h.add(api.unquote(b[:-1]))
            except api.err_duplicate:
                ssw("!duplicate\n")
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
                ssw("!n must be an integer\n")
                return
            sep = api.unquote(args[1][:-1])
            try:                       #3rd arg, make it raise instead of log
                ssw("honeypot.pick?'{}'\n".format(h.pick(n, sep, False)))
            except api.err_idiot:
                ssw("!n is too big\n")
                return
            return
        elif "remove" in a:
            try:
                h.remove(api.unquote(b[:-1]))
            except api.err_notfound:
                ssw("!not found\n")
                return
            except:
                ssw("!cannot remove, unknown reason\n")
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
        v("#READY\n")  #show this message after every command, if verbose
                    #It should be moved to line 666
        theline = sys.stdin.readline()          #TODO put the smiley here,
                                                #instead of everywhere else.
        if theline[0] == "#":           #comment
            continue
        if theline[0] == "|":           #pipe through
            ssw(theline[1:])
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
                    ssw("!cannot undo\n")
                    continue
                v("#undone something\n")
            elif "bells" in a or "whistles" in a:
                bells_and_whistles()
                continue
            elif "bugs" in a:
                bugs()
                continue
            elif "hell" in a:           #synonym for verbose:on
                verbose = True
                ssw("#verbose mode enabled\n")
            else:
                se()    #syntax-error
        else:
            #the string has been split
            b = twofields[1]
            if "passwd" in a:
                try:
                    passwd_cmds(b)      #passwd:*
                except:
                    ssw("!unhandled error\n")
            elif "honeypot" in a:
                try:
                    honeypot_cmds(b)    #honeypot:*
                except:
                    ssw("!unhandled error\n")
            elif "verbose" in a:
                if "on" in b:           #666
                    verbose = True
                    ssw("#verbose mode enabled\n")
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