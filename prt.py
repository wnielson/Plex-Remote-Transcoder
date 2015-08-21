#!/usr/bin/env python
import json
import logging
import os
import pipes
import shlex
import shutil
import subprocess
import sys
import time

from distutils.spawn import find_executable

log = open("/tmp/plex_transcode_log", "wa")

if sys.platform == "darwin":
    # OS X
    TRANSCODER_DIR  = "/Applications/Plex Media Server.app/Contents/Resources/"
    LD_LIBRARY_PATH = "/Applications/Plex Media Server.app/Contents/Frameworks/"
elif sys.platform.startswith('linux'):
    # Linux
    TRANSCODER_DIR  = "/usr/lib/plexmediaserver/Resources/"
    LD_LIBRARY_PATH = "/usr/lib/plexmediaserver"
else:
    raise NotImplementedError("This platform is not yet supported")

DEFAULT_CONFIG = {
    "ipaddress": "",
    "servers":   {}
}

# This is the name we give to the original transcoder, which must be renamed
NEW_TRANSCODER_NAME	 	 = "plex_transcoder"
ORIGINAL_TRANSCODER_NAME = "Plex New Transcoder"

REMOTE_ARGS = ("export LD_LIBRARY_PATH=%(ld_path)s;"
               "cd %(working_dir)s;"
               "%(command)s %(args)s")

__author__  = "Weston Nielson <wnielson@github>"
__version__ = "0.1.3"

def get_config():
    path = os.path.expanduser("~/.prt.conf")
    try:
        return json.load(open(path))
    except Exception, e:
        return DEFAULT_CONFIG.copy()

def save_config(d):
    path = os.path.expanduser("~/.prt.conf")
    try:
        json.dump(d, open(path, 'w'))
        return True
    except Exception, e:
        print "Error loading config: %s" % str(e)
    return False

def get_transcoder_path(name=NEW_TRANSCODER_NAME):
    """
    Returns the full path to ``name`` located in ``TRANSCODER_DIR``.
    """
    return os.path.join(TRANSCODER_DIR, name)

def rename_transcoder():
    """
    Moves the original transcoder "Plex New Transcoder" to the new name given
    by ``TRANSCODER_NAME``.
    """
    old_path = get_transcoder_path(ORIGINAL_TRANSCODER_NAME)
    new_path = get_transcoder_path(NEW_TRANSCODER_NAME)

    if os.path.exists(new_path):
        print "Transcoder appears to have been renamed previously...not renaming"
        return False
    
    try:
        os.rename(old_path, new_path)
    except Exception, e:
        print "Error renaming original transcoder: %s" % str(e)
        return False

    return True

def install_transcoder():
    prt_remote = find_executable("prt_remote")
    if not prt_remote:
        print "Couldn't find `prt_remote` executable"
        return

    print "Renaming original transcoder"
    if rename_transcoder():
        try:
            shutil.copyfile(prt_remote, get_transcoder_path(ORIGINAL_TRANSCODER_NAME))
            os.chmod(get_transcoder_path(ORIGINAL_TRANSCODER_NAME), 0777)
        except Exception, e:
            print "Error installing new transcoder: %s" % str(e)

def transcode_local():
    # The transcoder needs to have the propery LD_LIBRARY_PATH
    # set, otherwise it cannot run
    os.environ["LD_LIBRARY_PATH"] = "%s:$LD_LIBRARY_PATH" % LD_LIBRARY_PATH

    # Set up the arguments
    args = [get_transcoder_path()] + sys.argv[1:]

    log.write("Launching transcode_local: %s\n" % args)
    log.flush()

    # Spawn the process
    proc = subprocess.Popen(args)
    proc.wait()

def transcode_remote():
    command = REMOTE_ARGS % {
        "ld_path":      "%s:$LD_LIBRARY_PATH" % LD_LIBRARY_PATH,
        "working_dir":  os.getcwd(),
        "command":      "prt_local",
        "args":         ' '.join([pipes.quote(a) for a in sys.argv[1:]])
    }

    config = get_config()

    if len(config["servers"]) == 0:
        log.write("No hosts found...using local")
        return transcode_local()

    # TODO: Decide which host to use better.  For now, choose first one
    hostname, host = config["servers"].items()[0]

    # Remap the 127.0.0.1 reference to the proper address
    command.replace("127.0.0.1", config["ipaddress"])

    args = ["ssh", "%s@%s" % (host["user"], hostname), "-p", host["port"]] + [command]

    log.write("Launching transcode_remote: %s\n" % args)
    log.flush()

    # Spawn the process
    proc = subprocess.Popen(args)
    proc.wait()

def usage():
    return

def main():
    print "Plex Remote Transcoder version %s, Copyright (C) %s\n" % (__version__, __author__)

    if len(sys.argv) < 2:
        return usage()

    if sys.argv[1] == "install":
        print "Installing Plex Remote Transcoder"
        config = get_config()
        config["ipaddress"] = raw_input("IP address of this machine: ")
        save_config(config)

        install_transcoder()
    elif sys.argv[1] == "add_host":
        host = raw_input("Host: ")
        port = raw_input("Port: ")
        user = raw_input("User: ")

        print "We're going to add the following transcode host:"
        print "  Host: %s" % host
        print "  Port: %s" % port
        print "  User: %s" % user

        if raw_input("Proceed: [y/n]").lower() == "y":
            config = get_config()
            config["servers"][host] = {
                "port": port,
                "user": user
            }

            if save_config(config):
                print "Host successfully added"
