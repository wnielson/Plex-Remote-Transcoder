#!/usr/bin/env python
import json
import logging
import logging.config
import multiprocessing
import os
import pipes
import re
import shlex
import shutil
import subprocess
import sys
import time
#import requests

from distutils.spawn import find_executable

log = logging.getLogger("prt")

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
    "servers":   {},
    "logging":   {
        "version": 1,
        "disable_existing_loggers": False,
        "formatters": {
            "simple": {
                "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
            }
        },
        "handlers": {
            "file_handler": {
                "class": "logging.handlers.RotatingFileHandler",
                "level": "INFO",
                "formatter": "simple",
                "filename": "prt.log",
                "maxBytes": 10485760,
                "backupCount": 20,
                "encoding": "utf8"
            },
        },
        "loggers": {
            "prt": {
                "level": "DEBUG",
                "handlers": ["file_handler"],
                "propagate": "no"
            }
        }
    }
}

# This is the name we give to the original transcoder, which must be renamed
NEW_TRANSCODER_NAME	 	 = "plex_transcoder"
ORIGINAL_TRANSCODER_NAME = "Plex New Transcoder"

REMOTE_ARGS = ("export LD_LIBRARY_PATH=%(ld_path)s;"
               "cd %(working_dir)s;"
               "%(command)s %(args)s")

LOAD_AVG_RE = re.compile(r"load averages: ([\d\.]+) ([\d\.]+) ([\d\.]+)")

__author__  = "Weston Nielson <wnielson@github>"
__version__ = "0.2.0"

def get_config():
    path = os.path.expanduser("~/.prt.conf")
    try:
        return json.load(open(path))
    except Exception, e:
        return DEFAULT_CONFIG.copy()

def save_config(d):
    path = os.path.expanduser("~/.prt.conf")
    try:
        json.dump(d, open(path, 'w'), indent=4)
        return True
    except Exception, e:
        print "Error loading config: %s" % str(e)
    return False

def get_system_load_local():
    """
    Returns a list of float representing the percentage load of this machine.
    """
    nproc = multiprocessing.cpu_count()
    load  = os.getloadavg()
    return [l/nproc * 100 for l in load]

def get_system_load_remote(host, port, user):
    """
    Gets the result from ``get_system_load_local`` of a remote machine.
    """
    proc = subprocess.Popen(["ssh", "%s@%s" % (user, host), "-p", port, "prt", "get_load"], stdout=subprocess.PIPE)
    proc.wait()
    return [float(i) for i in proc.stdout.read().strip().split()]

def setup_logging():
    config = get_config()
    logging.config.dictConfig(config["logging"])

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
    setup_logging()

    # The transcoder needs to have the propery LD_LIBRARY_PATH
    # set, otherwise it cannot run
    os.environ["LD_LIBRARY_PATH"] = "%s:$LD_LIBRARY_PATH" % LD_LIBRARY_PATH

    # Set up the arguments
    args = [get_transcoder_path()] + sys.argv[1:]

    log.info("Launching transcode_local: %s\n" % args)

    # Spawn the process
    proc = subprocess.Popen(args)
    proc.wait()

def transcode_remote():
    setup_logging()

    #session_id = None
    #for i, v in enumerate(sys.argv[1:]):
    #    if v == "-progressurl":
    #        # TODO: This is crap, should use regex
    #        #requests.put(sys.argv[1:][i+1])
    #        session_id = sys.argv[1:][i+1].split("transcode/session/")[-1].split("/")[0]
    #        break

    #if session_id:
    #    xml = requests.get("http://127.0.0.1:32400/status/sessions")
    #    #dom = ET.parse(xml)
    #    log.debug("xml = %s" % xml.text)
   

    command = REMOTE_ARGS % {
        "ld_path":      "%s:$LD_LIBRARY_PATH" % LD_LIBRARY_PATH,
        "working_dir":  os.getcwd(),
        "command":      "prt_local",
        "args":         ' '.join([pipes.quote(a) for a in sys.argv[1:]])
    }

    config = get_config()

    if len(config["servers"]) == 0:
        log.info("No hosts found...using local")
        return transcode_local()

    hostname, host = None, None

    if len(config["servers"]) > 1:
        # Let's try to load-balance
        min_load = None
        
        for hostname, host in config["servers"].items():
            
            log.debug("Getting load for host '%s'" % hostname)
            load = get_system_load_remote(hostname, host["port"], host["user"])

            log.debug("Log for '%s': %s" % (hostname, str(load)))

            # XXX: Use more that just 1-minute load?
            if min_load is None or min_load[1] > load[0]:
                min_load = (hostname, load[0],)

        # Select lowest-load host
        log.info("Host with minimum load is '%s'" % min_load[0])
        hostname, host = min_load[0], config["servers"][min_load[0]]

    else:
        # We don't have a choice--use the only host
        hostname, host = config["servers"].items()[0]

    log.info("Using transcode host '%s'" % hostname)

    # Remap the 127.0.0.1 reference to the proper address
    command.replace("127.0.0.1", config["ipaddress"])

    #
    # TODO: Remap file-path to PMS URLs
    #

    args = ["ssh", "%s@%s" % (host["user"], hostname), "-p", host["port"]] + [command]

    log.info("Launching transcode_remote with args %s\n" % args)

    # Spawn the process
    proc = subprocess.Popen(args)
    proc.wait()

def usage():
    return

def main():
    if len(sys.argv) < 2:
        print "Plex Remote Transcoder version %s, Copyright (C) %s\n" % (__version__, __author__)
        return usage()

    if sys.argv[1] == "get_load":
        print " ".join([str(i) for i in get_system_load_local()])

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

