#!/usr/bin/env python
# Version 0.2.1 - Weston Nielson <wnielson@github>
#

import cgi
import filecmp
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
import urlparse

from distutils.spawn import find_executable

log = logging.getLogger("prt")

if sys.platform == "darwin":
    # OS X
    TRANSCODER_DIR  = "/Applications/Plex Media Server.app/Contents/Resources/"
    LD_LIBRARY_PATH = "/Applications/Plex Media Server.app/Contents/Frameworks/"
    LOG_PATH        = os.path.expanduser("~/Library/Logs/Plex Media Server.log")
elif sys.platform.startswith('linux'):
    # Linux
    TRANSCODER_DIR  = "/usr/lib/plexmediaserver/Resources/"
    LD_LIBRARY_PATH = "/usr/lib/plexmediaserver"
    LOG_PATH        = "/var/lib/plexmediaserver/Library/Application Support/Plex Media Server/Logs/Plex Media Server.log"
else:
    raise NotImplementedError("This platform is not yet supported")

DEFAULT_CONFIG = {
    "ipaddress": "",
    "path_script":    None,
    "servers_script": None,
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
__version__ = "0.2.2"


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
        print "Transcoder appears to have been renamed previously...not renaming (try overwrite option)"
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
            os.chmod(get_transcoder_path(ORIGINAL_TRANSCODER_NAME), 0755)
        except Exception, e:
            print "Error installing new transcoder: %s" % str(e)


# Overwrite_transcoder_after_upgrade function
def overwrite_transcoder_after_upgrade():
    """
    Moves the upgraded transcoder "Plex New Transcoder" to the new name given
    by ``TRANSCODER_NAME`` if the plex package has overwritten the old one.
    """
    old_path = get_transcoder_path(ORIGINAL_TRANSCODER_NAME)
    new_path = get_transcoder_path(NEW_TRANSCODER_NAME)

    prt_remote = find_executable("prt_remote")
    if not prt_remote:
        print "Couldn't find `prt_remote` executable"
        sys.exit(2)
    elif os.path.exists(new_path):
           print "Transcoder appears to have been renamed previously...checking if it's been overwritten"
           if not filecmp.cmp(prt_remote, get_transcoder_path(ORIGINAL_TRANSCODER_NAME), shallow=1):
               try:
                   shutil.copyfile(prt_remote, get_transcoder_path(ORIGINAL_TRANSCODER_NAME))
                   os.chmod(get_transcoder_path(ORIGINAL_TRANSCODER_NAME), 0755)
               except Exception, e:
                   print "Error installing new transcoder: %s" % str(e)
                   sys.exit(2)
           else:
               print "Transcoder hasn't been overwritten by upgrade, nothing to do"
               sys.exit(1)
    else:
         print "Transcoder hasn't been previously installed, please use install option"
         sys.exit(1)


def transcode_local():
    setup_logging()

    # The transcoder needs to have the propery LD_LIBRARY_PATH
    # set, otherwise it cannot run
    os.environ["LD_LIBRARY_PATH"] = "%s:$LD_LIBRARY_PATH" % LD_LIBRARY_PATH

    # Set up the arguments
    args = [get_transcoder_path()] + sys.argv[1:]

    try:
        session = get_transcode_session_details(args)
        log.info("Session details: %s" % str(session))
    except Exception, e:
        log.error("Error getting session details: %s" % str(e))

    log.info("Launching transcode_local: %s\n" % args)

    # Spawn the process
    proc = subprocess.Popen(args)
    proc.wait()


def transcode_remote():
    setup_logging()

    config = get_config()
    args   = sys.argv[1:]

    # Check to see if we need to call a user-script to replace/modify the file path
    if config.get("path_script", None):
        idx = 0
        # The file path comes after the "-i" command line argument
        for i, v in enumerate(args):
            if v == "-i":
                idx = i+1
                break

        # Found the requested video path
        path = args[idx]

        try:
            proc = subprocess.Popen([config.get("path_script"), path], stdout=subprocess.PIPE)
            proc.wait()
            new_path = proc.stdout.readline().strip()
            if new_path:
                log.debug("Replacing path with: %s" % new_path)
                args[idx] = new_path
        except Exception, e:
            log.error("Error calling path_script: %s" % str(e))

    command = REMOTE_ARGS % {
        "ld_path":      "%s:$LD_LIBRARY_PATH" % LD_LIBRARY_PATH,
        "working_dir":  os.getcwd(),
        "command":      "prt_local",
        "args":         ' '.join([pipes.quote(a) for a in args])
    }

    servers = config["servers"]

    # Look to see if we need to run an external script to get hosts
    if config.get("servers_script", None):
        try:
            proc = subprocess.Popen([config["servers_script"]], stdout=subprocess.PIPE)
            proc.wait()

            servers = {}
            for line in proc.stdout.readlines():
                hostname, port, user = line.strip().split()
                servers[hostname] = {
                    "port": port,
                    "user": user
                }
        except Exception, e:
            log.error("Error retreiving host list via '%s': %s" % (config["servers_script"], str(e)))

    hostname, host = None, None

    # Let's try to load-balance
    min_load = None
    for hostname, host in servers.items():

        log.debug("Getting load for host '%s'" % hostname)
        load = get_system_load_remote(hostname, host["port"], host["user"])

        if not load:
            # If no load is returned, then it is likely that the host
            # is offline or unreachable
            log.debug("Couldn't get load for host '%s'" % hostname)
            continue

        log.debug("Log for '%s': %s" % (hostname, str(load)))

        # XXX: Use more that just 1-minute load?
        if min_load is None or min_load[1] > load[0]:
            min_load = (hostname, load[0],)

    if min_load is None:
        log.info("No hosts found...using local")
        return transcode_local()

    # Select lowest-load host
    log.info("Host with minimum load is '%s'" % min_load[0])
    hostname, host = min_load[0], servers[min_load[0]]

    log.info("Using transcode host '%s'" % hostname)

    # Remap the 127.0.0.1 reference to the proper address
    command = command.replace("127.0.0.1", config["ipaddress"])

    #
    # TODO: Remap file-path to PMS URLs
    #

    args = ["ssh", "%s@%s" % (host["user"], hostname), "-p", host["port"]] + [command]

    log.info("Launching transcode_remote with args %s\n" % args)

    # Spawn the process
    proc = subprocess.Popen(args)
    proc.wait()


def get_transcode_session_details(args):
    """
    Extracts the session details from the Plex log file.  It does this by
    looking for all lines that contain a call to "/video/:/transcode/" and
    extracting the associated session data.  If session data was successfully
    found, this returns a `dict` similar to the following:

        {'Accept-Language':          'en',
         'X-Plex-Client-Identifier': '12345678',
         'X-Plex-Device':            'OSX',
         'X-Plex-Device-Name':       'Plex Web (Safari)',
         'X-Plex-Platform':          'Safari',
         'X-Plex-Platform-Version':  '9.0',
         'X-Plex-Product':           'Plex Web',
         'X-Plex-Username':          'wnielson',
         'X-Plex-Version':           '2.4.23',
         'audioBoost':               '100',
         'directPlay':               '0',
         'directStream':             '1',
         'fastSeek':                 '1',
         'mediaIndex':               '0',
         'offset':                   '0',
         'partIndex':                '0',
         'path':                     'http://127.0.0.1:32400/library/metadata/8',
         'protocol':                 'hls',
         'session':                  '6sfg5w1xv5c',
         'subtitleSize':             '100',
         'subtitles':                'burn'}
    """
    session_details = {}
    
    # Try to find the session ID in the args
    session_id = None
    for arg in args:
        if arg.find("video/:/transcode") > -1:
            session_id = arg.split("transcode/session/")[-1].split("/")[0]
            break

    # Open the plex log file and look for the session details
    fh = None
    if session_id:
        try:
            fh = open(LOG_PATH, "r")
        except:
            log.info("Couldn't open Plex log file: %s" % LOG_PATH)

    if fh:
        # Seek back from the end of the log file
        fh.seek(-8192, 2)
        for line in fh.xreadlines():
            if line.find("/video/:/transcode/") > -1:
                url = urlparse.urlparse(line.split("/video/:/transcode/")[-1].split(" ")[0])
                details = dict(cgi.parse_qsl(url.query))
                if details.get("session") == session_id:
                    session_details.update(details)
        fh.close()
    
    return session_details


def version():
    print "Plex Remote Transcoder version %s, Copyright (C) %s\n" % (__version__, __author__)


# Usage function
def usage():
    __runningfile__ = os.path.basename(__file__)
    print "Usage for Plex Remote Transcoder (prt)"
    print "%s [options]\n" % (__runningfile__)
    print "Options:\n" \
    "usage, help, -h, ?\tshows usage page\n" \
    "get_load\t\tshows the load of the system\n" \
    "install\t\t\tinstalls PRT for the first time and then sets up configuration\n" \
    "overwrite\t\tfixes PRT after PMS has had a version update breaking PRT\n" \
    "add_host\t\tadds an extra host to the list of slaves PRT is to use\n" \
    "remove_host\t\tremoves a host from the list of slaces PRT is to use\n"


def main():
    # Specific usage options
    if any( [len(sys.argv) < 2 , sys.argv[1] == "usage", sys.argv[1] == "help", sys.argv[1] == "-h",
             sys.argv[1] == "?",] ):
        usage()
        sys.exit(-1)

# TODO: get_load_all to show load currently across all nodes
# TODO: show_hosts_status to show current status across all nodes

    if sys.argv[1] == "get_load":
        print " ".join([str(i) for i in get_system_load_local()])

    elif sys.argv[1] == "install":
        print "Installing Plex Remote Transcoder"
        config = get_config()
        config["ipaddress"] = raw_input("IP address of this machine: ")
        save_config(config)

        install_transcoder()

    elif sys.argv[1] == "add_host":
        host = None
        port = None
        user = None

        if len(sys.argv) >= 3:
            host = sys.argv[2]
        if len(sys.argv) >= 4:
            port = sys.argv[3]
        if len(sys.argv) >= 5:
            user = sys.argv[4]

        if host is None:
            host = raw_input("Host: ")
        if port is None:
            port = raw_input("Port: ")
        if user is None:
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

    elif sys.argv[1] == "remove_host":
        config = get_config()
        try:
            del config["servers"][sys.argv[2]]
            print "Host removed"
        except Exception, e:
            print "Error removing host: %s" % str(e)

    # Added version option rather than just for no options
    elif any( [sys.argv[1] == "version", sys.argv[1] == "v", sys.argv[1] == "V"] ):
        version()
        sys.exit(0)

    # Overwrite option (for after plex package update/upgrade)
    elif sys.argv[1] == "overwrite":
            overwrite_transcoder_after_upgrade()
            print "Transcoder overwritten successfully"

    # Todo: list_hosts option to show current hosts to aid add/remove_host options - Liviynz

    # Anything not listed shows usage
    else:
        usage()
        sys.exit(-1)

