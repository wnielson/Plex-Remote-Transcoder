#!/usr/bin/env python
# Weston Nielson <wnielson@github>
# Andy Livingstone <liviynz@github>

import filecmp
import getpass
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
import urllib.request, urllib.parse, urllib.error
import urllib.request, urllib.error, urllib.parse
import uuid

from distutils.spawn import find_executable
import collections

try:
    from xml.etree import cElementTree as ET
except:
    from xml.etree import ElementTree as ET

import psutil

try:
    from termcolor import colored
except:
    def colored(msg, *args):
        return msg

#import pydevd_pycharm
#pydevd_pycharm.settrace('10.1.1.80', port=12345, stdoutToServer=True, stderrToServer=True)

log = logging.getLogger("prt3")

if sys.platform == "darwin":
    # OS X
    TRANSCODER_DIR = "/Applications/Plex Media Server.app/Contents/"
    SETTINGS_PATH  = "~/Library/Preferences/com.plexapp.plexmediaserver"
elif sys.platform.startswith('linux'):
    # Linux
    TRANSCODER_DIR = "/usr/lib/plexmediaserver/"
    SETTINGS_PATH  = "/var/lib/plexmediaserver/Library/Application Support/Plex Media Server/Preferences.xml"
else:
    raise NotImplementedError("This platform is not yet supported")

DEFAULT_CONFIG = {
    "ipaddress": "",
    "path_script":    None,
    "servers_script": None,
    "servers":   {},
    "auth_token": None,
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
                "filename": "/opt/plex/tmp/prt3.log",
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
NEW_TRANSCODER_NAME      = "plex_transcoder"
ORIGINAL_TRANSCODER_NAME = "Plex Transcoder"

REMOTE_ARGS = ("%(env)s;"
               "cd %(working_dir)s;"
               "%(command)s %(args)s")

LOAD_AVG_RE = re.compile(r"load averages: ([\d\.]+) ([\d\.]+) ([\d\.]+)")

PRT_ID_RE   = re.compile(r'PRT_ID=([0-9a-f]{32})', re.I)
SESSION_RE  = re.compile(r'/session/([^/]*)/')
SSH_HOST_RE = re.compile(r'ssh +([^@]+)@([^ ]+)')

__author__  = "Weston Nielson <wnielson@github>"
__version__ = "0.4.5"

def get_config():
    path = os.path.expanduser("~/.prt3.conf")
    try:
        return json.load(open(path))
    except Exception as e:
        return DEFAULT_CONFIG.copy()


def save_config(d):
    path = os.path.expanduser("~/.prt3.conf")
    try:
        json.dump(d, open(path, 'w'), indent=4)
        return True
    except Exception as e:
        print(("Error loading config: %s" % str(e)))
    return False


def printf(message, *args, **kwargs):
    color = kwargs.get('color')
    attrs = kwargs.get('attrs')
    sys.stdout.write(colored(message % args, color, attrs=attrs))
    sys.stdout.flush()

def get_auth_token():
    url = "https://plex.tv/users/sign_in.json"
    headeruser = input("Plex Username:")
    headerpw = getpass.getpass("Plex Password:")
    payload = urllib.parse.urlencode({
        "user[login]": headeruser,
        "user[password]": headerpw,
        "X-Plex-Client-Identifier": "Plex-Remote-Transcoder-v%s" % __version__,
        "X-Plex-Product": "Plex-Remote-Transcoder",
        "X-Plex-Version": __version__
    })

    req = urllib.request.Request(url, payload)
    try:
        res = urllib.request.urlopen(req)
    except:
        print("Error getting auth token...invalid credentials?")
        return False

    if res.code not in [200, 201]:
        print("Invalid credentials")
        return False

    data = json.load(res)
    return data['user']['authToken']


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
    proc = subprocess.Popen(["ssh", "%s@%s" % (user, host), "-p", port, "prt3", "get_load"], stdout=subprocess.PIPE)
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
    Moves the original transcoder "Plex Transcoder" to the new name given
    by ``TRANSCODER_NAME``.
    """
    old_path = get_transcoder_path(ORIGINAL_TRANSCODER_NAME)
    new_path = get_transcoder_path(NEW_TRANSCODER_NAME)

    if os.path.exists(new_path):
        print("Transcoder appears to have been renamed previously...not renaming (try overwrite option)")
        return False

    try:
        os.rename(old_path, new_path)
    except Exception as e:
        print(("Error renaming original transcoder: %s" % str(e)))
        return False

    return True


def install_transcoder():
    prt_remote = find_executable("prt3_remote")
    if not prt_remote:
        print("Couldn't find `prt3_remote` executable")
        return

    print("Renaming original transcoder")
    if rename_transcoder():
        try:
            shutil.copyfile(prt_remote, get_transcoder_path(ORIGINAL_TRANSCODER_NAME))
            os.chmod(get_transcoder_path(ORIGINAL_TRANSCODER_NAME), 0o755)
        except Exception as e:
            print(("Error installing new transcoder: %s" % str(e)))


# Overwrite_transcoder_after_upgrade function
def overwrite_transcoder_after_upgrade():
    """
    Moves the upgraded transcoder "Plex Transcoder" to the new name given
    by ``TRANSCODER_NAME`` if the plex package has overwritten the old one.
    """
    old_path = get_transcoder_path(ORIGINAL_TRANSCODER_NAME)
    new_path = get_transcoder_path(NEW_TRANSCODER_NAME)

    prt_remote = find_executable("prt3_remote")
    if not prt_remote:
        print("Couldn't find `prt3_remote` executable")
        sys.exit(2)
    elif os.path.exists(new_path):
           print("Transcoder appears to have been renamed previously...checking if it's been overwritten")
           if not filecmp.cmp(prt_remote, get_transcoder_path(ORIGINAL_TRANSCODER_NAME), shallow=1):
               try:
                   shutil.copyfile(prt_remote, get_transcoder_path(ORIGINAL_TRANSCODER_NAME))
                   os.chmod(get_transcoder_path(ORIGINAL_TRANSCODER_NAME), 0o755)
               except Exception as e:
                   print(("Error installing new transcoder: %s" % str(e)))
                   sys.exit(2)
           else:
               print("Transcoder hasn't been overwritten by upgrade, nothing to do")
               sys.exit(1)
    else:
         print("Transcoder hasn't been previously installed, please use install option")
         sys.exit(1)

def build_env(host=None):
    # TODO: This really should be done in a way that is specific to the target
    #       in the case that the target is a different architecture than the host
    ffmpeg_path = os.environ.get("FFMPEG_EXTERNAL_LIBS", "")
    backslashcheck = re.search(r'\\', ffmpeg_path)
    if backslashcheck is not None:
        ffmpeg_path_fixed = ffmpeg_path.replace('\\','')
        os.environ["FFMPEG_EXTERNAL_LIBS"] = str(ffmpeg_path_fixed)

    envs = ["export %s=%s" % (k, pipes.quote(v)) for k,v in list(os.environ.items())]
    envs.append("export PRT_ID=%s" % uuid.uuid1().hex)
    return ";".join(envs)


# def check_gracenote_tmp():



def transcode_local():
    setup_logging()

    # The transcoder needs to have the propery LD_LIBRARY_PATH
    # set, otherwise it cannot run
    #os.environ["LD_LIBRARY_PATH"] = "%s:$LD_LIBRARY_PATH" % LD_LIBRARY_PATH
    #for k, v in ENV_VARS.items():
    #    os.environ[k] = v

    config = get_config()
    is_debug = config['logging']['loggers']['prt']['level'] == 'DEBUG'

    if is_debug:
        log.info('Debug mode - enabling verbose ffmpeg output')

        # Change logging mode for FFMpeg to be verbose
        for i, arg in enumerate(sys.argv):
            if arg == '-loglevel':
                sys.argv[i+1] = 'verbose'
            elif arg == '-loglevel_plex':
                sys.argv[i+1] = 'verbose'

    # Set up the arguments
    args = [get_transcoder_path()] + sys.argv[1:]

    log.info("Launching transcode_local: %s\n" % args)

    # Spawn the process
    proc = subprocess.Popen(args, stderr=subprocess.PIPE)

    while True:
        output = proc.stderr.readline()
        if output == '' and proc.poll() is not None:
            break
        if output and is_debug:
            log.debug(output.strip('\n'))

def transcode_remote():
    setup_logging()

    log.info("Checking for orphaned PRT processes")
    found = 0
    for proc in psutil.process_iter():
        try:
            if proc.name == "ssh" and 'PLEX_MEDIA_SERVER' in ' '.join(proc.cmdline):
                if proc.parent.pid == 1:
                    log.info('Found orphaned PRT process (pid %s)...killing' % proc.pid)
                    found += 1
                    proc.terminate()
                    proc.wait()
        except psutil.NoSuchProcess:
            pass

    log.info("Found %d orphaned PRT processes" % found)

    config = get_config()
    args   = sys.argv[1:]


    # FIX: This is (temporary?) fix for the EasyAudioEncoder (EAE) which uses a
    #      hardcoded path in /tmp.  If we find that EAE is being used then we
    #      force transcoding on the master
    if 'eae_prefix' in ' '.join(args):
        log.info("Found EAE is being used...forcing local transcode")
        return transcode_local()

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
        except Exception as e:
            log.error("Error calling path_script: %s" % str(e))

    command = REMOTE_ARGS % {
        "env":          build_env(),
        "working_dir":  pipes.quote(os.getcwd()),
        "command":      "prt3_local",
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
        except Exception as e:
            log.error("Error retreiving host list via '%s': %s" % (config["servers_script"], str(e)))

    hostname, host = None, None

    # Let's try to load-balance
    min_load = None
    for hostname, host in list(servers.items()):

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
    #command = command.replace("127.0.0.1", config["ipaddress"])

    #
    # TODO: Remap file-path to PMS URLs
    #

    args = ["ssh", "-tt", "-R", "32400:127.0.0.1:32400", "%s@%s" % (host["user"], hostname), "-p", host["port"]] + [command]


    log.info("Launching transcode_remote with args %s\n" % args)

    # Spawn the process
    proc = subprocess.Popen(args)
    proc.wait()

    log.info("Transcode stopped on host '%s'" % hostname)


def re_get(regex, string, group=0, default=None):
    match = regex.search(string)
    if match:
        try:
            return match.groups()[group]
        except:
            if group == "all":
                return match.groups()
    return default

def et_get(node, attrib, default=None):
    if node is not None:
        return node.attrib.get(attrib, default)
    return default


def get_plex_sessions(auth_token=None):
    url = 'http://localhost:32400/status/sessions'
    if auth_token:
        url += "?X-Plex-Token=%s" % auth_token

    res = urllib.request.urlopen(url)
    dom = ET.parse(res)
    sessions = {}
    for node in dom.findall('.//Video'):
        session_id = et_get(node.find('.//TranscodeSession'), 'key')
        if session_id:
            sessions[session_id] = {
                'file': et_get(node.find('.//Media/Part'), 'file')
        }
    return sessions

def get_sessions():
    sessions = {}

    config = get_config()
    if config.get('auth_token') == None:
        config['auth_token'] = get_auth_token()
        if not config['auth_token']:
            return sessions
        save_config(config)

    sessions = {}

    plex_sessions = get_plex_sessions(auth_token=config['auth_token'])
    for proc in psutil.process_iter():
        parent_name = None
        try:
            if isinstance(proc.parent, collections.Callable):
                parent_name = proc.parent().name()
            else:
                parent_name = proc.parent.name
        except:
            continue

        if not parent_name:
            continue

        pinfo = proc.as_dict(['name', 'cmdline'])

        # Check the parent to make sure it is the "Plex Transcoder"
        if pinfo['name'] == 'ssh' and 'plex' in parent_name.lower():
            cmdline = ' '.join(pinfo['cmdline'])
            m = PRT_ID_RE.search(cmdline)
            if m:
                session_id = re_get(SESSION_RE, cmdline)
                data = {
                    'proc': pinfo,
                    'plex': plex_sessions.get(session_id, {}),
                    'host': {}
                }

                host = re_get(SSH_HOST_RE, cmdline, 'all')
                if host:
                    data['host'] = {
                        'user':    host[0],
                        'address': host[1]
                    }

                sessions[m.groups()[0]] = data
    return sessions

def check_config():
    """
    Run through various diagnostic checks to see if things are configured
    correctly.
    """
    config = get_config()
    errors = []

    printf("Performing PRT configuration check\n\n", color="blue", attrs=['bold'])

    # First, check the user
    user = getpass.getuser()
    if user != "plex":
        printf("WARNING: Current user is not 'plex'\n", color="red")

    try:
        settings_fh = open(SETTINGS_PATH)
        dom = ET.parse(settings_fh)
        settings = dom.getroot().attrib
    except Exception as e:
        printf("ERROR: Couldn't open settings file - %s", SETTINGS_PATH, color="red")
        return False

    config = get_config()
    if config.get('auth_token') == None:
        config['auth_token'] = get_auth_token()

    url = 'http://localhost:32400/library/sections'
    if config['auth_token']:
        url += "?X-Plex-Token=%s" % config['auth_token']

    res = urllib.request.urlopen(url)
    dom = ET.parse(res)
    media_paths = []
    for node in dom.findall('.//Location'):
        path = et_get(node, 'path')
        if path not in media_paths:
            media_paths.append(path)

    media_paths.append(TRANSCODER_DIR)
    paths_modes = {
        5: media_paths,
        7: [settings['TranscoderTempDirectory']]
    }

    # Let's check SSH access
    for address, server in list(config['servers'].items()):
        printf("Host %s\n", address)

        proc = subprocess.Popen(["ssh", "%s@%s" % (server["user"], address),
            "-p", server["port"], "prt3", "get_load"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        proc.wait()

        printf("  Connect: ")
        if proc.returncode != 0:
            printf("FAIL\n", color="red")
            printf("    %s\n" % proc.stderr.read())
            continue
        else:
            printf("OK\n", color="green")

        for req_mode, paths in list(paths_modes.items()):
            for path in paths:
                printf("  Path: '%s'\n", path)
                proc = subprocess.Popen(["ssh", "%s@%s" % (server["user"], address),
                    "-p", server["port"], "stat", "--printf='%U %a'", pipes.quote(path)],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                proc.wait()

                username, mode = proc.stdout.read().strip().split()
                printf("    User:  %s\n", username)
                printf("    Mode:  %s\n", mode)

                if username != 'plex':
                    printf("    WARN:  Not owned by plex user\n", color="yellow")
                    if int(mode[-1]) < req_mode:
                        printf("    ERROR: Bad permissions\n", color="red")
                else:
                    if int(mode[0]) < req_mode:
                        printf("    ERROR: Bad permissions\n", color="red")

        printf("\n")


def sessions():
    if psutil is None:
        print("Missing required library 'psutil'.  Try 'pip install psutil'.")
        return

    sessions = get_sessions()
    for i, (session_id, session) in enumerate(sessions.items()):
        print(("Session %s/%s" % (i+1, len(sessions))))
        print(("  Host: %s" % session.get('host', {}).get('address')))
        print(("  File: %s" % session.get('plex', {}).get('file')))


def version():
    print(("Plex Remote Transcoder version %s, Copyright (C) %s\n" % (__version__, __author__)))


# Usage function
def usage():
    version()
    print("Plex Remote Transcode comes with ABSOLUTELY NO WARRANTY.\n\n"\
          "This is free software, and you are welcome to redistribute it and/or modify\n"\
          "it under the terms of the MIT License.\n\n")
    print("Usage:\n")
    print(("  %s [options]\n" % os.path.basename(sys.argv[0])))
    print (
        "Options:\n\n" 
        "  usage, help, -h, ?    Show usage page\n" 
        "  get_load              Show the load of the system\n" 
        "  get_cluster_load      Show the load of all systems in the cluster\n" 
        "  install               Install PRT for the first time and then sets up configuration\n" 
        "  overwrite             Fix PRT after PMS has had a version update breaking PRT\n" 
        "  add_host              Add an extra host to the list of slaves PRT is to use\n" 
        "  remove_host           Removes a host from the list of slaves PRT is to use\n"
        "  sessions              Display current sessions\n"
        "  check_config          Checks the current configuration for errors\n")


def main():
    # Specific usage options
    if len(sys.argv) < 2 or any((sys.argv[1] == "usage", sys.argv[1] == "help", sys.argv[1] == "-h",
            sys.argv[1] == "?",)):
        usage()
        sys.exit(-1)

    #user = getpass.getuser()
    #if user != 'plex':
    #    print ("Warning: You are not running as the Plex user")
    #    return

    # TODO: show_hosts_status to show current status across all nodes

    if sys.argv[1] == "get_load":
        print((" ".join([str(i) for i in get_system_load_local()])))

    elif sys.argv[1] == "get_cluster_load":
        print("Cluster Load")
        config = get_config()
        servers = config["servers"]
        for address, server in list(servers.items()):
            load = ["%0.2f%%" % l for l in get_system_load_remote(address, server["port"], server["user"])]
            print(("  %15s: %s" % (address, ", ".join(load))))

    elif sys.argv[1] == "install":
        print("Installing Plex Remote Transcoder")
        config = get_config()
        config["ipaddress"] = input("IP address of this machine: ")
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
            host = input("Host: ")
        if port is None:
            port = eval(input("Port: "))
        if user is None:
            user = input("User: ")

        print("We're going to add the following transcode host:")
        print(("  Host: %s" % host))
        print(("  Port: %s" % port))
        print(("  User: %s" % user))

        if input("Proceed: [y/n]").lower() == "y":
            config = get_config()
            config["servers"][host] = {
                "port": port,
                "user": user
            }

            if save_config(config):
                print("Host successfully added")

    elif sys.argv[1] == "remove_host":
        config = get_config()
        try:
            del config["servers"][sys.argv[2]]
            save_config(config)
            print("Host removed")
        except Exception as e:
            print(("Error removing host: %s" % str(e)))

    # Added version option rather than just for no options
    elif any( [sys.argv[1] == "version", sys.argv[1] == "v", sys.argv[1] == "V"] ):
        version()
        sys.exit(0)

    # Overwrite option (for after plex package update/upgrade)
    elif sys.argv[1] == "overwrite":
            overwrite_transcoder_after_upgrade()
            print("Transcoder overwritten successfully")

    elif sys.argv[1] == "sessions":
        sessions()

    elif sys.argv[1] == "check_config":
        check_config()

    # Todo: list_hosts option to show current hosts to aid add/remove_host options - Liviynz

    # Anything not listed shows usage
    else:
        usage()
        sys.exit(-1)



