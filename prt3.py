#!/usr/bin/env python3
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
import base64
import shutil
from shlex import quote
import subprocess
import sys
import hashlib
import urllib.request, urllib.error, urllib.parse, urllib.response
import uuid
import asyncio

from distutils.spawn import find_executable

try:
    from xml.etree import cElementTree as ET
except:
    from xml.etree import ElementTree as ET

import psutil

try:
    from termcolor import colored, cprint
except:
    def colored(msg, *args):
        return msg


log = logging.getLogger("prt3")

path_quote_needed = None

if sys.platform == "darwin":
    # OS X
    TRANSCODER_DIR = "/Applications/Plex Media Server.app/Contents/"
    SETTINGS_PATH = "~/Library/Preferences/com.plexapp.plexmediaserver"
elif sys.platform.startswith('linux'):
    # Linux
    TRANSCODER_DIR = "/usr/lib/plexmediaserver/"
    SETTINGS_PATH = "/var/lib/plexmediaserver/Library/Application Support/Plex Media Server/Preferences.xml"
else:
    raise NotImplementedError("This platform is not yet supported")

DEFAULT_CONFIG = {
    "ipaddress": "",
    "path_script": None,
    "servers_script": None,
    "servers": {},
    "auth_token": None,
    "user": "plex",
    "logging": {
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
            "prt3": {
                "level": "DEBUG",
                "handlers": ["file_handler"],
                "propagate": "no"
            }
        }
    }
}

# This is the name we give to the original transcoder, which must be renamed
NEW_TRANSCODER_NAME = "plex_transcoder"
ORIGINAL_TRANSCODER_NAME = "Plex Transcoder"

prtuser = "plex"
prthomeabbr = '~' + prtuser + '/'
prthome = os.path.expanduser(prthomeabbr)
PRTSYSTEMDDIR = "/etc/systemd/system/plexmediaserver.service.d/"
PRTSYSTEMDFILE = "10-prt.conf"
PRTSYSTEMD = PRTSYSTEMDDIR + PRTSYSTEMDFILE
PMSSYSTEMD = "/lib/systemd/system/plexmediaserver.service"
PRTTMPVARS = ['TMPDIR', 'PLEX_MEDIA_SERVER_TMPDIR']
SYSTEMDENV = "Environment="
PRTSHARED = "/opt/plex/tmp/"
PRTNODES = prthome + '.ssh/prt_nodes/'
PRTNODESabbr = prthomeabbr + '.ssh/prt_nodes/'
prtsshconf = prthome + '.ssh/config'
prtconf = prthome + '.prt.conf'
prt3conf = prthome + '.prt3.conf'
plex_uid = os.getuid()
plex_guid = os.getgid()
prt_prev_conf = 'unknown'
prt_install = 'unknown'
prt3_prev_conf = 'unknown'
prt3_install = 'unknown'
pms_transcoder = None
pms_trans_file = None
pms_renamed_trans_file = None


REMOTE_ARGS = ("%(env)s;"
               "cd %(working_dir)s;"
               "%(command)s %(args)s")

LOAD_AVG_RE = re.compile(r"load averages: ([\d.]+) ([\d.]+) ([\d.]+)")

PRT_ID_RE = re.compile(r'PRT_ID=([0-9a-f]{32})', re.I)
SESSION_RE = re.compile(r'/session/([^/]*)/')
TRANSCODE_RE = re.compile(r'/transcode/session/([^/]*)/')
SSH_HOST_RE = re.compile(r'ssh +([^@]+)@([^ ]+)')

__author__ = "Andy Livingstone <liviynz@github>"
__creator__ = "Weston Nielson <wnielson@github>"
__version__ = "3.0.0"


def upgrade_config():
    if os.path.isfile(prtconf):
        clean_conf = DEFAULT_CONFIG.copy()
        old_conf = json.load(open(prtconf))
        del old_conf['logging']['loggers']['prt']
        old_conf['logging']['loggers']['prt3'] = clean_conf['logging']['loggers']['prt3']
        del old_conf['logging']['handlers']['file_handler']['filename']
        old_conf['logging']['handlers']['file_handler']['filename'] = clean_conf['logging']['handlers']['file_handler']['filename']
        merged_conf = {**clean_conf, **old_conf}
        del merged_conf['servers']
        merged_conf['servers'] = {}
        print(" ")
        cprint("A PRT config file has been found, importing it and converting it to PRT3 format.", 'blue', attrs=['bold'])
        cprint("In PRT3 we use simple names for systems rather than IP addressed, let's set some up.", 'blue',
        attrs=['bold'])
        for server, host in list(old_conf['servers'].items()):
            print(" ")
            accept_name = None
            while accept_name is None:
                new_name = input("Enter name to use for %s: " % server)
                if not re.search(r'^[0-9a-zA-Z]{1,10}$', new_name):
                    cprint("Name entered '%s' not valid! [1-10 Alphanumeric characters only]", 'red')
                else:
                    if input("Confirm to use name %s for %s? : [y/n]" % (new_name, server)).lower() == "y":
                        merged_conf['servers'][new_name] = {
                            'addr': server,
                            'port': host['port'],
                            'user': host['user'],
                            'group': 'default'
                        }
                        accept_name = 'accepted'

        return merged_conf.copy()
    else:
        return DEFAULT_CONFIG.copy()


def get_config():
    if not os.path.isfile(prt3conf):
        if os.path.isfile(prtconf):
            if os.geteuid() == 0:
                cprint("You are running prt3 with root privs, run it normally and it will attempt to auto sudo", 'red')
                exit(1)

            upgraded_config = upgrade_config()
            return upgraded_config
        else:
            return DEFAULT_CONFIG.copy()
    else:
        try:
            return json.load(open(prt3conf))
        except Exception as e:
            return DEFAULT_CONFIG.copy()



def save_config(d):
    try:
        json.dump(d, open(prt3conf, 'w'), indent=4)
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
    print(" ")
    headeruser = input("Plex Username: ")
    headerpw = getpass.getpass("Plex Password: ")
    client_name = "Plex-Remote-Transcoder-v%s" % __version__
    client_version = "Plex-Remote-Transcoder"
    client_id = hashlib.sha512('{} {}'.format(client_name, client_version).encode()).hexdigest()
    base64string = base64.b64encode('{}:{}'.format(headeruser, headerpw).encode())
    headers = {
        'Authorization': 'Basic {}'.format(base64string.decode('ascii')),
        "X-Plex-Client-Identifier": client_id,
        "X-Plex-Product": "Plex-Remote-Transcoder",
        "X-Plex-Version": __version__
    }
    req = urllib.request.Request(url, headers=headers, method='POST')
    try:
        res = urllib.request.urlopen(req)
    except Exception as e:
        print(str(e))
        print("Error getting auth token...invalid credentials?")
        return False

    if res.status not in [200, 201]:
        print("Invalid credentials")
        return False
    #
    ### print(res.status, res.headers)
    data = json.loads(res.read().decode())
    ### print('Auth-Token: {}'.format(data['user']['authentication_token']))
    return data['user']['authToken']


def get_system_load_local():
    """
    Returns a list of float representing the percentage load of this machine.
    """
    nproc = multiprocessing.cpu_count()
    load = os.getloadavg()
    return [int(l / nproc * 100) for l in load]


def get_system_load(*sshload):
    process = subprocess.run(
        [*sshload],
        encoding='utf-8',
        stdout=subprocess.PIPE)

    load = [int(i) for i in process.stdout.split()]
    #loaderror = stderr.decode().strip()
    loaderror = "blah"
    # log.debug("Result : %s, pid=%s, returncode=%s stderror=%s" % (remload, remloadpid, remloadreturn, remloaderror))
    return load


def get_cluster_load():
    log.debug("Staring Cluster Load Function")
    config = get_config()
    cluster_load = {}
    plex_home = os.getenv("HOME")
    for server, host in list(config['servers'].items()):
        log.debug(cluster_load)
        log.debug("Getting load for host '%s'" % server)
        if host['addr'] != "127.0.0.1":
            sshload = ['ssh', '%s' % (server), 'prt3', 'get_load']
            load = [l for l in get_system_load(*sshload)]
        else:
            load = [i for i in (get_system_load_local())]

        if not load:
            # If no load is returned, then it is likely that the host
            # is offline or unreachable
            log.debug("Couldn't get load for host '%s'" % server)
            cluster_load[server] = [int(99999), int(99999), int(99999)]
            continue
        else:
            log.debug("  %15s: %s%% %s%% %s%%" % (server, load[0], load[1], load[2]))
            log.info("Log for '%s': %s" % (server, str(load)))
            cluster_load[server] = load

    return cluster_load


async def remote_command(sshcmd):
    process = await asyncio.create_subprocess_shell(
        sshcmd,
        encoding='utf-8',
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE)

    stdout, stderr = await process.communicate()

    if process.returncode == 0:
        wibble = 1
    else:
        print(
            "Failed: %s, pid=%s, result: %s"
            % (sshcmd, process.pid, ' '.join([i for i in stdout.decode().strip().split()])),
            flush=True,
        )

    result = [i for i in stdout.decode().strip().split()]
    remotepid = process.pid
    remotereturn = process.returncode
    remoteerror = ' '.join([i for i in stderr.decode().strip()])

    try:
        remoteerror = 1
    except NameError:
       remoteerror = "No errors"
    else:
        if remoteerror is None:
            remoteerror = "No errors"

    log.debug("Result : %s, pid=%s, returncode=%s, error=%s" % (result, remotepid, remotereturn, remoteerror))
    return result, remotepid, remotereturn, remoteerror


def transcode_remote_command(*transcode):
    config = get_config()
    is_debug = config['logging']['loggers']['prt3']['level'] == 'DEBUG'

    if is_debug:
        try:
            remoteprocess = subprocess.run(
                [*transcode],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError as err:
            log.debug('ERROR:' % err)
    else:
        try:
            remoteprocess = subprocess.run(
                [*transcode],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL)
        except subprocess.CalledProcessError as err:
            log.debug('ERROR:' % err)

    if remoteprocess and remoteprocess.returncode is not None:
        remoteresult = remoteprocess.returncode
    else:
        remoteresult = '27'

    return remoteresult


def transcode_local_command(*transcode):
    config = get_config()
    is_debug = config['logging']['loggers']['prt3']['level'] == 'DEBUG'

    if is_debug:
        try:
            localprocess = subprocess.run(
                [*transcode],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError as err:
            log.debug('ERROR:' % err)
    else:
        try:
            localprocess = subprocess.run(
                [*transcode],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL)
        except subprocess.CalledProcessError as err:
            log.debug('ERROR:' % err)

    if localprocess and localprocess.returncode is not None:
        localresult = localprocess.returncode
    else:
        localresult = '27'

    return localresult


#async def transcode_local_command(*transcode):
#    config = get_config()
#    is_debug = config['logging']['loggers']['prt3']['level'] == 'DEBUG'
#
#    #localresult = ''
#    if is_debug:
#        try:
#            localprocess = await asyncio.create_subprocess_exec(
#                *transcode,
#                stdout=asyncio.subprocess.PIPE,
#                stderr=asyncio.subprocess.STDOUT)
#        except subprocess.CalledProcessError as err:
#            log.debug('ERROR:' % err)
#    else:
#        try:
#            localprocess = await asyncio.create_subprocess_exec(
#                *transcode,
#                stdout=asyncio.subprocess.DEVNULL,
#                stderr=asyncio.subprocess.DEVNULL)
#        except subprocess.CalledProcessError as err:
#            log.debug('ERROR:' % err)
#
#    stdout,stderr = await localprocess.communicate()
#
#    if localprocess and localprocess.returncode is not None:
#        localresult = localprocess.returncode
#    else:
#        localresult = '27'
#
#    return localresult


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
        cprint("Transcoder appears to have been renamed previously...not renaming at this time, continuing...", 'yellow', attrs=['bold'])
        cprint("Once the rest of the install process has completed restart prt3 using the 'overwrite' option", 'yellow', attrs=['bold'])
        cprint("Command to run when the prompt returns : prt3 overwrite", 'yellow', attrs=['bold'])
        return False

    try:
        os.rename(old_path, new_path)
    except Exception as e:
        print(("Error renaming original transcoder: %s" % str(e)))
        return False

    return True


def install_transcoder():
    prt3_remote = find_executable("prt3_remote")
    if not prt3_remote:
        print("Couldn't find `prt3_remote` executable")
        return

    cprint("Renaming original transcoder", 'blue')
    if rename_transcoder():
        try:
            shutil.copyfile(prt3_remote, get_transcoder_path(ORIGINAL_TRANSCODER_NAME))
            os.chmod(get_transcoder_path(ORIGINAL_TRANSCODER_NAME), 0o755)
            cprint("Put PRT in the original transcoders place", 'green')
        except Exception as e:
            cprint("Error installing new transcoder: %s" % str(e), 'red')


def overwrite_transcoder_after_upgrade():
    """
    Moves the upgraded transcoder "Plex Transcoder" to the new name given
    by ``TRANSCODER_NAME`` if the plex package has overwritten the old one.
    """
    old_path = get_transcoder_path(ORIGINAL_TRANSCODER_NAME)
    new_path = get_transcoder_path(NEW_TRANSCODER_NAME)

    prt3_remote = find_executable("prt3_remote")
    if not prt3_remote:
        print("Couldn't find `prt3_remote` executable")
        sys.exit(2)
    elif os.path.exists(new_path):
        if pms_trans_file == "prt":
            cprint("The transcoder was last renamed by the old PRT version so will force an overwrite", 'yellow')
            try:
                shutil.copyfile(prt3_remote, get_transcoder_path(ORIGINAL_TRANSCODER_NAME))
                os.chmod(get_transcoder_path(ORIGINAL_TRANSCODER_NAME), 0o755)
                cprint("Transcoder has been overwritten, it's good to go", 'green')
            except Exception as e:
                cprint("Error installing new transcoder: %s" % str(e), 'red')
                sys.exit(2)
        elif pms_trans_file == 'prt3':
            cprint("Transcoder appears to have been renamed previously...checking if it's been overwritten", 'yellow')
            if not filecmp.cmp(prt3_remote, get_transcoder_path(ORIGINAL_TRANSCODER_NAME), shallow=1):
                try:
                    shutil.copyfile(prt3_remote, get_transcoder_path(ORIGINAL_TRANSCODER_NAME))
                    os.chmod(get_transcoder_path(ORIGINAL_TRANSCODER_NAME), 0o755)
                except Exception as e:
                    cprint("Error installing new transcoder: %s" % str(e), 'red')
                    sys.exit(2)
                else:
                    cprint("Transcoder hasn't been overwritten by upgrade, nothing to do as it's good to go", 'green')
                    sys.exit(1)
        else:
            cprint("Not sure what's happened here, attempting anyway...", 'yellow')
            if not filecmp.cmp(prt3_remote, get_transcoder_path(ORIGINAL_TRANSCODER_NAME), shallow=1):
                try:
                    os.remove(get_transcoder_path(ORIGINAL_TRANSCODER_NAME))
                    shutil.copyfile(prt3_remote, get_transcoder_path(ORIGINAL_TRANSCODER_NAME))
                    os.chmod(get_transcoder_path(ORIGINAL_TRANSCODER_NAME), 0o755)
                except Exception as e:
                    cprint("Error installing new transcoder: %s" % str(e), 'red')
                    sys.exit(2)
                else:
                    cprint("Transcoder _should_ be ok now and good to go", 'green')
                    sys.exit(1)
    else:
        cprint("Transcoder hasn't been previously installed, please use install option", 'yellow')
        sys.exit(1)


def build_env(host=None):
    # TODO: This really should be done in a way that is specific to the target
    #       in the case that the target is a different architecture than the host
    ffmpeg_path = os.environ.get("FFMPEG_EXTERNAL_LIBS", "")
    backslashcheck = re.search(r'\\', ffmpeg_path)
    if backslashcheck is not None:
        ffmpeg_path_fixed = ffmpeg_path.replace('\\', '')
        os.environ["FFMPEG_EXTERNAL_LIBS"] = str(ffmpeg_path_fixed)

   # envs = ["export %s=\"%s\"" % (k, v) for k, v in list(os.environ.items())]
    envs = ["export %s=%s" % (k, quote(v)) for k, v in os.environ.items()]
    envs.append("export PRT_ID=%s" % uuid.uuid1().hex)
    return ";".join(envs)


# Todo: other types of transcoding, identify and multisystem


def transcode_local():
    setup_logging()
    mypid = os.getpid()
    myparent = os.getppid()
    log.debug("Transcode local function started...(%s from %s)" % (mypid, myparent))

    config = get_config()
    args = sys.argv[1:]

    log.debug("sys args are: %s" % sys.argv)
    log.debug("Before path script")
    log.debug("local args are: %s" % args)

    if config.get('path_script') is None:
        idx = 0
        # The file path comes after the "-i" command line argument
        for i, v in enumerate(args):
            if v == "-i":
                idx = i + 1
                break

        # Found the requested video: path
        path = args[idx]
        args[idx] = path
        log.debug("Found media path %s at argument %s - %s" % (path, idx, args[idx]))
    else:
        try:
            idx = 0
            # The file path comes after the "-i" command line argument
            for i, v in enumerate(args):
                if v == "-i":
                    idx = i + 1
                    break

            # Found the requested video: path
            path = args[idx]
            proc = subprocess.Popen([config.get("path_script"), path], stdout=subprocess.PIPE)
            proc.wait()
            new_path = proc.stdout.readline().strip()
            if new_path:
                log.debug("Replacing path with: %s" % new_path)
                args[idx] = str(new_path)
        except Exception as e:
            log.error("Error calling path_script: %s" % str(e))

    log.debug("Before is_debug")

    is_debug = config['logging']['loggers']['prt3']['level'] == 'DEBUG'

    if is_debug:
        log.info('Debug mode - enabling verbose ffmpeg output')

        # Change logging mode for FFMpeg to be verbose
        for i, arg in enumerate(args):
            if arg == '-loglevel':
                args[i + 1] = 'verbose'
            elif arg == '-loglevel_plex':
                args[i + 1] = 'verbose'

    transcode = [get_transcoder_path()] + args

    log.info("Launching transcode_local: %s\n" % transcode)

    #localresult = asyncio.run(transcode_local_command(*transcode))
    localresult = transcode_local_command(*transcode)

    if localresult != 0:
        log.error("Local transcode failed! %s" % localresult)
    else:
        log.info("Local transcode has finished. (pid %s)" % localresult)

    log.debug("Ending prt3_local (%s)" % mypid)


def transcode_remote():
    setup_logging()
    log.debug(" ")
    mypid = os.getpid()
    myparent = os.getppid()
    log.debug("Starting Remote Transcoding function (%s from %s)" % (mypid, myparent))

    config = get_config()
    args = sys.argv[1:]
    log.debug("args %s" % str(args))

    # Check to see if we need to call a user-script to replace/modify the file path
    if config.get('path_script') is None:
        idx = 0
        # The file path comes after the "-i" command line argument
        for i, v in enumerate(args):
            if v == "-i":
                idx = i + 1
                break

        # Found the requested video: path
        path = args[idx]
        #args[idx] = '\"%s\"' % (path)
        log.debug("Found media path %s at argument %s - %s" % (path, idx, args[idx]))
    else:
        try:
            idx = 0
            # The file path comes after the "-i" command line argument
            for i, v in enumerate(args):
                if v == "-i":
                    idx = i + 1
                    break

            # Found the requested video: path
            path = args[idx]
            proc = subprocess.Popen([config.get("path_script"), path], stdout=subprocess.PIPE)
            proc.wait()
            new_path = proc.stdout.readline().strip()
            if new_path:
                log.debug("Replacing path with: %s" % new_path)
                args[idx] = str(new_path)
        except Exception as e:
            log.error("Error calling path_script: %s" % str(e))

    # FIX: This is (temporary?) fix for the EasyAudioEncoder (EAE) which uses a
    #      hardcoded path in /tmp.  If we find that EAE is being used then we
    #      force transcoding on the master
    # Todo: have EAE multi system

    if 'eae_prefix' in ' '.join(args):
        log.info("Found EAE is being used...forcing local transcode")
        return transcode_local()

    log.debug("%s" % ' '.join([quote(a) for a in args]))
    command = REMOTE_ARGS % {
        "env": build_env(),
        "working_dir": pipes.quote(os.getcwd()),
        "command": "prt3_local",
        "args": ' '.join([quote(a) for a in args])
    }

    log.debug("%s" % command)

    min_load = None

    cluster_load = get_cluster_load()
    for server, load in cluster_load.items():
        if min_load is None:
            log.debug("Current min_load is empty")
        else:
            log.debug("Current min load is %s" % list(min_load))

        if (load[0] == 99999) and (load[1] == 99999) and (load[2] == 99999):
            if min_load is None:
                log.debug("Main function - Server %s is not responding, skipping" % server)
                log.debug("Min load stayed as empty")
            else:
                log.debug("Main function - Server %s is not responding, skipping" % server)
                log.debug("Min load stayed the same %s : %s" % (min_load[0], str(min_load[1])))
        else:
            log.debug("Main function - Server %s has load %s%%, %s%%, %s%%" % (server, load[0], load[1], load[2]))
            if min_load is None or min_load[1] > load[0]:
                min_load = (server, load[0])
                log.debug("Min load changed %s : %s" % (min_load[0], str(min_load[1])))
            else:
                log.debug("Min load stayed the same %s : %s" % (min_load[0], str(min_load[1])))


    if min_load is None:
        log.info("No hosts found...using local")
        return transcode_local()

    # Select lowest-load host
    target_server = min_load[0]
    target_addr = config['servers'][target_server]['addr']
    target_user = config['servers'][target_server]['user']
    target_port = config['servers'][target_server]['port']
    log.info("Host %s has minimum load of '%s'" % (target_server, str(min_load[1])))

    log.info("Using transcode host '%s'" % target_server)

    if target_addr != "127.0.0.1":
        sshcmd = ["ssh", target_server] + [command]
    else:
        return transcode_local()


    log.debug("remote sshcmd is %s" % sshcmd)
    remoteresult = transcode_remote_command(*sshcmd)

    log.info("Transcode stopped on host '%s'" % target_server)
    log.info("Result was : %s" % remoteresult)
    log.debug("Ending prt3_remote (%s)" % mypid)


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


def quiet_ssh(*sshping):
    process = subprocess.run(
        [*sshping],
        encoding='utf-8',
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL)
    return

def ping_slaves():
    config = get_config()

    for server, host in list(config['servers'].items()):
        if host['addr'] != "127.0.0.1":
            sshping = ["ssh", "-T", server, "true"]
            quiet_ssh(*sshping)

    return


def ping_cron():
    with open('/etc/cron.d/ping_slaves', 'w') as ping_slavesf:
        ping_slavesf.write('0 * * * * plex /usr/local/bin/prt3 ping_slaves 2>/dev/null\n')
    ping_slavesf.close()
    cprint("Setup tool to try and keep SSH quick", 'green')



def get_plex_sessions(auth_token=None):
    url = 'http://localhost:32400/status/sessions'
    if auth_token:
        url += "?X-Plex-Token=%s" % auth_token

    res = urllib.request.urlopen(url)
    dom = ET.parse(res)
    sessions = {}
    root = dom.getroot()
    transcoding = len(dom.findall('.//TranscodeSession'))
    if not transcoding:
        transcoding = 0

    sessions['overview'] = {
        'total': root.get('size'),
        'video': len(dom.findall('.//Video')),
        'track': len(dom.findall('.//Track')),
        'transcoding': transcoding
    }
    sessions['details'] = {}

    for session in root:
        session_id = et_get(session.find('.//Session'), 'id')
        media_type = session.tag
        sessions['details'][session_id] = {}
        sessions['details'][session_id]['media_type'] = media_type
        sessions['details'][session_id]['transcode_id'] = et_get(session.find('.//TranscodeSession'), 'key')
        sessions['details'][session_id]['bandwidth'] = et_get(session.find('.//Session'), 'bandwidth')
        sessions['details'][session_id]['user'] = et_get(session.find('.//User'), 'title')
        sessions['details'][session_id]['address'] = et_get(session.find('.//Player'), 'address')
        sessions['details'][session_id]['device'] = et_get(session.find('.//Player'), 'device')
        sessions['details'][session_id]['secure'] = et_get(session.find('.//Player'), 'secure')
        sessions['details'][session_id]['relayed'] = et_get(session.find('.//Player'), 'relayed')
        sessions['details'][session_id]['local'] = et_get(session.find('.//Player'), 'local')
        sessions['details'][session_id]['state'] = et_get(session.find('.//Player'), 'state')
        media_file = et_get(session.find('.//Media/Part'), 'file')
        if not media_file:
            mediakey = et_get(session.find('.'), 'key')
            keyurl = "http://localhost:32400%s" % mediakey
            keyurl += "?X-Plex-Token=%s" % auth_token
            media_res  = urllib.request.urlopen(keyurl)
            media_dom = ET.parse(media_res)
            media_file = et_get(media_dom.find('.//Part'), 'file')

        sessions['details'][session_id]['media_file'] = media_file

        if media_type == "Track":
            album_artist = et_get(session.find('.'), 'grandparentTitle')
            album_title = et_get(session.find('.'), 'parentTitle')
            track_artist = et_get(session.find('.'), 'originalTitle')
            track_title = et_get(session.find('.'), 'Title')
            track_number = et_get(session.find('.'), 'index')
            media_name = "%s - %s // %s" % (track_title, track_artist, album_title)
            sessions['details'][session_id]['media_type'] = media_type
        elif media_type == "Video":
            video_type = et_get(session.find('.'), 'type')
            if video_type == "movie":
                media_name = et_get(session.find('.'), 'title')
            elif video_type == "episode":
                show_title = et_get(session.find('.'), 'grandparentTitle')
                season_title = et_get(session.find('.'), 'parentTitle')
                season_number = et_get(session.find('.'), 'parentIndex')
                episode_title = et_get(session.find('.'), 'Title')
                episode_number = et_get(session.find('.'), 'index')
                media_name = "%s S%sE%s : %s" % (show_title, season_number, episode_number, episode_title)
            else:
                media_name = et_get(session.find('.'), 'title')

            sessions['details'][session_id]['media_type'] = video_type
        else:
            media_name = 'unknown'

        sessions['details'][session_id]['media_name'] = media_name

        if sessions['details'][session_id]['transcode_id']:
            sessions['details'][session_id]['video_decision'] = et_get(session.find('.//TranscodeSession'), 'videoDecision')
            sessions['details'][session_id]['audio_decision'] = et_get(session.find('.//TranscodeSession'), 'audioDecision')
            sessions['details'][session_id]['transcodeHwRequested'] = et_get(session.find('.//TranscodeSession'), 'transcodeHwRequested')
            sessions['details'][session_id]['transcodeHwFullPipeline'] = et_get(session.find('.//TranscodeSession'), 'transcodeHwFullPipeline')
            #transcode_id = re_get(TRANSCODE_RE, sessions['details'][session_id]['transcode_id'])
            for proc in psutil.process_iter():
                attrs = proc.as_dict(attrs=['pid', 'name', 'exe', 'cmdline'])
                if attrs['name'] == 'plex_transcoder':
                    cmdline = ' '.join(attrs['cmdline'])
                    transcode_id = re_get(TRANSCODE_RE, cmdline)
                    if transcode_id:
                       sessions['details'][session_id]['prt_node'] = 'master'
                       #log.debug(sessions['details'][session_id])
                       sessions['details'][session_id]['prt_pid'] = attrs['pid']
                elif attrs['name'] == 'ssh':
                    cmdline = ' '.join(attrs['cmdline'])
                    transcode_id = re_get(TRANSCODE_RE, cmdline)
                    if transcode_id:
                        sessions['details'][session_id]['prt_node'] = attrs['cmdline'][1]
                        #log.debug(print(sessions['details'][session_id]))
                        sessions['details'][session_id]['prt_pid'] = attrs['pid']

    log.debug(" ")
    log.debug("Overview")
    for k, v in sessions['overview'].items():
        log.debug("%s %s" % (k, v))

    log.debug(" ")
    log.debug("Details")
    for s in list(sessions['details']):
        log.debug(" ")
        log.debug("Session id: %s" % s)
        for k2, v2 in sessions['details'][s].items():
            log.debug("%s = %s" % (k2, v2))

    log.debug(" ")
    return sessions


def get_sessions():
    if psutil is None:
        print("Missing required library 'psutil'.  Try 'pip3 install psutil'.")
        return

    setup_logging()
    sessions = {}

    config = get_config()
    if config.get('auth_token') is None:
        config['auth_token'] = get_auth_token()
        if not config['auth_token']:
            return sessions
        save_config(config)

    sessions = get_plex_sessions(auth_token=config['auth_token'])
    print(" ")
    printf(" ")
    if int(sessions['overview']['total']) == 0:
        cprint("There is currently no sessions in use", 'blue', attrs=['bold', 'underline'])
    else:
        if int(sessions['overview']['total']) == 1:
            cprint("Currently there is %s active session" % sessions['overview']['total'], 'blue', attrs=['bold', 'underline'])
        else:
            cprint("Currently there are %s active sessions" % sessions['overview']['total'], 'blue', attrs=['bold', 'underline'])
            print(" ")

        direct_total = int(sessions['overview']['total']) - sessions['overview']['transcoding']
        print(" Transcoding: %s   Direct: %s" % (sessions['overview']['transcoding'], direct_total))
        print("       Video: %s    Audio: %s" % (sessions['overview']['video'], sessions['overview']['track']))
        print(" ")
        if len(sys.argv) == 3:
            #option = sys.argv[2]
            if sys.argv[2] == 'details' or sys.argv[2] == 'transcode':
                for session_id in sessions['details']:
                    if not sessions['details'][session_id]['transcode_id']:
                        if sys.argv[2] != 'transcode':
                            print("session type: direct stream")
                            for k2, v2 in sessions['details'][session_id].items():
                                print("%s: %s" % (k2, v2))
                                log.debug("%s: %s" % (k2, v2))
                            print(" ")
                    else:
                        print("session type: transcode")
                        print("running on: %s" % sessions['details'][session_id]['prt_node'])
                        log.debug("Transcoding running on: %s" % sessions['details'][session_id]['prt_node'])
                        for k2, v2 in sessions['details'][session_id].items():
                            print("%s: %s" % (k2, v2))
                            log.debug("%s: %s" % (k2, v2))
                        print(" ")
                        log.debug(" ")

    print(" ")
    return


def pre_install_analysis():

    print(" ")
    if sys.argv[1] != 'check_config':
        cprint("Just doing some quick sanity checks...", 'blue', attrs=['bold', 'underline'])
    else:
        cprint("Just doing some quick sanity checks...", 'blue', attrs=['underline'])


    #print(" ")
    if not os.path.exists(TRANSCODER_DIR):
        cprint("Either Plex Media Server isn't installed or is in a non-standard location!", 'red', attrs=['bold'])
        exit(1)
    else:
        if not os.path.isfile(get_transcoder_path(ORIGINAL_TRANSCODER_NAME)):
            cprint("There doesn't appear to be the Plex Transcoder file in it's directory, not good!", 'red', attrs=['bold'])
        else:
            process = subprocess.run(
                [ 'file', '%s' % get_transcoder_path(ORIGINAL_TRANSCODER_NAME) ],
                stdout=subprocess.PIPE)

            if 'Python' in str(process.stdout):
                with open(get_transcoder_path(ORIGINAL_TRANSCODER_NAME), 'r') as transcoderf:
                    if re.search(r'prt==.*', transcoderf.read()) is not None:
                        pms_trans_file = "prt"
                    elif re.search(r'prt3==.*', transcoderf.read()) is not None:
                        pms_trans_file = "prt3"
            else:
                pms_trans_file = "pms"

        if os.path.isfile(get_transcoder_path(NEW_TRANSCODER_NAME)):
            if sys.argv[1] != 'check_config':
                cprint("There appears to be a previously renamed Plex Transcoder, will work around it if need be", 'yellow')
                pms_renamed_trans_file = "true"

    if  os.path.isfile(prtconf):
        prt_prev_conf = "true"
    else:
        prt_prev_conf = None
    if find_executable("prt_remote"):
        prt_install = "true"
    else:
        prt_install = None
    if os.path.isfile(prt3conf):
        prt3_prev_conf = "true"
    else:
        prt3_prev_conf = None
    if find_executable("prt3_remote"):
        prt3_install = "true"
    else:
        prt3_install = None

    if prt_install is None and prt_prev_conf is None:
        cprint("No PRT (python2) install or configuration detected")
    else:
        if prt_install is not None and prt_prev_conf is not None:
            prt_message = 'package & configuration files'
        elif prt_install is not None:
            prt_message = 'package files'
        elif prt_prev_conf is not None:
            prt_message = 'configuration files'
        else:
            prt_message = 'not quite sure'

        cprint("A PRT (python2) setup has been detected: (%s)" % prt_message)

    if prt3_install is None and prt3_prev_conf is None:
        cprint("No PRT3 install or configuration detected")
    else:
        if prt3_install is not None and prt3_prev_conf is not None:
            prt3_message = 'package & configuration files'
        elif prt3_install is not None:
            prt3_message = 'package files'
        elif prt3_prev_conf is not None:
            prt3_message = 'configuration files'
        else:
            prt3_message = 'not quite sure'

        cprint("A PRT3 setup has been detected: (%s)" % prt3_message)



def check_config():
    """
    Run through various diagnostic checks to see if things are configured
    correctly.
    """
    config = get_config()
    errors = []
    checktmpdir = '/dev/shm/prt_tmp/'
    os.mkdir(checktmpdir)

    print(" ")
    cprint("Performing PRT3 configuration check", 'blue', attrs=['bold', 'underline'])
    pre_install_analysis()
    print(" ")

    cprint("Doing general PRT3 config checks...", 'blue', attrs=['underline'])
    if os.path.isfile('/lib/systemd/systemd'):
        if os.path.isfile(PRTSYSTEMD):
            with open('%soverride.conf' % checktmpdir, 'w') as tmp_prtsystemdf:
                tmp_prtsystemdf.write('[Service]\n')
                #for i in PRTEAEVARS:
                #    systemdf.write('%s%s=%s%s' % (SYSTEMDENV, i, PRTSHARED, EAEDIR))
                for ii in PRTTMPVARS:
                    tmp_prtsystemdf.write('%s%s=%s\n' % (SYSTEMDENV, ii, PRTSHARED))
                tmp_prtsystemdf.write('ExecStart=\n')
                with open(PMSSYSTEMD) as pmssystemdf:
                    for line in pmssystemdf:
                        if re.search(r'^(ExecStart.*)|(export\sPLEX.*)|(exec\s.*)', line) is not None:
                            tmp_prtsystemdf.write(line)

                pmssystemdf.close()
            tmp_prtsystemdf.close()

        if filecmp.cmp('%soverride.conf' % checktmpdir, PRTSYSTEMD, shallow=1):
            cprint("Systemd PRT file looks good", 'green')
        else:
            cprint("Systemd PRT file doesn't look right", 'red')

    if not os.path.isfile('%s' % prtsshconf):
        cprint("SSH config file is missing!", 'red')
    else:
        sshcheck = None
        with open('%s' % prtsshconf, 'r') as ssh_configf:
            for line in ssh_configf:
                if re.search(r'^Include\s~plex/\.ssh/prt_nodes/\*\.prt', line) is not None:
                    sshcheck = 'yes'
                    break
        ssh_configf.close()
        if sshcheck is not None:
            cprint("SSH config looks good", 'green')
        else:
            cprint("SSH config doesn't look right", 'red')

    if not os.path.isdir(PRTNODES):
        cprint("PRT nodes directory is missing!", 'red')
    else:
        if not os.path.isfile('%s_.prt' % PRTNODES):
            cprint("SSH control file is missing!", 'red')
        else:
            with open('%s_.prt' % checktmpdir, 'w') as prtssh_configf:
                prtssh_configf.write('ControlMaster auto\n')
                prtssh_configf.write('ControlPath ~plex/.ssh/prt_nodes/.%n-active\n')
                prtssh_configf.write('ControlPersist 2h\n')
                prtssh_configf.write('RemoteForward 32400 127.0.0.1:32400\n')
                prtssh_configf.write('RequestTTY force\n')
                prtssh_configf.write('LogLevel QUIET\n')
            prtssh_configf.close()
            if filecmp.cmp('%s_.prt' % checktmpdir, '%s_.prt' % PRTNODES, shallow=1):
                cprint("SSH control file looks good", 'green')
            else:
                cprint("SSH control file doesn't look right", 'red')

            for server, host in list(config['servers'].items()):
                if host['addr'] != "127.0.0.1":
                    nodessh_config = checktmpdir + server + '.prt'
                    with open(nodessh_config, 'w') as nodessh_configf:
                        nodessh_configf.write('Host %s\n' % server)
                        nodessh_configf.write('Hostname %s\n' % host['addr'])
                        nodessh_configf.write('User %s\n' % host['user'])
                        nodessh_configf.write('Port %s\n' % host['port'])
                    nodessh_configf.close()
                    origssh_config = PRTNODES + server + '.prt'
                    if filecmp.cmp(nodessh_config, origssh_config, shallow=1):
                        cprint("SSH server file for %s looks good" % server, 'green')
                    else:
                        cprint("SSH server file for %s doesn't look right!" % server, 'red')

    if (os.path.isfile('/etc/cron.d/ping_slaves')):
        with open('%sping_slaves' % checktmpdir, 'w') as ping_slavesf:
            ping_slavesf.write('0 * * * * plex /usr/local/bin/prt3 ping_slaves 2>/dev/null\n')
        ping_slavesf.close()
        if filecmp.cmp('%sping_slaves' % checktmpdir, '/etc/cron.d/ping_slaves'):
            cprint("SSH remote server check file looks good", 'green')
        else:
            cprint("SSH remote server check file doesn't look right!", 'red')
    else:
        cprint("SSH remote server check file doesn't exist!", 'red')

    shutil.rmtree(checktmpdir)

    # First, check the user
    user = getpass.getuser()
    if user != "plex":
        cprint("WARNING: Current user is not 'plex'", 'yellow')

    try:
        settings_fh = open(SETTINGS_PATH)
        dom = ET.parse(settings_fh)
        settings = dom.getroot().attrib
    except Exception as e:
        cprint("ERROR: Couldn't open settings file - %s" % SETTINGS_PATH, 'red')
        return False

    config = get_config()
    if config.get('auth_token') is None:
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

    print(" ")
    cprint("Moving on to checking the hosts and the mount points on each of them...", 'blue', attrs=['underline'])

    # Let's check SSH access
    for server, host in list(config['servers'].items()):
        print(" ")

        if host['addr'] != "127.0.0.1":
            sshload = ['ssh', '%s' % (server), 'prt3', 'get_load']
            load = [l for l in get_system_load(*sshload)]
        else:
            load = [str(i) for i in (get_system_load_local())]

        if not load:
            cprint("    Host: %s (%s)" % (server, host['addr']), 'blue')
            #loaderror = "Issue checking load"
            cprint(" Connect: FAIL", 'red')
            continue
        else:
            cprint("    Host: %s (%s)" % (server, host['addr']), 'blue')
            cprint(" Connect: OK", 'green')
            cprint("    Load: %s%%" % str(load[0]), 'green')

        for req_mode, paths in list(paths_modes.items()):
            for path in paths:
                cprint("    Path: '%s'" % path)
                pathoptions = '%U %a'
                cmdtorun = 'stat --printf=%s %s' % (format(quote(pathoptions)), format(quote(path)))
                #sshcmd = 'ssh %s@%s -p %s %s' % (host["user"], host["addr"], host["port"], format(quote(cmdtorun)))
                if host['addr'] != "127.0.0.1":
                    sshcmd = 'ssh %s %s' % (server, format(quote(cmdtorun)))
                    pathresult, pathpid, pathreturn, patherror = asyncio.run(remote_command(sshcmd))
                else:
                    pathresult, pathpid, pathreturn, patherror = asyncio.run(remote_command(cmdtorun))

                if pathreturn != 0:
                    cprint("FAIL", color="red")
                    cprint("    %s : %s" % (path, patherror), 'red')
                    continue
                else:
                    username, mode = pathresult[0], pathresult[1]
                    cprint("    User:  %s" % username, 'green')
                    cprint("    Mode:  %s" % mode, 'green')

                    if username != 'plex':
                        cprint("    WARN:  Not owned by plex user", 'yellow')
                        if int(mode[-1]) < req_mode:
                            cprint("    ERROR: Bad permissions", 'red')
                    else:
                        if int(mode[0]) < req_mode:
                            cprint("    ERROR: Bad permissions", 'red')
    #print(" ")

                #print(" ")
    print(" ")


def check_hosts():
    config = get_config()
    print(" ")
    total_servers = len(config['servers'])
    print(" ")
    cprint("Checking response from all %s servers" % total_servers, 'blue', attrs=['underline', 'bold'])
    print(" ")
    for server, host in list(config['servers'].items()):
        if host['addr'] != "127.0.0.1":
            sshload = ['ssh', '%s' % (server), 'prt3', 'get_load']
            load = [l for l in get_system_load(*sshload)]
            if not load:
                cprint("Server %s (%s) isn't responding" % (server, host['addr']), 'red')
            else:
                cprint("Server %s (%s) is up" % (server, host['addr']), 'green')
        else:
            cprint("Server %s (%s) is up" % (server, host['addr']), 'green')

    print(" ")


def list_hosts():
    config = get_config()
    print(" ")
    total_servers = len(config['servers'])
    printf(" ")
    cprint("Current configuration (%s servers)" % total_servers, 'blue', attrs=['underline', 'bold'])
    print(" ")
    for server, host in list(config['servers'].items()):
        print(" Server: %s" % server)
        print("     IP: %s" % host['addr'])
        print("   User: %s" % host['user'])
        print("   Port: %s" % host['port'])
        print("  Group: %s" % host['group'])
        print(" ")



def setup_prt3_systemd():
    config = get_config()
    if os.path.isfile('/lib/systemd/systemd'):
        if not os.path.isfile(PRTSYSTEMD):
            if os.geteuid() != 0:
                cprint("Not running this with as root, use sudo or su", 'red')
                exit(1)

            if not os.path.isdir(PRTSYSTEMDDIR):
                try:
                    os.mkdir(PRTSYSTEMDDIR)
                except OSError:
                    cprint("Creation of the directory %s failed" % PRTSYSTEMDDIR, 'red')
                else:
                    cprint("Successfully created the SystemD directory", 'green')
            else:
                cprint("PRT systemd directory already exists", 'green')

            with open(PRTSYSTEMD, 'w') as prtsystemdf:
                prtsystemdf.write('[Service]\n')
                #for i in PRTEAEVARS:
                #    systemdf.write('%s%s=%s%s' % (SYSTEMDENV, i, PRTSHARED, EAEDIR))
                for ii in PRTTMPVARS:
                    prtsystemdf.write('%s%s=%s\n' % (SYSTEMDENV, ii, PRTSHARED))
                prtsystemdf.write('ExecStart=\n')
                with open(PMSSYSTEMD) as pmssystemdf:
                    for line in pmssystemdf:
                        if re.search(r'^(ExecStart.*)|(export\sPLEX.*)|(exec\s.*)', line) is not None:
                            prtsystemdf.write(line)

                pmssystemdf.close()
            prtsystemdf.close()

            cprint("Systemd override file for PRT successfully installed", 'green')
            cprint("Please restart the PMS service at your earliest convenience", 'yellow')
            cprint("sudo systemctl daemon-reload && sudo systemctl restart plexmediaserver.service", 'yellow')
            print(" ")
        else:
            cprint("PRT Systemd override file already exists", 'green')
    else:
        cprint("Couldn't detect systemd", 'red')
        print(" ")
        exit(1)


def nodessh_write(server, addr, user, port):
    if addr != "127.0.0.1":
        nodessh_config = PRTNODES + server + '.prt'
        cprint("creating %s's ssh config" % server, 'green')
        with open(nodessh_config, 'w') as nodessh_configf:
            nodessh_configf.write('Host %s\n' % server)
            nodessh_configf.write('Hostname %s\n' % addr)
            nodessh_configf.write('User %s\n' % user)
            nodessh_configf.write('Port %s\n' % port)
        nodessh_configf.close()


def setup_multi_ssh():
    config = get_config()
    ssh_config_check = None

    user = getpass.getuser()
    if user != 'plex':
        cprint("Warning: You are not running as the Plex user", color="red")
        print(" ")
        exit(1)


    if not os.path.isfile('%s' % prtsshconf):
        #print("ssh config not present")
        log.debug("ssh config not present")
        with open('%s' % prtsshconf, 'w') as ssh_configf:
            log.debug("Writing ssh config include line")
            ssh_configf.write('Include %s*.prt\n' % PRTNODESabbr)
        ssh_configf.close()
        cprint("Written prt ssh config", 'green')
    else:
        with open('%s' % prtsshconf, 'r') as ssh_configf:
            for line in ssh_configf:
                if re.search(r'^Include\s~plex/\.ssh/prt_nodes/\*\.prt', line) is not None:
                    ssh_config_check = True
                    log.debug("ssh config already has Include line")
                    cprint("ssh config already has Include line", 'green')
                    break
        ssh_configf.close()

        if ssh_config_check is None:
            log.debug("Writing ssh config file")
            with open('%s' % prtsshconf, 'a') as ssh_configf:
                ssh_configf.write('Include %s*.prt\n' % PRTNODESabbr)
            ssh_configf.close()
            cprint("Written prt ssh config", 'green')

    if not os.path.isdir(PRTNODES):
        try:
            os.mkdir(PRTNODES)
        except OSError:
            cprint("Creation of the directory %s failed" % PRTNODES, 'red')
            exit(1)
        else:
            cprint("Successfully created the prt nodes directory", 'green')
    else:
        log.debug("prt nodes ssh directory already exists")

    if not os.path.isfile('%s_.prt' % PRTNODES):
        with open('%s_.prt' % PRTNODES, 'w') as prtssh_configf:
            log.debug("Writing ssh node control file")
            prtssh_configf.write('ControlMaster auto\n')
            prtssh_configf.write('ControlPath ~plex/.ssh/prt_nodes/.%n-active\n')
            prtssh_configf.write('ControlPersist 2h\n')
            prtssh_configf.write('RemoteForward 32400 127.0.0.1:32400\n')
            prtssh_configf.write('RequestTTY force\n')
            prtssh_configf.write('LogLevel QUIET\n')
        prtssh_configf.close()
        cprint("Written prt ssh main node file", 'green')
    else:
        cprint("prt ssh main node file already exists", 'green')


    for server, host in list(config['servers'].items()):
        if host['addr'] != "127.0.0.1":
            log.debug("Writing %s ssh file" % server)
            nodessh_write(server, host['addr'], host['user'], host['port'])
            cprint("Writen %s ssh file" % server, 'green')


def add_host():

    host = None
    addr = None
    port = None
    user = None
    # Todo: once setup group usage make option like rest
    group = 'Default'

    if host is None:
        host = input("Name: ")
    if addr is None:
        addr = input("IP: ")
    if port is None:
        port = eval(input("Port: "))
    if user is None:
        user = input("User: ")
    if group is None:
        group = input("Group: ")

    print("We're going to add the following transcode host:")
    print(("  Name: %s" % host))
    print(("    IP: %s" % addr))
    print(("  Port: %s" % port))
    print(("  User: %s" % user))
    print((" Group: %s" % group))

    if input("Proceed: [y/n]").lower() == "y":
        config = get_config()
        config["servers"][host] = {
            "addr": addr,
            "port": port,
            "user": user,
            "group": group
        }

        nodessh_write(host, addr, user, port)

        if save_config(config):
            print("Host %s successfully added" % config["servers"][host])


def remove_host():
    config = get_config()
    print(" ")
    cprint("Listing hosts in preparation to remove one from the config", 'blue', attrs=['bold', 'underline'])
    print(" ")
    list_hosts()
    accept_name = None
    while accept_name is None:
        remove_name = input("Enter server name to remove: ")
        if not config['servers'][remove_name]:
            cprint("Cannot find server %s in the configuration", remove_name)
            cprint("Listing server names again")
            for server in list(config['servers']):
                cprint("%s", server)
        else:
            if input("Confirm to delete for %s? : [y/n]" % (remove_name)).lower() == "y":
                accept_name = 'accepted'

        del config["servers"][remove_name]
        save_config(config)
        nodessh_config = PRTNODES + [remove_name] + '.prt'
        if os.path.isfile(nodessh_config):
            try:
                os.remove(nodessh_config)
            except OSError:
                cprint("Error removing ssh config file %s" % nodessh_config, 'red')
            else:
                cprint("Host %s removed" % config["servers"][remove_name], 'green')


def install_prt():
    if os.geteuid() != 0:
        pre_install_analysis()

    cprint("Installing Plex Remote Transcoder", 'blue')

    config = get_config()
    # config["ipaddress"] = input("IP address of this machine: ")
    # if os.geteuid() = !0:
    save_config(config)

    if os.geteuid() != 0:
        config = get_config()
        if config.get('auth_token') is None:
            cprint("Plex authorisation hasn't been setup yet, let's do that now...", 'yellow')
            config['auth_token'] = get_auth_token()
            if not config['auth_token']:
                cprint("Could't get Plex authorisation token!", 'red')
            else:
                save_config(config)

        print(" ")

        if len(config['servers']) == 0:
            cprint("There's currently no servers setup in the config so let's setup the local one", 'yellow')
            cprint("We'll call it master, you can always change it later...", 'yellow')
            config["servers"]['master'] = {
                "addr": '127.0.0.1',
                "port": '22',
                "user": 'plex',
                "group": 'default'
            }

            if save_config(config):
                cprint("Host master successfully added", 'green')

            list_hosts()

        setup_multi_ssh()
        cprint("Need root privs to complete install, sudo password/authority needed.", 'yellow')
        cprint("Id you haven't setup plex user for sudo just run via root another way prt3 install after you fail to sudo here", 'yellow')
        os.execvp('sudo', ['sudo', '/usr/local/bin/prt3', 'install'])

    install_transcoder()

    if (os.path.isfile('/lib/systemd/systemd')) and (not os.path.isfile(PRTSYSTEMD)):
        cprint("Setting up PRT adjustments to PMS startup...", 'blue')
        setup_prt3_systemd()
    else:
        cprint("PRT adjustments to PMS startup already done, skipping...", 'green')
    if not (os.path.isfile('/etc/cron.d/ping_slaves')):
        cprint("Setting up faster ssh...", 'blue')
        ping_cron()
    else:
        cprint("ssh acceleration already in place...", 'green')




def version():
    print(" ")
    cprint("Plex Remote Transcoder version %s, python3 re-write done by %s" % ((__version__, __author__)), attrs=['bold'])
    print("Original Plex Remote Transcoder version 0.4.4, Copyright (C) %s" % (__creator__))
    print("  - I just picked up the mantle he left...massive respect to Weston -  ")
    print(" ")


# Usage function
def usage():
    version()
    print("Plex Remote Transcode comes with ABSOLUTELY NO WARRANTY.\n\n"
          "This is free software, and you are welcome to redistribute it and/or modify\n"
          "it under the terms of the MIT License.\n\n")
    print("Usage:\n")
    print(("  %s [options]\n" % os.path.basename(sys.argv[0])))
    print(
        "Options:\n\n"
        "  usage, help, -h, ?    Show usage page\n"
        "  get_local_load        Show the load of the system\n"
        "  get_cluster_load      Show the load of all systems in the cluster\n"
        "  install               Install PRT for the first time and then sets up configuration\n"
        "  overwrite             Fix PRT after PMS has had a version update breaking PRT\n"
        "  list_hosts            Shows hosts from the current configuration\n"
        "  add_host              Add an extra host to the list of slaves PRT is to use\n"
        "  remove_host           Removes a host from the list of slaves PRT is to use\n"
        "  sessions [option]     Display current sessions (options: 'transcode' shows transcode only, 'details' shows all\n"
        "  check_hosts           Checks the hosts response status\n"
        "  check_config          Checks the current configuration for errors\n")


# def main(argv):
def main():
    # Specific usage options
    if len(sys.argv) < 2 or any((sys.argv[1] == "usage", sys.argv[1] == "help", sys.argv[1] == "-h",
                                 sys.argv[1] == "--help", sys.argv[1] == "?",)):
        usage()
        sys.exit(-1)


    user = getpass.getuser()
    if user != 'plex':
       cprint ("Warning: You are not running as the Plex user", color="red")
       print(" ")


    if not os.path.isfile(prt3conf):
        if not sys.argv[1] == "install":
            cprint("Warning: You do not yet have prt3 config setup, first thing to run is the install option!", color="red")
            cprint("Cancelling %s and redirecting you to the install option instead..." % sys.argv[1], color="red")
            return install_prt()


    if sys.argv[1] == "get_load":
        local_load = [i for i in (get_system_load_local())]
        print("%s %s %s" % (local_load[0], local_load[1], local_load[2]))


    elif sys.argv[1] == "get_local_load":
        local_load = [i for i in (get_system_load_local())]
        print("Local server has load %s%%, %s%%, %s%%" % (local_load[0], local_load[1], local_load[2]))


    # Todo - create upgrade option to help migrate to new config type
    elif sys.argv[1] == "get_cluster_load":
        setup_logging()
        print(" ")
        printf(" ")
        cprint("Current cluster Load", 'blue', attrs=['underline', 'bold'])
        print(" ")
        cluster_load = {}
        cluster_load = get_cluster_load()
        for server, load in cluster_load.items():
            if (load[0] == 99999) and (load[1] == 99999) and (load[2] == 99999):
                cprint(f"{server:>10}: not responding", 'red')
            else:
                cprint(f"{server:>10}: %s%%, %s%%, %s%%" % (load[0], load[1], load[2]))
        print(" ")


    elif sys.argv[1] == "install":
        install_prt()


    elif sys.argv[1] == "add_host":
        add_host()


    # Todo: do list_hosts and then make remove_host an input choice
    elif sys.argv[1] == "remove_host":
        remove_host()


    # Added version option rather than just for no options
    elif any([sys.argv[1] == "version", sys.argv[1] == "v", sys.argv[1] == "V"]):
        version()
        sys.exit(0)


    # Overwrite option (for after plex package update/upgrade)
    elif sys.argv[1] == "overwrite":
        if os.geteuid() != 0:
            cprint("Need root privs to complete overwrite, sudo password/authority needed.", 'yellow')
            os.execvp('sudo', ['sudo', '/usr/local/bin/prt3', 'overwrite'])
        overwrite_transcoder_after_upgrade()
        cprint("Transcoder overwritten successfully", 'green')
        if (os.path.isfile('/lib/systemd/systemd')) and (not os.path.isfile(PRTSYSTEMD)):
            cprint("Setting up PRT adjustments to PMS startup...")
            setup_prt3_systemd()
        if not (os.path.isfile('/etc/cron.d/ping_slaves')):
            ping_cron()


    elif sys.argv[1] == "sessions":
        get_sessions()


    elif sys.argv[1] == "check_config":
        check_config()


    elif sys.argv[1] == "check_hosts":
        check_hosts()


    elif sys.argv[1] == "list_hosts":
        list_hosts()


    elif sys.argv[1] == "ping_slaves":
        ping_slaves()


    # Anything not listed shows usage
    else:
        usage()
        sys.exit(-1)
