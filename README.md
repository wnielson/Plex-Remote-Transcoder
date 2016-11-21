# Plex Remote Transcoder

[![Join the chat at https://gitter.im/wnielson/Plex-Remote-Transcoder](https://badges.gitter.im/wnielson/Plex-Remote-Transcoder.svg)](https://gitter.im/wnielson/Plex-Remote-Transcoder?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge)

A distributed transcoding backend for Plex.

Please help by reporting bugs or with pull-requests.

For those interested in testing this out quickly, I've put together a step by
step guide for getting this working on two Ubuntu machines.  You can find the
guide [here](https://github.com/wnielson/Plex-Remote-Transcoder/wiki/Ubuntu-Install).

Addtionally, for proposed features and some current limitations, check out
[this page](https://github.com/wnielson/Plex-Remote-Transcoder/wiki/Improvements-&-Additional-Features).

**NOTE**

Upgrading `Plex Media Server` often breaks things and it takes us some time to figure out what needs to be fixed.  It is suggested that you avoid upgrading your Plex server before checking here first.

**The latest confirmed working version** is `Plex Media Server` `1.2.3.2914-1ff0f18`.  If you try a newer version and encounter an issue, please report it.  In order to get this working, users have reported that the following steps need to be taken:

1. Remove the codec directory: `rm -rf /var/lib/plexmediaserver/Library/Application Support/Plex Media Server/Codecs/5a2d9a2-1127-linux-ubuntu-x86_64`)
2. Remove the previous encoder: `rm -rf /usr/lib/plexmediaserver/plex_transcoder`
3. Install Plex: `dpkg -i plexmediaserver_1.2.3.2914-1ff0f18_amd64.deb`

## Releases

For versions of Plex Media Server below version 1.1.0. use release [0.3.5](https://github.com/wnielson/Plex-Remote-Transcoder/releases/tag/0.3.5).

For versions of Plex Media Server below version 1.0, use release [0.2.2](https://github.com/wnielson/Plex-Remote-Transcoder/releases/tag/0.2.2).

For the newest version of Plex Media Server, use the main branch or the [newest release](https://github.com/wnielson/Plex-Remote-Transcoder/releases).

## Contributing

Bug fixes/reports and feature requests are welcome!  Either submit a pull request or create a new issue.  There is also a [discussion board](https://gitter.im/wnielson/Plex-Remote-Transcoder).

## How Does it Work?

There have been quite a few projects attempting to load balance a Plex server,
most of which involve proxying HTTP requests between multiple
`Plex Media Server` (`PMS`) installations.  This project takes a different, and
arguably easier approach that simply involves running the `Plex New Transcoder`
on a remote host.  In this setup there is only ever **one** `PMS` installation
(the `master` node), but there can be any number of transcode hosts (`slave`
nodes).  Since transcoding is typically the most processor intensive aspect of
`PMS`, it makes sense to be able to distribute this workload among all available
computing resources.

The way this works is by replacing the default `Plex New Transcoder` binary on
the master `PMS` with a wrapper.  This wrapper allows us to intercept the
transcode request on the `master` node and send it to a transcode `slave` node.
The transcode `slave` invokes the true `Plex New Transcoder` binary, does the
(trans|en)coding and saves the video segments to a network mounted shared
filesystem on the `master`.  The `master` then sends these segments to the
client and the video is played back just like normal.

## How is the Useful?

That depends.  It may not be if you have a powerful `PMS` and/or very few
simultaneous users/devices.  If however you often see your main server being
ground to halt because of the transcoder **and** you have access to additional
computational capacity, this might be useful to you.

This approach also makes it possible, in theory, to take advantage of scalable
computing via services like Amazon's ECS and Google's Compute Engine.  By
default you could have a  dedicated, cheap instance (like ECS's `t2.micro`)
running `PMS`, then when a user requests a stream, a larger ECS instance could
be spawned to do the encoding.  When the user is done watching, the extra ECS
instance can be turned off, thereby saving you money.

## Help

Right now, things are pretty rough.  Trying to figure out why something isn't
working is difficult, but we're working on making this easier.  Also,
installation isn't easy and there are lots of places to make mistakes, we're
working on that too.

## Configuration

The configuration file is located in a file named `~/.prt.conf`.  It should be a
valid `JSON` file and is created for you the first time you run `prt install`.
Below is a list of some configuration options that can currently only be set
by manually editing this file.

**`servers_script`**

This option can be used to specify the path to an executable that will return a
list of currently available transcode `slave` node.  It is called before every
transcode request and should return a list of transcode nodes in the following
format:

```
hostname-1 22 plex
hostname-2 22 plex
```

where each line is a new host, consisting of three entries: the hostname or IP
address, SSH port and SSH username.

**`path_script`**

This option can be used to specify the path to an executable that accepts a
single argument at the command line and returns a single line to `stdout`.  The
single input parameter is the full path to the requested item to transcode.  If
the path is to be modified or changed, then the new path should be written back
to `stdout`.  A simple example in Python that simply returns the same path is
given below.

```python
#!/usr/bin/env python
import sys

if len(sys.argv) > 1:
    path = sys.argv[1]
    sys.stdout.write(path)
```


**`logging`**

TODO: Document this.

## Contributors

* Weston Nielson (Owner) - wnielson@github
* Andy Livingstone - liviynz@github


## Donations

Some people have ask about how to dontate, so if you want to buy me a beer here are some links.  Cheers!

[![Donate at https://patreon.com/wnielson](https://img.shields.io/badge/patreon-donate-yellow.svg)](https://patreon.com/wnielson)

[![Donate at https://www.paypal.me/wnielson](https://img.shields.io/badge/paypal-donate-yellow.svg)](https://www.paypal.me/wnielson)
