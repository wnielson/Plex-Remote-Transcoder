# Plex Remote Transcoder

A distributed transcoding backend for Plex.

At the present, this is more of a working proof-of-concept.  More testing and development is
still needed, so please help by reporting bugs or with pull-requests.

## How Does it Work?

There have been quite a few projects attempting to load balance a Plex server,
most of which involve proxying HTTP requests between multiple
`Plex Media Server` (`PMS`) installations.  This project takes a different, and arguably
easier approach that simply involves running the `Plex New Transcoder` on a
remote host.  In this setup there is only ever **one** `PMS`
installation, but there can be any number of transcode hosts.  Since transcoding
is typically the most processor intensive aspect of Plex, it makes sense to be
able to distribute this workload among all available computing resources.

The way this works is by replacing the default `Plex New Transcoder` binary on the
master `PMS` with a wrapper.  This wrapper allows us to intercept the transcode request
on the `master` and send it to a different host (a transcode `slave`).  The transcode `slave`
invokes the true `Plex New Transcoder` binary, does the encoding and saves the transcoded
segments to a network mounted shared filesystem on the `master`.  The `master` then sends these
segments to the client and the video is played back just like normal.

## How is the Useful?

That depends.  It may not be if you have a powerful `PMS` and/or very few simultaneous
users/devices.  If however you often see your main server being ground to halt because of the
transcoder **and** you have access to additional computational capacity, this might be useful to you.

This approach also makes it possible, in theory, to take advantage of scalable computing
via services like Amazon's ECS and Google's Compute Engine.  By default you could have a 
dedicated, cheap instance (like ECS's `t2.micro`) running `PMS`, then when a user requests
a stream, a larger ECS instance could be spawned to do the encoding.  When the user is done watching,
the extra ECS instance can be turned off, thereby saving you money.

## Installation

There are a number of things that must be done in order to get this working.  First of all, on the `master`,
we need to download and install the code

```bash
git clone https://github.com/wnielson/Plex-Remote-Transcoder.git
cd Plex-Remote-Transcoder
python setup.py install
```
Once installed, you then need to actually install the remote transcode wrapper via:

```bash
prt install
```

This will rename the `Plex New Transcoder` binary to `plex_transcoder` and then install
a new `Plex New Transcoder` (the wrapper).

### Setup Network Shares

This bit will vary depending on your operating system and which service you decide to use
for sharing files over the network.  The directions here are for using NFS, but the same
principles apply if you are using Samba or AFP, ect.

First, we need to share the directory containing the `PMS` configuration files.  On Linux,
this is located `/var/lib/plexmediaserver`, on OS X it is
`~/Library/Application Support/Plex Media Server`.  Check the Plex docs if you are on a different
platform.  For Linux/OS X, assuming NFS is installed, we can simply add this to the `exports` file
(usually `/etc/export`):

```
/var/lib/plexmediaserver 192.168.0.0/24(ro,sync,no_subtree_check)
```

If the above NFS share syntax is confusing, do a quick Google search about how to do NFS sharing,
but basically, we are making `/var/lib/plexmediaserver` available to any host in the
`192.168.0.0/24` network with read-only (`ro`) access.  Obviously if you have a different network
configuration or are worried about security issues, be sure to make the appropriate adjustments.

We also need to share the temporary transcoder directory.  The location of this directory can be
found/changed via Plex's web interface.  Log in, go to settings, select your server, click
"Show Advanced", click on "Transcoder" and the path will be under "Transcoder temporary directory".
Let's assume that it is set to `/opt/tmp`, then we update `/etc/exports` and add the following:

```
/opt/tmp 192.168.0.0/24(rw,sync,no_subtree_check)
```

The main difference here is that the mount **must be read-write** (`rw`), since this is the location
that the transcode `slave`(s) will write the transcoded segments to.

The last thing to share are the directories where the media files are stored.  It is important that you
make sure that **all** of the media directories are available to the `slave` machines in
**exactly the same location** as they are on the `master`.  For example, if your `PMS` is
configured to look for media in `/mnt/disk1/TV` and `/mnt/disk2/Movies`, then you need to make
sure that each `slave` has the same directories **with the same content**.  This is easy to do, like
the above example.

On each transcode `slave`, we need to make sure that these shares are mounted.  On Linux this is done
easily by updating `/etc/fstab`.  In the following example, we will assume the `master` IP address
is `192.168.0.2`.

```
# Transcoder temporary directory
192.168.0.2:/opt/tmp /opt/tmp nfs defaults 0 0
# Plex configuration directory
192.168.0.2:/var/lib/plexmediaserver /var/lib/plexmediaserver nfs defaults 0 0
# Media directories
192.168.0.2:/mnt/disk1 /mnt/disk1 nfs defaults 0 0
192.168.0.2:/mnt/disk2 /mnt/disk2 nfs defaults 0 0
```

### Install `Plex New Transcoder` on the Slaves

On each of the `slave` machines, we need to install the original `Plex New Transcoder`
distributed by Plex.  If your `master` and `slave` are the same artitecture and
platform, you can just copy the entire directory from the `master` and put it in
the same location on the `slave`.  For Linux, this folder is `/usr/lib/plexmediaserver`,
OS X it is just the entire `Plex Media Server.app` located in the `/Applications` directory.

For example, on Linux we can copy from the `master` (`192.168.0.2`) to the `slave`
(`192.168.0.3`):

```
scp -r /usr/lib/plexmediaserver root@192.168.0.3:/usr/lib/
```

`Plex-Remote-Transcoder` must also be installed on each `slave` as well using the same
procedure as we did on the `master`.

### Configure the `master`

The `master` must know about the available transcode `slave` machines.  To do this
we can use the `prt` command like so on the `master`:

```bash
prt add_host
```

You will be prompted to provide the `slave` machine's host name, port and username.
The port and username must correspond to a valid SSH account.  We don't need to supply
a password because key-based authentication must be done (see below).

#### Password-less Login

SSH facilitates password-less logins by using keys.  The public key on the `master`
needs to be added to the `~/.ssh/authorized_keys` file on each `slave`.  If this is
foreign to you, Google "ssh key-based authentication" and follow a guide.

## Try it out

Finally, you should be able to test it.  Fire up a video (not via a direct-stream device) and
see if your transcoding happens on the `slave` that you're configured.

## Help

Right now, things are pretty rough.  Trying to figure out why something isn't working
is difficult, but we're working on making this easier.  Also, installation isn't easy
and there are lots of places to make mistakes, we're working on that too.

