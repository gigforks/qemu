# 0-db Block Driver
This is a fork of qemu with a custom 0-db block driver

# Installation
Theses instruction are made for Ubuntu 16.04 docker.

- `apt-get install -y git python build-essential gcc pkg-config glib-2.0 libglib2.0-dev libsdl1.2-dev libaio-dev libcap-dev libattr1-dev libpixman-1-dev libhiredis-dev`
- `git clone https://github.com/gigforks/qemu qemu-zdb`
- `cd qemu-zdb`
- `git submodule update --init`
- `./configure --target-list="x86_64-softmmu" --enable-kvm`
- `make -j 5`

Now you can use this qemu:
- `./x86_64-softmmu/qemu-system-x86_64 [options]`

# Block Driver
In order to use `0-db` as backend to a disk, you need to use `zdb` driver. Theses are available options:

## Default behavior
- `host`: hostname of the 0-db server
- `port`: port to reach the 0-db server, using tcp
- `socket`: socket filename to reach 0-db server, using unix socket, this option override host/port
- `size`: virtual disk size (input like `10G` is accepted)
- `blocksize`: aggregation blocksize in the backend (input like 8k are accepted)
- `namespace`: namespace to use in 0-db, one namespace per vdisk
- `password`: if the namespace is protected by a password, you can provide it

> Default value: host=localhost, port=9900, size=1G, blocksize=4k

## Thin-provisioning
Thin provisioning allows you to specify another server/namespace where to look at if data are not found on the default 0-db.

This allows you to use one existing disk (in read-only mode) to provide default data to your disk, without duplicating them.

Additionnal options to use thin-provisioning:
- `thin-host`
- `thin-port`
- `thin-socket`
- `thin-namespace`
- `thin-password`

Theses option act exactly like the default behavior, but it used for the thin backend.

> The blocksize and the disk size **needs** to be the same for both namespace otherwise unexpected result will occurs

## Active-Active Backup
This mode simply write data to two servers on the same time. If one of them dies, only the remaining one is used (read and write).

Additionnal options to use active backup:
- `backup-host`
- `backup-port`
- `backup-socket`
- `backup-namespace`
- `backup-password`

Theses option act exactly like the default behavior, but it used for the thin backend.

> The blocksize and the disk size **needs** to be the same for both namespace otherwise unexpected result will occurs

# Notes
- Namespace **needs** to exists, otherwise you'll hit an error, nothing is created
- Using same namespace on same server in different virtual machine on the same time will make unexpected results
- All of theses argument are valid for a single disk, you can specify all of theses per disk you add

# Example
Single disk, all default value
```
qemu-system-x86_64 -drive driver=zdb
```

Single disk, with unix socket server and specific namespace:
```
qemu-system-x86_64 -drive driver=zdb,socket=/tmp/zdb.sock,namespace=hello
```

Another example:
```
qemu-system-x86_64 -drive driver=zdb,port=8888,namespace=disk1,size=50G,blocksize=8k
```

Using a thin-provisioning server:
```
qemu-system-x86_64 -drive driver=zdb,port=1234,namespace=disk1,thin-host=server2,thin-namespace=sourcedisk
```

Mixing thin and backup (localhost, 9900 for original disk, /tmp/zdb2.sock for thin server and localhost, port 1234 for backup):
```
qemu-system-x86_64 -drive driver=zdb,namespace=original,size=5G,thin-socket=/tmp/zdb2.sock,namespace=thin-disk,backup-port=1234,namespace=bkp
```

Using two disks
```
qemu-system-x86_64 -drive driver=zdb,namespace=disk1,size=100G,blocksize=8k -drive driver=zdb,namespace=disk2,size=10G,blocksize=16k
```
