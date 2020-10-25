# Sweeper

What if your filesystem supported file expiration?

## Example
```shell
➜  ~ cargo build && sudo RUST_BACKTRACE=1 target/debug/sweeper
```

In another terminal, create a file and set an expiration date in an extended attribute (`xattr`):
```shell
➜  ~ touch bye
# The path has to be absolute!
➜  ~ attr -s expire_at -V $(($(date +"%s") + 5)) $PWD/bye
Attribute "expire_at" set to a 10 byte value for /home/javierhonduco/bye:
1603651402
```

You should see how the file is deleted 5 seconds later:
```
📅 Event: (path=/home/javierhonduco/bye, name=user.expire_at, value=1603651457)
╰ 🧹 Scheduled for deletion
🚮 Deleting /home/javierhonduco/bye
```

## Why!?
Chatting with a friend about filesystems, he brought up how badly he wanted all filesystems to have built-in file expiration, as some blob storage systems offer. Implementing this in the VFS layer is _a bit_ complicated, so thought of hacking this together, as it could be used in applications without major modifications except calling an extra standard syscall to set the extended attribute.

Note: This is just a project made for fun, do not use in production!

## How does it work?
Using [BPF](https://ebpf.io/), we trace the system calls (`[l]setxattr(2)`) used to set extended attributes. When a key matching `user.expire_at` is set, it examines the value, and if it looks like like it could potentially be a timestamp, it saves it into a sqlite database.

Another thread polls from the DB and if there's something that should be deleted, it goes ahead and removes the file.

## Limitations / TODO
The main limitation is that your FS should support extended attributes, and that `sweeper` needs to be running when an expiration is set, otherwise the expiration request can't be recorded. Due to the way BPF programs communicate with userspace it can also drop events, so it may not catch all the expiration requests.

The provided path to the extended attribute syscall must be absolute.

- There are several TODOs scattered in the source code. But some of them are:
  - Dry-run mode
  - Better logging
  - Proper error handling
  - No support to remove expirations (except modifying the sqlite DB yourself)
  - No indexing in the DB, but this is just a toy!
  - Not deleting DB entries and keep a log of actions
  - Add proper checks
  - Run the key / value checks in th BPF program
