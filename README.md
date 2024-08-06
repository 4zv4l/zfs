# zfs

Zig File Server (very basic file server)

## How it works

- A client connects and requests a file
- The server replies with the md5sum (raw, not in hex (16 bytes)) and the file size in bytes (u64)
- If the md5sum is all 0 and size is 0, means an error occured and data following will be the error message
- Then the server send the file data

## Example

Server side:
```
$ ./zig-out/bin/zfs -d tmp -b 127.0.0.1 8080
info: Listening on 127.0.0.1:8080 and serving tmp/
info: New client on 127.0.0.1:49633
info: Request 'tmp/foo'
info: Got stat from file
info: Got md5hash from file
info: Sent metadata: { hash: c157a79031e1c40f85931829bc5fc552, size: 4 }
info: Sent file
info: New client on 127.0.0.1:49698
info: Request 'tmp/bar'
warning: error: FileNotFound
```

Client side:
```
$ echo 'foo' | nc -v 127.0.0.1 8080
Connection to 127.0.0.1 port 8080 [tcp/http-alt] succeeded!
W1�)_�bar

$ echo 'bar' | nc -v 127.0.0.1 8080
Connection to 127.0.0.1 port 8080 [tcp/http-alt] succeeded!
FileNotFound
```
