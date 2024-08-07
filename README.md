# zfs

Zig File Server (very basic file server)

## How it works

- A client connects and requests a file
- The server replies with the md5sum (raw, not in hex (16 bytes)) and the file size in bytes (u64)
- If the md5sum is all 0, means an error occured and data following will be the error len (u64) and message
- Otherwise (no error) the server send the file data

## Example

Server side:
```
$ ./zig-out/bin/zfs -d tmp 8080
info: Listening on 0.0.0.0:8080 and serving tmp/
info: New client on 127.0.0.1:51598 [1/10]
info: Request 'tmp/weirdFileName'
warning: FileNotFound
info: Request 'tmp/hello'
info: Got stat from file
info: Got md5hash from file
info: Sent metadata: { hash: 4a8a470360bf6b3ca86c519812851d0a, size: 10 }
info: Sent file
info: Client 127.0.0.1:51598 left
```

Client side:
```
$ ./zfs_client.pl
> weirdFileName
md5sum => '00000000000000000000000000000000'
filesize => 12
FileNotFound
> hello
md5sum => '4a8a470360bf6b3ca86c519812851d0a'
filesize => 10
Downloaded 10/10 bytes
md5sum matches !
>
```
