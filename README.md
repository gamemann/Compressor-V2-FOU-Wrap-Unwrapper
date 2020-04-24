# Compressor V2 FOU Wrap/Unwrap

## Description
Two TC BPF programs being used for [Compressor V2](https://gitlab.com/srcds-compressor/compressor). One program is responsible for wrapping incoming packets into FOU and sending it to the game server. The other is for unwrapping FOU packets sent from the game server and sending it back out as the forwarding/Anycast IP address.

## Compiling
You may use the Make file to build these two files. For example:

```
make clean
make
```

## Requirements
* Linux kernel 5.3 or higher.

## Credits
* [Christian Deacon](https://www.linkedin.com/in/christian-deacon-902042186/) - Creating TC programs.
* [Dreae](http://github.com/dreae) - Helping with code and understanding FOU-encapped packets. Also creator of Compressor V2.