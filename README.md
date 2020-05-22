This QEMU patch introduces irix/solaris userland emulation. It currently runs
only under linux and macOS (though BSD support would probably be feasable).

### compiling

Configure QEMU for irix/solaris userland emulation for linux and compile (see the original
QEMU README for further instructions):

```
configure --target-list=irix-linux-user,irixn32-linux-user,irix64-linux-user,solaris-linux-user
make && make install
```

Or, configure QEMU for irix userland emulatin for macOS

```
./configure --target-list=irix-darwin-user \
    --disable-vnc \
    --disable-sdl \
    --disable-gtk \
    --disable-cocoa \
    --disable-opengl \
    --disable-capstone \
    --disable-hax \
    --disable-hvf \
    --disable-tools
make
```

### using

I recommend using binfmt. I have prepared some scripts for this which you can
obtain from my qemu-irix-helpers repository at github. Adapt the wrapper scripts
to your setup and install them somewhere in your executable path. Activate them
with the binfmt install scripts.

Now you should be able to directly execute irix/solaris binaries from the shell.
As a rather simple test, try:

```
<target rootfs>/bin/ls
```

### notes

IRIX threading uses a local TLS storage area named PRDA which is privately mapped
into each thread at address 0x20000. qemu-irix will emulate this behaviour if
QEMU_IRIXPRDA is set in the environment. You most probably need to do so for any
IRIX software using multithreading. Be aware that this will noticably harm the
performance of the emulation since every memory access is checked for PRDA access
(AFAIK it isn't possible to emulate this directly on linux or BSD).

For conveniance I have also extended the handling of QEMU_LD_PREFIX to allow
the specification of multiple paths separated by ':'. That way you can keep the
target os root separate from additional software. Moreover, for a noticable
speed gain at qemu startup, QEMU_LD_PREFIX is not pre-scanned anymore. Instead,
it is now caching any directories accessed by the emulated program.

send bug reports, fixes etc to Kai-Uwe Bloem  (<derkub@gmail.com>)
