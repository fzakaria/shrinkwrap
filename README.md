# Shrinkwrap

[![built with nix](https://builtwithnix.org/badge.svg)](https://builtwithnix.org)


>  A tool that embosses the needed dependencies on the top level executable

It can be useful to _freeze_ all the dynamic shared objects needed by an application.

_shrinkwrap_ is a tool which will discover all transitive dynamic shared objects, and lift them up to the executable referenced by absolute path.

Here is an example where we will apply this to _ruby_. 

Lets take a look at all the _dynamic shared objects_ needed by the Ruby interpreter.

```console
❯ ldd $(which ruby)
	linux-vdso.so.1 (0x00007ffeed386000)
	/lib/x86_64-linux-gnu/libnss_cache.so.2 (0x00007f638ddf8000)
	libruby-2.7.so.2.7 => /lib/x86_64-linux-gnu/libruby-2.7.so.2.7 (0x00007f638da79000)
	libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f638d8b4000)
	libpthread.so.0 => /lib/x86_64-linux-gnu/libpthread.so.0 (0x00007f638d893000)
	librt.so.1 => /lib/x86_64-linux-gnu/librt.so.1 (0x00007f638d888000)
	libgmp.so.10 => /lib/x86_64-linux-gnu/libgmp.so.10 (0x00007f638d807000)
	libdl.so.2 => /lib/x86_64-linux-gnu/libdl.so.2 (0x00007f638d7ff000)
	libcrypt.so.1 => /lib/x86_64-linux-gnu/libcrypt.so.1 (0x00007f638d7c4000)
	libm.so.6 => /lib/x86_64-linux-gnu/libm.so.6 (0x00007f638d67f000)
	/lib64/ld-linux-x86-64.so.2 (0x00007f638de06000)
```

We can see also that the _ruby_ application only lists a few needed shared objects itself.

```console
❯ patchelf --print-needed $(which ruby)
libruby-2.7.so.2.7
libc.so.6
```

Let's now apply _shrinkwrap_ and see the results.

```console
❯ nix run github:fzakaria/shrinkwrap $(which ruby
```

It automatically creates a `_stamped` copy of the filename if none provided and sets all the _NEEDED_ sections.

```console
❯ patchelf --print-needed ruby_stamped
/lib/x86_64-linux-gnu/libm.so.6
/lib/x86_64-linux-gnu/libcrypt.so.1
/lib/x86_64-linux-gnu/libdl.so.2
/lib/x86_64-linux-gnu/libgmp.so.10
/lib/x86_64-linux-gnu/librt.so.1
/lib/x86_64-linux-gnu/libpthread.so.0
/lib/x86_64-linux-gnu/libruby-2.7.so.2.7
/lib/x86_64-linux-gnu/libc.so.6

❯ ldd ruby_stamped
	linux-vdso.so.1 (0x00007ffe641f3000)
	/lib/x86_64-linux-gnu/libnss_cache.so.2 (0x00007f9cd4320000)
	/lib/x86_64-linux-gnu/libm.so.6 (0x00007f9cd41db000)
	/lib/x86_64-linux-gnu/libcrypt.so.1 (0x00007f9cd41a0000)
	/lib/x86_64-linux-gnu/libdl.so.2 (0x00007f9cd419a000)
	/lib/x86_64-linux-gnu/libgmp.so.10 (0x00007f9cd4119000)
	/lib/x86_64-linux-gnu/librt.so.1 (0x00007f9cd410e000)
	/lib/x86_64-linux-gnu/libpthread.so.0 (0x00007f9cd40eb000)
	/lib/x86_64-linux-gnu/libruby-2.7.so.2.7 (0x00007f9cd3d8c000)
	/lib/x86_64-linux-gnu/libc.so.6 (0x00007f9cd3bc7000)
	/lib64/ld-linux-x86-64.so.2 (0x00007f9cd4336000)
```

Thanks to [@trws](https://github.com/trws) for the inspiration and original version of this Python script.