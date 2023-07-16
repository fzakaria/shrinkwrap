# Shrinkwrap

![main](https://github.com/fzakaria/shrinkwrap/actions/workflows/main.yml/badge.svg)
[![built with nix](https://builtwithnix.org/badge.svg)](https://builtwithnix.org)

>  A tool that embosses the needed dependencies on the top level executable

# Introduction

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
❯ nix run github:fzakaria/shrinkwrap $(which ruby)
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

## Motivation

Certain _store_ based build tools such as [Guix](https://guix.gnu.org/), [Nix](https://nixos.org) or [Spack](https://spack.io/) make heavy use of _RUNPATH_ to help create reproducible and hermetic binaries.

One problem with the heavy use of _RUNPATH_, is that the search space could effect startup as it's `O(n)` on the number of entries (potentially worse if using _RPATH_). This can alo be expensive in _stat syscalls_, that has been well documented by in [this blog post](https://guix.gnu.org/blog/2021/taming-the-stat-storm-with-a-loader-cache/).

Secondly, shared dynamic objects may be found due to the fact that they are cached during the linking stage. Meaning, if another shared object requires the same dependency but failed to specify where to find it, it may still properly resolved if discovered earlier in the linking process. This is extremely error prone and changing any of the executable's dependencies can change the link order and potentially cause the binary to no longer work.

Lifting up the needed shared objects to the top executable makes the dependency discovery _simple_, _quick_ and _hermetic_ since it can no longer change based on the order of visited dependencies.

## Pitfalls

At the moment this only works with _glibc_ and not other _Standard C Libraries_ such as _musl_. The reason is that other linkers seem to resolve duplicate shared object files differently when they appear in the traversal. Consider the following example:

```
              +------------+
              |            |
              | Executable |
              |            |
      +-------+------------+----+
      |                         |
      |                         |
+-----v-----+            +------v----+
|           |            |           |
| libbar.so |            | libfoo.so |
|           |            |           |
+-----+-----+            +-----------+
      |               /some-fixed-path/libfoo.so
      |
+-----v------+
|            |
| libfoo.so  |
|            |
+------------+
```

In _glibc_ the cache is keyed by the _soname_ value on the shared object. That allows the first found _libfoo.so_ at _/some-fixed-path/libfoo.so_ to be used for the one which _libbar.so_ depends on.

Unfortunately, _musl_ does not support this functionality and ongoing discussions of inclusing it can be followed on the [mailing list](https://www.openwall.com/lists/musl/2021/12/21/1).

## Development

You must have [Nix](https://nixos.org) installed for development.

This package uses [poetry2nix](https://github.com/nix-community/poetry2nix) to easily setup a development environment.

```console
> nix develop
```

A helping `Makefile` is provided to run all the _linters_ and _formatters_.

```console
> make lint
```

Note: I publish artifacts to [cachix](https://cachix.org/) that you can use to develop faster.
```console
> cachix use fzakaria
```

## Experiments

Included in the flake are different experiments for evaluating Shrinkwrap.
In most cases they provide a Docker image (tar.gz) which can be loaded.

### emacs

Creates a stamped version of the popular emacs editor similarly to the Guix experiment outlined in the [blog post](https://guix.gnu.org/blog/2021/taming-the-stat-storm-with-a-loader-cache/).

You can build the Docker image and inside will be `emacs-wrapped` as well as `emacs` and `strace` to recreate the experiment.
```console
> nix build .#experiments.emacs
> docker load < result
643ace721190: Loading layer [==================================================>]  786.9MB/786.9MB
Loaded image: shrinkwrap-emacs-experiment:7jjlknqq660x1crrw7gm4m2qzalp71qj
> docker run -it emacs-experiment:7jjlknqq660x1crrw7gm4m2qzalp71qj /bin/bash
> patchelf --print-needed /bin/emacs-stamped
/nix/store/m756011mkf1i0ki78i8y6ac3gf8qphvi-gcc-10.3.0-lib/lib/libstdc++.so.6
/nix/store/xif6gg595hgmqawrcarapa8j2r7fbz9w-icu4c-70.1/lib/libicudata.so.70
/nix/store/i6cmh2d4hbyp00rnh5rpf48pc7xfzx6j-libgpg-error-1.42/lib/libgpg-error.so.0
/nix/store/q39ykk5fnhlbnl119iqjbgaw44kd65fy-util-linux-2.37.2-lib/lib/libblkid.so.1
/nix/store/b1k5z0fdj0pnfz89k440al7ww4a263bf-libglvnd-1.3.4/lib/libGLX.so.0

```

If you'd like you can pull the image directly from DockerHub via [fmzakari/shrinkwrap-emacs-experiment:7jjlknqq660x1crrw7gm4m2qzalp71qj](https://hub.docker.com/layers/shrinkwrap-emacs-experiment/fmzakari/shrinkwrap-emacs-experiment/7jjlknqq660x1crrw7gm4m2qzalp71qj/images/sha256-4633059bdf6c7ddbe23a4c6da11eba7ff58029eb870af01c98f10ada03324ee0?context=explore).

```console
> docker pull fmzakari/shrinkwrap-emacs-experiment:7jjlknqq660x1crrw7gm4m2qzalp71qj
> docker run -it fmzakari/shrinkwrap-emacs-experiment:7jjlknqq660x1crrw7gm4m2qzalp71qj /bin/bash
> patchelf --print-needed /bin/emacs-stamped
/nix/store/m756011mkf1i0ki78i8y6ac3gf8qphvi-gcc-10.3.0-lib/lib/libstdc++.so.6
/nix/store/xif6gg595hgmqawrcarapa8j2r7fbz9w-icu4c-70.1/lib/libicudata.so.70
/nix/store/i6cmh2d4hbyp00rnh5rpf48pc7xfzx6j-libgpg-error-1.42/lib/libgpg-error.so.0
/nix/store/q39ykk5fnhlbnl119iqjbgaw44kd65fy-util-linux-2.37.2-lib/lib/libblkid.so.1
/nix/store/b1k5z0fdj0pnfz89k440al7ww4a263bf-libglvnd-1.3.4/lib/libGLX.so.0
```
## Contributions

Thanks to [@trws](https://github.com/trws) for the inspiration and original version of this Python script.