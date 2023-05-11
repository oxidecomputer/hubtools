# `hubtools`

The `hubtools` repository is a place for logic that wants to be shared between
[Hubris](https://github.com/oxidecomputer/hubris) and _other stuff_.

It should not contain code that runs _within_ the Hubris embedded OS; that kind
of code is implemented in the Hubris repository, and the resulting archives are
wrangled by [Humility](https://github.com/oxidecomputer/humility).

Instead, it's a place for things like "convert an SREC file to a bunch of
different binary file formats"; small functions that are useful when working
with a Hubris archives from a host system.

Right now, this repository contains two things:

- `hubtools` is a crate for miscellaneous Hubris archive manipulation
- `hubedit` is a command-line executable for making post-build modifications to
  a Hubris archive, e.g. as part of a release engineering pipeline.
