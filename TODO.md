# TODO / wishlist

## Improve runtime documentation and manpage

    Print out more information on -help and complete manpage with all
    possible options and flags compiled at runtime.

## Eliminate all dynamic memory allocation

    When parsing binaries for checksum do not allocate their size
    dynamically in memory, but load fixed size chunks and use
    sha256_update on each one.

## Send signals to process names (kill etc.)

    Allow to send signals (default SIGTERM for kill) to PIDs of
    processes whose name matches the authorized list.
    This should be a compile-time flag.

## Daemon mode flag

    Isolate daemon forking code into #ifdefs to make it optional at
    compile time.

## Setuidgid flag

    Isolate target_uid/gid options into #ifdefs to make then optional
    at compile time.
