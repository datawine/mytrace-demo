# mytrace-demo

This is a demo using strace to hijack syscall. 

Skeleton is anywhere outside comment `//specific logic`.

`./tracer` is the parent process who hijack `./tracee`'s syscall. In this example, it hijacks `mmap` and copied it to a 
specific area.

Note that it can't run directly because the current code is part of a bigger project. 

## Make

``` shell script
# make clean
make
```

## usage
``` shell
./tracee
./tracer $(pidof tracee)
```

## references
- https://www.man7.org/linux/man-pages/man2/ptrace.2.html
- https://gist.github.com/willb/14488/80deaf4363ed408a562c53ab0e56d8833a34a8aa