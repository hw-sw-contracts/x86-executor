# Install
Tested on Linux v5.6.6-300 and v5.6.13-100.
No guarantees about other versions.

To build the executor, run:

```
cd src/executor/x86 
sudo rmmod x86-executor
make clean
make
sudo insmod x86-executor.ko
```

# Using the executor

Use the Revizor CLI (`src/cli.py`).
This executor is not meant to be used standalone.

On your own peril, you could try using it directly, through the `/sys/x86-executor/` pseudo file system.
You can find an example of how to use it in `src/executor.py:X86Intel`.
But I promise you, it's a bad idea.
Better not.