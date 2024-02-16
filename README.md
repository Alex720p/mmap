
# x64 usermode dll manual mapper


## Usage

```
mmap.exe process.exe module.dll
```


## Features

- Uses codecaves for shellcode injection (or simply allocates a page if no codecaves are found)
- Thread hijacking for shellcode execution
- Erases PE Header + .reloc section
- Recursively manual maps dependencies
