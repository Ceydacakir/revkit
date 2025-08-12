### Linux/macOS
```bash
mkdir -p examples/build
cc -O1 -s -o examples/build/challenge examples/challenge.c
```

### Windows (MSYS2/MinGW)
```bash
mkdir examples\build
x86_64-w64-mingw32-gcc -O1 -s -o examples\build\challenge.exe examples\challenge.c
```
