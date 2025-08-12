# revkit

Eğitim amaçlı tersine mühendislik aracı. Sadece *kendi derlediğiniz* veya **açıkça izniniz olan** dosyaları analiz edin. Kötüye kullanım yasaktır.

## Özellikler
- Dosya türü/magic tespiti (ELF/PE/Mach-O)
- Bölüm ve temel metadata çıkarımı (LIEF varsa ayrıntılı)
- String çıkarma (ASCII/UTF-16), entropy hesaplama
- Basit disassembly (Capstone) — otomatik mimari tespiti (LIEF varsa) veya parametre ile
- Byte patch etme (offset + hex bayt)
- Wildcard'lı byte pattern arama (`??` destekli)

## Kurulum
```bash
# önerilen: Python 3.10+
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -U pip
pip install -r requirements.txt
pip install -e .
```
> Eğer `lief` kurulumu ortamınızda sorun çıkarırsa, `pip install --only-binary=:all: lief` deneyin. Disassembly için `capstone` gereklidir.

## Kullanım
```bash
# yardım
revkit -h

# analiz (temel özet)
revkit analyze ./examples/build/challenge

# strings ve entropy ile
revkit analyze ./examples/build/challenge --strings --entropy

# bölümler ve importlar (LIEF kuruluysa)
revkit analyze ./examples/build/challenge --sections --imports

# disassembly (otomatik mimari tespit edilirse start/size yeterli)
revkit disasm ./examples/build/challenge --start 0x0 --size 0x200
# mimari manuel verme (ör: x86-64)
revkit disasm ./file.bin --arch x86 --mode 64 --start 0x401000 --size 512

# patch etme
revkit patch ./file.bin --offset 0x123 --bytes "90 90 90" --out ./file_patched.bin

# wildcard pattern arama
revkit find ./file.bin --pattern "E8 ?? ?? ?? ?? 85 C0"
```

## Örnek ikiliyi derlemek
Bkz. `examples/build_instructions.md`. Kısaca Linux/macOS:
```bash
mkdir -p examples/build
cc -O1 -s -o examples/build/challenge examples/challenge.c
```
Windows (MSYS2/MinGW):
```bash
mkdir examples\build
x86_64-w64-mingw32-gcc -O1 -s -o examples\build\challenge.exe examples\challenge.c
```

## Testler
```bash
pytest -q
```

## Docker ile
```bash
docker build -t revkit .
docker run --rm -it -v "$PWD":/work -w /work revkit revkit -h
```

## Lisans
MIT — ayrıntı için LICENSE.
