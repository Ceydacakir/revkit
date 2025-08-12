# revkit

revkit, eğitim amaçlı bir tersine mühendislik aracı. Kendi derlediğin (veya analiz izni olan) ikili dosyalar üzerinde hızlıca özet çıkarma, string bulma, entropy ölçme, temel disassembly, byte patch etme ve wildcard’lı imza arama yapmanı sağlıyor. CTF/lab seviyesinde “ilk bakış” analizlerinde pratik olsun diye yazıldı.

Neleri yapıyor?
Dosya türü tespiti: ELF / PE / Mach-O (basit “magic” kontrolü).

Özet analiz: Boyut, tür, (LIEF varsa) bölümler ve importlar.

Strings & entropy: ASCII ve basit UTF-16 string’leri listeler; dosyanın entropy değerini hesaplar (0–8).

Disassembly (x86/x64): Capstone ile belli bir aralığı hexdump yerine assembly olarak gösterir (mimariyi LIEF’ten tahmin etmeye çalışır).

Byte patch: Dosyada belirttiğin offset’e hex bayt yazıp yeni bir dosya üretir.

Wildcard pattern arama: E8 ?? ?? ?? ?? 85 C0 gibi maskeli byte imzalarını bulur.

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
