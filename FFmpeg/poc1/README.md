## SUMMARY

stack-buffer-overflow in FFmpeg N-111029-g402d98c9d4 allows a local attacker to execute arbitrary code, and cause a denial of service via the get_bits_long function in FFmpeg/libavcodec/get_bits.h.

How to reproduce:

```bash
./configure --enable-lto --enable-gpl --enable-libx265 --disable-shared --disable-inline-asm --enable-debug=1
./ffmpeg_g -i ./poc ./test.mkv
```

ASAN Log:

![alt text](assets/image.png)