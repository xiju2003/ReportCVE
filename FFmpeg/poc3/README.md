## SUMMARY

heap-buffer-overflow in FFmpeg version 6.1.1 allows a local attacker to execute arbitrary code, and cause a denial of service via the pnm_decode_frame function in FFmpeg-n6.1.1/libavcodec/pnmdec.c:297

How to reproduce:

```bash
./configure --enable-lto --enable-gpl --enable-libx265 --disable-shared --disable-inline-asm --enable-debug=1
./ffmpeg_g -i ./poc ./test.mkv
```

ASAN Log:

![alt text](assets/image.png)