gcc -o emv emv.c main.cpp params.c tlv.c tools.c init.c nn.c sha1.c `pkg-config --cflags --libs libpcsclite`
