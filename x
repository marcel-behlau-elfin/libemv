gcc -o emv emv.c main.cpp params.c tlv.c tools.c init.c nn.c sha1.c ca_pub_keys.c `pkg-config --cflags --libs libpcsclite`
