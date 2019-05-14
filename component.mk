COMPONENT_ADD_INCLUDEDIRS=include
COMPONENT_SRCDIRS=.

COMPONENT_OBJS= emv.o \
		init.o \
		params.o \
		tlv.o \
		tools.o



CPPFLAGS +=-Wno-pointer-sign
CFLAGS +=-Wno-pointer-sign
