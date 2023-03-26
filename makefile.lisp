OPT = -g0 -O3

LIB_SOURCES1 = awsmlisp.c parser.c
LIB_SOURCES = $(addprefix src/, $(LIB_SOURCES1))

CC = gcc
TARGET = lisp
LIB_OBJECTS =$(LIB_SOURCES:.c=.o)
LDFLAGS= -L. $(OPT) -Wall -Wextra
LIBS= -lm
ALL= $(TARGET)
CFLAGS = -Isrc/ -Iinclude/ -Ilibmicroio/include/ -std=gnu11 -c $(OPT) -Wall  -Wextra -Werror=implicit-function-declaration -Wformat=0 -D_GNU_SOURCE -Wwrite-strings -Werror -Werror=maybe-uninitialized #-fprofile-use=profile.out -v -fprofile-generate=./profile.out   #

ifneq ($(BUILD),release)
    CFLAGS += -DDEBUG
    OPT = -g3 -O0
endif

$(TARGET): $(LIB_OBJECTS) libawsm.a
	$(CC)  $(LDFLAGS) $(LIB_OBJECTS)  libawsm.a libmicroio/libmicroio.a $(LIBS)  -o $@

release debug:
	$(MAKE) BUILD=$@

all: $(ALL)

.c.o: $(HEADERS) $(LEVEL_CS)
	$(CC) $(CFLAGS) $< -o $@ -MMD -MF $@.depends

depend: h-depend
clean:
	rm -f $(LIB_OBJECTS) $(ALL) src/*.o.depends src/*.o

-include $(LIB_OBJECTS:.o=.o.depends)
