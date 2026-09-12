ECHO = @echo
ECHOFLAGS =

RM = @rm
RMFLAGS = -f

COMP = gcc
COMPFLAGS = -pedantic -Wall -Wextra -m32 -fstack-protector-strong -Wl,-z,noexecstack

LINK = gcc
LINKFLAGS = -pedantic -Wall -Wextra -m32 -fstack-protector-strong -Wl,-z,noexecstack

BIN = mymalloc
OBJS = mymalloc.o pwn.o
LIBS =
CLEAN = clean


# Linking
$(BIN) : $(OBJS)
	$(ECHO) $(ECHOFLAGS) [+] Linking...
	$(LINK) $(LINKFLAGS) -o $(BIN) $(OBJS) $(LIBS)
	$(ECHO) $(ECHOFLAGS)

# Generic compilation of single C file
%.o : %.c mymalloc.h
	$(ECHO) $(ECHOFLAGS) [+] Compilation of "$@" ...
	$(COMP) $(COMPFLAGS) -c $<
	$(ECHO) $(ECHOFLAGS)

# Cleaning rule
$(CLEAN) :
	$(RM) $(RMFLAGS) $(BIN) $(OBJS) core
