COMPILER = gcc
SOURCES = main.c
CFLAGS = -g3
LFLAGS = -lpcap
EXECUTABLE = uflood
DEBUGGER = gdb
DFLAGS = -q --args
DTARGET = uflood
DARGS = -d vboxnet0						\
	-sm 0a:00:27:00:00:00				\
	-dm 08:00:27:be:bc:6c				\
	-sa 192.168.56.1					\
	-da 192.168.56.101					\
	-sp 80								\
	-dp 80								\
	-c 15000							\
	-cd 10000


# Debug + release
all:
	$(COMPILER) $(CFLAGS) $(SOURCES) $(LFLAGS) -o $(EXECUTABLE)
	$(COMPILER) $(SOURCES) $(LDFLAGS) -o $(EXECUTABLE)

# Debug version
debug:
	$(COMPILER) $(CFLAGS) $(SOURCES) $(LFLAGS) -o $(EXECUTABLE)

# Release version
out:
	$(COMPILER) $(SOURCES) $(LFLAGS) -o $(EXECUTABLE)

# Debug program
gdb:
	$(DEBUGGER) $(DFLAGS) $(DTARGET) $(DARGS)

# Launch program
launch:
	sudo ./uflood $(DARGS)
