CC			= g++
SRCS		= slowloris.cpp
OBJS		= $(SRCS:.cpp=.o)

UNAME := $(shell uname)

ifeq ($(UNAME), Linux)
	CFLAGS		= -std=c++11 -pthread -Wall -march=native -O2
	LINKFLAGS	= -lboost_system -lboost_program_options -lboost_thread
	PROG		= slowloris
else
	CFLAGS 		= -std=c++11 -Wall -march=native -O2
	LINKFLAGS	= -lboost_system -lboost_program_options -lboost_thread -lwsock32 -lws2_32
	PROG		= slowloris.exe
endif

all: $(SRCS) $(PROG)

$(PROG): $(OBJS)
	$(CC) $(CFLAGS) $(OBJS) -o $@ $(INCFLAGS) $(LINKFLAGS)

.cpp.o:
	$(CC) $(CFLAGS) $< -c -o $@ $(INCFLAGS)

depend:
	makedepend $(INCFLAGS) -Y $(SRCS)

clean:
	rm $(OBJS) $(PROG)