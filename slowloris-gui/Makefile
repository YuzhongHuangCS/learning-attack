CC			= g++
SRCS		= main.cpp slowloris.cpp slowloris-gui.cpp
OBJS		= $(SRCS:.cpp=.o)

UNAME := $(shell uname)

ifeq ($(UNAME), Linux)
	CFLAGS		= -std=c++11 -pthread -Wall -march=native -O2 `pkg-config --cflags gtkmm-3.0`
	LINKFLAGS	= -lboost_system -lboost_thread `pkg-config --libs gtkmm-3.0`
	PROG		= slowloris-gui
else
	CFLAGS 		= -std=c++11 -Wall -mwindows -march=native -O2 `pkg-config --cflags gtkmm-3.0`
	LINKFLAGS	= -lboost_system -lboost_thread -lwsock32 -lws2_32 `pkg-config --libs gtkmm-3.0`
	PROG		= slowloris-gui.exe
	OBJS		+= logo.o
endif

all: $(SRCS) $(PROG)

$(PROG): $(OBJS)
	$(CC) $(CFLAGS) $(OBJS) -o $@ $(INCFLAGS) $(LINKFLAGS)

logo.o:
	windres logo.rc logo.o

.cpp.o:
	$(CC) $(CFLAGS) $< -c -o $@ $(INCFLAGS)

depend:
	makedepend $(INCFLAGS) -Y $(SRCS)

clean:
	rm $(OBJS) $(PROG)
