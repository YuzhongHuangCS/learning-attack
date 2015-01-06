CC			= g++
CFLAGS		= -std=c++11 -pthread -Wall -march=native -O3 `pkg-config --cflags gtkmm-3.0`
LINKFLAGS	= -lboost_system -lboost_thread `pkg-config --libs gtkmm-3.0`
SRCS		= main.cpp slowloris.cpp slowloris-gui.cpp
OBJS		= $(SRCS:.cpp=.o)
PROG		= slowloris-gui

all: $(SRCS) $(PROG)

$(PROG): $(OBJS)
	$(CC) $(CFLAGS) $(OBJS) -o $@ $(INCFLAGS) $(LINKFLAGS)

.cpp.o:
	$(CC) $(CFLAGS) $< -c -o $@ $(INCFLAGS)

depend:
	makedepend $(INCFLAGS) -Y $(SRCS)

clean:
	rm $(OBJS) $(PROG)