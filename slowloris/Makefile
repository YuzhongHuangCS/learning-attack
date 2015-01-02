CC			= g++
CFLAGS		= -std=c++11 -pthread -Wall -march=native -O3
LINKFLAGS	= -lboost_system -lboost_program_options
SRCS		= slowloris.cpp
OBJS		= $(SRCS:.cpp=.o)
PROG		= slowloris

all: $(SRCS) $(PROG)

$(PROG): $(OBJS)
	$(CC) $(CFLAGS) $(OBJS) -o $@ $(INCFLAGS) $(LINKFLAGS)

.cpp.o:
	$(CC) $(CFLAGS) $< -c -o $@ $(INCFLAGS)

depend:
	makedepend $(INCFLAGS) -Y $(SRCS)

clean:
	rm $(OBJS) $(PROG)