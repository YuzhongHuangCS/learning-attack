CC			= g++
CFLAGS		= -std=c++11 -pthread -Wall -march=native
LINKFLAGS	= -lboost_system
SRCS		= learn.cpp
OBJS		= $(SRCS:.cpp=.o)
PROG		= learn

all: $(SRCS) $(PROG)

$(PROG): $(OBJS)
	$(CC) $(CFLAGS) $(OBJS) -o $@ $(INCFLAGS) $(LINKFLAGS)

.cpp.o:
	$(CC) $(CFLAGS) $< -c -o $@ $(INCFLAGS)

depend:
	makedepend $(INCFLAGS) -Y $(SRCS)

clean:
	rm $(OBJS) $(PROG)