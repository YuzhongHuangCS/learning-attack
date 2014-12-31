CC			= g++
CFLAGS		= -Wall -march=native -O3
LINKFLAGS	=
SRCS		= flood.cpp
OBJS		= $(SRCS:.cpp=.o)
PROG		= flood

all: $(SRCS) $(PROG)

$(PROG): $(OBJS)
	$(CC) $(CFLAGS) $(OBJS) -o $@ $(INCFLAGS) $(LINKFLAGS)

.cpp.o:
	$(CC) $(CFLAGS) $< -c -o $@ $(INCFLAGS)

depend:
	makedepend $(INCFLAGS) -Y $(SRCS)

clean:
	rm $(OBJS) $(PROG)