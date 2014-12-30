CC			= g++
CFLAGS		= -Wall -march=native -fopenmp -O3
LINKFLAGS	=
SRCS		= my.cpp
OBJS		= $(SRCS:.cpp=.o)
PROG		= my.out

all: $(SRCS) $(PROG)

$(PROG): $(OBJS)
	$(CC) $(CFLAGS) $(OBJS) -o $@ $(INCFLAGS) $(LINKFLAGS)

.cpp.o:
	$(CC) $(CFLAGS) $< -c -o $@ $(INCFLAGS)

depend:
	makedepend $(INCFLAGS) -Y $(SRCS)

clean:
	rm $(OBJS) $(PROG)