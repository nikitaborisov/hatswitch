CXXFLAGS =	-O2 -g -Wall -D_REENTRANT

OBJS =		net.o thread.o socks.o StringTokenizer.o R.o Packet.o

LIBS =		-lpthread

TARGET =	libmyutil.so

$(TARGET):	$(OBJS)
	$(CXX) -shared -o $(TARGET) $(OBJS) $(LIBS)

all:	clean $(TARGET)

clean:
	rm -f $(OBJS) $(TARGET)

.PHONY : clean all
