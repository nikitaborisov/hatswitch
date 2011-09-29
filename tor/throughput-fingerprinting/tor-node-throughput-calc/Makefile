CXXFLAGS =	-O2 -g -Wall -D_REENTRANT

OBJS =		tor-node-throughput-calc.o

LIBS =		-L../myutil -lmyutil -lpthread -lpcap

TARGET =	tor-node-throughput-calc

$(TARGET):	$(OBJS)
	$(CXX) -o $(TARGET) $(OBJS) $(LIBS)

all:	clean $(TARGET)

clean:
	rm -f $(OBJS) $(TARGET)

.PHONY : clean all
