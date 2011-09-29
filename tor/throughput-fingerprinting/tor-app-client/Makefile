CXXFLAGS =	-O2 -g -Wall -D_REENTRANT 

OBJS =		tor-app-client.o

LIBS =		-lmyutil -lpthread -lpcap

TARGET =	tor-app-client

$(TARGET):	$(OBJS)
	$(CXX) -L../myutil -o $(TARGET) $(OBJS) $(LIBS)

all:	clean $(TARGET)

clean:
	rm -f $(OBJS) $(TARGET)

.PHONY : clean all
