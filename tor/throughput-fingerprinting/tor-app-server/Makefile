CXXFLAGS =	-O2 -g -Wall -D_REENTRANT

OBJS =		tor-app-server.o

LIBS =		-lmyutil -lpthread

TARGET =	tor-app-server

$(TARGET):	$(OBJS)
	$(CXX) -L../myutil -o $(TARGET) $(OBJS) $(LIBS)

all:	clean $(TARGET)

clean:
	rm -f $(OBJS) $(TARGET)

.PHONY : clean all
