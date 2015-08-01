CFLAGS+=-I.. -g -W -Wall

all: testC89 testC99 testCPP98 testCPP0x testCPP11

testC89: test_main.o
	$(CC) $(CFLAGS) -std=c89 ../airbag_fd.c -ldl -lpthread $^ -o $@
testC99: test_main.o
	$(CC) $(CFLAGS) -std=c99 ../airbag_fd.c -ldl -lpthread $^ -o $@
testCPP98: test_main.o
	$(CXX) $(CFLAGS) -std=c++98 ../airbag_fd.c -ldl -lpthread $^ -o $@
testCPP0x: test_main.o
	$(CXX) $(CFLAGS) -std=c++0x ../airbag_fd.c -ldl -lpthread $^ -o $@
testCPP11: test_main.o
	$(CXX) $(CFLAGS) -std=c++11 ../airbag_fd.c -ldl -lpthread $^ -o $@

clean:
	rm -f test_*.o testC*
