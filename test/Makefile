CFLAGS+=-I.. -g

test: test_main.o
	$(CXX) $(CFLAGS) ../airbag_fd.c -ldl -lpthread $^ -o $@

clean:
	rm -f test_*.o test
