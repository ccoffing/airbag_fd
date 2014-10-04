CFLAGS+=-I..

test: test_main.o
	$(CC) $(CFLAGS) ../airbag_fd.c -ldl -lpthread $^ -o $@

clean:
	rm -f test_*.o test
