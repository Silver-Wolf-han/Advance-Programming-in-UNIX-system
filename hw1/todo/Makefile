CC = gcc
CFLAGS = -shared -Wall -g -fPIC

all: ex1 ex2 part2

ex1:
	$(CC) ex1.c $(CFLAGS) -o libzpoline.so.1

ex2:
	$(CC) ex2.c $(CFLAGS) -o libzpoline.so.2 -lcapstone

ex3:
	$(CC) ex3.c $(CFLAGS) -o libzpoline.so -lcapstone

part2: ex3
	$(CC) logger.c $(CFLAGS) -o logger.so

rm_exe_file:
	rm -f *html* *vsyscall* main.c

clean: rm_exe_file
	rm -f *.so*
	
.PHONY: clean

run_ex1: ex1
	LD_PRELOAD=./libzpoline.so.1 ./examples/ex1

run_ex2: ex2
	LD_PRELOAD=./libzpoline.so.2 /usr/bin/echo '7h15 15 4 l337 73x7'
	LD_PRELOAD=./libzpoline.so.2 /usr/bin/echo 'uphw{7h15_15_4_51mpl3_fl46_fr0m_200l4b}'
	LD_PRELOAD=./libzpoline.so.2 cat ./examples/ex2-2.txt

run_ex3: ex3
	LD_PRELOAD=./libzpoline.so LIBZPHOOK=./examples/libex3hook.so ./examples/ex3

run_ex4: part2
	LD_PRELOAD=./libzpoline.so LIBZPHOOK=./logger.so touch main.c
	LD_PRELOAD=./libzpoline.so LIBZPHOOK=./logger.so cat /etc/hosts

run_ex5: part2
	LD_PRELOAD=./libzpoline.so LIBZPHOOK=./logger.so wget http://www.google.com -q -t 1

run_ex6: part2
	LD_PRELOAD=./libzpoline.so LIBZPHOOK=./logger.so python3 -c 'import os; os.system("wget http://www.google.com -q -t 1")'

run_hidden_1: part2
	LD_PRELOAD=./libzpoline.so LIBZPHOOK=./logger.so cp ./examples/ex3 '[vsyscall]'
	LD_PRELOAD=./libzpoline.so LIBZPHOOK=./logger.so ./'[vsyscall]'

run_hidden_2_server: part2
	LD_PRELOAD=./libzpoline.so LIBZPHOOK=./logger.so nc -lkU /tmp/hidden3.sock

run_hidden_2_client:
	LD_PRELOAD=./libzpoline.so LIBZPHOOK=./logger.so nc -U /tmp/hidden3.sock

run_hidden_3: part2
	LD_PRELOAD=./libzpoline.so LIBZPHOOK=./logger.so bash -c 'curl -s file:///etc/hosts'

run_hidden_4: part2
	LD_PRELOAD=./libzpoline.so LIBZPHOOK=./logger.so python3 -c 'import os; os.system("python3 -c '\''import os; os.system(\"id\")'\''")'

run_myex: part2
	LD_PRELOAD=./libzpoline.so LIBZPHOOK=./logger.so $(COMMAND)

run_all_test: run_ex1 run_ex2 run_ex3 run_ex4 run_ex5 run_ex6 run_hidden_1 run_hidden_3 run_hidden_4
