all: disasm.c wbt.cpp chopelf.c patch-ctrlflow.c
	g++ -g -c -I../include wbt.cpp -o wbt.o
	gcc -g -c -I../include disasm.c -o disasm.o
	gcc -g -c -I../include chopelf.c -o chopelf.o
	gcc -g -c -I../include patch-ctrlflow.c -o patch-ctrlflow.o
	gcc disasm.o patch-ctrlflow.o wbt.o chopelf.o -o elfpatch -lbfd -lopcodes -lstdc++
	rm -rf *.o
