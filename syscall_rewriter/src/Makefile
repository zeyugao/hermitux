CXX=g++
CXXFLAGS=-I/home/ella717/usr/dyninst/include
LDFLAGS=-lpatchAPI -lsymtabAPI -linstructionAPI \
		-ldyninstAPI -lparseAPI -L/home/ella717/usr/dyninst/lib \
		-lpthread
SRC=$(shell ls *.cpp)
OBJ=$(SRC:.cpp=.o)
PROG=rewrite_syscalls

all: $(PROG)

$(PROG): $(OBJ)
	$(CXX) $^ -o $(PROG) $(LDFLAGS)

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $^ -o $@

clean:
	rm -rf *.o $(PROG)
