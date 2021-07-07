CXX=g++
CXXFLAGS=-I../../../../dyninst-11.0.1/bin/include
LDFLAGS=-lpatchAPI -lsymtabAPI -linstructionAPI \
		-ldyninstAPI -lparseAPI -L../../../../dyninst-11.0.1/bin/lib \
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
