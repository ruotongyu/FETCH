CXX=g++
CXXFLAGS=-g -O2

CXXFLAGS= -O2 -std=c++11
LDFLAGS= -L/usr/local/lib -lparseAPI -linstructionAPI -lsymtabAPI -ldyninstAPI -lcommon -lglog -lgflags -lprotobuf -lboost_system -lpthread

all: dyninstStackHeight stackheight.pb.cc EhframeParser.o

stackheight.pb.cc: ../proto/stackheight.proto
	protoc --cpp_out=. --proto_path=../proto stackheight.proto

InstructionCache.o: InstructionCache.cc
	$(CXX) -c $(CXXFLAGS) -o $@ $^

livenessAnaEhframe.o: livenessAnaEhframe.cc
	$(CXX) -c $(CXXFLAGS) -o $@ $^

dyninstStackHeight: dyninstStackHeight.cpp stackheight.pb.cc livenessAnaEhframe.o InstructionCache.o
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)

EhframeParser.o: EhframeParser.cc
	$(CXX) -c $(CXXFLAGS) -o $@ $^ 

clean:
	rm *.o dyninstStackHeight stackheight.pb.*
