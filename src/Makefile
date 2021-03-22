all: dyninstBB_extent

CXXFLAGS=-O2 -std=c++11
CXX=g++
LDFLAGS=-L/usr/local/lib -lcommon -ldyninstAPI -linstructionAPI -lparseAPI -lsymtabAPI -lglog -lgflags -lprotobuf -lboost_system -lpthread -lcapstone -ldwarf


InstructionCache.o: InstructionCache.cc
	g++ -c $(CXXFLAGS) -o $@ $^ 

livenessAnaEhframe.o: livenessAnaEhframe.cc
	g++ -c $(CXXFLAGS) -o $@ $^ 

EhframeParser.o: stackheight/ehframe/EhframeParser.cc
	$(CXX) -c -o $@ $^

dyninstBB_extent: dyninstBB_extent.cpp protobuf/blocks.pb.cc protobuf/refInf.pb.cc utils.cpp loadInfo.cpp Reference.cpp livenessAnaEhframe.o InstructionCache.o EhframeParser.o tailcall/tailcall.cc
	g++ $(CXXFLAGS) -o $@ $^ $(LDFLAGS)
