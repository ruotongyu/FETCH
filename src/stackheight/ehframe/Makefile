CXX=g++
CXXFLAGS= -O2 -std=c++11
LDFLAGS= -L/usr/local/lib -ldwarf -lprotobuf -lglog -lgflags -lpthread 


all: EhStackHeight EhSummary

stackheight.pb.cc: ../proto/stackheight.proto ../../blocks.proto
	protoc --cpp_out=. --proto_path=../proto stackheight.proto

blocks.pb.cc: ../../blocks.proto
	protoc --cpp_out=. --proto_path=../../ blocks.proto

EhStackHeight: EhStackHeight.cc EhframeParser.cc stackheight.pb.cc blocks.pb.cc
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)

EhSummary: EhSummary.cc EhframeParser.cc 
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)
clean:
	rm EhStackHeight blocks.pb.* stackheight.pb.* EhSummary
