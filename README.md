This is repository for FETCH. a fast and easy to use binary disassembing tool.


FETCH is build on top of the Dyninst


## Dependency:

1. Dyninst 10.1.0: The dependency of Dyninst is [here](https://github.com/dyninst/dyninst/wiki/Building-Dyninst#source_long)

   ```
   cd dyninst && mkdir build && cmake .. && make install
   ```

2. [capstone](https://github.com/aquynh/capstone):
   ```
    cmake --build . --config Release --target install
   ```

3. [Protocol Buffers](https://developers.google.com/protocol-buffers):
   
   The build script is:
   ```
	sudo apt-get install autoconf automake libtool curl make g++ unzip
        git clone https://github.com/protocolbuffers/protobuf.git
	cd protobuf
	git submodule update --init --recursive
	./autogen.sh

        ./configure
	 make
	 make check
	 sudo make install
	 sudo ldconfig # refresh shared library cache.
   ```

4. [libdwarf](https://sourceforge.net/projects/libdwarf/)

   ```
    # download the code
    wget -c https://www.prevanders.net/libdwarf-20210305.tar.gz
    tar xvf libdwarf-20210305.tar.gz
    cd libdwarf-20210305
    ./configure && make install
   ```

5. Generate protobuf files.

   ```
       pushd $PWD
       cd src/proto
       protoc --cpp_out=. --proto_path=. blocks.proto
       popd

       cd script
       protoc --python_out=. blocks.proto
   ```

## Build:

Build FETCH with following command:
   ```
   cd src && make
   ```

## How to run

You can run the tool with following command:

```
./FETCH <path of executable> <x64 or x86> <path of output>
```

For example:

```
./FETCH ../example/readelf.strip x64 /tmp/readelf_fetch.pb
```

To read Function Info from output pb file: 

```
cd ../script
python3 readPbFunc.py <path of pb file>
```
