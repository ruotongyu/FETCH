#! /bin/bash

print_help(){
  echo "-p: Required. Tool prefix."
  echo "-d: Required. The directory that to be handled."
  echo "-o: Required. The compared result that saved."
  echo "-b: Optional. Need binary or not."
  echo "-P: Optional. Need pdb file or not."
}

BINARY=0
PDBFILE=0
NEW=0
while getopts "p:d:o:t:hbPn" arg
do
  case $arg in
    p)
      PREFIX=$OPTARG;;
    d)
      DIR=$OPTARG;;
    o)
      OUTPUT=$OPTARG;;
    b)
      BINARY=1;;
    t)
      TOOL=$OPTARG;;
    P)
      PDBFILE=1;;
    n)
      NEW=1;;
    h | *)
      print_help;;
  esac
done

if [ ! -d $DIR ]; then
  echo "Please input valid directory with (-d)!"
  exit -1
fi

#if [ ! -d $OUTPUT ]; then
#  echo "mkdir the output directory $OUTPUT"
#  mkdir -p $OUTPUT
#  if [ $? -ne 0 ]; then
#    echo "mkdir $OUTPUT error!"
#    exit -1
#  fi
#fi

if [ ! -f $TOOL ]; then
  echo "can't file tool file path $TOOL"
  exit -1
fi

for file in `find $DIR -name "angrSymbols-*"`; do
  #echo "current to be handled file is $file"
  echo "<<<<<<<<<<<<<<<<<<<<<>>>>>>>>>>>>>>>>>>>>>>>>"
  echo "<<<<<<<<<<<<<<<<<<<<<>>>>>>>>>>>>>>>>>>>>>>>>"
  echo "[Handle File]: $binary_file"
  echo "python3 $TOOL -i $file"
  #timeout 1h python3 $TOOL -g $gtBlock_file -c $angr_file -b $binary_file
done
