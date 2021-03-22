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
for file in `find -name "angrAlign-*" | xargs grep "False negitive number" | grep -v 'is 0' | cut -d ' ' -f1 | cut -d ':' -f1`; do
  #echo "current to be handled file is $file"
  dir_name=$(echo "$file" | cut -d '/' -f2)
  base_name=$(echo "$file" | cut -d '-' -f2)
  opt=$(echo "$file" | rev | cut -d '-' -f1 |rev | cut -d '.' -f1)
  strip_opt=${opt//_/_strip_}
  
  if [ $base_name = "libc" ]; then
  	  base_name=$(echo "$file" | cut -d '-' -f2-3)
  fi
  if [ $dir_name = "cpu2006" ]; then
	  dir_name=utils/$dir_name
  	  base_name=$(echo "$file" | cut -d '-' -f2-5)
  fi
  if [ $dir_name = "binutils" ]; then
	  dir_name=utils/$dir_name
  fi
  if [ $dir_name = "coreutils" ]; then
	  dir_name=utils/$dir_name
  fi
  if [ $dir_name = "findutils" ]; then
	  dir_name=utils/$dir_name
  fi
  gtBlock=/data/testsuite/$dir_name/$opt/gtBlock_${base_name}.pb
  binary=/data/testsuite/$dir_name/$opt/$base_name
  compare=/data/testsuite/$dir_name/$strip_opt/Block-angrAlign-$base_name.strip.pb
  echo $gtBlock
  echo $binary
  echo $compare
  echo $file
  
  #gtBlock_file=${replace_tmp//Block-$PREFIX-/gtBlock_}
  
  optimized_dir=`echo $file | rev | cut -d '/' -f2 | rev`
  #echo "optimized dir is $optimized_dir"
  #echo "groundtruth file is $gtBlock_file"
  optimized_dir=${optimized_dir//strip_/}

  utils_dir=`echo $file | rev | cut -d '/' -f3 | rev`
  #echo "util directory is $utils_dir"

  last_dir=`echo $file | rev | cut -d '/' -f4 | rev`
  if [ $last_dir == "." ]; then
    last_dir=""
  else
    last_dir="$last_dir@"
  fi


  #pure_binary_file=`basename $binary_file`
  #output_path="$OUTPUT/data@testsuite@$last_dir$utils_dir@$optimized_dir@$pure_binary_file"
  #echo "output path is $output_path"

  if [ ! -f $binary ]; then
    echo "[Error]: can't find binary file $binary_file"
    continue
  fi

  #if [ -f $output_path -a $NEW -eq 0 ]; then
  #  echo "already compare it!, skip!"
  #  continue
  #fi
  echo "<<<<<<<<<<<<<<<<<<<<<>>>>>>>>>>>>>>>>>>>>>>>>"
  echo "<<<<<<<<<<<<<<<<<<<<<>>>>>>>>>>>>>>>>>>>>>>>>"
  echo "[Handle File]: $binary"
  #echo "timeout 1h python3 $TOOL -g $gtBlock -c $compare -b $binary"
  timeout 1h python3 $TOOL -g $gtBlock -c $compare -b $binary
done
