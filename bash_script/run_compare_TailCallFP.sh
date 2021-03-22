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

for file in `find $DIR -name *.strip | grep -v frame | grep -v _strip | grep O2 | grep -v _m32 | grep -v ida_ | grep -v shuffle`; do
  #echo "current to be handled file is $file"
  replace_tmp1=${file//strip_/}
  binary_file=${replace_tmp1//\.strip/}
  dir_name=`dirname $binary_file`
  tmp1=$(echo "$dir_name" | cut -d'_' -f 1)
  tmp2=${tmp1}_strip
  sdir=${dir_name/$tmp1/$tmp2}
  base_name=`basename $binary_file`
  if [ $base_name = "libc-2.27.so" ]; then
	  continue
  fi
  ehname=${sdir}/Block-dyninstBB_ehframe-${base_name}.strip.pb
  gtBlock_file=${dir_name}/gtBlock_${base_name}.pb
  ref=${dir_name}/gtRef_${base_name}.pb
  TailCall_file=${dir_name}/ehTailCall_${base_name}.pb
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


  pure_binary_file=`basename $binary_file`
  output_path="$OUTPUT/data@testsuite@$last_dir$utils_dir@$optimized_dir@$pure_binary_file"
  #echo "output path is $output_path"

  if [ ! -f $binary_file ]; then
    echo "[Error]: can't find binary file $binary_file"
    continue
  fi

  if [ -f $output_path -a $NEW -eq 0 ]; then
    echo "already compare it!, skip!"
    continue
  fi
  echo "<<<<<<<<<<<<<<<<<<<<<>>>>>>>>>>>>>>>>>>>>>>>>"
  echo "<<<<<<<<<<<<<<<<<<<<<>>>>>>>>>>>>>>>>>>>>>>>>"
  echo "[Handle File]: $binary_file"
  #echo "timeout 1h python3 $TOOL -g $gtBlock_file -i $TailCall_file -b $binary_file -e $ehname -r $ref"
  timeout 1h python3 $TOOL -g $gtBlock_file -i $TailCall_file -e $ehname -b $binary_file -r $ref
done
