#!/bin/sh

# This file is the script file that extract the ground truth for executable file or directory 

print_help(){
  echo -e "\t-h Help"
  echo -e "\t-d directory to be handledd"
  echo -e "\t-t tool path"
  echo -e "\t-s speculative mode. default is 1. 0 represents turn off the dyninst speculative mode. 1 represents use idiom mode."
  echo -e "\t\t2 represents using preamble. 3 represents turn on both modes."
}

#SCRIPT_PATH=/home/binpang/binary_reasemble/disassemble_compare/extract_proto
#SHUFFLE_SCRIPT=$SCRIPT_PATH/shuffleInfoReader.py
#BLOCK_SCRIPT=$SCRIPT_PATH/ccrBasicBlock.py

DIRECTORY=""
TOOL=""
SPEC=1
# compare the ground truth with mcsema
extract(){
  BINARYPATH=$1
  baseFile=`basename $BINARYPATH`
  dirName=`dirname $BINARYPATH`
  toolName=`basename $2`
  echo "toolname is Block-$toolName-$baseFile.pb"
  dyninst_log="$dirName/Log-$toolName-$baseFile.log"
  scriptCom="$2 --binary $BINARYPATH --output $dirName/Block-$toolName-$baseFile.pb --speculative $SPEC --statics $dirName/Stat-$toolName-$baseFile.log"
  echo $scriptCom
  eval $scriptCom
}


while getopts "hd:t:s:" arg
do
  case $arg in
    h)
      print_help
      exit 0
      ;;
    d)
      DIRECTORY=$OPTARG
      ;;
    t)
      TOOL=$OPTARG
      ;;
    s)
      SPEC=$OPTARG
      ;;
    esac
done


if [ ! -f "$TOOL" ]
then
 echo "please input the correct tool script path!"
 exit 1  
fi

if [ -f "$DIRECTORY" ]
then
  file_type=`file $DIRECTORY`
  if [[ $file_type == *"executable"* ]]
  then
  echo "file type is $file_type"
  extract $DIRECTORY $TOOL
  fi
fi


if [ -d "$DIRECTORY" ]
then
  files=`ls $DIRECTORY | awk {'print $1'}`
  for entry in $files
  do
    file_path=$DIRECTORY/$entry
    echo "$file_path"
    if [ -f "$file_path" ]
    then
      file_type=`file $file_path`
      echo $file_type
      if [[ $file_type == *"executable"* ]] || [[ $file_type == *"shared object,"* ]]
      then
	echo $file_path
	extract $file_path $TOOL 
      fi
    fi
  done
fi
