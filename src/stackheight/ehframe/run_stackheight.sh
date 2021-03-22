#! /bin/bash
while getopts "d:" arg
do
    case $arg in
	d)
	    DIR=$OPTARG;;
    esac
done


if [[ ! -d $DIR ]];then
    echo "Can't find the directory $DIR"
    exit -1
fi

cur_dir=`dirname $0`

tool_path=${cur_dir}/EhStackHeight


for file in `find ${DIR} -name "ehRes_*" | grep O1`; do
    binary_path=${file//ehRes_/}
    binary_path=${binary_path//\.pb/\.strip}
    output_path=${file//ehRes_/ehStackHeight_}
    exec_cmd="$tool_path --binary $binary_path --instrpb $file --output $output_path"
    echo "$exec_cmd"
    $exec_cmd
done
