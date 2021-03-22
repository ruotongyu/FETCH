#!/bin/bash
while getopts "d:" arg
do
    case $arg in 
	d)
	    DIR=$OPTARG;;
    esac
done

if [ ! -d $DIR ]; then
    echo "Please input directory with(-d)!"
    exit
fi

dir_file=`dirname $0`
script_file="${dir_file}/compare_pdata.py"

for f in `find $DIR -name "*.exe" -o -name "*.dll" | grep -v _strip | grep -v _m32 | grep -v binary`; do
    pb_file=${f//\.exe/\.pdb}
    pb_file=${pb_file//\.dll/\.pdb}

    echo "current file is ===============$f==============="

    python3 $script_file -b $f -p $pb_file
done
