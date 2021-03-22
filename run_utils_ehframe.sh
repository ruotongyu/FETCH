while getopts ":i:f" opt; do
	case $opt in
		i) 
			dirt=$OPTARG;;
		f)
			FLAG=$OPTARG;;
	esac
done
fnum=0

for file in `find $dirt -name "*.strip" | grep -v "shuffle"`; do
	binary=$(echo "$file" | cut -d'/' -f 7)
	tmp=${binary/.strip/}
	pb="ehRes_${tmp}"
	pb="${pb}.pb"
	pbRes=${file/$binary/$pb}
	opt=$(echo "$file" | cut -d'/' -f 6 | cut -d'_' -f 2)
	flag="x64"
	if [ $opt = "m32" ]; then
		flag="x32"
	fi
	echo "./dyninstBB_extent $file $flag $pbRes"
	#./dyninstBB_extent $file $flag $pbRes
	fnum=$((fnum+1))
done
echo "File Number: $fnum"
