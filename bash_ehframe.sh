input="/data/compare_ehframe/all_fn.log"
fnum=0
while IFS= read -r line
do
	SUB=$(echo "$line" | cut -d':' -f 5)
	NUM=$(echo "$SUB" | cut -d'#' -f 2)
	path=$(echo "$line" | cut -d':' -f 1)
	tmp=$(echo "$path" | cut -d'@' -f 3) 
	res=${path//@//}
	res=${res/./}
	# skip nginx and continue
	if [ $tmp = "utils" ]; then
		file=$(echo "$path" | cut -d'@' -f 6)
		cmp=$(echo "$line" | cut -d'@' -f 5)
	else
		file=$(echo "$path" | cut -d'@' -f 5)
		cmp=$(echo "$line" | cut -d'@' -f 4)
	fi
	block="gtBlock_${file}"
	block="${block}.pb"
	gt="gtRef_${file}"
	gt="${gt}.pb"
	pb=${res/$file/$gt}
	bPb=${res/$file/$block}
	res="${res}.strip"
	flag="x64"
	opt=$(echo "$cmp" | cut -d'_' -f 2)
	if [ $opt = "m32" ]; then
		flag="x32"
	fi
		# res is striped binary file
	# pb is ground truth reference file
	# bPb is ground truth block file
	if [ $NUM = "0]" ]; then
		echo "Result for $res"
		#echo "./dyninstBB_extent $res $pb $bPb $flag"
		fnum=$((fnum+1))
		./dyninstBB_extent $res $pb $bPb $flag
		#exit 1
	fi
done < "$input"
echo "File Number: $fnum" 
