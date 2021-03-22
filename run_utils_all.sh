declare -a files=("binutils/" "coreutils/" "cpu2006/" "findutils/")
declare -a options=("gcc_O0 gcc_O2 gcc_O3 gcc_Os gcc_Of gcc_m32_O0 gcc_m32_O2 gcc_m32_O3 gcc_m32_Os gcc_m32_Of ccr_O0 ccr_O2 ccr_O3 ccr_Os ccr_Of")

for val in ${files[@]}; do
	cmd="run_utils_ehframe.sh -i /data/testsuite/utils/"
       	cmd="${cmd}$val"	
	#if [ $val != "binutils/" ]; then
	#	continue
	#fi
	for opt in ${options[@]}; do
	#if [ $val != "binutils/" ]; then
	#	continue
	#fi
		res="${cmd}$opt"
		echo "Run Command: $res"
		bash $res
		echo "=============next=========="
	done
done
