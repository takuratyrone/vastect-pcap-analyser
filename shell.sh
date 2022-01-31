
a = 0

while [ $a -lt 20 ]
do
	python src/pcap_test.py pcap_files/simp.pcap pcap_files/simp_anon.cap
	a = `expr $a + 1`
done
