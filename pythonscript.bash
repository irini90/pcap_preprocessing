#!/bin/bash
numberOfFiles=$(ls -1q /Users/ireneanthi/Desktop/ics_data/*.pdml | wc -l)
count=1
for file in /Users/ireneanthi/Desktop/ics_data/*.pdml
do
  ((count++))
  python2.7 pdml2arff.py "$file"
  echo -n "$((${count}*100/${numberOfFiles} | bc)) %     "
  echo -n R | tr 'R' '\r'
  sleep 2
done
