#!/bin/bash

KEY_DIR=local_keys
KEYS=$KEY_DIR/key
HOSTLIST=$KEY_DIR/hostlist
NUMBER=${1:-2}
rm -f $HOSTLIST

rm -rf $KEY_DIR
mkdir $KEY_DIR

for a in $( seq 1 $NUMBER ); do
  PORT=$(( 2000 + $a * 10 ))
  ./bitcosi keygen localhost:$PORT -key $KEYS$a
done
cat $KEYS*.pub >> $HOSTLIST

./bitcosi build $HOSTLIST

for a in $( seq 2 $NUMBER ); do
  ./bitcosi run -key $KEYS$a &
done
./bitcosi -debug 2 run -key ${KEYS}1
