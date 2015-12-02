#!/bin/bash

DBG=${4:-5}
KEY_DIR=local_keys
KEYS=$KEY_DIR/key
HOSTLIST=$KEY_DIR/hostlist
NUMBER=${1:-2}
COMMAND=bitcosi
rm -f $HOSTLIST

rm -rf $KEY_DIR
mkdir $KEY_DIR

for a in $( seq 1 $NUMBER ); do
  PORT=$(( 2000 + $a * 10 ))
  ./$COMMAND keygen localhost:$PORT -key $KEYS$a
done
cat $KEYS*.pub >> $HOSTLIST

./$COMMAND build $HOSTLIST

for a in $( seq 2 $NUMBER ); do
  ./$COMMAND -debug $DBG run -key $KEYS$a &
done
./$COMMAND -debug $DBG run -key ${KEYS}1
