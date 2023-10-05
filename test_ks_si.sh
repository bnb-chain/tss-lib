#!/bin/bash
CUR_DIR=`pwd`

# test 2(THRESHOLD)-fo-3(TOTAL)
TEST_ALGS=(EC ED)
TOTAL=3
THRESHOLD=2
GROUP_NAME=test
SIGN_TEST_COUNT=5
SIGN_MESSAGE=this_is_plain_text_for_sign,if_you_will_use_hex_string_more_develop
TEST_DIR=~/Test/TSSLib

function shuffle() {
  RANDOM=$$

  declare -a array=($@)
  declare -i k n=${#array[@]}
 
  while [ $n -ge 0 ]
  do
    let "k = RANDOM % (n + 1)"
    swap+=(${array[$k]})
    array[k]=${array[$n]}
    array[n]=$swap
    let "n--"
  done
 
  echo "${swap[@]}"
}

# build
go build

# copy new build
for ((i=0; i<${TOTAL}; i++))
do
  mkdir -p ${TEST_DIR}/${i}
  cp ./tss-lib ${TEST_DIR}/${i}
done

# test
for ALG in "${TEST_ALGS[@]}"
do
  # test keygen
  AUSERS=()
  for ((j=0; j<${TOTAL}; j++))
  do
    AUSERS+=(${j})
    cd ${TEST_DIR}/${j}
    ./tss-lib ${ALG} KEYGEN ${GROUP_NAME} ${TOTAL} ${THRESHOLD} ${j} &
  done

  wait
  
  # shuffle user index for signing 
  for ((k=1; k<=${SIGN_TEST_COUNT}; k++))
  do
    SRET=$(shuffle ${AUSERS[@]})
    IFS=' ' read -ra SUSERS <<< ${SRET}

    SIGNERS=()
    SIGNERINDEXES=""
    COMMA=""
    for ((l=0; l<${THRESHOLD}; l++))
    do
      CURSIGNER=(${SUSERS[${l}]})
      SIGNERS+=(${CURSIGNER})
      SIGNERINDEXES=${SIGNERINDEXES}${COMMA}${CURSIGNER}
      COMMA=","
    done

    # test signing     
    for SIGNER in "${SIGNERS[@]}"
    do
      cd ${TEST_DIR}/${SIGNER}
      ./tss-lib ${ALG} SIGNING ${GROUP_NAME} ${TOTAL} ${THRESHOLD} ${SIGNER} ${SIGNERINDEXES} ${SIGN_MESSAGE} &
    done

    wait
  done  
  
done

cd ${CUR_DIR}
