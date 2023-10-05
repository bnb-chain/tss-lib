# BNB MPC Library For FSL

오리지널 BNB 라이브러리는 이곳을 참조하며

자세한 설명, 참조사항등을 보기위해서 이곳을 참조하도록 한다. [2.0.1 github](https://github.com/bnb-chain/tss-lib/tree/v2.0.1).

 

## 라이브러리 선택시 장점
해당 라이브러리는 gg18의 보안 취약점을 패치한 버전이다.

EDDSA(ED25519) 또한 지원한다. (자신들만의 알고리즘을 이용하지만)

## 라이브러리 선택시 단점
gg18만 지원한다.

EDDSA사용시 자신들만의 알고리즘을 이용하므로 믿을수있을지 검토해봐야 한다.

## 라이브러리 이용
클라이언트에서 사용할 라이브러리 형식으로 컴파일을 해야 한다. (wsam or javascript or binary lib(so,dylib,dll) 등등)

## 수정 사항
원본의 Test Code중 로컬동작을 위한 로직을 수정, KeyGen시 리모트를 호출할수있는 함수 생성

FSL용 편하게 사용하기 위한 패키지 추가 (./tss-lib/mpc)

외부와 소통은 프로세스간 통신을 이용한다. ( file read / write )

resharing 은 구현하지 않았다. 

## 샘플
선작업

프로젝트 루트로 이동하여 go build 를 실행하여 컴파일 한다.

컴파일한 tss-lib 실행파일을 아래와 같이 복사한다.

아래는 2-of-3 테스트시 각 파티별 디렉토리구조이다. 

```bash
~
└── Test
    └── TSSLib
        ├── 0
        │   └── tss-lib
        ├── 1
        │   └── tss-lib
        └── 2
            └── tss-lib
```

KeyGen 샘플 (ECDSA 2-of-3, 그룹명: FSL_Test_MPC)
```bash
//n-of-m
tss-lib [알고리즘(EC or ED)] KEYGEN [그룹명] [모든파티 갯수(m)] [사이너 갯수(n)] [자신의 인텍스]
# 설공시 자신의 하위 디렉토리(keys/알고리즘_그룹명[n-of-m][자신의 인덱스]/key.json)에 키 파일이 생성된다.
```
```bash
# ecdsa 2-of-3 키 생성시 예제
# 독립된 프로세서(터미널)에서 실행 첫번째(0) 파티
./tss-lib EC KEYGEN FSL_Test_MPC 3 2 0
# 출력되는 키정보는 매우 길어서 이곳에 넣지는 않는다. 
...

# 독립된 프로세서(터미널)에서 실행 두번째(1) 파티
./tss-lib EC KEYGEN FSL_Test_MPC 3 2 1
# 출력되는 키정보는 매우 길어서 이곳에 넣지는 않는다.
...

# 독립된 프로세서(터미널)에서 실행 세번째(2) 파티
./tss-lib EC KEYGEN FSL_Test_MPC 3 2 2
# 출력되는 키정보는 매우 길어서 이곳에 넣지는 않는다.
```

Signing 샘플 (ECDSA 2-of-3, 그룹명: FSL_Test_MPC, Signer들: 1,2, 사인메시지: this_is_plain_text_for_sign,if_you_will_use_hex_string_more_develop)
```bash
//n-of-m
tss-lib [알고리즘(EC or ED)] SIGNING [그룹명] [모든파티 갯수(m)] [사이너 갯수(n)] [자신의 인텍스] [Signer들] [사인메시지]
# 설공시 콘솔에 서명 메시지를 참조한다.
```
```bash
# ecdsa 2-of-3 키 생성시 예제
# 독립된 프로세서(터미널)에서 실행 두번째(1) 파티
./tss-lib EC SIGNING FSL_Test_MPC 3 2 1 1,2 signMessage
signing result [{
  "PublicKey": {
    "Curve": "secp256k1",
    "X": "b356c1e66d091befd0cc56295b2b223ffdb236f7b3eef98962e6f34eeae46bde",
    "Y": "466a19a604c0295cb03b045fac8723108a4b1cf7adcb8e1a61e04914734b11e7",
    "Encode": "04b356c1e66d091befd0cc56295b2b223ffdb236f7b3eef98962e6f34eeae46bde466a19a604c0295cb03b045fac8723108a4b1cf7adcb8e1a61e04914734b11e7"
  },
  "Message": "48690881b1b8b0dadec14c4e8ead19b5cf4df5678bccb7ae57db11ac7e306614",
  "R": "8fc521975f7d14a572e712431f512f0caf35726e71aac917153ae68376b2384c",
  "S": "77ffcf2dd95497c12d3980b99dc72475ce5af6b1165635c524c981853039e99c",
  "Rec": "00",
  "Encode": "304402208fc521975f7d14a572e712431f512f0caf35726e71aac917153ae68376b2384c022077ffcf2dd95497c12d3980b99dc72475ce5af6b1165635c524c981853039e99c"
}]
...

# 독립된 프로세서(터미널)에서 실행 세번째(2) 파티
./tss-lib EC SIGNING FSL_Test_MPC 3 2 2 1,2 signMessage
sign verify success
signing result [{
  "PublicKey": {
    "Curve": "secp256k1",
    "X": "b356c1e66d091befd0cc56295b2b223ffdb236f7b3eef98962e6f34eeae46bde",
    "Y": "466a19a604c0295cb03b045fac8723108a4b1cf7adcb8e1a61e04914734b11e7",
    "Encode": "04b356c1e66d091befd0cc56295b2b223ffdb236f7b3eef98962e6f34eeae46bde466a19a604c0295cb03b045fac8723108a4b1cf7adcb8e1a61e04914734b11e7"
  },
  "Message": "48690881b1b8b0dadec14c4e8ead19b5cf4df5678bccb7ae57db11ac7e306614",
  "R": "8fc521975f7d14a572e712431f512f0caf35726e71aac917153ae68376b2384c",
  "S": "77ffcf2dd95497c12d3980b99dc72475ce5af6b1165635c524c981853039e99c",
  "Rec": "00",
  "Encode": "304402208fc521975f7d14a572e712431f512f0caf35726e71aac917153ae68376b2384c022077ffcf2dd95497c12d3980b99dc72475ce5af6b1165635c524c981853039e99c"
}]
```

## 자동 테스트 
./test_ks_si.sh 파일을 실행한다.
```bash
sh ./test_ks_si.sh
# KeyGen( ec , 2-of-3 ) -> loop 5 Signing( rand(사이너들) )
# KeyGen( ed , 2-of-3 ) -> loop 5 Signing( rand(사이너들) )
```

## 외부 툴을 이용한 검증
아래의 링크로 가서 서명의 유효성을 검증해본다.

https://kjur.github.io/jsrsasign/sample/sample-ecdsa.html

1. ECC curve name을 secp256k1 으로 설정
2. EC public key (hex): 란에 signing result.PublicKey.Encode 값 복사
3. Message strign to be signed: 란에 signing시 입력한 signMessage 값 복사
4. Signature value (hex): 란에 signing result.Encode 값을 복사
5. verify it! 을 클릭하여 생성된 값을 검증한다.
