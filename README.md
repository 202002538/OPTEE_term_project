# OPTEE_term_project
2023.4.30 시스템 및 네트워크 보안 텀프로젝트 (TEE환경에서의 시저 암호화/복호화 구현)

< 암호화 기능 >
- CA에서 평문 텍스트 파일 읽고, TA로 암호화 요청
- TA에서 암호화를 위한 랜덤키(1~26) 생성
- 랜덤키로 평문 암호화, TA루트키로 랜덤키 암호화
- TA에서 CA로 암호문과 암호화된 랜덤키 전달
- CA에서 받은 암호문, 암호화된 랜덤키 txt파일로 저장


< 복호화 기능 >
- CA에서 암호문, 암호화된 키 텍스트 파일 읽고, TA로 복호화 요청
- TA에서 암호화된 키를 루트키로 복호화
- 랜덤키로 암호문을 복호화(기존 평문 획득)
- TA에서 복호화된 평문과 랜덤키를 CA로 전달
- CA에서 받은 평문, 랜덤키 txt파일로 저장
