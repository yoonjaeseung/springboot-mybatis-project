CREATE TABLE test (
NAME VARCHAR(50), PASSWORD VARCHAR(50)
);
CREATE TABLE user_account(
 id BIGINT AUTO_INCREMENT COMMENT 'id' PRIMARY KEY,
 accountEmail VARCHAR(80) NOT NULL UNIQUE COMMENT '계정이메일',
 accountPassword VARCHAR(80) NULL COMMENT '계정암호',
 userName VARCHAR(60) NULL COMMENT '사용자명',
 userPhoneNumber VARCHAR(20) NULL COMMENT '사용자폰번호',
 birthDay VARCHAR(8) NULL COMMENT '생년월일',
 sexCode VARCHAR(1) NULL COMMENT '성별코드',
 createDatetime DATETIME DEFAULT CURRENT_TIMESTAMP() NOT NULL COMMENT '생성일시',
 createHost VARCHAR(40) NOT NULL COMMENT '생성ID',
 updateDatetime DATETIME DEFAULT CURRENT_TIMESTAMP() NOT NULL COMMENT '수정일시',
 updateHost VARCHAR(40) NOT NULL COMMENT '수정ID'
) COMMENT '계정' COLLATE = UTF8MB4_BIN;


CREATE TABLE bbs_account(
 id BIGINT(20) AUTO_INCREMENT COMMENT 'id' PRIMARY KEY,
 accountEmail VARCHAR(80) NOT NULL UNIQUE COMMENT '계정이메일',
 accountPassword VARCHAR(80) NULL COMMENT '계정암호',
 userName VARCHAR(60) NULL COMMENT '사용자명',
 userPhoneNumber VARCHAR(20) NULL COMMENT '사용자폰번호',
 birthDay VARCHAR(8) NULL COMMENT '생년월일',
 sexCode VARCHAR(1) NULL COMMENT '성별코드',
 createDatetime DATETIME DEFAULT CURRENT_TIMESTAMP() NOT NULL COMMENT '생성일시',
 createHost VARCHAR(40) NOT NULL COMMENT '생성ID',
 updateDatetime DATETIME DEFAULT CURRENT_TIMESTAMP() NOT NULL COMMENT '수정일시',
 updateHost VARCHAR(40) NOT NULL COMMENT '수정ID'
) COMMENT '계정' COLLATE = UTF8MB4_BIN;


CREATE TABLE bbs_board(
 id BIGINT(20) AUTO_INCREMENT COMMENT 'id' PRIMARY KEY,
 accountId VARCHAR(80) notnull UNIQUE COMMENT '계정ID',
 title VARCHAR(500) NOT NULL COMMENT '글제목',
 content VARCHAR(1000) NULL COMMENT '글내용',
 viewCnt BIGINT(20) NOT NULL COMMENT '조회수',
 boardDatetime DATETIME NOT NULL COMMENT '글생성일시'
) COMMENT '게시판' COLLATE = UTF8MB4_BIN;


CREATE TABLE bbs_reply(
 id BIGINT(20) AUTO_INCREMENT COMMENT 'id' PRIMARY KEY,
 accountId bigint(20) not null UNIQUE COMMENT '계정ID'
 boardId bigint(20) NOT NULL UNIQUE COMMENT '게시판ID'
 replyContent VARCHAR(20) NULL COMMENT '댓글내용',
 replyId VARCHAR(8) NULL COMMENT '댓글ID',
 replyDatetime DATETIME NULL COMMENT '댓글생성일시'
) COMMENT '게시판댓글' COLLATE = UTF8MB4_BIN;


CREATE TABLE bbs_file(
 id BIGINT(20) AUTO_INCREMENT COMMENT 'id' PRIMARY KEY,
 boardId bigint(20) NOT NULL UNIQUE COMMENT '게시판ID'
 fileName VARCHAR(300) NULL COMMENT '파일이름',
 fileSize VARCHAR(500) NOT NULL COMMENT '파일사이즈',
) COMMENT '파일' COLLATE = UTF8MB4_BIN;

