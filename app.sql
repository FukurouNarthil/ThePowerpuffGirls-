CREATE SCHEMA IF NOT EXISTS `acdemo` DEFAULT CHARACTER SET utf8mb4 ;
GRANT Insert,Select,Delete,Update ON `acdemo`.* TO `acuser`@`%` IDENTIFIED by 'password123';
flush privileges;

DROP TABLE IF EXISTS `files`;
CREATE TABLE `files` (
    `id` int(11) NOT NULL AUTO_INCREMENT,
    `name` varchar(255) DEFAULT NULL,
    `size` int(11) DEFAULT NULL,
    `enckey` text comment '文件对称加密秘钥，使用用户pubkey加密保存',
    `sha256` char(64) DEFAULT NULL comment '明文文件的sha256，16进制字符形式保存',
    `uid` int(11) NOT NULL comment '文件所有者的id',
    `create_time` datetime DEFAULT NULL comment '文件上传时间',
    PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8mb4;

DROP TABLE IF EXISTS `users`;
CREATE TABLE `users` (
    `id` int(11) NOT NULL AUTO_INCREMENT,
    `name` varchar(255) NOT NULL,
    `password` char(255) NOT NULL,
    `pubkey` text NOT NULL,
    `privkey` text NOT NULL comment '使用用户明文的password作为私钥导出的passphrase',
    PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8mb4;

alter TABLE users modify password char(255);

DROP TABLE IF EXISTS `share`;
CREATE TABLE `share` (
    `id` int(11) NOT NULL AUTO_INCREMENT,
    `fid` int(11) NOT NULL,
    `dcount` int(11) NOT NULL DEFAULT '0' COMMENT '文件被下载次数',
    `access_time` datetime DEFAULT NULL COMMENT '最近被下载时间',
    `sharekey` char(60) NOT NULL COMMENT '分享链接使用的解密口令，采用与登录口令相同的单向慢速散列存储方法',
    `enckey` text NOT NULL,
    `filepath` varchar(255) NOT NULL COMMENT '文件保存路径',
    `nonce` char(8) NOT NULL COMMENT '避免同一个文件被重复分享，每次分享时随机产生',
    PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=12 DEFAULT CHARSET=utf8mb4;

DROP PROCEDURE IF exists sp_createUser;
delimiter //
CREATE PROCEDURE sp_createUser(IN username VARCHAR(255), IN pass CHAR(255), IN pub TEXT, IN pri TEXT) 
	BEGIN
		INSERT INTO users SET users.name=username, users.password=pass, users.pubkey=pub, users.privkey=pri;
	END
    //
delimiter ;

DROP PROCEDURE IF exists sp_createFile;
delimiter //
CREATE PROCEDURE sp_createFile(IN filename varchar(255), IN size int(11), IN enckey text, IN sha char(64), IN uid int(11), IN create_time datetime)
	BEGIN
		INSERT INTO files SET name=filename, size=size, enckey=enckey, sha256 = sha, uid = uid, create_time = create_time;
	END
    //
delimiter ;

SET @@global.sql_mode = '';
