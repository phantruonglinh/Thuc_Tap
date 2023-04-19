create database testdb;
use testdb;
create table users(
	id bigint(20) not null auto_increment,
    email varchar(50),
    password varchar(120),
    username varchar(20),
    primary key(id),
    unique(email,username)
) ENGINE = InnoDB
  DEFAULT CHARACTER SET = utf8mb4;
  
create table roles(
	id int(11) not null auto_increment,
    name varchar(20),
    primary key(id)
) ENGINE = InnoDB
  DEFAULT CHARACTER SET = utf8mb4;
  
create table user_roles(
	user_id bigint(20) not null,
    role_id int(11) not null,
    foreign key(user_id) references users(id),
    foreign key(role_id) references roles(id)
) ENGINE = InnoDB
  DEFAULT CHARACTER SET = utf8mb4;
INSERT INTO roles(name) VALUES('ROLE_USER');
INSERT INTO roles(name) VALUES('ROLE_MODERATOR');
INSERT INTO roles(name) VALUES('ROLE_ADMIN');