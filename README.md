# dockerSSH

## 介绍
dockerSSH是一个go语言实现的ssh服务端，可以让你用ssh直连到docker容器内部

## 安装使用
```
go get github.com/myml/dockerSSH
cd $GOPATH/bin
./dockerSSH 
```
使用ssh ff756b3ea527@127.0.0.1 -p 2022登陆到ID为ff756b3ea527的容器内（请确保容器正在运行中）

## 注意
dockerSSH默认监听2022端口   
dockerSSH在每次运行时创建新的ssh密钥，请核实公钥指纹   
dockerSSH使用~/.ssh/authorized_keys验证用户登陆   
dockerSSH使用unix:///var/run/docker.sock连接docker，当用户目录存在.docker目录时会使用TLS连接   
以上功能暂未实现命令行或环境变量更改

## 计划
+ 通过环境变量或命令行实现参数更改
+ scp
+ sftp
+ 容器独立密钥验证
+ 断线重连