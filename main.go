package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os/user"
	"strings"

	"github.com/fsouza/go-dockerclient"
	"github.com/lunixbochs/struc"
	"golang.org/x/crypto/ssh"
)

var dockerClient *docker.Client

func init() {
	log.SetFlags(log.Ltime | log.Lshortfile)

	host := "tcp://192.168.99.100:2376"
	u, err := user.Current()
	if err != nil {
		log.Panic(err)
	}
	config := u.HomeDir + "/.docker"
	dockerClient, err = docker.NewTLSClient(
		host,
		config+"/cert.pem",
		config+"/key.pem",
		config+"/ca.pem")
	if err != nil {
		log.Panic("docker连接失败：", err)
	}
	version, err := dockerClient.Version()
	if err != nil {
		log.Panic("docker连接失败：", err)
	}
	log.Printf("docker版本：%v", version.Get("Version"))
}
func main() {
	//创建密钥
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Panic(err)
	}
	private, err := ssh.NewSignerFromKey(key)
	if err != nil {
		log.Panic(err)
	}
	//计算指纹
	publickey, err := ssh.NewPublicKey(&key.PublicKey)
	if err != nil {
		log.Panic(err)
	}
	log.Println("主机密钥指纹(MD5):", ssh.FingerprintLegacyMD5(publickey))
	log.Println("主机密钥指纹(SHA256):", ssh.FingerprintSHA256(publickey))

	//验证配置
	sshConfig := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			return nil, nil
		},
		PublicKeyCallback: func(c ssh.ConnMetadata, pubKey ssh.PublicKey) (*ssh.Permissions, error) {
			u, err := user.Current()
			if err != nil {
				log.Panic("user.Current", err)
				return nil, err
			}
			b, err := ioutil.ReadFile(u.HomeDir + "/.ssh/authorized_keys")
			if err != nil {
				log.Printf("读取authorized_keys错误：%v", err)
				return nil, err
			}
			for {
				out, _, _, rest, err := ssh.ParseAuthorizedKey(b)
				if err != nil {
					log.Printf("解析authorized_keys错误：%v", err)
					break
				}
				if bytes.Contains(out.Marshal(), pubKey.Marshal()) {
					return nil, nil
				}
				if rest == nil {
					break
				}
				b = rest
			}
			return nil, fmt.Errorf("%v验证未通过", c.User())
		},
	}
	//添加密钥
	sshConfig.AddHostKey(private)
	//监听
	s, err := net.Listen("tcp", ":2022")
	if err != nil {
		log.Panic(err)
	}
	//	go ssh2docker()
	log.Println("ssh地址：127.0.0.1:2022")
	for {
		c, err := s.Accept()
		if err != nil {
			log.Panic(err)
		}
		sshConn, newChannels, req, err := ssh.NewServerConn(c, sshConfig)
		if err != nil {
			log.Println("NewServerConn error:", err)
			continue
		}
		go ssh.DiscardRequests(req)
		go startSSH(sshConn, newChannels)
	}
}

func startSSH(sshConn *ssh.ServerConn, newChannels <-chan ssh.NewChannel) {
	log.Printf("%v在%v登录", sshConn.User(), sshConn.RemoteAddr())
	for newChannel := range newChannels {
		log.Printf("%v开启一个%v通道", sshConn.User(), newChannel.ChannelType())

		if newChannel.ChannelType() != "session" {
			log.Println("不支持的通道类型：", newChannel.ChannelType())
			newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
			continue
		}
		channel, reqChannel, err := newChannel.Accept()
		if err != nil {
			log.Println("接受通道请求失败：", err)
			continue
		}
		req := <-reqChannel
		switch req.Type {
		case "pty-req":
			ssh2docker("bash", sshConn.User(), channel, req, reqChannel)
		case "exec":
			type exec struct {
				L    int `struc:"int32,sizeof=Comm"`
				Comm string
			}
			e := exec{}
			err := struc.Unpack(bytes.NewReader(req.Payload), &e)
			if err != nil {
				log.Println("解析exec失败：", err)
				break
			}
			ssh2docker(e.Comm, sshConn.User(), channel, req, reqChannel)
		}
	}
}

type sshDocker struct {
	containerID string
	command     string
	stream      ssh.Channel
	req         *ssh.Request
	reqs        <-chan *ssh.Request
}

func ssh2docker(
	command,
	containerID string,
	stream ssh.Channel,
	req *ssh.Request,
	reqs <-chan *ssh.Request) {
	//	cs,err:=docker.ListContainersOptions(docker.ListContainersOptions{
	//		Limit:1,
	//		Filters:map[string][]string{"id":{containerID}}
	//	})
	//	if err!=nil||len(cs)==0{

	//	}
	createOpt := docker.CreateExecOptions{
		AttachStderr: true,
		AttachStdin:  true,
		AttachStdout: true,
		Tty:          true,
		Container:    containerID,
		Cmd:          strings.Fields(command),
	}
	execRet, err := dockerClient.CreateExec(createOpt)
	if err != nil {
		log.Println("在%v创建%v命令失败：%v", containerID, command, err)
		return
	}
	startOpt := docker.StartExecOptions{
		Tty:          true,
		RawTerminal:  true,
		InputStream:  stream,
		ErrorStream:  stream,
		OutputStream: stream,
	}
	go func() {
		type TtySize struct {
			Width  int `struc:"int32"`
			Height int `struc:"int32"`
		}
		type pty struct {
			NameLen int `struc:"int32,sizeof=Name"`
			Name    string
			TtySize
		}
		//		log.Printf("%v第一个请求：%#v", containerID, req)
		if req.Type == "pty-req" {
			p := pty{}
			err = struc.Unpack(bytes.NewReader(req.Payload), &p)
			if err != nil {
				log.Printf("解析pty-req信息失败：%v", err)
				return
			}
			log.Printf("%#v", p)
			err = dockerClient.ResizeExecTTY(execRet.ID, p.Height, p.Width)
			if err != nil {
				log.Printf("重设TTY大小失败：%v", err)
				return
			}
		}
		for req := range reqs {
			//			log.Printf("%v再次发来的请求：%#v", containerID, req)
			if req.Type == "window-change" {
				ts := TtySize{}
				err = struc.Unpack(bytes.NewReader(req.Payload), &ts)
				if err != nil {
					log.Printf("解析window-change信息失败：%v", err)
					return
				}
				err = dockerClient.ResizeExecTTY(execRet.ID, ts.Height, ts.Width)
				if err != nil {
					log.Printf("重设TTY大小失败：%v", err)
					return
				}
			}
		}
	}()
	err = dockerClient.StartExec(execRet.ID, startOpt)
	if err != nil {
		log.Println("在%v创建%v命令失败：%v", containerID, command, err)
		return
	}
	log.Printf("%v退出:%v", containerID, err)
}
