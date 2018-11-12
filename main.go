package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"os"
	"path"
	"time"

	"golang.org/x/crypto/ssh"
)

type ScpClient struct {
	Client   *ssh.Client
	FilePath string
	Host     string
	Session  *ssh.Session
}

func newClient(filePath string, host string, client *ssh.Client) (*ScpClient, error) {
	session, err := client.NewSession()
	if err != nil {
		fmt.Println("newClient err:", err)
		client.Close()
		return nil, err
	}
	return &ScpClient{
		Client:   client,
		FilePath: filePath,
		Host:     host,
		Session:  session,
	}, nil
}

func (sc *ScpClient) Copy() error {
	filename := path.Base(sc.FilePath)
	dir := "/tmp"
	f, _ := os.Open(sc.FilePath)
	defer f.Close()
	fileBytes, _ := ioutil.ReadAll(f)
	fileBytesReader := bytes.NewReader(fileBytes)
	go func() {
		w, err := sc.Session.StdinPipe()
		defer w.Close()
		if err != nil {
			fmt.Println("StdinPipe err:", err)
			return
		}
		fmt.Fprintln(w, "C0655", len(fileBytes), filename)
		io.Copy(w, fileBytesReader)
		fmt.Fprintln(w, "\x00")
	}()
	err := sc.Session.Run("/usr/bin/scp -qt " + dir)
	return err
}

func (sc *ScpClient) Close() {
	sc.Session.Close()
	sc.Client.Conn.Close()
}

func main() {
	filePath := flag.String("filePath", "you file path", "local file path")
	password := flag.String("password", "you password", "password")
	user := flag.String("user", "user name", "user name")
	host := flag.String("host", "host", "host")
	flag.Parse()
	auth := make([]ssh.AuthMethod, 0)
	auth = append(auth, ssh.Password(*password))
	hostKeyCallback := func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		return nil
	}

	clientConfig := &ssh.ClientConfig{
		User:            *user,
		Auth:            auth,
		HostKeyCallback: hostKeyCallback,
		Timeout:         30 * time.Second,
	}
	client, err := ssh.Dial("tcp", *host, clientConfig)
	if err != nil {
		fmt.Println("Couldn't establisch a connection to the remote server ", err)
		return
	}
	defer client.Close()
	scpClient, err := newClient(*filePath, *host, client)
	if err != nil {
		fmt.Println("newClient err: ", err)
		return
	}
	scpClient.Copy()
}
