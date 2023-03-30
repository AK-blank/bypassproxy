package main

import (
	"BypassProxy/byProxy"
	"log"
	"net"
	_ "net/http/pprof"
	"os/exec"
	"regexp"
	"runtime"
)

//目前问题
//1.程序刚启动时,连接代理可能会提示失败,可能是程序启动初始化还未完成. 暂未解决
//2.第一次代理连接HTTPS时会提示失败,暂未解决
//目前只支持ipv4代理模式
func main() {
	//go func() {
	//	log.Println(http.ListenAndServe("localhost:6060", nil))
	//}()
	host := "0.0.0.0"
	port := "7777"
	addr := host+":"+port
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalln(err)
	}
	runtime.GOMAXPROCS(runtime.NumCPU())
	if CheckRst(){
		ruleAdd := "iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP"
		//fmt.Println(ruleAdd)
		err = exec.Command("/bin/bash", "-c", ruleAdd).Run()
		log.Fatalln(err)
	}
	//var wg = sync.WaitGroup{}
	//var waitGroup sync.WaitGroup
	log.Println("初始化完成:", addr)
	for {
		client, err := listener.Accept()
		if err != nil {
			log.Println("创建监听错误:",err)
		}
		log.Println("Receive from:", client.RemoteAddr())
		go byProxy.SuperProxy(client, 1460, false, false,true,false)
	}
}


func CheckRst() bool{
	ruleCk := "iptables -C OUTPUT -p tcp --tcp-flags RST RST -j DROP"
	runrst := exec.Command("/bin/bash", "-c",ruleCk)
	rst, err := runrst.CombinedOutput()
	if err != nil{
		log.Fatalln(err)
	}
	ckReg, _ := regexp.Compile("Bad rule")
	rst_str := string(rst)
	if ckReg.MatchString(rst_str){
		return true
	}else {
		return false
	}
}