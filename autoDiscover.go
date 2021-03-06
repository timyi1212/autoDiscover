package main

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path"
	"sort"
	"strings"
)

const (
	WebLogicIcon  = "fa fa-lg fa-file"
	WebLogicColor = "#5d9cec"
	DomainIcon    = "fa fa-lg fa-angle-right"
	DomainColor   = "#5d9cec"
	LinuxIcon     = "fa fa-lg fa-file"
	LinuxColor    = "#26C6DA"
	LoginURL      = "http://10.211.55.8:3000/auth/signin"
	PostCiURL     = "http://10.211.55.8:3000/cfgitems"
	UserName      = "tpuser"
	PassWord      = "tpuser123"
)

type Login struct {
	UserName string `json:"username"`
	PassWord string `json:"password"`
}
type WebLogicCi struct {
	ListenAddress string `json:"listenAddress"`
	ListenPort    string `json:"listenPort"`
	HostName      string `json:"hostName"`
	DomainName    string `json:"domainName"`
	BasicCI
}

type BasicCI struct {
	Type    string `json:"type"`
	SubType string `json:"subtype"`
	Icon    string `json:"icon"`
	Color   string `json:"color"`
	Name    string `json:"name"`
	Iname   string `json:"iname"`
}
type DomainCi struct {
	AdminAddress string `json:"adminAddress"`
	AdminPort    string `json:"adminPort"`
	HostNames    string `json:"hostNames"`
	LogPath      string `json:"logPath"`
	WebLogicHome string `json:"webLogicHome"`
	ProdHome     string `json:"prodHome"`
	DomainPath   string `json:"domainPath"`
	BasicCI
}

type LinuxCi struct {
	Ip      string `json:"ip"`
	Version string `json:"version"`
	BasicCI
}

type XmlResult struct {
	DomainName string `xml:"security-configuration>name"`
	//XMLName     xml.Name `xml:"servers"`
	//Version     string   `xml:"version,attr"`
	Servers []Server `xml:"server"`
}

type Server struct {
	ListenPort    string `xml:"listen-port"`
	ServerName    string `xml:"name"`
	ListenAddress string `xml:"listen-address"`
}

var (
	localIp       string
	localHostName string
)

func runShell(s string) string {
	cmd := exec.Command("/bin/sh", "-c", s)
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		fmt.Println(err.Error())
		fmt.Println("cmd execute error")
		return ("false")
	}
	return out.String()[:len(out.String())-1]
}

func GetRuntimeJavaInfo() ([]map[string]string, []string) {
	localIp = runShell("hostname -i")
	if localIp == "false" {
		log.Fatal("localIP get failed")
	} else {
		if localIp == "127.0.0.1" {
			log.Fatal("localIP get failed, it is 127.0.0.1")
		}
	}

	processResult := runShell("ps -ef | grep java| grep weblogic | grep verbose:gc | grep -v grep")
	if processResult == "false" {
		log.Fatal("no weblogic process")

	}
	runtimeJavaInfoes := make([]map[string]string, 0, 100)
	prodHomes := make([]string, 0, 100)
	wlsProcessArray := strings.Split(processResult, "\n")

	for i, v := range wlsProcessArray {

		pid := strings.TrimSpace(v[strings.Index(v, " "):])[:strings.Index(strings.TrimSpace(v[strings.Index(v, " "):]), " ")]
		webLogicPort := runShell(fmt.Sprintf("netstat -anp | grep %v/java | grep %v | grep tcp | grep LISTEN | awk -F ' ' '{print $4}' | awk -F ':' '{print $NF}'", pid, localIp))

		runtimeJavaInfoes = runtimeJavaInfoes[:i+1]
		prodHomes = prodHomes[:i+1]

		webLogicHome := v[strings.Index(v, "-Dplatform.home=")+16 : 16+strings.Index(v, "-Dplatform.home=")+strings.Index(string(v[strings.Index(v, "-Dplatform.home=")+16:]), " ")]
		prodHome, _ := path.Split(webLogicHome)
		webLogicName := v[strings.Index(v, "-Dweblogic.Name=")+16 : 16+strings.Index(v, "-Dweblogic.Name=")+strings.Index(string(v[strings.Index(v, "-Dweblogic.Name=")+16:]), " ")]

		runtimeJavaInfo := map[string]string{}
		runtimeJavaInfo["webLogicHome"] = webLogicHome
		runtimeJavaInfo["prodHome"] = prodHome[:len(prodHome)-1]
		runtimeJavaInfo["webLogicName"] = webLogicName
		runtimeJavaInfo["webLogicPort"] = webLogicPort
		managedServerIndex := strings.Index(v, "-Dweblogic.management.server=")
		if managedServerIndex != -1 {
			runtimeJavaInfo["isManaged"] = "1"
			leftIndex := strings.Index(v, "-Dweblogic.management.server=")
			rightIndex := strings.Index(v[leftIndex+29:], " ")
			tmp := v[leftIndex+29 : leftIndex+29+rightIndex]
			runtimeJavaInfo["adminListenAddress"] = strings.Split(tmp, ":")[1][2:]
			runtimeJavaInfo["adminListenPort"] = strings.Split(tmp, ":")[2]
		}

		runtimeJavaInfo["serverDuplicatedCount"] = "0"

		runtimeJavaInfoes[i] = runtimeJavaInfo
		prodHomes[i] = prodHome
	}
	return runtimeJavaInfoes, prodHomes

}

func listFiles(dirname string) ([]string, error) {
	files, err := ioutil.ReadDir(dirname)
	if err != nil {
		return nil, err
	}
	configs := make([]string, 0, 10)
	var index int = 0
	for _, file := range files {

		if file.IsDir() {
			domainName := file.Name()
			domainName = path.Join(dirname, domainName)
			configName := path.Join(domainName, "config/config.xml")
			//
			if _, err := os.Stat(configName); os.IsNotExist(err) {
				continue
			}
			configs = configs[:index+1]
			configs[index] = configName

		}
		index++
	}
	return configs, nil
}

func main() {
	runtimeJavaInfoes, prodHomes := GetRuntimeJavaInfo()
	sort.Strings(prodHomes)
	prodHomes = RemoveDuplicatesAndEmpty(prodHomes)
	fmt.Println("runtimeJavaInfoes: ", runtimeJavaInfoes)
	fmt.Println("prodHomes: ", prodHomes)
	wlsCis := make([][6]string, 0, 100)
	wlsCiIndex := 0
	domainCis := make([][9]string, 0, 100)
	domainCiIndex := 0
	linuxCi := make([]string, 4, 10)

	localHostName := runShell("hostname")
	if localHostName == "false" {
		log.Fatal("localHostName get failed")
	} else {

		if localHostName == "localhost.localdoamin" {
			log.Fatal("localHostName get failed, it is localhost.localdoamin")

		}
	}
	linuxCiName := fmt.Sprintf("%s_%s", localIp, localHostName)
	linuxIname := localHostName
	linuxIp := localIp
	linuxCi[0] = linuxCiName
	linuxCi[1] = linuxIname
	linuxCi[2] = linuxIp
	release := runShell("lsb_release -a| grep Release | awk -F ' ' '{print $2}'")
	linuxCi[3] = release

	for _, prodHome := range prodHomes {
		domainPath := path.Join(prodHome, "user_projects/domains")
		configs, err := listFiles(domainPath)
		sort.Strings(configs)
		configs = RemoveDuplicatesAndEmpty(configs)
		if err != nil {
			continue
		}
		fmt.Println("prodHome:", prodHome, "configs:", configs)
		for configIndex, config := range configs {
			fmt.Println(configIndex, config)
			configFile, xmlOpenErr := os.Open(config)
			if xmlOpenErr != nil {
				fmt.Printf("error: %v\n", xmlOpenErr)
				continue
			}

			data, readXmlErr := ioutil.ReadAll(configFile)
			if readXmlErr != nil {
				fmt.Printf("error: %v\n", readXmlErr)
				continue
			}
			xmlResult := XmlResult{}
			xmlUnmarshalErr := xml.Unmarshal(data, &xmlResult)
			if xmlUnmarshalErr != nil {
				fmt.Printf("error: %v", xmlUnmarshalErr)
				continue
			}
			domainName := xmlResult.DomainName
			servers := xmlResult.Servers
			hosts := localIp
			hostsArray := make([]string, 0, 100)

			hostIndex := 0
			for _, host := range servers {

				listenAddress := host.ListenAddress
				if listenAddress != "" && listenAddress != hosts {

					hostsArray = hostsArray[:hostIndex+1]
					hostsArray[hostIndex] = listenAddress
					hostIndex++

				}
			}
			sort.Strings(hostsArray)
			noDuplicatedHostsArray := RemoveDuplicatesAndEmpty(hostsArray)
			for _, v := range noDuplicatedHostsArray {
				hosts = hosts + "," + v
			}
			for _, server := range servers {
				serverName := server.ServerName
				listenAddress := server.ListenAddress
				listenPort := server.ListenPort
				if listenPort == "" {
					listenPort = "7001"
				}
				for _, runtimeJavaInfo := range runtimeJavaInfoes {

					if serverName == runtimeJavaInfo["webLogicName"] && listenPort == runtimeJavaInfo["webLogicPort"] {

						if runtimeJavaInfo["serverDuplicatedCount"] == "1" {
							log.Fatal("servername:", serverName, " serverport:", listenPort, " duplicated")
						} else {
							runtimeJavaInfo["serverDuplicatedCount"] = "1"

							wlsCiIndex++
						}

						if listenAddress == "" {
							listenAddress = localIp
						}

						wlsCiname := fmt.Sprintf("%s_%s_%s_%s", listenAddress, listenPort, domainName, serverName)
						wlsIname := serverName
						wlsHost := fmt.Sprintf("%s_%s", listenAddress, localHostName)
						//wlsHost := listenAddress
						wlsListenAddress := listenAddress
						wlsListenPort := listenPort
						wlsDomain := ""
						if runtimeJavaInfo["isManaged"] == "1" {
							wlsDomain = fmt.Sprintf("%s_%s_%s", runtimeJavaInfo["adminListenAddress"], runtimeJavaInfo["adminListenPort"], domainName)
						} else {
							wlsDomain = fmt.Sprintf("%s_%s_%s", listenAddress, listenPort, domainName)
						}
						wlsCis = wlsCis[:wlsCiIndex]
						wlsCis[wlsCiIndex-1][0] = wlsCiname
						wlsCis[wlsCiIndex-1][1] = wlsIname
						wlsCis[wlsCiIndex-1][2] = wlsListenAddress
						wlsCis[wlsCiIndex-1][3] = wlsListenPort
						wlsCis[wlsCiIndex-1][4] = wlsHost
						wlsCis[wlsCiIndex-1][5] = wlsDomain

						if serverName == "AdminServer" {
							domainCiIndex++

							domainCis = domainCis[:domainCiIndex]
							domainCiName := fmt.Sprintf("%s_%s_%s", listenAddress, listenPort, domainName)
							domainIname := domainName
							domainListenAddress := listenAddress
							domainListenPort := listenPort
							domainHosts := hosts
							domainLogPath := path.Join(domainPath, domainName, "logs")
							domainProdHome := runtimeJavaInfo["prodHome"]
							domainWlsHome := runtimeJavaInfo["webLogicHome"]
							domainHome := path.Join(domainPath, domainName)
							domainCis[domainCiIndex-1][0] = domainCiName
							domainCis[domainCiIndex-1][1] = domainIname
							domainCis[domainCiIndex-1][2] = domainListenAddress
							domainCis[domainCiIndex-1][3] = domainListenPort
							domainCis[domainCiIndex-1][4] = domainHosts
							domainCis[domainCiIndex-1][5] = domainLogPath
							domainCis[domainCiIndex-1][6] = domainProdHome
							domainCis[domainCiIndex-1][7] = domainWlsHome
							domainCis[domainCiIndex-1][8] = domainHome
						}

					}

				}
			}

		}

	}
	for _, v := range runtimeJavaInfoes {
		if v["serverDuplicatedCount"] == "0" {
			fmt.Println("serverName:", v["webLogicName"], " serverPort:", v["webLogicPort"], " error, no match config.xml")
		} else {
			fmt.Println("serverName:", v["webLogicName"], " serverPort:", v["webLogicPort"], " ok, match config.xml")

		}
	}
	fmt.Println("====================LinuxCI====================")
	fmt.Println(linuxCi)
	fmt.Println("====================WebLogicCIs====================")
	fmt.Println(wlsCis)
	fmt.Println("====================DomainCIs====================")
	fmt.Println(domainCis)
	cookie := LoginTpUser(UserName, PassWord, LoginURL)
	fmt.Println("====================POST OS.LINUX CI====================")
	osCi := LinuxCi{}
	osCi.Type = "os"
	osCi.SubType = "linux"
	osCi.Icon = LinuxIcon
	osCi.Color = LinuxColor
	osCi.Name = linuxCi[0]
	osCi.Iname = linuxCi[1]
	osCi.Ip = linuxCi[2]
	osCi.Version = linuxCi[3]
	postCiJson, _ := json.Marshal(osCi)
	PostCI(linuxCi[0], postCiJson, PostCiURL, cookie)
	fmt.Println("====================POST WEBLOGIC.SERVR CI====================")
	for _, wlsCi := range wlsCis {
		webLogicServerCi := WebLogicCi{}
		webLogicServerCi.Type = "wls"
		webLogicServerCi.SubType = "wls.server"
		webLogicServerCi.Icon = WebLogicIcon
		webLogicServerCi.Color = WebLogicColor
		webLogicServerCi.Name = wlsCi[0]
		webLogicServerCi.Iname = wlsCi[1]
		webLogicServerCi.ListenAddress = wlsCi[2]
		webLogicServerCi.ListenPort = wlsCi[3]
		webLogicServerCi.HostName = wlsCi[4]
		webLogicServerCi.DomainName = wlsCi[5]
		postCiJson, _ := json.Marshal(webLogicServerCi)
		PostCI(wlsCi[0], postCiJson, PostCiURL, cookie)

	}
	fmt.Println("====================POST WEBLOGIC.DOMAIN CI====================")
	for _, domainCi := range domainCis {
		webLogicDomainCi := DomainCi{}
		webLogicDomainCi.Type = "wls"
		webLogicDomainCi.SubType = "wls.domain"
		webLogicDomainCi.Icon = DomainIcon
		webLogicDomainCi.Color = DomainColor
		webLogicDomainCi.Name = domainCi[0]
		webLogicDomainCi.Iname = domainCi[1]
		webLogicDomainCi.AdminAddress = domainCi[2]
		webLogicDomainCi.AdminPort = domainCi[3]
		webLogicDomainCi.HostNames = domainCi[4]
		webLogicDomainCi.LogPath = domainCi[5]
		webLogicDomainCi.ProdHome = domainCi[6]
		webLogicDomainCi.WebLogicHome = domainCi[7]
		webLogicDomainCi.DomainPath = domainCi[8]
		postCiJson, _ := json.Marshal(webLogicDomainCi)
		PostCI(domainCi[0], postCiJson, PostCiURL, cookie)

	}

}

func RemoveDuplicatesAndEmpty(a []string) (ret []string) {
	a_len := len(a)
	for i := 0; i < a_len; i++ {
		if (i > 0 && a[i-1] == a[i]) || len(a[i]) == 0 {
			continue
		}
		ret = append(ret, a[i])
	}
	return
}

func LoginTpUser(username string, password string, loginUrl string) (cookie string) {
	login := Login{}
	login.UserName = username
	login.PassWord = password
	loginJson, _ := json.Marshal(login)

	req, _ := http.NewRequest("POST", loginUrl, bytes.NewBuffer(loginJson))
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("login failed")
		panic(err)
	} else {
		cookie = strings.Split(resp.Header["Set-Cookie"][0], ";")[0]
		defer resp.Body.Close()
		return cookie
	}

}

func PostCI(ciname string, ciSlice []byte, postUrl string, cookie string) {
	fmt.Println("post ciname:", ciname)
	req, _ := http.NewRequest("POST", postUrl, bytes.NewBuffer(ciSlice))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Cookie", cookie)
	client := &http.Client{}
	resp, err := client.Do(req)
	//defer resp.Body.Close()
	if err != nil {
		fmt.Println("post ci failed, post json:", string(ciSlice))
		fmt.Println(err)
		//panic(err)
	} else {

		fmt.Println("post ci ok, post json:", string(ciSlice))
		fmt.Println("response code", resp.Status)
		defer resp.Body.Close()
	}
	fmt.Println("*****************************************")

}
