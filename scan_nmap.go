package main

import (
    "encoding/csv"
    "encoding/xml"
    "fmt"
    "os"
    "os/exec"
    "strings"
    "time"
)

// NmapRun, Host и др. — структуры для парсинга Nmap XML (полная структура можно расширить)
type NmapRun struct {
    Hosts []Host `xml:"host"`
}

type Host struct {
    Status    Status     `xml:"status"`
    Addresses []Address  `xml:"address"`
    Hostnames Hostnames  `xml:"hostnames"`
    OS        OS         `xml:"os"`
}

type Status struct {
    State string `xml:"state,attr"`
}

type Address struct {
    Addr     string `xml:"addr,attr"`
    AddrType string `xml:"addrtype,attr"`
}

type Hostnames struct {
    Hostname []Hostname `xml:"hostname"`
}

type Hostname struct {
    Name string `xml:"name,attr"`
}

type OS struct {
    OSMatches []OSMatch `xml:"osmatch"`
}

type OSMatch struct {
    Name string `xml:"name,attr"`
}

func runNmapScan(subnet string) ([]Host, error) {
    cmd := exec.Command("nmap", "-O", "-sP", "--osscan-guess", "-oX", "-", subnet)
    output, err := cmd.Output()
    if err != nil {
        return nil, err
    }

    var nmaprun NmapRun
    err = xml.Unmarshal(output, &nmaprun)
    if err != nil {
        return nil, err
    }
    return nmaprun.Hosts, nil
}

func saveToCSV(hosts []Host, filename string) error {
    file, err := os.Create(filename)
    if err != nil {
        return err
    }
    defer file.Close()

    writer := csv.NewWriter(file)
    defer writer.Flush()

    writer.Write([]string{"#", "IP", "Hostname", "OS", "Timestamp"})
    now := time.Now().Format("2006-01-02 15:04:05")

    for i, host := range hosts {
        if host.Status.State != "up" {
            continue
        }
        ip := ""
        for _, addr := range host.Addresses {
            if addr.AddrType == "ipv4" {
                ip = addr.Addr
                break
            }
        }
        hostname := ""
        if len(host.Hostnames.Hostname) > 0 {
            hostname = host.Hostnames.Hostname[0].Name
        }
        osName := ""
        if len(host.OS.OSMatches) > 0 {
            osName = host.OS.OSMatches[0].Name
        }
        writer.Write([]string{
            fmt.Sprintf("%d", i+1),
            ip,
            hostname,
            osName,
            now,
        })
    }
    return nil
}

func main() {
    subnet := "192.168.35.0/24"
    fmt.Println("Запуск сканирования Nmap по сети:", subnet)
    hosts, err := runNmapScan(subnet)
    if err != nil {
        fmt.Println("Ошибка запуска Nmap:", err)
        return
    }

    fmt.Printf("Найдено хостов: %d\n", len(hosts))

    if err := saveToCSV(hosts, "scan_result.csv"); err != nil {
        fmt.Println("Ошибка сохранения CSV:", err)
        return
    }

    fmt.Println("Результаты записаны в scan_result.csv")
}
