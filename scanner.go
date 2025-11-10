package main

import (
    "encoding/csv"
    "fmt"
    "net"
    "os"
    "os/exec"
    "runtime"
    "strings"
    "sync"
    "time"
)

// pingHost выполняет пинг IP-адреса и сообщает, если он отвечает
func pingHost(ip string, wg *sync.WaitGroup, results chan<- string) {
    defer wg.Done()

    var cmd *exec.Cmd
    if runtime.GOOS == "windows" {
        cmd = exec.Command("ping", "-n", "1", "-w", "1000", ip)
    } else {
        cmd = exec.Command("ping", "-c", "1", "-W", "1", ip)
    }

    output, err := cmd.Output()
    if err != nil {
        return
    }

    if strings.Contains(strings.ToLower(string(output)), "ttl=") {
        results <- ip
    }
}

// scanNetwork сканирует диапазон IP-адресов и возвращает список активных узлов
func scanNetwork(subnet string) []string {
    ip, ipnet, err := net.ParseCIDR(subnet)
    if err != nil {
        fmt.Println("Ошибка сети:", err)
        return nil
    }

    var wg sync.WaitGroup
    results := make(chan string, 256)

    for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); inc(ip) {
        ipCopy := make(net.IP, len(ip))
        copy(ipCopy, ip)
        wg.Add(1)
        go pingHost(ipCopy.String(), &wg, results)
    }

    go func() {
        wg.Wait()
        close(results)
    }()

    var hosts []string
    for host := range results {
        hosts = append(hosts, host)
    }
    return hosts
}

// inc инкрементирует IP
func inc(ip net.IP) {
    for j := len(ip) - 1; j >= 0; j-- {
        ip[j]++
        if ip[j] > 0 {
            break
        }
    }
}

// saveToCSV сохраняет список хостов в CSV-файл
func saveToCSV(hosts []string, filename string) error {
    file, err := os.Create(filename)
    if err != nil {
        return err
    }
    defer file.Close()

    writer := csv.NewWriter(file)
    defer writer.Flush()

    writer.Write([]string{"#","IP address","Timestamp"})
    now := time.Now().Format("2006-01-02 15:04:05")

    for i, host := range hosts {
        writer.Write([]string{fmt.Sprintf("%d", i+1), host, now})
    }

    return nil
}

func main() {
    subnet := "192.168.35.0/24"
    fmt.Println("Сканирование сети:", subnet)
    hosts := scanNetwork(subnet)
    fmt.Printf("Найдено активных хостов: %d\n", len(hosts))

    for _, h := range hosts {
        fmt.Println("Online:", h)
    }

    if err := saveToCSV(hosts, "scan_result.csv"); err != nil {
        fmt.Println("Ошибка записи CSV:", err)
        return
    }

    fmt.Println("Результат записан в scan_result.csv")
}