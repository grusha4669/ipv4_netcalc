package main

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"strings"
)

// Вспомогательная функция для форматирования в HEX (A.B.C.D -> AA.BB.CC.DD)
func toHex(ip net.IP) string {
	ipv4 := ip.To4()
	if ipv4 == nil {
		return ""
	}
	return fmt.Sprintf("%02X.%02X.%02X.%02X", ipv4[0], ipv4[1], ipv4[2], ipv4[3])
}

// Вспомогательная функция для бинарного вида с разделителем "|" по границе маски
func toBin(ip net.IP, maskOnes int) string {
	ipv4 := ip.To4()
	if ipv4 == nil {
		return ""
	}
	// Собираем сплошную строку из 32 бит
	binStr := fmt.Sprintf("%08b%08b%08b%08b", ipv4[0], ipv4[1], ipv4[2], ipv4[3])

	var result strings.Builder
	for i := 0; i < 32; i++ {
		if i > 0 && i%8 == 0 {
			if i == maskOnes {
				result.WriteString(" | ")
			} else {
				result.WriteString(".")
			}
		} else if i == maskOnes {
			result.WriteString(" | ")
		}
		result.WriteByte(binStr[i])
	}
	return result.String()
}

func main() {
	scanner := bufio.NewScanner(os.Stdin)

	for {
		fmt.Print("Введите IP/Маску (например, 192.168.0.1/16): ")
		if !scanner.Scan() {
			break
		}

		input := strings.TrimSpace(scanner.Text())
		if strings.ToLower(input) == "exit" {
			break
		}
		if input == "" {
			continue
		}

		// Строгая валидация формата CIDR
		ip, ipNet, err := net.ParseCIDR(input)
		if err != nil || ip.To4() == nil || !strings.Contains(input, "/") {
			fmt.Println("Ошибка: неверный формат. Используйте только вид A.B.C.D/M (IPv4)\n")
			continue
		}

		// Расчет параметров сети
		ones, _ := ipNet.Mask.Size()
		netInt := binary.BigEndian.Uint32(ipNet.IP)
		numHosts := uint32(1 << (32 - ones))
		broadInt := netInt | (numHosts - 1)

		maskIP := net.IP(ipNet.Mask)

		wildcardIP := make(net.IP, 4)
		for i := 0; i < 4; i++ {
			wildcardIP[i] = ^ipNet.Mask[i]
		}

		broadcastIP := make(net.IP, 4)
		binary.BigEndian.PutUint32(broadcastIP, broadInt)

		var hostminStr, hostmaxStr, totalHostsStr string
		if ones < 31 {
			fIP, lIP := make(net.IP, 4), make(net.IP, 4)
			binary.BigEndian.PutUint32(fIP, netInt+1)
			binary.BigEndian.PutUint32(lIP, broadInt-1)
			hostminStr, hostmaxStr, totalHostsStr = fIP.String(), lIP.String(), fmt.Sprintf("%d", numHosts-2)
		} else if ones == 31 {
			hostminStr, hostmaxStr, totalHostsStr = ipNet.IP.String(), broadcastIP.String(), "2"
		} else {
			hostminStr, hostmaxStr, totalHostsStr = ipNet.IP.String(), ipNet.IP.String(), "1"
		}

		hMinIP := net.ParseIP(hostminStr)
		hMaxIP := net.ParseIP(hostmaxStr)

		// Вывод текстовой таблицы с фиксированной шириной колонок
		fmt.Println()
		fmt.Printf("%-12s %-16s %-15s %s\n", "Имя", "Значение", "16-ричный код", "Бинарное значение")
		fmt.Printf("%-12s %-16s %-15s %s\n", "Адрес", ip.String(), toHex(ip), toBin(ip, ones))
		fmt.Printf("%-12s %-16s %-15s %s\n", "Bitmask", fmt.Sprintf("%d", ones), "", "")
		fmt.Printf("%-12s %-16s %-15s %s\n", "Netmask", maskIP.String(), toHex(maskIP), toBin(maskIP, ones))
		fmt.Printf("%-12s %-16s %-15s %s\n", "Wildcard", wildcardIP.String(), toHex(wildcardIP), toBin(wildcardIP, ones))
		fmt.Printf("%-12s %-16s %-15s %s\n", "Network", ipNet.IP.String(), toHex(ipNet.IP), toBin(ipNet.IP, ones))
		fmt.Printf("%-12s %-16s %-15s %s\n", "Broadcast", broadcastIP.String(), toHex(broadcastIP), toBin(broadcastIP, ones))
		fmt.Printf("%-12s %-16s %-15s %s\n", "Hostmin", hostminStr, toHex(hMinIP), toBin(hMinIP, ones))
		fmt.Printf("%-12s %-16s %-15s %s\n", "Hostmax", hostmaxStr, toHex(hMaxIP), toBin(hMaxIP, ones))
		fmt.Printf("%-12s %-16s %-15s %s\n", "Hosts", totalHostsStr, "", "")
		fmt.Println()
		break
	}
}
