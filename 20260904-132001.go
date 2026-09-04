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

// Вспомогательная функция для форматирования числа хостов с разделителями-запятыми (1073741822 -> 1,073,741,822)
func formatHosts(n uint32) string {
	in := fmt.Sprintf("%d", n)
	numOfDigits := len(in)
	if numOfDigits <= 3 {
		return in
	}

	var result strings.Builder
	// Считаем, сколько символов пойдет до первой запятой
	firstGroupLen := numOfDigits % 3
	if firstGroupLen == 0 {
		firstGroupLen = 3
	}

	result.WriteString(in[:firstGroupLen])

	// Добавляем оставшиеся группы по 3 цифры с запятыми перед ними
	for i := firstGroupLen; i < numOfDigits; i += 3 {
		result.WriteString(",")
		result.WriteString(in[i : i+3])
	}

	return result.String()
}

// Вспомогательная функция для бинарного вида (в точности как на скриншоте)
func toBin(ip net.IP, maskOnes int) string {
	ipv4 := ip.To4()
	if ipv4 == nil {
		return ""
	}

	// Сначала строим стандартную строку IP с точками: 00000001.00000001.00000001.00000001
	rawBin := fmt.Sprintf("%08b.%08b.%08b.%08b", ipv4[0], ipv4[1], ipv4[2], ipv4[3])

	// На скриншоте для маски /32 разделитель вообще не выводится
	if maskOnes == 32 {
		return rawBin
	}

	// Каждые 8 бит разделены точкой, рассчитываем точное смещение для вставки '|'
	dotOffset := 0
	if maskOnes > 24 {
		dotOffset = 3
	} else if maskOnes > 16 {
		dotOffset = 2
	} else if maskOnes > 8 {
		dotOffset = 1
	}

	insertPos := maskOnes + dotOffset

	// Формируем строку с разделителем: пробел-палочка-пробел " | "
	return rawBin[:insertPos] + " | " + rawBin[insertPos:]
}

// Выполняет расчет и красиво печатает таблицу параметров сети
func calculateAndPrint(input string) bool {
	// Строгая валидация формата CIDR
	ip, ipNet, err := net.ParseCIDR(input)
	if err != nil || ip.To4() == nil || !strings.Contains(input, "/") {
		fmt.Println("Ошибка: неверный формат. Используйте только вид A.B.C.D/M (IPv4)")
		return false
	}

	ip = ip.To4()
	ipNet.IP = ipNet.IP.To4()

	ones, _ := ipNet.Mask.Size()
	netInt := binary.BigEndian.Uint32(ipNet.IP)
	numHosts := uint32(1 << (32 - ones))
	broadInt := netInt | (numHosts - 1)

	maskIP := net.IP(ipNet.Mask).To4()
	wildcardIP := make(net.IP, 4)
	for i := 0; i < 4; i++ {
		wildcardIP[i] = ^ipNet.Mask[i]
	}

	broadcastIP := make(net.IP, 4)
	binary.BigEndian.PutUint32(broadcastIP, broadInt)

	// Расчет Hostmin и Hostmax в точности как на скриншоте сайта
	var hostminIP, hostmaxIP net.IP
	var totalHostsStr string

	if ones <= 30 {
		hMin, hMax := make(net.IP, 4), make(net.IP, 4)
		binary.BigEndian.PutUint32(hMin, netInt+1)
		binary.BigEndian.PutUint32(hMax, broadInt-1)
		hostminIP, hostmaxIP = hMin, hMax
		totalHostsStr = formatHosts(numHosts - 2)
	} else if ones == 31 {
		// На сайте для /31 Hostmin совпадает с Network, а Hostmax с Broadcast
		hostminIP, hostmaxIP = ipNet.IP, broadcastIP
		totalHostsStr = "0"
	} else { // ones == 32
		// На сайте для /32 Hostmin совпадает с Network, а Hostmax с Broadcast
		hostminIP, hostmaxIP = ipNet.IP, broadcastIP
		totalHostsStr = "0"
	}

	fmt.Println()
	fmt.Printf("%-12s %-16s %-15s %s\n", "Имя", "Значение", "16-ричный код", "Бинарное значение")
	fmt.Printf("%-12s %-16s %-15s %s\n", "Адрес", ip.String(), toHex(ip), toBin(ip, ones))
	fmt.Printf("%-12s %-16s %-15s %s\n", "Bitmask", fmt.Sprintf("%d", ones), "", "")
	fmt.Printf("%-12s %-16s %-15s %s\n", "Netmask", maskIP.String(), toHex(maskIP), toBin(maskIP, ones))
	fmt.Printf("%-12s %-16s %-15s %s\n", "Wildcard", wildcardIP.String(), toHex(wildcardIP), toBin(wildcardIP, ones))
	fmt.Printf("%-12s %-16s %-15s %s\n", "Network", ipNet.IP.String(), toHex(ipNet.IP), toBin(ipNet.IP, ones))
	fmt.Printf("%-12s %-16s %-15s %s\n", "Broadcast", broadcastIP.String(), toHex(broadcastIP), toBin(broadcastIP, ones))
	fmt.Printf("%-12s %-16s %-15s %s\n", "Hostmin", hostminIP.String(), toHex(hostminIP), toBin(hostminIP, ones))
	fmt.Printf("%-12s %-16s %-15s %s\n", "Hostmax", hostmaxIP.String(), toHex(hostmaxIP), toBin(hostmaxIP, ones))
	fmt.Printf("%-12s %-16s %-15s %s\n", "Hosts", totalHostsStr, "", "")
	fmt.Println()

	if ones == 31 {
		fmt.Println("Согласно RFC 3021")
		fmt.Println()
	}

	return true
}

func main() {
	// Если передан аргумент из терминала (длина os.Args > 1)
	if len(os.Args) > 1 {
		input := strings.TrimSpace(os.Args[1])
		calculateAndPrint(input)
		return
	}

	// Иначе включаем привычный интерактивный режим ввода
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

		// Вызываем расчет. Если формат верный — выходим из цикла после вывода таблицы
		if calculateAndPrint(input) {
			break
		}
	}
}
