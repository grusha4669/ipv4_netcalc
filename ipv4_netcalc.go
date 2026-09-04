// Copyright (C) 2026 grusha4669
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License.

package main

import (
	"bufio"
	"encoding/binary"
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
)

// Helper function for HEX formatting (A.B.C.D -> AA.BB.CC.DD)
func toHex(ip net.IP) string {
	ipv4 := ip.To4()
	if ipv4 == nil {
		return ""
	}
	return fmt.Sprintf("%02X.%02X.%02X.%02X", ipv4[0], ipv4[1], ipv4[2], ipv4[3])
}

// Helper function to format the host count with comma separators (1073741822 -> 1,073,741,822)
func formatHosts(n uint32) string {
	in := fmt.Sprintf("%d", n)
	numOfDigits := len(in)
	if numOfDigits <= 3 {
		return in
	}

	var result strings.Builder
	firstGroupLen := numOfDigits % 3
	if firstGroupLen == 0 {
		firstGroupLen = 3
	}

	result.WriteString(in[:firstGroupLen])

	for i := firstGroupLen; i < numOfDigits; i += 3 {
		result.WriteString(",")
		result.WriteString(in[i : i+3])
	}

	return result.String()
}

// Helper function for binary view (exactly as in the screenshot)
func toBin(ip net.IP, maskOnes int) string {
	ipv4 := ip.To4()
	if ipv4 == nil {
		return ""
	}

	rawBin := fmt.Sprintf("%08b.%08b.%08b.%08b", ipv4[0], ipv4[1], ipv4[2], ipv4[3])

	if maskOnes == 32 {
		return rawBin
	}

	dotOffset := 0
	if maskOnes > 24 {
		dotOffset = 3
	} else if maskOnes > 16 {
		dotOffset = 2
	} else if maskOnes > 8 {
		dotOffset = 1
	}

	insertPos := maskOnes + dotOffset

	if rawBin[insertPos] == '.' {
		// Replace the dot with the " | " separator, skipping the dot itself (insertPos+1)
		return rawBin[:insertPos] + " | " + rawBin[insertPos+1:]
	}
	return rawBin[:insertPos] + " | " + rawBin[insertPos:]
}

// Performs calculation and beautifully prints the network parameters table
func calculateAndPrint(input string) bool {
	ip, ipNet, err := net.ParseCIDR(input)
	if err != nil || ip.To4() == nil || !strings.Contains(input, "/") {
		fmt.Println("Error: invalid format. Use only A.B.C.D/M format (IPv4)")
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

	var hostminIP, hostmaxIP net.IP
	var totalHostsStr string

	if ones <= 30 {
		hMin, hMax := make(net.IP, 4), make(net.IP, 4)
		binary.BigEndian.PutUint32(hMin, netInt+1)
		binary.BigEndian.PutUint32(hMax, broadInt-1)
		hostminIP, hostmaxIP = hMin, hMax
		totalHostsStr = formatHosts(numHosts - 2)
	} else if ones == 31 {
		hostminIP, hostmaxIP = ipNet.IP, broadcastIP
		totalHostsStr = "0"
	} else { // ones == 32
		hostminIP, hostmaxIP = ipNet.IP, broadcastIP
		totalHostsStr = "0"
	}

	fmt.Println()
	fmt.Printf("%-12s %-16s %-15s %s\n", "Name", "Value", "Hex Code", "Binary Value")
	fmt.Printf("%-12s %-16s %-15s %s\n", "Address", ip.String(), toHex(ip), toBin(ip, ones))
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
		fmt.Println("According to RFC 3021")
		fmt.Println()
	}

	return true
}

func waitExit() {
	fmt.Println("Press [Enter] to exit...")
	bufio.NewReader(os.Stdin).ReadBytes('\n')
}

func main() {
	// Customizing the built-in help text for -h / --help
	flag.Usage = func() {
		// filepath.Base("path/to/file") will return just the file name
		exeName := filepath.Base(os.Args[0])
		fmt.Printf("Usage: %s [-c IP/Mask]\n\n", exeName)
		fmt.Println("Flags:")
		flag.PrintDefaults()
	}

	// Declare the -c flag
	cidrFlag := flag.String("c", "", "CIDR network for calculation (e.g., 192.168.0.1/16)")
	flag.Parse()

	// 1. If the -c flag is passed
	if *cidrFlag != "" {
		calculateAndPrint(strings.TrimSpace(*cidrFlag))
		return
	}

	// 2. If arguments are passed without a flag (for backward compatibility, e.g., go run main.go 1.1.1.1/31)
	if flag.NArg() > 0 {
		calculateAndPrint(strings.TrimSpace(flag.Arg(0)))
		return
	}

	// 3. If run with no parameters at all — enable interactive mode
	scanner := bufio.NewScanner(os.Stdin)
	for {
		fmt.Print("Enter IP/Mask (e.g., 192.168.0.1/16): ")
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

		if calculateAndPrint(input) {
			break
		}
	}
	waitExit()
}
