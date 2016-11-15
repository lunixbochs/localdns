package main

import (
	"fmt"
	"github.com/miekg/dns"
	"log"
	"net"
	"os"
	"strings"
	"sync"
)

var dhcp4Map = make(map[string]net.IP)
var dhcp6Map = make(map[string]net.IP)
var dhcpLock sync.RWMutex

func handleRequest(w dns.ResponseWriter, r *dns.Msg) {
	if len(r.Question) != 1 {
		return
	}
	domain := r.Question[0].Name
	hostname := strings.TrimRight(domain, ".")
	dhcpLock.RLock()
	defer dhcpLock.RUnlock()

	m := new(dns.Msg)
	m.SetReply(r)
	switch r.Question[0].Qtype {
	case dns.TypeA, dns.TypeAAAA:
		if ip4, ok := dhcp4Map[hostname]; ok {
			fmt.Printf("[DNS] %s %s\n", domain, ip4.String())
			rr := &dns.A{
				Hdr: dns.RR_Header{Name: domain, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 0},
				A:   ip4.To4(),
			}
			m.Answer = append(m.Answer, rr)
		}
		if ip6, ok := dhcp6Map[hostname]; ok {
			fmt.Printf("[DNS] %s %s\n", domain, ip6.String())
			rr := &dns.AAAA{
				Hdr:  dns.RR_Header{Name: domain, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 0},
				AAAA: ip6,
			}
			m.Answer = append(m.Answer, rr)
		}
	}
	if len(m.Answer) == 0 {
		fmt.Printf("[DNS] %s NXDOMAIN\n", domain)
		m.SetRcode(r, dns.RcodeNameError)
	}
	w.WriteMsg(m)
}

func mapIP(hostname string, ip net.IP) {
	dhcpLock.Lock()
	if ip4 := ip.To4(); ip4 != nil {
		dhcp4Map[hostname] = ip
	} else {
		dhcp6Map[hostname] = ip
	}
	dhcpLock.Unlock()
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "Usage: %s <capture interface>\n", os.Args[0])
		os.Exit(1)
	}
	capture, err := Capture(os.Args[1])
	if err != nil {
		log.Fatal(err)
	}

	hostname, err := os.Hostname()
	if err == nil {
		ifv, err := net.InterfaceByName(os.Args[1])
		if err != nil {
			log.Fatal(err)
		}
		addrs, err := ifv.Addrs()
		if err != nil {
			log.Fatal(err)
		}
		for _, addr := range addrs {
			ipnet := addr.(*net.IPNet)
			mapIP(hostname, ipnet.IP)
		}
	}

	server := &dns.Server{Addr: ":53", Net: "udp"}
	go server.ListenAndServe()
	dns.HandleFunc(".", handleRequest)

	for l := range capture {
		mapIP(l.hostname, l.ip)
		fmt.Printf("[DHCP] %s -> %s %s\n", l.mac, l.ip, l.hostname)
	}
}
