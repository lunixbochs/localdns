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

var dhcpMap = make(map[string]net.IP)
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
	var rr dns.RR
	if ip, ok := dhcpMap[hostname]; !ok {
		fmt.Printf("[DNS] %s NXDOMAIN\n", domain)
		m.SetRcode(r, dns.RcodeNameError)
	} else {
		fmt.Printf("[DNS] %s %s\n", domain, ip.String())
		if ip.To4() != nil {
			rr = &dns.A{
				Hdr: dns.RR_Header{Name: domain, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 0},
				A:   ip.To4(),
			}
		} else {
			rr = &dns.AAAA{
				Hdr:  dns.RR_Header{Name: domain, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 0},
				AAAA: ip,
			}
		}
		m.Answer = append(m.Answer, rr)
	}
	w.WriteMsg(m)
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

	server := &dns.Server{Addr: ":53", Net: "udp"}
	go server.ListenAndServe()
	dns.HandleFunc(".", handleRequest)

	for l := range capture {
		dhcpLock.Lock()
		dhcpMap[l.hostname] = l.ip
		dhcpLock.Unlock()
		fmt.Printf("[DHCP] %s -> %s %s\n", l.mac, l.ip, l.hostname)
	}
}
