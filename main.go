package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/miekg/dns"
)

var rootCmd = &cobra.Command{
	Use: "dotperf",
	Run: serv,
}

func init() {
	rootCmd.PersistentFlags().StringP("server", "s", "localhost@53", "target server")
	rootCmd.PersistentFlags().StringP("transport", "p", "udp", "transport udp,tcp,tls,https")
	rootCmd.PersistentFlags().Uint16P("proc-num", "n", 16, "goroutine num")
	rootCmd.PersistentFlags().Uint16P("time", "m", 30, "running minute")
	rootCmd.PersistentFlags().BoolP("ticket", "t", false, "enable session ticket")
	rootCmd.PersistentFlags().BoolP("tlsv13", "", false, "select TLSv1.3")
	rootCmd.PersistentFlags().BoolP("tlsv12", "", false, "select TLSv1.2")
}
func main() {
	rootCmd.Execute()
}
func serv(cmd *cobra.Command, args []string) {
	var port int
	var err error
	transport, err := cmd.PersistentFlags().GetString("transport")
	switch transport {
	case "tcp", "TCP":
		transport = "tcp"
		port = 53
	case "dot", "DoT", "DOT", "tls", "tcp-tls", "TLS", "TCP-TLS":
		transport = "tcp-tls"
		port = 853
	case "doh", "DoH", "DOH", "https":
		transport = "https"
		port = 443
	default:
		transport = "udp"
		port = 53
	}

	s, err := cmd.PersistentFlags().GetString("server")
	if err != nil {
		log.Fatal(err)
	}
	server := strings.Split(s, "@")
	if len(server) > 1 {
		port, err = strconv.Atoi(server[1])
		if err != nil {
			log.Fatal("server %s is invalid", s)
		}
	}
	proc_num, err := cmd.PersistentFlags().GetUint16("proc-num")
	if err != nil {
		log.Fatal(err)
	}
	proc_time, err := cmd.PersistentFlags().GetUint16("time")
	if err != nil {
		log.Fatal(err)
	}
	ticket, err := cmd.PersistentFlags().GetBool("ticket")
	if err != nil {
		log.Fatal(err)
	}
	tlsv13, err := cmd.PersistentFlags().GetBool("tlsv13")
	if err != nil {
		log.Fatal(err)
	}
	tlsv12, err := cmd.PersistentFlags().GetBool("tlsv12")
	if err != nil {
		log.Fatal(err)
	}
	host := server[0] + ":" + strconv.Itoa(port)
	workers := []*worker{}
	ctx, cancel := context.WithCancel(context.Background())
	startCtx, start := context.WithCancel(context.Background())
	for i := uint16(0); i < proc_num; i++ {
		cache := tls.NewLRUClientSessionCache(10)
		tlsConfig := &tls.Config{
			InsecureSkipVerify: true,
			ClientSessionCache: cache,
			MinVersion:         tls.VersionTLS12,
			MaxVersion:         tls.VersionTLS13,
		}
		if !ticket {
			tlsConfig.SessionTicketsDisabled = true
		}
		if tlsv12 {
			tlsConfig.MaxVersion = tls.VersionTLS12
			tlsConfig.MinVersion = tls.VersionTLS12
		}
		if tlsv13 {
			tlsConfig.MaxVersion = tls.VersionTLS13
			tlsConfig.MinVersion = tls.VersionTLS13
		}
		worker := NewWorker(host, transport, tlsConfig)
		go worker.run(ctx, startCtx)
		workers = append(workers, worker)
	}
	fmt.Printf("Target Server: %s\n", host)
	fmt.Printf("transport: %s\n", transport)
	fmt.Printf("goroutinnum: %d\n", proc_num)
	fmt.Printf("proc_time: %d\n", proc_time)
	fmt.Printf("session_ticket: %v\n", ticket)

	sig := make(chan os.Signal)
	signal.Notify(sig, syscall.SIGQUIT, syscall.SIGINT, syscall.SIGTERM)
	timer := time.NewTimer(time.Second * time.Duration(proc_time))
	start_time := time.Now()
	start()
	select {
	case <-sig:
		timer.Stop()
	case <-timer.C:
	}
	cancel()
	end_time := time.Now()

	duration := end_time.Sub(start_time)
	var (
		count           uint64
		succsess        uint64
		connectionError uint64
		responseError   uint64
		dnsError        uint64
	)
	for _, worker := range workers {
		count = count + worker.Count
		succsess = succsess + worker.Success
		connectionError = connectionError + worker.ConnectionError
		responseError = responseError + worker.ResponseError
		dnsError = dnsError + worker.DNSError
	}
	fmt.Printf("ALL COUNT: %v\n", count)
	fmt.Printf("Success: %v\n", succsess)
	fmt.Printf("Connection Error: %v\n", connectionError)
	fmt.Printf("Response Error: %v\n", responseError)
	fmt.Printf("DNS Error: %v\n", dnsError)
	fmt.Printf("Success QPS: %f\n", float64(succsess)/duration.Seconds())
}

type worker struct {
	server          string
	tlsConfig       *tls.Config
	transport       string
	Count           uint64
	Success         uint64
	ConnectionError uint64
	ResponseError   uint64
	DNSError        uint64
}

func NewWorker(server string, transport string, tlsConfig *tls.Config) *worker {
	return &worker{
		server:    server,
		transport: transport,
		tlsConfig: tlsConfig,
	}
}

func (w *worker) run(ctx context.Context, waitCtx context.Context) {
WAIT:
	for {
		select {
		case <-waitCtx.Done():
			break WAIT
		case <-ctx.Done():
			return
		}
	}
	for {
		select {
		case <-ctx.Done():
			return
		default:
			w.Count++
			m := new(dns.Msg)
			m.SetQuestion("localhost.", dns.TypeA)

			c := new(dns.Client)
			c.TLSConfig = w.tlsConfig
			c.Net = w.transport
			r, _, err := c.Exchange(m, w.server)
			if err != nil {
				fmt.Println(err)
				w.ConnectionError++
				continue
			}
			if r == nil {
				w.ResponseError++
				continue
			}
			if r.Rcode != dns.RcodeSuccess {
				w.DNSError++
				continue
			}
			w.Success++
		}
	}
}
