// Internal measurement server.
//
// Runs mtr directly (the image it ships in has mtr installed and NET_RAW), so
// there is no docker-in-docker. It exposes a small HTTP API that the flasksite
// app calls over localhost.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const (
	resultsDir         = "/app/results"
	measurementTimeout = 60 * time.Second
)

var (
	targetRe      = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,253}$`)
	protocolFlags = map[string][]string{
		"icmp": {},
		"tcp":  {"--tcp"},
		"udp":  {"--udp"},
	}
	// Same header perform_mtr.sh writes (note the blank columns).
	csvHeader = "hostname,Mtr_Version,Start_Time,Status,Host,Hop,Ip,Asn,Loss%,Snt, ,Last,Avg,Best,Wrst,StDev,"
)

type performRequest struct {
	Target   string `json:"target"`
	Protocol string `json:"protocol"`
}

func main() {
	// CLI mode: a destination argument runs a single measurement and exits.
	//   measurement-server <destination> [protocol]
	if len(os.Args) > 1 {
		runCLI(os.Args[1:])
		return
	}

	// Otherwise, run as the HTTP server.
	port := os.Getenv("PORT")
	if port == "" {
		port = "5002"
	}
	addr := ":" + port

	http.HandleFunc("/perform", handlePerform)
	fmt.Printf("measurement server listening on %s\n", addr)
	if err := http.ListenAndServe(addr, nil); err != nil {
		panic(err)
	}
}

// runCLI performs one measurement for the given destination and prints the hops
// as JSON Lines (one JSON object per line), then exits.
func runCLI(args []string) {
	target := args[0]
	protocol := "icmp"
	if len(args) > 1 {
		protocol = args[1]
	}

	if !targetRe.MatchString(target) {
		fmt.Fprintln(os.Stderr, "invalid target")
		os.Exit(2)
	}
	flag, ok := protocolFlags[protocol]
	if !ok {
		fmt.Fprintln(os.Stderr, "invalid protocol (use icmp, tcp, or udp)")
		os.Exit(2)
	}

	hops, err := runMeasurement(target, flag)
	if err != nil {
		fmt.Fprintf(os.Stderr, "measurement failed: %v\n", err)
		os.Exit(1)
	}

	enc := json.NewEncoder(os.Stdout)
	for _, hop := range hops {
		_ = enc.Encode(hop)
	}
}

func handlePerform(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "POST only"})
		return
	}

	var req performRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid json"})
		return
	}
	if req.Protocol == "" {
		req.Protocol = "icmp"
	}
	if !targetRe.MatchString(req.Target) {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid target"})
		return
	}
	flag, ok := protocolFlags[req.Protocol]
	if !ok {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid protocol"})
		return
	}

	hops, err := runMeasurement(req.Target, flag)
	if err == context.DeadlineExceeded {
		writeJSON(w, http.StatusGatewayTimeout, map[string]any{"ok": false, "error": "timeout"})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]any{"ok": false, "error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "target": req.Target, "hops": hops})
}

// runMeasurement runs mtr with a timeout, writes the CSV, and returns the hops.
func runMeasurement(target string, protoFlag []string) ([]map[string]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), measurementTimeout)
	defer cancel()

	args := []string{"-b", "-z"}
	args = append(args, protoFlag...)
	args = append(args, "--report", "--csv", "-c", "1", target)

	out, err := exec.CommandContext(ctx, "mtr", args...).Output()
	if ctx.Err() == context.DeadlineExceeded {
		return nil, context.DeadlineExceeded
	}
	if err != nil {
		return nil, fmt.Errorf("mtr failed: %w", err)
	}

	hostname, _ := os.Hostname()
	return writeAndParse(target, hostname, out)
}

// writeAndParse mirrors perform_mtr.sh: skip mtr's header line, prepend the
// source hostname to each row, persist the CSV, and return parsed records.
func writeAndParse(target, hostname string, mtrOut []byte) ([]map[string]string, error) {
	lines := strings.Split(strings.TrimRight(string(mtrOut), "\n"), "\n")
	dataLines := []string{}
	if len(lines) > 1 {
		dataLines = lines[1:] // drop mtr's own header
	}

	var b strings.Builder
	b.WriteString(csvHeader + "\n")
	for _, line := range dataLines {
		b.WriteString(hostname + "," + line + "\n")
	}

	outPath := filepath.Join(resultsDir, "mtr_"+target+".csv")
	if err := os.WriteFile(outPath, []byte(b.String()), 0o644); err != nil {
		return nil, fmt.Errorf("write results: %w", err)
	}

	cols := strings.Split(csvHeader, ",")
	records := []map[string]string{}
	for _, line := range dataLines {
		fields := strings.Split(hostname+","+line, ",")
		rec := map[string]string{}
		for i, col := range cols {
			col = strings.TrimSpace(col)
			if col == "" || i >= len(fields) { // skip the blank header columns
				continue
			}
			rec[col] = strings.TrimSpace(fields[i])
		}
		records = append(records, rec)
	}
	return records, nil
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
