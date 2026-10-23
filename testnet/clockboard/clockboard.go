package main

import (
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/csv"
	"flag"
	"fmt"
	"html/template"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

const (
	maxAge    = 24 * time.Hour
	plotLimit = "1e-05"
)

var pageTemplate = template.Must(template.New("page").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Clockboard</title>
<style>
body {margin: 5% auto; background: #ffffff; color: #444444; font-family: system-ui, -apple-system, sans-serif; font-size: 16px; line-height: 1.8; max-width: 73%;}
code {background: #f2f2f2;}
h2:not(:first-of-type) {margin-top: 2em;}
img {width: 100%; height: auto; display: block; margin-bottom: 1.5em;}
table {width: 100%; border-collapse: collapse; line-height: 1.5; font-variant-numeric: tabular-nums;}
th, td {text-align: left; padding: 0.15em 0; border-bottom: 1px solid #e5e5e5; white-space: nowrap;}
th {width: 6.5em; font-weight: 600;}
</style>
</head>
<body>
<h1>Clockboard</h1>
<p>Clock offsets over the last {{.MaxAge}} hours.</p>
{{range .Buckets}}
<h2>{{.Name}}</h2>
{{if .Image}}<img src="{{.Image}}" alt="Offset plot for {{.Name}}">
<table>
{{range .Stats}}<tr><th>{{.Key}}</th><td>{{.Value}}</td></tr>
{{end}}</table>
<p>Updated {{.Updated}} UTC.</p>{{end}}
{{if .Error}}<p>Error: <code>{{.Error}}</code></p>{{end}}
{{end}}
<script>
new EventSource("/events").onmessage = (e) => { if (e.data !== "{{.Version}}") location.reload(); };
</script>
</body>
</html>
`))

type bucketInfo struct {
	name      string
	region    string
	accessKey string
	secretKey string
}

type stat struct {
	Key   string
	Value string
}

type bucketResult struct {
	Name    string
	Image   template.URL
	Stats   []stat
	Updated string
	Error   string
}

func parseStats(line string) []stat {
	var stats []stat
	for _, part := range strings.Split(line, ", ") {
		k, v, _ := strings.Cut(part, "=")
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		if k == "n" {
			k = "samples"
		}
		stats = append(stats, stat{Key: k, Value: v})
	}
	return stats
}

func appendObject(ctx context.Context, client *s3.Client, bucket, key string, w io.Writer) error {
	out, err := client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		return err
	}
	defer out.Body.Close()
	zr, err := gzip.NewReader(out.Body)
	if err != nil {
		return err
	}
	defer zr.Close()
	_, err = io.Copy(w, zr)
	return err
}

func fetchLog(ctx context.Context, client *s3.Client, bucket string, keys []string, logPath string) error {
	f, err := os.Create(logPath)
	if err != nil {
		return err
	}
	defer f.Close()
	for _, key := range keys {
		if err := appendObject(ctx, client, bucket, key, f); err != nil {
			return fmt.Errorf("%s: %w", key, err)
		}
	}
	return f.Close()
}

func plot(ctx context.Context, client *s3.Client, bucket string, keys []string, offplotDir string) (png []byte, stats []stat, err error) {
	logPath, err := filepath.Abs(bucket + ".log")
	if err != nil {
		return nil, nil, err
	}
	pngPath := strings.TrimSuffix(logPath, ".log") + ".png"
	defer os.Remove(logPath)
	defer os.Remove(pngPath)
	if err := fetchLog(ctx, client, bucket, keys, logPath); err != nil {
		return nil, nil, err
	}
	cmd := exec.Command("go", "run", ".", "-png", "-l", plotLimit, logPath)
	cmd.Dir = offplotDir
	cmd.Stderr = os.Stderr
	stdout, err := cmd.Output()
	if err != nil {
		return nil, nil, fmt.Errorf("offplot: %w", err)
	}
	png, err = os.ReadFile(pngPath)
	if err != nil {
		return nil, nil, err
	}
	stats = parseStats(strings.TrimPrefix(strings.TrimSpace(string(stdout)), logPath+": "))
	return png, stats, nil
}

func listKeys(ctx context.Context, client *s3.Client, bucket string, since time.Time) ([]string, error) {
	var keys []string
	sinceStr := since.Format("20060102-150405.000")
	paginator := s3.NewListObjectsV2Paginator(client, &s3.ListObjectsV2Input{
		Bucket: aws.String(bucket),
	})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, obj := range page.Contents {
			// Keys have the form "UNIT_20060102-150405.000.log.gz" (see testnet/journaltail),
			// so the timestamps compare lexicographically.
			key := aws.ToString(obj.Key)
			i := strings.LastIndex(key, "_")
			if i < 0 || key[i+1:] < sinceStr {
				continue
			}
			keys = append(keys, key)
		}
	}
	return keys, nil
}

func newClient(ctx context.Context, b bucketInfo) (*s3.Client, error) {
	cfg, err := config.LoadDefaultConfig(ctx,
		config.WithRegion(b.region),
		config.WithCredentialsProvider(
			credentials.NewStaticCredentialsProvider(b.accessKey, b.secretKey, "")),
	)
	if err != nil {
		return nil, err
	}
	return s3.NewFromConfig(cfg), nil
}

func readBucketInfo(path string) ([]bucketInfo, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	records, err := csv.NewReader(f).ReadAll()
	if err != nil {
		return nil, err
	}
	var buckets []bucketInfo
	for i, rec := range records {
		if len(rec) != 3 {
			return nil, fmt.Errorf("%s:%d: expected 3 fields, got %d", path, i+1, len(rec))
		}
		rec0 := strings.Split(rec[0], ".")
		if len(rec0) != 5 || rec0[1] != "s3" || rec0[3] != "amazonaws" || rec0[4] != "com" {
			return nil, fmt.Errorf("%s:%d: unexpected bucket host: %s", path, i+1, rec[0])
		}
		name, region := rec0[0], rec0[2]
		buckets = append(buckets, bucketInfo{
			name:      name,
			region:    region,
			accessKey: rec[1],
			secretKey: rec[2],
		})
	}
	return buckets, nil
}

func main() {
	var bucketsFile, offplot, addr string
	var poll time.Duration
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [options]\n\n"+
			"Plots the entries created within the last %s in the S3 buckets given in\n"+
			"a CSV file with lines of the form\n"+
			"BUCKET.s3.REGION.amazonaws.com,ACCESS_KEY,SECRET_KEY\n"+
			"using offplot (run via \"go run\") and serves the plots as a web page.\n\n"+
			"Options:\n", os.Args[0], maxAge)
		flag.PrintDefaults()
	}
	flag.StringVar(&bucketsFile, "buckets", "", "CSV file with buckets and credentials (required)")
	flag.StringVar(&offplot, "offplot", "", "Path to the offplot source directory (required)")
	flag.StringVar(&addr, "addr", "localhost:8080", "HTTP listen address")
	flag.DurationVar(&poll, "poll", 5*time.Minute, "Interval between S3 polls")
	flag.Parse()
	if bucketsFile == "" {
		fmt.Fprintf(os.Stderr, "Error: CSV file with buckets and credentials is required\n")
		flag.Usage()
		os.Exit(1)
	}
	if offplot == "" {
		fmt.Fprintf(os.Stderr, "Error: path to the offplot source directory is required\n")
		flag.Usage()
		os.Exit(1)
	}

	buckets, err := readBucketInfo(bucketsFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading buckets: %s\n", err)
		os.Exit(1)
	}

	var mu sync.Mutex
	version := 0                   // incremented on every update of results
	updated := make(chan struct{}) // closed and replaced on every update of results
	results := make([]bucketResult, len(buckets))
	for i, b := range buckets {
		results[i].Name = b.name
	}

	ctx := context.Background()
	clients := make([]*s3.Client, len(buckets))
	for i, b := range buckets {
		clients[i], err = newClient(ctx, b)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error creating S3 client for %s: %s\n", b.name, err)
			os.Exit(1)
		}
	}

	go func() {
		prevKeys := make([][]string, len(buckets)) // keys plotted last, nil if the last attempt failed
		for {
			since := time.Now().UTC().Add(-maxAge)
			for i, b := range buckets {
				var png []byte
				var stats []stat
				keys, err := listKeys(ctx, clients[i], b.name, since)
				if err == nil {
					if slices.Equal(keys, prevKeys[i]) {
						continue
					}
					png, stats, err = plot(ctx, clients[i], b.name, keys, offplot)
				}
				mu.Lock()
				if err != nil {
					fmt.Fprintf(os.Stderr, "Error plotting %s: %s\n", b.name, err)
					prevKeys[i] = nil
					results[i].Error = err.Error()
				} else {
					prevKeys[i] = keys
					results[i].Image = template.URL("data:image/png;base64," +
						base64.StdEncoding.EncodeToString(png))
					results[i].Stats = stats
					results[i].Updated = time.Now().UTC().Format("2006-01-02 15:04:05")
					results[i].Error = ""
				}
				version++
				close(updated)
				updated = make(chan struct{})
				mu.Unlock()
			}
			time.Sleep(poll)
		}
	}()

	http.HandleFunc("/{$}", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		page := struct {
			MaxAge  float64
			Version int
			Buckets []bucketResult
		}{maxAge.Hours(), version, slices.Clone(results)}
		mu.Unlock()
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		pageTemplate.Execute(w, page)
	})
	// Server-sent events: the current version on connect and on every update.
	http.HandleFunc("/events", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-store")
		for {
			mu.Lock()
			v, ch := version, updated
			mu.Unlock()
			fmt.Fprintf(w, "data: %d\n\n", v)
			if err := http.NewResponseController(w).Flush(); err != nil {
				return
			}
			select {
			case <-ch:
			case <-r.Context().Done():
				return
			}
		}
	})

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error listening on %s: %s\n", addr, err)
		os.Exit(1)
	}
	url := "http://" + addr
	fmt.Fprintf(os.Stderr, "Serving on %s\n", url)
	if runtime.GOOS == "darwin" {
		if err := exec.Command("open", url).Run(); err != nil {
			fmt.Fprintf(os.Stderr, "Error opening browser: %s\n", err)
		}
	}
	if err := http.Serve(ln, nil); err != nil {
		fmt.Fprintf(os.Stderr, "Error serving: %s\n", err)
		os.Exit(1)
	}
}
