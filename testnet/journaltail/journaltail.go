package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/feature/s3/transfermanager"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

const (
	maxBufferLength = 4 * 1024 * 1024
	uploadTimeout   = 4 * time.Second
)

type uploadRequest struct {
	bucket string
	key    string
	data   []byte
}

func newKey(unit string) string {
	timestamp := time.Now().UTC().Format("20060102-150405.000")
	return fmt.Sprintf("%s_%s.log.gz", unit, timestamp)
}

func compressData(data []byte) ([]byte, error) {
	var buf bytes.Buffer
	wr := gzip.NewWriter(&buf)
	if _, err := wr.Write(data); err != nil {
		return nil, err
	}
	if err := wr.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func uploadData(cfg aws.Config, bucket, key string, data []byte) error {
	data, err := compressData(data)
	if err != nil {
		return err
	}
	tm := transfermanager.New(s3.NewFromConfig(cfg))
	ctx, cancel := context.WithTimeout(context.Background(), uploadTimeout)
	defer cancel()
	_, err = tm.UploadObject(ctx, &transfermanager.UploadObjectInput{
		Bucket:      aws.String(bucket),
		Key:         aws.String(key),
		Body:        bytes.NewReader(data),
		ContentType: aws.String("application/gzip"),
	})
	if err != nil {
		return err
	}
	return nil
}

func queueUpload(ch chan uploadRequest, bucket, key string, data []byte) {
	select {
	case ch <- uploadRequest{
		bucket: bucket,
		key:    key,
		data:   data,
	}:
	default:
		fmt.Fprintf(os.Stderr, "Upload channel full, discarding buffer (%d bytes) for key: %s\n",
			len(data), key)
	}
}

func startUploader(cfg aws.Config, wg *sync.WaitGroup, ch chan uploadRequest) {
	wg.Add(1)
	go func() {
		defer wg.Done()
		for req := range ch {
			fmt.Fprintf(os.Stderr, "Uploading %d bytes to S3: %s/%s\n",
				len(req.data), req.bucket, req.key)
			err := uploadData(cfg, req.bucket, req.key, req.data)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error uploading to S3: %s\n", err)
			}
		}
	}()
}

func main() {
	var (
		region string
		bucket string
		follow bool
	)
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [options] UNIT\n\n"+
			"Captures journald entries for the specified systemd unit and uploads to S3.\n\n"+
			"Options:\n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.StringVar(&region, "region", "us-east-1", "AWS S3 region")
	flag.StringVar(&bucket, "bucket", "", "AWS S3 bucket name (required)")
	flag.BoolVar(&follow, "f", false, "Follow the journal (wait for new entries)")
	flag.Parse()
	if bucket == "" {
		fmt.Fprintf(os.Stderr, "Error: AWS S3 bucket name is required\n")
		flag.Usage()
		os.Exit(1)
	}
	if flag.NArg() != 1 {
		fmt.Fprintf(os.Stderr, "Error: Systemd unit name is required\n")
		flag.Usage()
		os.Exit(1)
	}
	unit := flag.Arg(0)
	if unit == "" {
		fmt.Fprintf(os.Stderr, "Error: Systemd unit name is required\n")
		flag.Usage()
		os.Exit(1)
	}

	cfg, err := config.LoadDefaultConfig(context.TODO(), config.WithRegion(region))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading AWS config: %s\n", err)
		os.Exit(1)
	}

	ch := make(chan uploadRequest, 1) // cap(ch) == 1; only one upload at a time
	var wg sync.WaitGroup
	startUploader(cfg, &wg, ch)
	cleanup := func() {
		close(ch)
		wg.Wait()
	}

	args := []string{"-u", unit}
	if follow {
		args = append(args, "-f")
	}
	cmd := exec.Command("journalctl", args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating stdout pipe: %s\n", err)
		cleanup()
		os.Exit(1)
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "Error starting journalctl: %s\n", err)
		cleanup()
		os.Exit(1)
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		cmd.Process.Kill()
	}()

	var buf []byte
	key := newKey(unit)
	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		line := scanner.Text() + "\n"
		buf = append(buf, line...)
		if len(buf) >= maxBufferLength {
			queueUpload(ch, bucket, key, bytes.Clone(buf))
			key = newKey(unit)
			buf = buf[:0]
		}
	}
	if err := scanner.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "Error reading journalctl output: %s\n", err)
	}

	if len(buf) > 0 {
		queueUpload(ch, bucket, key, bytes.Clone(buf))
	}

	if err := cmd.Wait(); err != nil {
		if _, ok := err.(*exec.ExitError); !ok {
			fmt.Fprintf(os.Stderr, "Error running journalctl: %s\n", err)
			cleanup()
			os.Exit(1)
		}
	}

	cleanup()
	os.Exit(0)
}
