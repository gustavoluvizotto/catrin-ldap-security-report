package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"github.com/rs/zerolog/log"
)

const (
	endpoint = "localhost:8080"
	bucket   = "catrin"
)

func main() {
	var portArg int
	flag.IntVar(&portArg,
		"port",
		0,
		"Port number to add to the upload path")

	var logFile string
	flag.StringVar(&logFile,
		"log-file",
		"",
		"Path to the log file")

	var scanDateArg string
	flag.StringVar(&scanDateArg,
		"scan-date",
		"",
		"Date the certificates were collected. Format: YYYYMMDD")

	var protocolArg string
	flag.StringVar(&protocolArg,
		"protocol",
		"",
		"Protocol used on the traceroute, e.g. tcp, udp, icmp")

	var link string
	flag.StringVar(&link,
		"link",
		"",
		"Link used in the traceroute, e.g. starlink, uva, internet, 2stic")

	flag.Parse()

	if logFile == "" {
		log.Fatal().Msg("Log file is required")
	}
	if portArg == 0 {
		log.Fatal().Msg("Port number is required")
	}
	if scanDateArg == "" {
		log.Fatal().Msg("Scan date is required")
	}
	if protocolArg == "" {
		log.Fatal().Msg("Protocol is required")
	}
	if link == "" {
		log.Fatal().Msg("Link is required")
	}

	resultPath := "results"
	filesToUpload, err := getFilesToUploadMap(logFile, portArg, scanDateArg, protocolArg, link, resultPath)
	if err != nil {
		log.Fatal().Err(err).Msg("Error getting upload files")
	}

	minioClient, err := getMinioClient("upload")
	if err != nil {
		log.Fatal().Err(err).Msg("Error getting Minio client")
	}

	for localFile, remoteFile := range filesToUpload {
		err = uploadS3(minioClient, localFile, remoteFile)
		if err != nil {
			log.Error().Err(err).Str("file", localFile).Msg("Error uploading file, try again...")
		} else {
			err2 := os.Remove(localFile)
			if err2 != nil {
				log.Warn().Err(err2).Msg("Could not remove file.")
			}
		}
	}
	if err != nil {
		log.Fatal().Err(err).Msg("Error uploading files, please check logs")
	}
}

func getMinioClient(profile string) (*minio.Client, error) {
	cred := credentials.NewFileAWSCredentials("credentials", profile)
	minioClient, err := minio.New(endpoint, &minio.Options{
		Creds:  cred,
		Secure: false,
	})
	if err != nil {
		return nil, err
	}
	return minioClient, nil
}

func getFilesToUploadMap(logFile string, port int, scanDate string, protocol string, link string, outputPath string) (map[string]string, error) {
	timestamp, err := time.Parse("20060102", scanDate)
	if err != nil {
		return nil, err
	}
	yearMonthDay := fmt.Sprintf("year=%04d/month=%02d/day=%02d", timestamp.Year(), timestamp.Month(), timestamp.Day())
	timestampStr := fmt.Sprintf("%04d%02d%02d", timestamp.Year(), timestamp.Month(), timestamp.Day())

	fileMap := make(map[string]string)

	if logFile != "" {
		fileMap[logFile] = fmt.Sprintf("artefacts/tool=mtr/vp=nl/link=%s/protocol=%s/port=%d/%s/mtr_%s.log",
			link, protocol, port, yearMonthDay, timestampStr)
	}

	outputFiles, err := getOutputFiles(outputPath)
	if err != nil {
		return nil, err
	}
	for _, outputFile := range outputFiles {
		// Extract the IPv4 address from the log file name
		ipv4, err := extractIPv4FromFilename(outputFile)
		if err != nil {
			return nil, err
		}
		// output file = mtr_35.213.199.152.csv; map entry = \
		// measurements/tool=mtr/format=csv/vp=nl/link=uva/protocol=icmp/port=22/year=2023/month=09/day=20/mtr_35.213.199.152.csv
		fileMap[outputFile] = fmt.Sprintf("measurements/tool=mtr/format=csv/vp=nl/link=%s/protocol=%s/port=%d/%s/mtr_%s.csv",
			link, strings.ToLower(protocol), port, yearMonthDay, ipv4)
	}
	return fileMap, nil
}

func getOutputFiles(outputPath string) ([]string, error) {
	var outputFiles []string
	files, err := os.ReadDir(outputPath)
	if err != nil {
		return outputFiles, err
	}

	for _, file := range files {
		if file.IsDir() {
			log.Warn().Str("directory", file.Name()).Msg("Skipping directory")
			continue
		}

		if filepath.Ext(file.Name()) != ".csv" {
			log.Warn().Str("fileName", file.Name()).Msg("Skipping non-CSV file")
			continue
		}
		outputFiles = append(outputFiles, filepath.Join(outputPath, file.Name()))
	}
	return outputFiles, nil
}

func extractIPv4FromFilename(filename string) (string, error) {
	// Regular expression to match IPv4 addresses
	// This pattern matches 4 groups of 1-3 digits separated by dots
	ipv4Pattern := `(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})`

	re := regexp.MustCompile(ipv4Pattern)

	// Find the first match in the filename
	match := re.FindString(filename)
	if match == "" {
		return "", fmt.Errorf("no IPv4 address found in filename: %s", filename)
	}

	return match, nil
}

func uploadS3(minioClient *minio.Client, localFile string, remoteFile string) error {
	file, err := os.Open(localFile)
	if err != nil {
		return err
	}
	defer func(file *os.File) {
		err := file.Close()
		if err != nil {
			log.Warn().Err(err).Msg("Error closing file.")
		}
	}(file)

	fileStat, err := file.Stat()
	if err != nil {
		return err
	}

	ctx := context.Background()
	opts := minio.PutObjectOptions{ContentType: "application/octet-stream", DisableMultipart: true}
	uploadInfo, err := minioClient.PutObject(ctx, bucket, remoteFile, file, fileStat.Size(), opts)
	if err != nil {
		return err
	}

	log.Info().Str("ETag", uploadInfo.ETag).Msg("Successfully uploaded")

	return nil
}
