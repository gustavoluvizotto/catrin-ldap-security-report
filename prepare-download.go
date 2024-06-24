package main

import (
	"context"
	"errors"
	"fmt"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"os"
	"regexp"
	"sort"
	"strconv"
)

const (
	endpoint              = "localhost:8080"
	bucket                = "catrin"
	zmapS3FilePrefix      = "measurements/tool=zmap/dataset=default"
	goscannerS3FilePrefix = "measurements/tool=goscanner/format=raw"
)

func main() {
	minioClient, err := getMinioClient("read")
	if err != nil {
		panic(err)
	}
	portNr, err := getZmapPorts(minioClient)
	if err != nil {
		panic(err)
	}

	zmapPortDate, err := getLatestDates(minioClient, portNr, zmapS3FilePrefix)
	if err != nil {
		panic(err)
	}

	err = writeZmapPortDate(zmapPortDate)
	if err != nil {
		panic(err)
	}

	goscannerPortDate, err := getLatestDates(minioClient, []int{636, 389}, goscannerS3FilePrefix)
	if err != nil {
		panic(err)

	}

	err = writeGoscannerPortDate(goscannerPortDate)
	if err != nil {
		panic(err)
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

func getZmapPorts(minioClient *minio.Client) ([]int, error) {
	re := regexp.MustCompile(`.*/port=(\d+)/.*`)
	listOpts := minio.ListObjectsOptions{
		Prefix:    zmapS3FilePrefix,
		Recursive: true,
	}
	ctx := context.Background()
	port := make(map[int]bool)
	for obj := range minioClient.ListObjects(ctx, bucket, listOpts) {
		if obj.Err != nil {
			return nil, obj.Err
		}
		matches := re.FindStringSubmatch(obj.Key)
		if matches == nil || len(matches) < 2 {
			return nil, errors.New("no matches")
		}
		portNr, err := strconv.Atoi(matches[1])
		if err != nil {
			continue
		}
		port[portNr] = true
	}

	var portNr []int
	for k := range port {
		portNr = append(portNr, k)
	}
	return portNr, nil
}

func getLatestDates(minioClient *minio.Client, portNr []int, prefix string) (map[int]string, error) {
	listOpts := minio.ListObjectsOptions{
		Prefix:    prefix,
		Recursive: true,
	}
	ctx := context.Background()
	latestDateList := make(map[int][]string)
	for obj := range minioClient.ListObjects(ctx, bucket, listOpts) {
		if obj.Err != nil {
			return nil, obj.Err
		}
		for _, p := range portNr {
			re := regexp.MustCompile(fmt.Sprintf(`.*/port=%d.*(year=(\d{4})/month=(\d{2})/day=(\d{2}))/.*`, p))
			if re.MatchString(obj.Key) {
				matches := re.FindStringSubmatch(obj.Key)
				if matches == nil || len(matches) < 5 {
					return nil, errors.New("no matches")
				}
				year := matches[2]
				month := matches[3]
				day := matches[4]
				date := fmt.Sprintf("%s%s%s", year, month, day)
				if _, ok := latestDateList[p]; !ok {
					latestDateList[p] = []string{date}
				} else {
					latestDateList[p] = append(latestDateList[p], date)
				}
			}
		}
	}

	latestDate := make(map[int]string)
	for k, _ := range latestDateList {
		sort.Strings(latestDateList[k])
		last := len(latestDateList[k]) - 1
		latestDate[k] = latestDateList[k][last]
	}
	return latestDate, nil
}

func writeZmapPortDate(portDate map[int]string) error {
	file, err := os.Create("zmap-port-date.csv")
	if err != nil {
		return err
	}
	defer file.Close()

	// Write the map to the csv file: port,timestamp
	for portNr, timestamp := range portDate {
		_, err = file.WriteString(fmt.Sprintf("%d,%s\n", portNr, timestamp))
		if err != nil {
			return err
		}
	}
	return nil
}

func writeGoscannerPortDate(portDate map[int]string) error {
	file, err := os.Create("goscanner-port-date.csv")
	if err != nil {
		return err
	}
	defer file.Close()

	// Write the map to the csv file: port,scan,result,timestamp
	// Note: commented out unnecessary data download
	for portNr, timestamp := range portDate {

		scan := "ldap_metadata"
		result := "ldap_root_dse"
		_, err = file.WriteString(fmt.Sprintf("%d,%s,%s,%s\n", portNr, scan, result, timestamp))
		if err != nil {
			return err
		}
		//result = "ldap_schema"
		//_, err = file.WriteString(fmt.Sprintf("%d,%s,%s,%s\n", portNr, scan, result, timestamp))
		//if err != nil {
		//	return err
		//}

		if portNr == 389 {
			scan = "starttls_ldap"
			result = "starttls_ldap"
		} else { // portNr == 636
			scan = "ldap"
			result = "ldap"
		}
		_, err = file.WriteString(fmt.Sprintf("%d,%s,%s,%s\n", portNr, scan, result, timestamp))
		if err != nil {
			return err
		}

		scan = "tcp"
		result = "hosts"
		_, err = file.WriteString(fmt.Sprintf("%d,%s,%s,%s\n", portNr, scan, result, timestamp))
		if err != nil {
			return err
		}

		scan = "tls"
		result = "cert_chain"
		_, err = file.WriteString(fmt.Sprintf("%d,%s,%s,%s\n", portNr, scan, result, timestamp))
		if err != nil {
			return err
		}
		result = "certs"
		_, err = file.WriteString(fmt.Sprintf("%d,%s,%s,%s\n", portNr, scan, result, timestamp))
		if err != nil {
			return err
		}
		//result = "tls-keylog"
		//_, err = file.WriteString(fmt.Sprintf("%d,%s,%s,%s\n", portNr, scan, result, timestamp))
		//if err != nil {
		//	return err
		//}
		result = "tls_verbose"
		_, err = file.WriteString(fmt.Sprintf("%d,%s,%s,%s\n", portNr, scan, result, timestamp))
		if err != nil {
			return err
		}
	}
	return nil
}
