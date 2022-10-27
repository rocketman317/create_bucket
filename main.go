package main

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
)

func main() {
	hash := md5.Sum([]byte(time.Now().UTC().String()))
	defaultPrefix := fmt.Sprintf("pf-%s", hex.EncodeToString(hash[:]))

	service := flag.Bool("service", false, "service name")
	key := flag.String("key", "", "access key to be used")
	secret := flag.String("secret", "", "secret to be used")
	prefix := flag.String("prefix", defaultPrefix, "prefix to be used")
	region := flag.String("region", "us-west-1", "region to be used")

	flag.Parse()

	ctx, _ := context.WithTimeout(context.Background(), time.Minute)

	if *key == "" {
		log.Fatalf("key is required")
	}

	if *secret == "" {
		log.Fatalf("secret is required")
	}

	accessKey, accessSecret := *key, *secret

	// if service option is enabled, we'll create a service account using the key and secret as Seagate Lyve API credentials.
	if *service {
		var err error
		accessKey, accessSecret, err = CreateServiceAccount(ctx, *key, *secret, *prefix)
		if err != nil {
			log.Fatalf("failed to create service account")
		}
	}

	// log the values we're using to create bucket
	endpoint := fmt.Sprintf("https://s3.%v.lyvecloud.seagate.com", *region)
	bucketName := fmt.Sprintf("%v-%v", *prefix, *region)
	log.Printf("trying to create a [%v] at [%v]", bucketName, endpoint)

	// create a session
	sess, err := session.NewSession(&aws.Config{
		Credentials:      credentials.NewStaticCredentials(accessKey, accessSecret, ""),
		Endpoint:         aws.String(endpoint),
		Region:           aws.String(*region),
		DisableSSL:       aws.Bool(false),
		S3ForcePathStyle: aws.Bool(true),
	})
	if err != nil {
		log.Fatalf("failed to create aws session: %v", err)
	}

	// create S3 client
	svc := s3.New(sess)

	// create a bucket
	_, err = svc.CreateBucketWithContext(ctx, &s3.CreateBucketInput{
		Bucket: aws.String(bucketName),
	})
	if err != nil {
		log.Fatalf("failed to create bucket [%v]: %v", bucketName, err)
	} else {
		log.Printf("successfully created bucket [%v]", bucketName)
	}
}
