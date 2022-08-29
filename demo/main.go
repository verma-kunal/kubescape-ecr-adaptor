package main

import (
	"context"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	"github.com/aws/aws-sdk-go-v2/service/ecr/types"
	"github.com/aws/aws-sdk-go/aws"
	"log"
)

// vulnerabilityOut returns the scan results
func vulnerabilityOut(output *ecr.DescribeImageScanFindingsOutput) {

	findings := output.ImageScanFindings.Findings                   // array
	severityCount := output.ImageScanFindings.FindingSeverityCounts // map
	scanStatus := output.ImageScanStatus

	// fetching all the scan findings:
	for index := range findings {
		fmt.Printf("{%v - %v} {%v}\n\n", *findings[index].Name, *findings[index].Description, findings[index].Severity)
		//fmt.Printf("%v\n", *findings[index].Uri) // the URLs for all severities (more info)
	}

	fmt.Println(" -------------------------------------------------------------------------------")

	// fetching total severity count:
	for key, value := range severityCount {
		fmt.Println(key, "=>", value)
	}
	fmt.Println(" -------------------------------------------------------------------------------")

	// printing out the scan status:
	fmt.Printf("%v", *scanStatus.Description)

}

func main() {

	ctx := context.TODO()
	// Loading the AWS shared configuration:
	cfg, err := config.LoadDefaultConfig(ctx, config.WithSharedConfigProfile("default"))
	if err != nil {
		log.Fatalf("failed to load configuration, %v", err)
	}

	// Creating an ECR service client:
	client := ecr.NewFromConfig(cfg)

	// entering the details of the image - of which we want to find the vulnerabilities
	scanFindings, err := client.DescribeImageScanFindings(ctx, &ecr.DescribeImageScanFindingsInput{
		ImageId: &types.ImageIdentifier{
			ImageDigest: aws.String("sha256:5045e645eb8963b389d773acd5b769020a0ad893564484c3bd9554186104c6d3"),
			ImageTag:    aws.String("latest"),
		},
		RepositoryName: aws.String("hello-world"),
	})
	if err != nil {
		log.Fatal(err)
	}

	// calling out the results here:
	vulnerabilityOut(scanFindings)

}
