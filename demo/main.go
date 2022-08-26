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

/*
import (
	"context"
	"fmt"
	"log"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
)
*/

// vulnerabilityOut returns the scan results
func vulnerabilityOut(output *ecr.DescribeImageScanFindingsOutput) {

	// printing out the description of one of the vulnerabilities:
	fmt.Println(*output.ImageScanFindings.Findings[0].Description)

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
