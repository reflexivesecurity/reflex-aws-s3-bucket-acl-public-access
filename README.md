# reflex-aws-s3-bucket-acl-public-access
Detect when a bucket has ACL rules that grant public access.
## Usage
To use this rule either add it to your `reflex.yaml` configuration file:  
```
rules:
  - reflex-aws-s3-bucket-acl-public-access:
      version: latest
```

or add it directly to your Terraform:  
```
...

module "reflex-aws-s3-bucket-acl-public-access" {
  source           = "github.com/cloudmitigator/reflex-aws-s3-bucket-acl-public-access"
}

...
```

## License
This Reflex rule is made available under the MPL 2.0 license. For more information view the [LICENSE](https://github.com/cloudmitigator/reflex-aws-s3-bucket-acl-public-access/blob/master/LICENSE) 