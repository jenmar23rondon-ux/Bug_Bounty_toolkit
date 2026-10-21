# Provider CNAME References

The toolkit uses local CNAME suffix patterns as routing hints, not provider error-page fingerprints. Provider domains and product behavior can change; update these patterns only from current provider documentation.

| Provider | Initial CNAME pattern | Primary reference |
| --- | --- | --- |
| Amazon S3 | Regional `s3` and `s3-website` endpoints under `amazonaws.com` | [S3 website endpoints](https://docs.aws.amazon.com/AmazonS3/latest/userguide/WebsiteEndpoints.html), [S3 virtual hosting](https://docs.aws.amazon.com/AmazonS3/latest/userguide/VirtualHosting.html) |
| Heroku | `herokudns.com`, `herokuapp.com` | [Heroku custom domains](https://devcenter.heroku.com/articles/custom-domains) |
| GitHub Pages | `github.io` | [GitHub Pages custom domains](https://docs.github.com/en/pages/configuring-a-custom-domain-for-your-github-pages-site/managing-a-custom-domain-for-your-github-pages-site) |
| Netlify | `netlify.app` | [Netlify custom domains](https://docs.netlify.com/domains-https/custom-domains/) |

These patterns only recognize that a hostname routes toward a known provider. They do not inspect provider error pages, check resource availability, or prove a dangling configuration. A DNS match must be independently reviewed with the service owner and program policy.
