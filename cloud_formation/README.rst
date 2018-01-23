Cloud Formation to deploy al_agent_install_report_sns
=====================================================
This CloudFormation will launch 2 lambda function, the encryption helper lambda (to encrypt environment variables) and the main function to generate report.
All output will be published to SNS end point. You will need to manually subscribe to the SNS end point (i.e. use Email)

Parameters
------------
* ParentCID = the target Alert Logic account ID that you wish to generate the report.
* Datacenter = choose your data residency, either ASHBURN, DENVER or NEWPORT
* UserName = this can be either your login email address or your Access Key
* Password = this can be either your login password or your Secret Key
* APIKey = Cloud Defender API Key


Contributing
------------
Since this is just an example, the script will be provided AS IS, with no long-term support.

License and Authors
===================
License:
Distributed under the Apache 2.0 license.

Authors:
Welly Siauw (welly.siauw@alertlogic.com)
