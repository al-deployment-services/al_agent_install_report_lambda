Using Alert Logic API to check AL Agent install status with Lambda and SNS
==========================================================================
This is adaptation from the original code: https://github.com/fss18/al_agent_install_report
The main difference is this example run via Lambda function and utilize SNS to send the report (i.e. as email)

This is a demonstration script on how to use Alert Logic Cloud Defender and Cloud Insight API in order to check status of AL Agent installation in your environment.
Two API end-point that will be used in this demonstration:

* Cloud Defender API (https://docs.alertlogic.com/developer/)
* Cloud Insight API (https://console.cloudinsight.alertlogic.com/api/#/)

Requirements
------------
* AWS credentials with sufficient permission to deploy Lambda, IAM roles, SNS, KMS key and launch Cloud Formation (optional)
* Alert Logic Account ID (CID)
* Credentials to Alert Logic Cloud Insight (user name and password, or access key and secret key)
* Credentials to Alert Logic Cloud Defender API (API KEY)
* This sample script will check both parent Alert Logic CID and the respective child, your credentials must have access to child CID


Sample Usage
------------
* Use the provided Cloud Formation to quickly deploy the stack.
* Alternatively you can use the provided Lambda packages and deploy it by your self.
* Or adapt the source code and use it on your own custom Lambda code.


Contributing
------------
Since this is just an example, the script will be provided AS IS, with no long-term support.

License and Authors
===================
License:
Distributed under the Apache 2.0 license.

Authors:
Welly Siauw (welly.siauw@alertlogic.com)
