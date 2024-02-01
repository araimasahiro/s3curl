#!/usr/bin/env bash
#References:
# https://czak.pl/2015/09/15/s3-rest-api-with-curl.html
# https://qiita.com/ototo/items/dab78254efd67c2bd110
#set -u

function hmac_sha256 {
  key="$1"
  data="$2"
  echo -n "$data" | openssl dgst -sha256 -mac HMAC -macopt "$key" | sed 's/^.* //'
}

# Evaluate args.
for x in $(seq 1 $#); do
    #S3://で始まる引数をS3URIとして扱い,それ以外はcurlコマンドにそのまま渡す 
    if [ ${1:0:5} == "s3://" ]; then
        S3URI=$(echo "$1" | sed 's#s3://##g')
        BUCKET=${S3URI%%/*}
        OBJECT=${S3URI#*/}
    else
        OPTIONS=$(eval echo "$OPTIONS $1")
    fi
    shift
done

EC2=$(grep compute.internal /etc/resolv.conf)
if [ "$EC2" ]; then
    echo "Using IAM Role credentials"
    ROLE=$(curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials)
    RET=$(curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/${ROLE})
    ACCKEY=$(echo $RET | jq -r '.AccessKeyId')
    SECKEY=$(echo $RET | jq -r '.SecretAccessKey')
    TOKEN=$(echo $RET | jq -r '.SessionToken')
    CONTENT="host;x-amz-content-sha256;x-amz-date;x-amz-security-token"
    TOKEN_HEADER="x-amz-security-token: $TOKEN"
elif [ -n "$AWS_ACCESS_KEY_ID" ]; then
    # echo "Using short-term AccessKey"
    ACCKEY=${AWS_ACCESS_KEY_ID}
    SECKEY=${AWS_SECRET_ACCESS_KEY}
    TOKEN=${AWS_SESSION_TOKEN}
    CONTENT="host;x-amz-content-sha256;x-amz-date;x-amz-security-token"
    TOKEN_HEADER="x-amz-security-token: $TOKEN"
elif [ -e ~/.aws/credentials ]; then
    # echo "Using long-term AccessKey"
    ACCKEY=$(aws configure get aws_access_key_id)
    SECKEY=$(aws configure get aws_secret_access_key)
    CONTENT="host;x-amz-content-sha256;x-amz-date"
    unset TOKEN_HEADER
else
    echo "Error: Cannot resolve AWS_ACCESS_KEY_ID : AWS_SECRET_ACCESS_KEY"
    return 0
fi

DATE=$(date -u "+%Y%m%dT%H%M%SZ")
SIGN_DATE=$(date -u "+%Y%m%d")
SHA256=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
# Four-step signing key calculation
region=ap-northeast-1
service=s3
dateKey=$(hmac_sha256 key:"AWS4$SECKEY" "$SIGN_DATE")
dateRegionKey=$(hmac_sha256 hexkey:$dateKey $region)
dateRegionServiceKey=$(hmac_sha256 hexkey:$dateRegionKey $service)
SIGNING_KEY=$(hmac_sha256 hexkey:$dateRegionServiceKey "aws4_request")
# echo ---
# echo BUCKET=$BUCKET
# echo OBJECT=$OBJECT
# echo DATE=$DATE
# echo ACCKEY=$ACCKEY
# echo SECKEY=$SECKEY
# echo SIGN_DATE=$SIGN_DATE
# echo SIGNING_KEY=$SIGNING_KEY
# echo CONTENT=$CONTENT
# echo TOKEN_HEADER=$TOKEN_HEADER
# echo ---

# Step1: Canonical RequestとそのHashを取得
if [ -z "$TOKEN_HEADER" ]; then
    REQUEST_STR="GET\\n/$BUCKET/$OBJECT\\n\\nhost:s3.ap-northeast-1.amazonaws.com\\nx-amz-content-sha256:$SHA256\\nx-amz-date:$DATE\\n\\n$CONTENT\\n$SHA256"
else
    REQUEST_STR="GET\\n/$BUCKET/$OBJECT\\n\\nhost:s3.ap-northeast-1.amazonaws.com\\nx-amz-content-sha256:$SHA256\\nx-amz-date:$DATE\\nx-amz-security-token:$TOKEN\\n\\n$CONTENT\\n$SHA256"
fi
REQUEST=$(echo -en "$REQUEST_STR" | openssl dgst -sha256 | awk '{print $2}')
# echo $REQUEST_STR
# echo REQUEST=$REQUEST
# echo ---

# Step2: Signature v4の作成
SIGNATURE_STR="AWS4-HMAC-SHA256\\n$DATE\\n$SIGN_DATE/ap-northeast-1/s3/aws4_request\\n$REQUEST"
SIGNATURE=$(echo -en "$SIGNATURE_STR" | openssl dgst -sha256 -mac HMAC -macopt hexkey:$SIGNING_KEY | awk '{print $2}')
# echo $SIGNATURE_STR
# echo SIGNATURE=$SIGNATURE
# echo ---

if [ -z "$TOKEN_HEADER" ]; then
curl https://s3.ap-northeast-1.amazonaws.com/$BUCKET/$OBJECT \
-H "Authorization: AWS4-HMAC-SHA256 Credential=$ACCKEY/$SIGN_DATE/$region/s3/aws4_request,SignedHeaders=$CONTENT,Signature=$SIGNATURE" \
-H "x-amz-content-sha256: $SHA256" \
-H "x-amz-date: $DATE" \
$OPTIONS
else
curl -v https://s3.ap-northeast-1.amazonaws.com/$BUCKET/$OBJECT \
-H "Authorization: AWS4-HMAC-SHA256 Credential=$ACCKEY/$SIGN_DATE/$region/s3/aws4_request,SignedHeaders=$CONTENT,Signature=$SIGNATURE" \
-H "x-amz-content-sha256: $SHA256" \
-H "x-amz-date: $DATE" \
-H "$TOKEN_HEADER" \
$OPTIONS
fi