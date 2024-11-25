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

function usage {
    echo "Usage:"
    echo " ${0##*/} {-curl options} [PUT|GET] {file://path-to-file} s3://URI"
    echo "    PUT:          PutObject from file://filname to S3://URL"
    echo "    GET:          GetObject from s3://URL to current directory"
    echo "    path-to-file: Required when PUT"
    echo "    URI:          Required Object URI when GET"
}

# Check whether jq is installed
which jq > /dev/null 2&>1
if [ $? -ne 0 ]; then
    echo "ERROR: jq is not installed."
    echo "Please install jq, with sudo yum install jq or sudo apt install jq"
    exit 1
fi
# Evaluate args.
for i in $(seq 1 $#); do
    #PUT か GETであればコマンドとして扱う
    if [ "$1" == "PUT" ] || [ "$1" == "GET" ]; then
        CMD=$1
    #S3://で始まる引数をS3URIとして扱う
    elif [ ${1:0:5} == "s3://" ]; then
        S3URL=$(echo "$1" | sed 's#s3://##g')
        BUCKET=${S3URI%%/*}
        OBJECT=${S3URI#*/}
    #file://で始まる引数をファイルとして扱う
    elif [ ${1:0:7} == "file://" ]; then
        UPLOAD_FILE=$(echo "$1" | sed 's#file://##g')
    #それ以外はcurlオプションとして扱う
    else
        OPTIONS=$(eval echo "$OPTIONS $1")
    fi
    shift #切り捨てて次の引数を$1で評価できるようループ
done
# Check args' error
if [ -z $CMD ] || [ -z $S3URI ]; then #必須引数がない
    usage
    exit 1
elif [ $CMD == "PUT" ] && [ -z $UPLOAD_FILE ]; then #PUTだがファイル引数がない
    usage
    exit 1
elif [ $CMD == "GET"] && [ -z $OBJECT]; then #GETだがS3 URIにobject名がない
    usage
    exit 1
fi

#クレデンシャルを動作環境に応じて取得
EC2=$(grep compute.internal /etc/resolv.conf)
if [ "$EC2" ]; then
    # echo "Using IAM Role credentials"
    IMDSv2_TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
    ROLE=$(curl -s -H "X-aws-ec2-metadata-token: $IMDSv2_TOKEN" http://169.254.169.254/latest/meta-data/iam/security-credentials)
    RET=$(curl -s -H "X-aws-ec2-metadata-token: $IMDSv2_TOKEN" http://169.254.169.254/latest/meta-data/iam/security-credentials/${ROLE})
    ACCKEY=$(echo $RET | jq -r '.AccessKeyId')
    SECKEY=$(echo $RET | jq -r '.SecretAccessKey')
    TOKEN=$(echo $RET | jq -r '.SessionToken')
    CONTENT="host;x-amz-content-sha256;x-amz-date;x-amz-security-token"
    TOKEN_HEADER="x-amz-security-token: $TOKEN"
elif [ -n "$AWS_ACCESS_KEY_ID" ]; then
    # echo "Using short-term credentials"
    ACCKEY=${AWS_ACCESS_KEY_ID}
    SECKEY=${AWS_SECRET_ACCESS_KEY}
    TOKEN=${AWS_SESSION_TOKEN}
    CONTENT="host;x-amz-content-sha256;x-amz-date;x-amz-security-token"
    TOKEN_HEADER="x-amz-security-token: $TOKEN"
elif [ -e ~/.aws/credentials ]; then
    ACCKEY=$(aws configure get aws_access_key_id)
    SECKEY=$(aws configure get aws_secret_access_key)
    TOKEN=$(aws configure get aws_session_token)
    if [ -z "$TOKEN" ]; then
        # echo "Using long-term AccessKey"
        CONTENT="host;x-amz-content-sha256;x-amz-date"
        unset TOKEN_HEADER
    else
        # echo "Using short-term credentials (i.e. MFA)"
        CONTENT="host;x-amz-content-sha256;x-amz-date;x-amz-security-token"
        TOKEN_HEADER="x-amz-security-token: $TOKEN"
    fi
else
    echo "Error: Cannot resolve AWS_ACCESS_KEY_ID : AWS_SECRET_ACCESS_KEY"
    exit 1
fi

#PUTだったら転送するファイルのハッシュ値を計算、ファイル名をオブジェクト名にする
if [ "$CMD" == "PUT" ]; then
    SHA256=$(cat "$UPLOAD_FILE" | openssl dgst -sha256 | awk '{print $2}')
    OBJECT=${UPLOAD_FILE##*/}
    OPTIONS=$(eval echo "-s $UPLOAD_FILE $OPTIONS $1")
else
    SHA256=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
fi
DATE=$(date -u "+%Y%m%dT%H%M%SZ")
SIGN_DATE=$(date -u "+%Y%m%d"
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

# AWS SignatureV4を計算する
# Step1: Canonical RequestとそのHashを取得
if [ -z "$TOKEN_HEADER" ]; then
    REQUEST_STR="$CMD\\n/$BUCKET/$OBJECT\\n\\nhost:s3.ap-northeast-1.amazonaws.com\\nx-amz-content-sha256:$SHA256\\nx-amz-date:$DATE\\n\\n$CONTENT\\n$SHA256"
else
    REQUEST_STR="$CMD\\n/$BUCKET/$OBJECT\\n\\nhost:s3.ap-northeast-1.amazonaws.com\\nx-amz-content-sha256:$SHA256\\nx-amz-date:$DATE\\nx-amz-security-token:$TOKEN\\n\\n$CONTENT\\n$SHA256"
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

#リクエスト送信
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