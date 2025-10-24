# API for scanning files for viruses

### Build docker
```
export DATABASE_URI="YOUR POSTGRESS DB URL"
export CLAMD_HOST="YOUR HOSTNAME"
export CLAMD_PORT=3310

docker build --build-arg DATABASE_URI=$DATABASE_URI --build-arg CLAMD_HOST=$CLAMD_HOST --build-arg CLAMD_PORT=$CLAMD_PORT -t clamav-api:latest .

```
### Start
```
docker compose up -d
```

### Create access token
In postgress DB:
```
\c clamav

insert into api_token(token,description) values ('a2b45e7eaa7a4376cffb1b13fd313421','COMMENT HERE');
```

## HOW TO USE
```
curl http://127.0.0.1:5000/scan -v -X POST -F "file=@test_file" -H "Authorization: Bearer a2b45e7eaa7a4376cffb1b13fd313421"
```
The response comes in JSON format and contains information about the verification status of the uploaded file.

### Example of a successful response:
 ```
{
  "test2.zip": {
    "contents": {
      "ca.cer": {
        "status": "CLEAN"
      },
      "test-new.zip": {
        "contents": {
          "Trololo.exe": {
            "status": [
              "FOUND",
              "Win.Trojan.MSIL-31"
            ]
          },
          "test-pas.zip": {
            "contents": {},
            "status": "PASSWORD_PROTECTED"
          }
        },
        "status": [
          "FOUND",
          "Win.Trojan.MSIL-31"
        ]
      }
    },
    "status": [
      "FOUND",
      "Nested archive contains threats"
    ]
  }
}
```

### Response field descriptions
CLEAN – the file is safe, no malicious objects were found.

FOUND – a threat was detected in the file, its name is indicated (e.g., Win.Trojan.MSIL-31).

error – if an error occurred while processing the file.

PASSWORD_PROTECTED – if the file could not be verified (e.g., because it is password-protected).

### Example response for an error
```
{
  "error": "File size is more than 100MB"
}
```

### Restrictions
Maximum upload size: 100 MB.

If the uploaded file is an archive, it will be automatically unzipped and its contents verified.

Password-protected archives cannot be verified
