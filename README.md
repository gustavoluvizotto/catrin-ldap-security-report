# catrin-ldap-security-report

## Requirements

You two credentials files: ```credentials``` and ```credentials_clickhouse.py```  

credentials:  

```shell
[read]
aws_access_key_id = 
aws_secret_access_key = 
```

credentials_clickhouse.py:  

```python
default_user = ""
aws_access_key_id = ""
aws_secret_access_key = ""
```

The ```aws``` keys are to access the S3 data storage and the ```default_user``` is the key of the clickhouse database default user.  

You must have clickhouse installed. Please see https://clickhouse.com/docs/en/install#available-installation-options.
Then, you must start the clickhouse server as super user:

```shell
service clickhouse-server start
```

## Usage

First run the prepare script, to setup the Python environment and the clickhouse database:  

```shell
./prepare.sh
```

Then run the flask application. You may want to run this application within a tmux (or screen):  

```shell
venv/bin/python app.py
```
