chgrp -R www-data /flasksite_dynamic
chgrp -R www-data /flasksite_data
chmod -R ug=rwx,o-rwx /flasksite_dynamic
chmod -R ug=rwx,o-rwx /flasksite_data

service clickhouse-server start

./prepare.sh

/venv/bin/python3 app.py
