# Log_Reader
A Bash script to do some basic analysis on Apache access logs

It is expecting the log file to follow the following formatting:

    "%h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-agent}i\""

details on each field can be found here: https://httpd.apache.org/docs/1.3/logs.html
