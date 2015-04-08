# Creating a TAP server.

This is directory structure on theserver:

1. Create a new user - rekalltest with home directory: /home/rekalltest/
2. Within this directory:
  - git clone -depth 1 https://github.com/google/rekall.git
  - git clone -depth 1 https://github.com/scudette/rekall-test.git

3. Create a new virtualenv environment for running tests:
  - virtualenv /home/rekalltest/Test

4. Serve the rekall-test directory via apache:
   - Edit /etc/apache2/sites-available/000-default.conf

```
<Directory /home/rekalltest/rekall-test/>
        Options Indexes FollowSymLinks
        AllowOverride None
        Require all granted
</Directory>

<VirtualHost *:80>
        ServerAdmin webmaster@localhost
        DocumentRoot /home/rekalltest/rekall-test/
        ServerName tap.rekall-forensic.com

        ErrorLog ${APACHE_LOG_DIR}/error.log
        CustomLog ${APACHE_LOG_DIR}/access.log combined
        Include conf-available/serve-cgi-bin.conf
</VirtualHost>
```

Now copy submit.py to /usr/lib/cgi-bin/ make it executable and edit the file to
set the password and control file location. The control file is written by the
cgi script and this kicks off the entire process so we need to ensure this is
somewhere the apache user can write to.


Finally start the `runner.sh`. This program just checks for the control file
every few seconds and if it is found, it launches the main script `run_test.sh`
and then removes the control file.