graylog2-plugin-output-socket
=============================

Graylog2 plugin to output message stream to socket

Socket is hardcoded at moment to 1978. The nature of how the plugin is initialised is
why this cant be a config option - others may spot a means ... the plugin will output
lines in a 'parsable' format - prepending, host, level, info etc, with the message at
the end.

Compile, (mvn clean package) and rename the target jar (rename.sh), then copy 
to the graylog2 servers plugin/outputs directory and do a restart. It compiles to a
nice small jar.

To get all messages to the plugin, create a stream (called Tail in our case) that
collects all DEBUG level messages and up, in the 'Outputs' tab, attach it to the
socket plugin. Now telnet to the graylog server on the port and enjoy ...

Ive included a perl script that will connect to a graylog2 server using this plugin
and parse, then format messages from the port ... use -h to see options, typically:

./graylog2_tail.pl -g logs.test.box -p -s ERROR,DEBUG -h web -f foo,bar

this will connect to the logs.test.box graylog2 server (make sure the 1978 port
is open) and display messages with severity ERROR or DEBUG, from hosts containing
the string 'web' and facilities with strings 'foo' or 'bar'
