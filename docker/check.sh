#!/bin/bash 

java -jar joanaudit-1.0-jar-with-dependencies.jar \
    -cfg $PWD/joanaudit/config/ \
    -cp "$PWD/servlet_stubs.jar:$PWD/wg_stubs.jar" \
    -dir "/usr/local/tomcat/webapps/WebGoat-5.4/WEB-INF/classes/" \
    -ept "org.owasp.webgoat.lessons.XPATHInjection.createContent(Lorg/owasp/webgoat/session/WebSession;)Lorg/apache/ecs/Element;" \
    -src "/opt/webgoat-src/WebGoat-5.4/src/" \
    -repout "/var/www/html" \
    -repfmt "HTML"

exit 0
