FROM tomcat:6.0

MAINTAINER julian.thome@uni.lu

RUN wget -O "/usr/local/tomcat/webapps/WebGoat-5.4.war" "https://www.dropbox.com/s/7a5ubt4kev4y555/WebGoat-5.2.war?dl=1" 

RUN mkdir /opt/webgoat-src
RUN mkdir /opt/joanaudit

RUN wget -O "/opt/joanaudit/joanaudit-1.0-jar-with-dependencies.jar" "https://www.dropbox.com/s/wb8d8eoar0pgj1w/joanaudit-1.0-jar-with-dependencies.jar?dl=1"
RUN wget -O "/opt/webgoat-src/WebGoat-5.4-src.tar.gz" "https://www.dropbox.com/s/grjr98cpi0fwaj7/WebGoat-5.4-src.tar.gz?dl=1"

COPY lept.sh /opt/joanaudit
COPY check.sh /opt/joanaudit
RUN chmod +x /opt/joanaudit/*.sh

RUN cd /opt/webgoat-src && tar xvf "WebGoat-5.4-src.tar.gz"
COPY tomcat-users.xml /usr/local/tomcat/conf

RUN echo "deb http://ppa.launchpad.net/webupd8team/java/ubuntu xenial main" | \
  tee /etc/apt/sources.list.d/webupd8team-java.list
RUN echo "deb-src http://ppa.launchpad.net/webupd8team/java/ubuntu xenial main" | \
  tee -a /etc/apt/sources.list.d/webupd8team-java.list
RUN apt-key adv --keyserver hkp://keyserver.ubuntu.com:80 --recv-keys EEA14886
RUN apt-get update
RUN echo debconf shared/accepted-oracle-license-v1-1 select true | debconf-set-selections
RUN echo debconf shared/accepted-oracle-license-v1-1 seen true | debconf-set-selections
RUN apt-get -y install oracle-java8-installer apache2 openssh-server git-core maven
RUN sed -i 's/PermitRootLogin without-password/PermitRootLogin yes/' /etc/ssh/sshd_config

RUN echo "root:root" | chpasswd

RUN mkdir -p /var/lock/apache2 /var/run/apache2 /var/run/sshd /var/log/supervisor
RUN cd /opt/joanaudit && git clone https://github.com/julianthome/joanaudit.git

RUN wget -O "/opt/joanaudit/servlet_stubs.jar" "https://www.dropbox.com/s/ncqejezhu8ov5uu/servlet_stubs.jar?dl=1"
RUN wget -O "/opt/joanaudit/wg_stubs.jar" "https://www.dropbox.com/s/j0bbvah7wfcnodr/wg_stubs.jar?dl=1"

env APACHE_RUN_USER    www-data
env APACHE_RUN_GROUP   www-data
env APACHE_PID_FILE    /var/run/apache2.pid
env APACHE_RUN_DIR     /var/run/apache2
env APACHE_LOCK_DIR    /var/lock/apache2
env APACHE_LOG_DIR     /var/log/apache2
env LANG               C

EXPOSE 80
EXPOSE 22

COPY starter.sh starter.sh
RUN chmod +x starter.sh
CMD ./starter.sh
