# Use an official Ubuntu as a base image
FROM ubuntu:18.04

# Install dependencies
RUN apt-get update \
    && apt-get install -y \
        wget build-essential libxml2-dev libssl-dev libcurl4-openssl-dev libjpeg-dev \
        libpng-dev libfreetype6-dev libzip-dev libonig-dev libmcrypt-dev libsqlite3-dev \
        perl git unzip autoconf fonts-dejavu java-common libasound2 libfontconfig1 libxi6 \
        libxrender1 libxtst6 python3-pip graphviz libgraphviz-dev vim

RUN mkdir -p /usr/local/php7.0/etc/ \
    && mkdir -p /usr/local/php7.4/etc/

# Download and install PHP 7.0 from source
RUN mkdir -p /usr/src/php7.0 \
    && cd /usr/src/php7.0 \
    && wget https://www.php.net/distributions/php-7.0.33.tar.gz \
    && tar -xzvf php-7.0.33.tar.gz \
    && cd php-7.0.33 \
    && ./configure \
        --prefix=/usr/local/php7.0 \
        --with-config-file-path=/usr/local/php7.0/etc \
 		\
		--enable-cgi      \
		--enable-ftp      \
		--enable-mbstring \
		--with-gd         \
		\
		--with-mysql      \
		--with-openssl      \
		--with-mysqli      \
		--with-pdo-mysql  \
		--with-zlib       \
    && make \
    && make install

# Download and install PHP 7.4 from source
RUN mkdir -p /usr/src/php7.4 \
    && cd /usr/src/php7.4 \
    && wget https://www.php.net/distributions/php-7.4.33.tar.gz \
    && tar -xzvf php-7.4.33.tar.gz \
    && cd php-7.4.33 \
    && ./configure \
        --prefix=/usr/local/php7.4 \
        --with-config-file-path=/usr/local/php7.4/etc \
 		\
		--enable-cgi      \
		--enable-ftp      \
		--enable-mbstring \
		--with-gd         \
		\
		--with-mysql      \
		--with-openssl      \
		--with-mysqli      \
		--with-pdo-mysql  \
		--with-zlib       \
    && make \
    && make install

# Clean up
RUN apt-get clean \
    && rm -rf /var/lib/apt/lists/* /usr/src/*

# Set environment variables for PHP 7.0
ENV PATH="/usr/local/php7.0/bin:${PATH}"
ENV PHP_INI_DIR="/usr/local/php7.0/etc"

#+ install static analysis environment and tools +
RUN mkdir /static-tools && cd /static-tools &&\
    git clone https://github.com/nikic/php-ast.git &&\
    cd php-ast &&\
    git checkout 701e853 &&\
    phpize &&\
    ./configure &&\
    make && make install

# Set environment variables for PHP 7.4
ENV PATH="/usr/local/php7.4/bin:${PATH}"
ENV PHP_INI_DIR="/usr/local/php7.4/etc"

RUN cd /static-tools/php-ast &&\
    git checkout tags/v1.1.1 &&\
    phpize &&\
    ./configure &&\
    make && make install

# Add the extension configuration to php.ini
RUN echo 'extension=ast.so' | tee -a /usr/local/php7.0/etc/php.ini && \
    echo 'extension=ast.so' | tee -a /usr/local/php7.4/etc/php.ini && \
    echo 'memory_limit = -1' | tee -a /usr/local/php7.0/etc/php.ini && \
    echo 'memory_limit = -1' | tee -a /usr/local/php7.4/etc/php.ini

# install php-cs-fixer
RUN cd /static-tools &&\
    wget https://cs.symfony.com/download/php-cs-fixer-v3.phar -O php-cs-fixer &&\
    chmod +x php-cs-fixer

# install phpjeorn and TChecker
RUN cd /static-tools &&\
    git clone https://github.com/1TreeForest/phpjoern.git &&\
    git clone https://github.com/1TreeForest/TCheckerD.git
# Install OpenJDK 1.8
RUN cd /static-tools &&\
    wget https://builds.openlogic.com/downloadJDK/openlogic-openjdk/8u392-b08/openlogic-openjdk-8u392-b08-linux-x64-deb.deb &&\
    apt install -y ./openlogic-openjdk-8u392-b08-linux-x64-deb.deb &&\
    rm openlogic-openjdk-8u392-b08-linux-x64-deb.deb
#+ install gradle2
RUN cd /static-tools &&\
    wget https://services.gradle.org/distributions/gradle-2.1-bin.zip &&\
    unzip -d /opt/gradle gradle-2.1-bin.zip &&\
    ln -s /opt/gradle/gradle-2.1/bin/gradle /usr/bin/gradle &&\
    rm gradle-2.1-bin.zip
#+ install oldjoern
RUN cd /static-tools &&\
    git clone https://github.com/1TreeForest/joern.git &&\
    pip3 install pygraphviz==1.5 &&\
    ls -l &&\
    mv joern oldjoern &&\
    cd oldjoern &&\
    gradle build -x test